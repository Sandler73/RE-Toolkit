#!/usr/bin/env bash
# =============================================================================
# stages/static/83-authenticode.sh
# =============================================================================
#
# Synopsis:
#     Authenticode signature chain validation for PE targets.
#
# Description:
#     Type-guarded: only PE binaries (pe-native and pe-dotnet) carry
#     Authenticode signatures. The stage exits cleanly on non-PE input.
#
#     Builds on top of v2.4.0's pesec / osslsigncode invocation in stage_pe.
#     That stage extracts and parses; this stage validates the chain against
#     /etc/ssl/certs/ca-certificates.crt and checks the signer organization
#     against a bundled list of common code-signing CAs.
#
#     Sourced by analyze-binaries.sh; not directly executable. This file
#     defines the stage function only. The driver decides whether it runs,
#     based on the detected file type and the active skip controls.
#
# Execution Parameters:
#     $1  target   Path to the sandboxed copy of the target binary.
#     $2  outdir   Path to this target's output directory.
#
# Provides:
#     stage_authenticode()
#
# Output subtrees:
#     ${outdir}/83-authenticode/
#
# Skip controls:
#     SKIP_AUTHENTICODE
#
# Tools invoked (run_tool labels):
#     osslsigncode-verify, osslsigncode-verify-CAfile
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_authenticode() {
    local target="$1" outdir="$2"
    local ac="${outdir}/83-authenticode"

    if [[ ${SKIP_AUTHENTICODE:-0} -eq 1 ]]; then
        log_step "authenticode: skipped (SKIP_AUTHENTICODE=1)"
        return 0
    fi

    # Type guard: only run on PE binaries. detect_type was called once at
    # the top of analyze_one and stored in OUTPUT_ROOT/_run-manifest.txt;
    # but since this stage is invoked from dispatch.sh AFTER stage_iocs
    # which itself runs on all types, we re-test cheaply here.
    local file_out
    file_out=$(file -b "$target" 2>/dev/null)
    if ! echo "$file_out" | grep -qE "PE32|MS-DOS|Mono/.Net"; then
        log_step "authenticode: not a PE binary; skipping"
        return 0
    fi

    mkdir -p "$ac"

    # Step 1: chain validation against system CA store
    local CA_FILE=""
    for c in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do
        if [[ -f "$c" ]]; then CA_FILE="$c"; break; fi
    done

    if command -v osslsigncode >/dev/null 2>&1; then
        if [[ -n "$CA_FILE" ]]; then
            run_tool "osslsigncode-verify-CAfile" "${ac}/chain-validation.txt" 60 \
                osslsigncode verify -CAfile "$CA_FILE" -in "$target"
        else
            run_tool "osslsigncode-verify" "${ac}/chain-validation.txt" 60 \
                osslsigncode verify -in "$target"
            echo "WARN: no system CA file found at /etc/ssl/certs/ca-certificates.crt" >> "${ac}/chain-validation.txt"
        fi
    fi

    # Step 2: signer organization extraction & known-org check
    if [[ -f "${ac}/chain-validation.txt" ]]; then
        # osslsigncode output contains "Signer Certificate:" lines with subject DN
        grep -aE "Subject:|Issuer:|Signer Certificate" "${ac}/chain-validation.txt" \
            > "${ac}/signers.txt" 2>/dev/null || true
    fi

    # Step 3: known-good-signer match. Bundled list of common code-signing
    # organizations (Microsoft, Adobe, Google, Apple, Mozilla, ...). A
    # match here means "this looks legitimate"; absence does NOT mean
    # malicious - many legitimate small vendors don't appear.
    {
        echo "=== Known code-signing organization match ==="
        if [[ -s "${ac}/signers.txt" ]]; then
            local known_orgs=(
                "Microsoft Corporation" "Microsoft Code Signing"
                "Adobe Systems" "Adobe Inc"
                "Google LLC" "Google Inc" "Apple Inc"
                "Mozilla Corporation" "Oracle Corporation"
                "Intel Corporation" "NVIDIA Corporation"
                "VMware, Inc" "Citrix Systems"
                "Symantec Corporation" "DigiCert Inc"
                "GlobalSign" "Sectigo Limited" "Comodo Security"
                "GeoTrust" "Entrust" "VeriSign"
                "Amazon Web Services" "Cisco Systems"
                "Dell Inc" "Hewlett-Packard"
                "Red Hat" "Canonical Ltd"
            )
            local matched=""
            for org in "${known_orgs[@]}"; do
                if grep -qF "$org" "${ac}/signers.txt"; then
                    matched="$org"
                    echo "  MATCH: $org"
                    break
                fi
            done
            if [[ -z "$matched" ]]; then
                echo "  No match against bundled known-org list"
                echo "  (this does NOT mean the binary is malicious; many legitimate"
                echo "   small vendors aren't on the list)"
            fi
        else
            echo "  No signer certificates extracted; skipping known-org check"
        fi
    } > "${ac}/known-org-check.txt"

    # Step 4: aggregate verdict
    {
        echo "=== Authenticode chain verdict ==="
        if [[ -f "${ac}/chain-validation.txt" ]]; then
            local validates="unknown"
            if grep -q "Signature verification: ok" "${ac}/chain-validation.txt" 2>/dev/null; then
                validates="yes"
            elif grep -q "Signature verification: failed" "${ac}/chain-validation.txt" 2>/dev/null; then
                validates="no"
            elif grep -q "No signature found" "${ac}/chain-validation.txt" 2>/dev/null; then
                validates="not-signed"
            fi
            echo "  Chain validates: $validates"
            local self_signed=""
            if grep -qE "self.?signed|Self-Signed" "${ac}/chain-validation.txt" 2>/dev/null; then
                self_signed="yes"; echo "  Self-signed leaf: yes"
            fi
            local expired=""
            if grep -qE "expired|Certificate has expired" "${ac}/chain-validation.txt" 2>/dev/null; then
                expired="yes"; echo "  Cert expired: yes"
            fi
        else
            echo "  No chain-validation.txt produced"
        fi
    } > "${ac}/verdict.txt"

    log_step "authenticode: $(cat "${ac}/verdict.txt" 2>/dev/null | grep -m1 'Chain validates' || echo 'no verdict')"
}
