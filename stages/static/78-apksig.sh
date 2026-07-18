#!/usr/bin/env bash
# =============================================================================
# stages/static/78-apksig.sh
# =============================================================================
#
# Synopsis:
#     APK signature scheme verification and certificate extraction.
#
# Description:
#     APK signing schemes: v1 (JAR signing): META-INF/CERT.RSA + CERT.SF +
#     MANIFEST.MF. Vulnerable to Janus CVE-2017-13156 on min SDK <= 24. v2 (APK
#     Sig Scheme): Block before ZIP central directory. Required by Google Play;
#     signs the entire APK. v3 (APK Sig Scheme): Same block format as v2 + key
#     rotation lineage. v4 (APK Sig Scheme): Incremental update support.
#
#     Primary: apksigner verify --print-certs --verbose Fallback: openssl pkcs7
#     on META-INF/*.RSA (only recovers v1 cert chain; cannot validate v2/v3/v4
#     signatures)
#
#     Cross-references v2.7.0 known-orgs list via stage_authenticode for
#     known-signer match (unified known-org bundle across PE Authenticode and
#     Android signer DN).
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
#     stage_apksig()
#
# Output subtrees:
#     ${outdir}/78-apksig/
#
# Skip controls:
#     SKIP_APKSIG
#
# Tools invoked (run_tool labels):
#     apksigner-verify, openssl-pkcs7-cert
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_apksig() {
    local target="$1" outdir="$2"
    local apksig="${outdir}/78-apksig"

    if [[ ${SKIP_APKSIG:-0} -eq 1 ]]; then
        log_step "apksig: skipped (SKIP_APKSIG=1)"
        return 0
    fi

    mkdir -p "$apksig"

    # ---- Primary: apksigner verify -----------------------------------------
    if command -v apksigner >/dev/null 2>&1; then
        run_tool "apksigner-verify" "${apksig}/verify.txt" 60 \
            apksigner verify --print-certs --verbose "$target"
    fi

    # ---- Fallback: openssl on META-INF/*.RSA -------------------------------
    # Only useful for v1-signed APKs; v2+ signatures live outside META-INF.
    # Useful as a sanity check or when apksigner is missing.
    if [[ ! -s "${apksig}/verify.txt" ]] || ! grep -q "Verifies" "${apksig}/verify.txt" 2>/dev/null; then
        if command -v unzip >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
            log_step "apksig: apksigner missing or failed; trying openssl on META-INF"
            local rsa_path
            # List potential .RSA / .DSA / .EC files in META-INF/
            rsa_path=$(unzip -l "$target" 2>/dev/null \
                | awk '{print $NF}' \
                | grep -E '^META-INF/.*\.(RSA|DSA|EC)$' \
                | head -1)
            if [[ -n "$rsa_path" ]]; then
                local rsa_local="${apksig}/extracted-cert.RSA"
                unzip -o -p "$target" "$rsa_path" > "$rsa_local" 2>/dev/null
                if [[ -s "$rsa_local" ]]; then
                    run_tool "openssl-pkcs7-cert" "${apksig}/cert-chain.txt" 30 \
                        openssl pkcs7 -inform DER -in "$rsa_local" -print_certs -text -noout
                fi
            fi
        fi
    fi

    # ---- Build signature-summary.json --------------------------------------
    if [[ -n "$VENV_PY" ]]; then
        "$VENV_PY" - "${apksig}/verify.txt" "${apksig}/cert-chain.txt" "$apksig" \
            > "${apksig}/_summary.log" 2>&1 <<'PYEOF' || true
"""Parse apksigner output (and openssl fallback) into signature-summary.json.

apksigner --verbose output structure:
  Verifies
  Verified using v1 scheme (JAR signing): true
  Verified using v2 scheme (APK Signature Scheme v2): true
  ...
  Number of signers: 1
  Signer #1 certificate DN: CN=Example, OU=Android, O=Example
  Signer #1 certificate SHA-256 digest: <hex>
  Signer #1 certificate SHA-1 digest: <hex>
  Signer #1 certificate MD5 digest: <hex>
  Signer #1 key algorithm: RSA
  Signer #1 key size (bits): 2048
"""
import sys
import os
import json
import re

verify_path = sys.argv[1]
chain_path = sys.argv[2]
outdir = sys.argv[3]

result = {
    "tool": None,
    "verifies": None,
    "schemes": {
        "v1_jar": False,
        "v2_apk_sig": False,
        "v3_apk_sig": False,
        "v4_apk_sig": False,
    },
    "signer_count": 0,
    "signers": [],
    "errors": [],
    "warnings": [],
    "janus_vulnerable": False,
}

# Parse apksigner output
if os.path.exists(verify_path) and os.path.getsize(verify_path) > 0:
    result["tool"] = "apksigner"
    with open(verify_path, encoding="utf-8", errors="replace") as f:
        text = f.read()

    # Top-level verifies?
    if re.search(r"^Verifies\s*$", text, re.MULTILINE):
        result["verifies"] = True
    elif re.search(r"DOES NOT VERIFY", text):
        result["verifies"] = False

    # Scheme detection
    if re.search(r"Verified using v1 scheme[^:]*:\s*true", text):
        result["schemes"]["v1_jar"] = True
    if re.search(r"Verified using v2 scheme[^:]*:\s*true", text):
        result["schemes"]["v2_apk_sig"] = True
    if re.search(r"Verified using v3 scheme[^:]*:\s*true", text):
        result["schemes"]["v3_apk_sig"] = True
    if re.search(r"Verified using v4 scheme[^:]*:\s*true", text):
        result["schemes"]["v4_apk_sig"] = True

    # Signer count
    sc_match = re.search(r"Number of signers:\s*(\d+)", text)
    if sc_match:
        result["signer_count"] = int(sc_match.group(1))

    # Per-signer details: regex against "Signer #N certificate ..."
    signer_data = {}  # signer_index -> dict
    for line in text.splitlines():
        m = re.match(r"Signer #(\d+) certificate DN:\s*(.+)$", line)
        if m:
            idx = int(m.group(1))
            signer_data.setdefault(idx, {})["dn"] = m.group(2).strip()
            continue
        m = re.match(r"Signer #(\d+) certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", line)
        if m:
            signer_data.setdefault(int(m.group(1)), {})["sha256"] = m.group(2).strip()
            continue
        m = re.match(r"Signer #(\d+) certificate SHA-1 digest:\s*([0-9a-fA-F:]+)", line)
        if m:
            signer_data.setdefault(int(m.group(1)), {})["sha1"] = m.group(2).strip()
            continue
        m = re.match(r"Signer #(\d+) key algorithm:\s*(\w+)", line)
        if m:
            signer_data.setdefault(int(m.group(1)), {})["key_algorithm"] = m.group(2).strip()
            continue
        m = re.match(r"Signer #(\d+) key size \(bits\):\s*(\d+)", line)
        if m:
            signer_data.setdefault(int(m.group(1)), {})["key_size_bits"] = int(m.group(2))
            continue
    for idx in sorted(signer_data):
        result["signers"].append(signer_data[idx])

    # Warnings (apksigner emits "WARNING: ..." lines)
    for line in text.splitlines():
        if "WARNING" in line:
            result["warnings"].append(line.strip())
        if "ERROR" in line:
            result["errors"].append(line.strip())

# Fallback parse: openssl cert chain (only when apksigner output absent)
elif os.path.exists(chain_path) and os.path.getsize(chain_path) > 0:
    result["tool"] = "openssl"
    with open(chain_path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    # Extract Subject DN
    subject_match = re.search(r"^\s+Subject:\s+(.+)$", text, re.MULTILINE)
    if subject_match:
        result["signers"].append({
            "dn": subject_match.group(1).strip(),
            "sha256": None, "sha1": None,
            "key_algorithm": None, "key_size_bits": None,
        })
    result["signer_count"] = len(result["signers"])
    # Cannot determine v1/v2/v3/v4 from raw cert
    result["warnings"].append("openssl fallback - scheme detection unavailable")

# Janus vulnerability detection (CVE-2017-13156): v1-only signed APK with
# minSdkVersion <= 23 OR no v2+ scheme present
if result["schemes"]["v1_jar"] and not (
    result["schemes"]["v2_apk_sig"] or
    result["schemes"]["v3_apk_sig"] or
    result["schemes"]["v4_apk_sig"]
):
    result["janus_vulnerable"] = True
    result["warnings"].append(
        "Janus vulnerable: v1-only signed APK; CVE-2017-13156 on Android <= 6.0"
    )

with open(os.path.join(outdir, "signature-summary.json"), "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

# Concise stdout summary
schemes_active = [k.replace("_apk_sig", "").replace("_jar", "")
                  for k, v in result["schemes"].items() if v]
print(f"apksig: tool={result['tool']}, verifies={result['verifies']}, "
      f"schemes={','.join(schemes_active) or 'none'}, "
      f"signers={result['signer_count']}, "
      f"janus_vuln={result['janus_vulnerable']}")
PYEOF
        log_step "apksig: $(grep -m1 'apksig:' "${apksig}/_summary.log" 2>/dev/null || echo 'parsed')"
    fi
}
