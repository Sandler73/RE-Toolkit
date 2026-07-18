#!/usr/bin/env bash
# =============================================================================
# stages/static/72-apk.sh
# =============================================================================
#
# Synopsis:
#     APK container extraction and resource decoding.
#
# Description:
#     Container-extraction stage. Mirrors v2.4.0 stage_upx pattern: 1. apktool
#     d -f -o <outdir>/72-apk-extracted/ <apk> decodes resources, AXML
#     manifest, baksmali's classes.dex, copies lib/ 2. Walks extracted tree to
#     enumerate components 3. Per-component dispatch is handled by
#     lib/dispatch.sh AFTER stage_apk returns: stage_axml on
#     AndroidManifest.xml, stage_apksig on the APK itself, stage_dex on
#     classes*.dex, stage_elf recursion on largest .so per ABI under lib/<abi>/
#
#     Apktool is heavyweight (~50MB Java jar) but is the canonical Android RE
#     tool; aapt2 dump xmltree is a lighter fallback for AXML-only when apktool
#     fails.
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
#     stage_apk()
#
# Output subtrees:
#     ${outdir}/72-apk/
#     ${outdir}/72-apk-extracted/
#
# Skip controls:
#     SKIP_APK
#
# Tools invoked (run_tool labels):
#     apk-listing, apktool-decode
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_apk() {
    local target="$1" outdir="$2"
    local apk_meta="${outdir}/72-apk"
    local apk_extracted="${outdir}/72-apk-extracted"

    if [[ ${SKIP_APK:-0} -eq 1 ]]; then
        log_step "apk: skipped (SKIP_APK=1)"
        return 0
    fi

    mkdir -p "$apk_meta"

    # ---- File listing & basic structural inventory --------------------------
    if command -v unzip >/dev/null 2>&1; then
        run_tool "apk-listing" "${apk_meta}/listing.txt" 60 \
            unzip -l "$target"
    fi

    # Component inventory: count of classes*.dex, lib/<abi>/*.so per ABI,
    # presence of META-INF/CERT.RSA, AndroidManifest.xml, resources.arsc
    {
        echo "=== APK component inventory ==="
        if [[ -f "${apk_meta}/listing.txt" ]]; then
            echo ""
            echo "Total entries: $(grep -cE "^[[:space:]]*[0-9]+" "${apk_meta}/listing.txt")"
            echo ""
            echo "DEX files:"
            grep -aE "[[:space:]]classes[0-9]*\.dex$" "${apk_meta}/listing.txt" || echo "  (none)"
            echo ""
            echo "Native libraries (lib/<abi>/*.so):"
            grep -aE "^[[:space:]]*[0-9]+.*[[:space:]]lib/[^/]+/[^/]+\.so$" "${apk_meta}/listing.txt" || echo "  (none)"
            echo ""
            echo "Manifest & resources:"
            grep -aE "[[:space:]](AndroidManifest\.xml|resources\.arsc)$" "${apk_meta}/listing.txt" || echo "  (none)"
            echo ""
            echo "Signing metadata (META-INF/):"
            grep -aE "[[:space:]]META-INF/.*\.(RSA|DSA|EC|SF|MF)$" "${apk_meta}/listing.txt" || echo "  (none)"
        else
            echo "(unzip listing not available)"
        fi
    } > "${apk_meta}/inventory.txt"

    # ---- apktool extraction (primary tool) ----------------------------------
    if command -v apktool >/dev/null 2>&1; then
        # apktool insists on creating its output dir; use --force-manifest
        # so it always emits AndroidManifest.xml even if other resource
        # decoding fails. -f forces overwrite of destination.
        run_tool "apktool-decode" "${apk_meta}/apktool.log" "${TOOL_TIMEOUT:-600}" \
            apktool d -f --force-manifest --keep-broken-res \
                -o "$apk_extracted" "$target"

        # Verify expected outputs landed
        {
            echo "=== apktool output verification ==="
            if [[ -d "$apk_extracted" ]]; then
                echo "Extraction directory: $apk_extracted"
                if [[ -f "${apk_extracted}/AndroidManifest.xml" ]]; then
                    local manifest_lines
                    manifest_lines=$(wc -l < "${apk_extracted}/AndroidManifest.xml" 2>/dev/null)
                    echo "AndroidManifest.xml: ${manifest_lines} lines (decoded)"
                else
                    echo "AndroidManifest.xml: NOT decoded"
                fi
                if [[ -d "${apk_extracted}/smali" ]]; then
                    local smali_count
                    smali_count=$(find "${apk_extracted}/smali" -name '*.smali' 2>/dev/null | wc -l)
                    echo "smali class files: $smali_count"
                fi
                if [[ -d "${apk_extracted}/res" ]]; then
                    local res_count
                    res_count=$(find "${apk_extracted}/res" -type f 2>/dev/null | wc -l)
                    echo "decoded resources: $res_count"
                fi
                if [[ -d "${apk_extracted}/lib" ]]; then
                    echo "Native ABIs present:"
                    find "${apk_extracted}/lib" -maxdepth 1 -mindepth 1 -type d \
                        -printf "  %f\n" 2>/dev/null
                fi
            else
                echo "Extraction directory NOT created (apktool failed)"
            fi
        } > "${apk_meta}/extraction-summary.txt"
    else
        log_warn "apk: apktool not installed; skipping extraction. AXML and"
        log_warn "       DEX dispatch will fail unless this is a forensics-"
        log_warn "       extracted APK already with decoded artifacts."
        echo "apktool not installed" > "${apk_meta}/apktool.log"
    fi

    # ---- Per-component dispatch -------------------------------------------
    # The actual dispatch happens in lib/dispatch.sh via stage_axml /
    # stage_apksig / stage_dex / stage_elf; this stage produces the
    # extracted tree and inventory. We emit a manifest of WHAT to
    # dispatch, which lib/dispatch.sh reads.

    {
        echo "# Component dispatch manifest"
        echo "# Format: <component_type> <abs_path>"
        if [[ -f "${apk_extracted}/AndroidManifest.xml" ]]; then
            echo "axml ${apk_extracted}/AndroidManifest.xml"
        fi
        # apksig dispatch operates on the original .apk, not on extracted
        # META-INF (apksigner needs the full APK for v2/v3/v4 verification)
        echo "apksig ${target}"
        # DEX dispatch: each classes*.dex inside the APK. apktool baksmalis
        # them into smali/, but the original .dex bytes are needed for
        # jadx + dex2jar. We extract them via unzip on demand.
        if [[ -f "${apk_meta}/listing.txt" ]]; then
            grep -aE "[[:space:]]classes[0-9]*\.dex$" "${apk_meta}/listing.txt" \
                | awk '{print $NF}' | while read -r dex_path; do
                # Extract this dex file to a known location for dispatch
                local dex_local="${apk_meta}/$(basename "$dex_path")"
                if command -v unzip >/dev/null 2>&1; then
                    unzip -o -p "$target" "$dex_path" > "$dex_local" 2>/dev/null
                    if [[ -s "$dex_local" ]]; then
                        echo "dex ${dex_local}"
                    fi
                fi
            done
        fi
        # Native lib dispatch: largest .so per ABI to avoid redundant analysis
        if [[ -d "${apk_extracted}/lib" ]]; then
            for abi_dir in "${apk_extracted}/lib"/*/; do
                [[ -d "$abi_dir" ]] || continue
                local largest_so
                largest_so=$(find "$abi_dir" -maxdepth 1 -name '*.so' -type f \
                    -printf '%s %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
                if [[ -n "$largest_so" && -f "$largest_so" ]]; then
                    echo "elf ${largest_so}"
                fi
            done
        fi
    } > "${apk_meta}/dispatch-manifest.txt"

    log_step "apk: $(wc -l < "${apk_meta}/dispatch-manifest.txt" 2>/dev/null) components queued for dispatch"
}
