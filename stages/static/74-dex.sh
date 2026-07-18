#!/usr/bin/env bash
# =============================================================================
# stages/static/74-dex.sh
# =============================================================================
#
# Synopsis:
#     DEX decompilation through jadx, dex2jar, and baksmali.
#
# Description:
#     Three-tier decompilation strategy: Tier 1 (PRIMARY): jadx -> Java source.
#     Best quality. Tier 2 (FALLBACK): baksmali -> smali. Always works. Tier 3
#     (TERTIARY): dex2jar -> .jar -> CFR -> Java.
#
#     All three run because they hit different code paths and their failures
#     are independent. The summary parser counts which tiers produced output.
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
#     stage_dex()
#
# Output subtrees:
#     ${outdir}/74-dex/
#
# Skip controls:
#     SKIP_DEX
#
# Tools invoked (run_tool labels):
#     baksmali-disassemble, cfr-from-dex2jar, dex2jar, jadx-decompile
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_dex() {
    local target="$1" outdir="$2"
    local dx="${outdir}/74-dex"

    if [[ ${SKIP_DEX:-0} -eq 1 ]]; then
        log_step "dex: skipped (SKIP_DEX=1)"
        return 0
    fi

    mkdir -p "$dx"

    # Tier 1: jadx (primary)
    if command -v jadx >/dev/null 2>&1; then
        run_tool "jadx-decompile" "${dx}/jadx.log" "${TOOL_TIMEOUT:-600}" \
            jadx -d "${dx}/jadx" -j 2 --deobf --escape-unicode "$target"
        if [[ -d "${dx}/jadx" ]]; then
            local java_count
            java_count=$(find "${dx}/jadx" -name '*.java' -type f 2>/dev/null | wc -l)
            echo "jadx Java file count: $java_count" > "${dx}/jadx-summary.txt"
        fi
    fi

    # Tier 2: baksmali (fallback)
    if command -v baksmali >/dev/null 2>&1; then
        run_tool "baksmali-disassemble" "${dx}/baksmali.log" "${TOOL_TIMEOUT:-600}" \
            baksmali disassemble -o "${dx}/smali" "$target"
        if [[ -d "${dx}/smali" ]]; then
            local smali_count
            smali_count=$(find "${dx}/smali" -name '*.smali' -type f 2>/dev/null | wc -l)
            echo "baksmali smali file count: $smali_count" > "${dx}/baksmali-summary.txt"
        fi
    fi

    # Tier 3: dex2jar (tertiary) + CFR follow-through
    local d2j_cmd=""
    for candidate in d2j-dex2jar d2j-dex2jar.sh dex2jar; do
        if command -v "$candidate" >/dev/null 2>&1; then
            d2j_cmd="$candidate"
            break
        fi
    done
    if [[ -n "$d2j_cmd" ]]; then
        run_tool "dex2jar" "${dx}/dex2jar.log" "${TOOL_TIMEOUT:-300}" \
            "$d2j_cmd" -o "${dx}/classes.jar" --force "$target"
        if [[ -f "${dx}/classes.jar" ]] && [[ -f "/opt/cfr/cfr.jar" ]]; then
            mkdir -p "${dx}/cfr"
            run_tool "cfr-from-dex2jar" "${dx}/cfr.log" "${TOOL_TIMEOUT:-600}" \
                java -jar /opt/cfr/cfr.jar "${dx}/classes.jar" \
                    --outputdir "${dx}/cfr"
            if [[ -d "${dx}/cfr" ]]; then
                local cfr_count
                cfr_count=$(find "${dx}/cfr" -name '*.java' -type f 2>/dev/null | wc -l)
                echo "CFR Java file count (via dex2jar): $cfr_count" > "${dx}/cfr-summary.txt"
            fi
        fi
    fi

    # Aggregate stage summary
    {
        echo "=== DEX decompilation tier summary ==="
        if [[ -f "${dx}/jadx-summary.txt" ]]; then
            cat "${dx}/jadx-summary.txt"
        else
            echo "jadx: not run (not installed)"
        fi
        if [[ -f "${dx}/baksmali-summary.txt" ]]; then
            cat "${dx}/baksmali-summary.txt"
        else
            echo "baksmali: not run (not installed)"
        fi
        if [[ -f "${dx}/cfr-summary.txt" ]]; then
            cat "${dx}/cfr-summary.txt"
        elif [[ -n "$d2j_cmd" ]]; then
            echo "dex2jar+CFR: dex2jar ran but no CFR follow-through"
        else
            echo "dex2jar: not run (not installed)"
        fi
    } > "${dx}/_summary.txt"

    log_step "dex: $(safe_grep_count "file count" "${dx}/_summary.txt") tier(s) produced output"
}
