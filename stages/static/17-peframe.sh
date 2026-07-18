#!/usr/bin/env bash
# =============================================================================
# stages/static/17-peframe.sh
# =============================================================================
#
# Synopsis:
#     peframe PE behavioral static analyzer.
#
# Description:
#     Peframe (https://github.com/guelfoweb/peframe) is a Python-based static
#     analyzer for PE files and malicious MS Office documents. It detects:
#     packers, XOR, digital signatures, mutexes, anti-debug techniques, anti-VM
#     checks, suspicious sections and API patterns, MS Office macros.
#     Complementary to Manalyze with a more behavior-focused detection set.
#
#     The RE-Toolkit invocation requests JSON for the structured form and the
#     default short output for analyst readability:
#
#     Peframe -j <target> # JSON peframe <target> # short readable summary
#
#     Note: only meaningful for PE files. Driver dispatches this stage only for
#     pe-native and pe-dotnet binary types.
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
#     stage_peframe()
#
# Output subtrees:
#     ${outdir}/17-peframe/
#
# Skip controls:
#     SKIP_PEFRAME
#
# Tools invoked (run_tool labels):
#     peframe-json, peframe-short, peframe-strings
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_peframe() {
    local target="$1" outdir="$2"
    local pf="${outdir}/17-peframe"

    if [[ ${SKIP_PEFRAME:-0} -eq 1 ]]; then
        log_step "peframe: skipped (SKIP_PEFRAME=1)"
        return 0
    fi

    if ! command -v peframe >/dev/null 2>&1; then
        log_warn "peframe: 'peframe' command not found - skipping"
        log_warn "  Install via: pip install https://github.com/guelfoweb/peframe/archive/master.zip"
        return 0
    fi

    mkdir -p "$pf"

    # JSON output - the structured form parsed by stage_summary
    run_tool "peframe-json" "${pf}/peframe.json" "${TOOL_TIMEOUT:-600}" \
        peframe -j "$target"

    # Short human-readable summary
    run_tool "peframe-short" "${pf}/peframe.txt" "${TOOL_TIMEOUT:-600}" \
        peframe "$target"

    # Strings extraction (peframe applies its own filters which may differ
    # from FLOSS / strings(1) - kept as a separate file for cross-reference)
    run_tool "peframe-strings" "${pf}/peframe-strings.txt" "${TOOL_TIMEOUT:-600}" \
        peframe -s "$target"
}
