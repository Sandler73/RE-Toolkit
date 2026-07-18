#!/usr/bin/env bash
# =============================================================================
# stages/static/16-manalyze.sh
# =============================================================================
#
# Synopsis:
#     Manalyze static PE analyzer with plugin-based scoring.
#
# Description:
#     Manalyze (https://github.com/JusticeRage/Manalyze) is a static PE
#     analyzer with a plugin framework. The RE-Toolkit invocation requests every
#     dump section, every plugin, and full hash output:
#
#     Manalyze --pe <target> --output=json --dump=all --plugins=all --hashes
#
#     Plugins include: imports analyzer (suspicious API combinations), packer
#     detection, resource analyzer, mitigation flags
#     (ASLR/DEP/SEH/SafeSEH/...), overlay detection, ClamAV-derived YARA rules,
#     and cryptographic constant detection. Output is a single JSON document
#     per binary.
#
#     Note: only meaningful for PE files (native and .NET). Driver dispatches
#     this stage only for pe-native and pe-dotnet binary types.
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
#     stage_manalyze()
#
# Output subtrees:
#     ${outdir}/16-manalyze/
#
# Skip controls:
#     SKIP_MANALYZE
#
# Tools invoked (run_tool labels):
#     manalyze-json, manalyze-raw
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_manalyze() {
    local target="$1" outdir="$2"
    local mz="${outdir}/16-manalyze"

    if [[ ${SKIP_MANALYZE:-0} -eq 1 ]]; then
        log_step "Manalyze: skipped (SKIP_MANALYZE=1)"
        return 0
    fi

    if ! command -v manalyze >/dev/null 2>&1; then
        log_warn "Manalyze: 'manalyze' command not found - skipping"
        log_warn "  Install via: cd Manalyze && cmake . && make && sudo make install"
        return 0
    fi

    mkdir -p "$mz"

    # v3.0.10 (audit-14 A2) - CLI fix: drop --pe flag, pass target as
    # positional argument. Per Manalyze docs/usage.rst: "Targets are also
    # accepted as positional arguments; this means that listing them on
    # the command line without prefixing them with any particular flag
    # will work." The --pe flag IS documented in --help, but some build
    # configurations of boost::program_options reject unrecognized
    # options at parse time. Operator's v3.0.9 install reported "[!]
    # Error: Could not parse the command line (The following argument
    # was not expected: --pe)." The positional form works on all
    # documented build configurations. Also switched --output=foo and
    # --dump=foo to space-separated form for the same compatibility
    # reason (older boost versions parse `--output json` more reliably
    # than `--output=json`).

    # JSON output - the structured form parsed by stage_summary
    run_tool "manalyze-json" "${mz}/manalyze.json" "${TOOL_TIMEOUT:-600}" \
        manalyze "$target" \
            --output json \
            --dump all \
            --plugins all \
            --hashes

    # Raw text output - the human-readable form preserved for analyst review.
    # Default --output=raw gives the colorized terminal output; we strip
    # ANSI escape sequences post-hoc since logs aren't TTYs.
    run_tool "manalyze-raw" "${mz}/manalyze.txt" "${TOOL_TIMEOUT:-600}" \
        manalyze "$target" \
            --output raw \
            --dump all \
            --plugins all \
            --hashes
}
