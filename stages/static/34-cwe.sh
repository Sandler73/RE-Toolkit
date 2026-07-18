#!/usr/bin/env bash
# =============================================================================
# stages/static/34-cwe.sh
# =============================================================================
#
# Synopsis:
#     cwe_checker static CWE detection over binary intermediate representation.
#
# Description:
#     Cwe_checker (https://github.com/fkie-cad/cwe_checker) is a Rust-based
#     vulnerability scanner that runs static analysis over Ghidra-extracted IR
#     to find patterns matching well-known CWE classes:
#     - CWE-119 (Buffer Overflow)
#     - CWE-125 (Out-of-bounds Read)
#     - CWE-190 (Integer Overflow / Wraparound)
#     - CWE-252 (Unchecked Return Value)
#     - CWE-415 (Double Free)
#     - CWE-416 (Use After Free)
#     - CWE-476 (NULL Pointer Dereference)
#     - CWE-787 (Out-of-bounds Write)
#
#     ... and others.
#
#     IMPORTANT: cwe_checker internally invokes Ghidra Headless to produce its
#     IR, which adds ~5-10 minutes per binary on top of RE-Toolkit's existing
#     Ghidra stage. For this reason, the stage is OPT-IN via
#     --enable-cwe-checker rather than default-ON. Most analyses do not need it
#     and the cost is substantial. See the Development wiki page for the design
#     rationale.
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
#     stage_cwe()
#
# Output subtrees:
#     ${outdir}/34-cwe/
#
# Skip controls:
#     ENABLE_CWE_CHECKER
#
# Tools invoked (run_tool labels):
#     cwe-checker-json, cwe-checker-text
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_cwe() {
    local target="$1" outdir="$2"
    local cd="${outdir}/34-cwe"

    if [[ ${ENABLE_CWE_CHECKER:-0} -ne 1 ]]; then
        return 0
    fi

    if ! command -v cwe_checker >/dev/null 2>&1; then
        log_warn "cwe_checker: command not found - skipping"
        log_warn "  Install via: cd cwe_checker && make all GHIDRA_PATH=/opt/ghidra"
        return 0
    fi

    mkdir -p "$cd"
    log_info "cwe_checker: starting (this may take 5-10 minutes; runs Ghidra internally)"

    # JSON output: parsed by stage_summary into the report's Vulnerabilities tab.
    # Long timeout because cwe_checker's analysis is heavyweight; default
    # TOOL_TIMEOUT (600s) is usually fine but allow override via CWE_CHECKER_TIMEOUT.
    local cwe_timeout="${CWE_CHECKER_TIMEOUT:-1800}"
    run_tool "cwe-checker-json" "${cd}/cwe_checker.json" "$cwe_timeout" \
        cwe_checker --json "$target"

    # Plain-text output: same content, more readable.
    run_tool "cwe-checker-text" "${cd}/cwe_checker.txt" "$cwe_timeout" \
        cwe_checker "$target"

    # Quick log summary: count CWE hits if the JSON parsed.
    if [[ -f "${cd}/cwe_checker.json" ]]; then
        local cwe_hits
        cwe_hits=$(safe_grep_count '"name"\s*:\s*"CWE' "${cd}/cwe_checker.json")
        [[ ${cwe_hits:-0} -gt 0 ]] && log_step "cwe_checker: ${cwe_hits} CWE hit(s)"
    fi
}
