#!/usr/bin/env bash
# =============================================================================
# stages/static/18-bulk.sh
# =============================================================================
#
# Synopsis:
#     bulk_extractor raw PII and IOC scanner, applicable to any binary.
#
# Description:
#     Runs all scanners EXCEPT `accts` (the credit-card / SSN / phone scanner),
#     disabled per user direction to avoid FP noise. Output is a directory tree
#     of per-scanner .txt files which stage_iocs merges into _iocs.json.
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
#     stage_bulk()
#
# Output subtrees:
#     ${outdir}/18-bulk/
#
# Skip controls:
#     SKIP_BULK
#
# Tools invoked (run_tool labels):
#     bulk_extractor
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_bulk() {
    local target="$1" outdir="$2"
    [[ $SKIP_BULK -eq 1 ]] && return 0
    if ! command -v bulk_extractor >/dev/null 2>&1; then
        return 0
    fi

    local be="${outdir}/18-bulk"
    # bulk_extractor REQUIRES an empty or non-existent output dir.
    rm -rf "$be"
    mkdir -p "$be"

    local threads; threads="$(nproc 2>/dev/null || echo 2)"
    [[ "$threads" -gt 8 ]] && threads=8  # cap to 8 -- more threads = diminishing returns

    # Rationale for each flag:
    #   -E all       enable every scanner
    #   -x accts     disable credit-card/SSN/phone scanner (FP noise)
    #   -o <dir>     output dir
    #   -q -1        quiet
    #   -Z           zero disk space between blocks
    #   -j <n>       parallel threads
    # Long timeout because bulk_extractor scans byte-by-byte.
    run_tool "bulk_extractor" "${be}/_tool.log" 600 \
        bulk_extractor -E all -x accts -o "$be" -q -1 -Z -j "$threads" "$target"

    if [[ -f "${be}/report.xml" ]]; then
        local ur em ip
        ur=$(wc -l < "${be}/url.txt"    2>/dev/null || echo 0)
        em=$(wc -l < "${be}/email.txt"  2>/dev/null || echo 0)
        ip=$(wc -l < "${be}/ip.txt"     2>/dev/null || echo 0)
        log_step "bulk_extractor: URLs=$ur emails=$em ips=$ip"
    fi
}
