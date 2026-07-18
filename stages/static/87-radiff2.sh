#!/usr/bin/env bash
# =============================================================================
# stages/static/87-radiff2.sh
# =============================================================================
#
# Synopsis:
#     radiff2 comparative binary diffing against a reference target.
#
# Description:
#     COMPARATIVE STAGE: only runs when --diff-against PATH was passed at the
#     CLI. The reference binary lives at $DIFF_AGAINST and is compared against
#     every analyzed target. Use cases:
#     - Original vs unpacked: --diff-against original.exe
#     - Sample vs known-bad: --diff-against known-malware.bin
#     - Version A vs B: --diff-against v1.2.3.exe
#
#     Radiff2 ships with radare2 (already installed as of v2.4.0).
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
#     stage_radiff2()
#
# Output subtrees:
#     ${outdir}/87-radiff2/
#
# Tools invoked (run_tool labels):
#     radiff2-count, radiff2-functions, radiff2-imports, radiff2-similarity,
#     radiff2-strings
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_radiff2() {
    local target="$1" outdir="$2"
    local rd="${outdir}/87-radiff2"

    if [[ -z "${DIFF_AGAINST:-}" ]]; then
        # No reference set; this is the normal case. radiff2 is comparative,
        # not per-binary, so skipping silently is correct.
        return 0
    fi

    if [[ ! -f "$DIFF_AGAINST" ]]; then
        log_warn "radiff2: --diff-against path '$DIFF_AGAINST' not found; skipping"
        return 0
    fi

    if ! command -v radiff2 >/dev/null 2>&1; then
        log_warn "radiff2: not installed (should be present via radare2 apt package)"
        return 0
    fi

    # Don't diff a binary against itself
    if [[ "$(readlink -f "$target")" == "$(readlink -f "$DIFF_AGAINST")" ]]; then
        log_step "radiff2: skipping (target == reference)"
        return 0
    fi

    mkdir -p "$rd"

    # Record which reference we're comparing against
    echo "Reference: $(readlink -f "$DIFF_AGAINST")" > "${rd}/_reference.txt"
    echo "Target:    $(readlink -f "$target")" >> "${rd}/_reference.txt"

    # 1. Similarity score (high-level percentage)
    run_tool "radiff2-similarity" "${rd}/similarity.txt" 60 \
        radiff2 -s "$DIFF_AGAINST" "$target"

    # 2. Function-level match table (requires analysis of both with -A)
    run_tool "radiff2-functions" "${rd}/functions.txt" "${TOOL_TIMEOUT:-600}" \
        radiff2 -A -C "$DIFF_AGAINST" "$target"

    # 3. Import diff
    run_tool "radiff2-imports" "${rd}/imports.txt" 60 \
        radiff2 -i "$DIFF_AGAINST" "$target"

    # 4. String diff
    run_tool "radiff2-strings" "${rd}/strings.txt" 120 \
        radiff2 -z "$DIFF_AGAINST" "$target"

    # 5. Change count (single number summary)
    run_tool "radiff2-count" "${rd}/count.txt" 60 \
        radiff2 -c "$DIFF_AGAINST" "$target"

    log_step "radiff2: $(grep -m1 'similarity' "${rd}/similarity.txt" 2>/dev/null || echo 'computed')"
}
