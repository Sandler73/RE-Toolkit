#!/usr/bin/env bash
# =============================================================================
# stages/static/40-alternative.sh
# =============================================================================
#
# Synopsis:
#     Alternative-perspective dispatcher for objdump, radare2, rizin, and LLVM.
#
# Description:
#     Backwards-compatible shim: stage_alternative still exists and dispatches
#     to the four split stages. The main loop's dispatch was updated to call
#     the split stages directly, but if any external script references
#     stage_alternative we keep behavior.
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
#     stage_alternative()
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_alternative() {
    local target="$1" outdir="$2"
    stage_objdump_deep  "$target" "$outdir"
    stage_r2_deep       "$target" "$outdir"
    stage_rizin_deep    "$target" "$outdir"
    stage_llvm_objdump  "$target" "$outdir"
}
