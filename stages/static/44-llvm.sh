#!/usr/bin/env bash
# =============================================================================
# stages/static/44-llvm.sh
# =============================================================================
#
# Synopsis:
#     llvm-objdump disassembly complementing the GNU objdump perspective.
#
# Description:
#     Llvm-objdump handles formats GNU objdump doesn't (CodeView, some DWARF
#     variants, better Mach-O); worth having both.
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
#     stage_llvm_objdump()
#
# Output subtrees:
#     ${outdir}/44-llvm/
#
# Tools invoked (run_tool labels):
#     llvm-objdump
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_llvm_objdump() {
    local target="$1" outdir="$2"
    command -v llvm-objdump >/dev/null 2>&1 || return 0
    local ld="${outdir}/44-llvm"
    mkdir -p "$ld"

    # Try every flag llvm-objdump accepts for maximum coverage. Some flags
    # are silently ignored for formats where they don't apply -- that's OK.
    run_tool "llvm-objdump" "${ld}/llvm-objdump-full.txt" "$TOOL_TIMEOUT" \
        llvm-objdump \
            --disassemble-all \
            --all-headers \
            --reloc \
            --section-headers \
            --source \
            --demangle \
            --show-all-symbols \
            --print-imm-hex \
            "$target"
    log_step "llvm-objdump: → ${ld}/llvm-objdump-full.txt"
}
