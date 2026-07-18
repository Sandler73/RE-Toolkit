#!/usr/bin/env bash
# =============================================================================
# stages/static/40-objdump.sh
# =============================================================================
#
# Synopsis:
#     GNU objdump deep invocation: headers, disassembly, and DWARF.
#
# Description:
#     Objdump stays in 40-r2/ (they're related disassembly perspectives), but
#     the invocation gets every informational flag the tool supports.
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
#     stage_objdump_deep()
#
# Output subtrees:
#     ${outdir}/40-r2/
#
# Tools invoked (run_tool labels):
#     objdump-disasm, objdump-dwarf, objdump-headers
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_objdump_deep() {
    local target="$1" outdir="$2"
    command -v objdump >/dev/null 2>&1 || return 0

    local r2="${outdir}/40-r2"
    mkdir -p "$r2"

    # Headers (fast)
    run_tool "objdump-headers" "${r2}/objdump-headers.txt" 60 \
        objdump -x --all-headers --private-headers "$target"

    # Full disassembly with everything
    run_tool "objdump-disasm"  "${r2}/objdump-disasm.txt" "$TOOL_TIMEOUT" \
        objdump \
            --disassemble-all \
            --reloc \
            --dynamic-reloc \
            --syms \
            --dynamic-syms \
            --prefix-addresses \
            --demangle=auto \
            --show-raw-insn \
            --wide \
            "$target"

    # DWARF (if any); safe no-op on non-DWARF binaries
    run_tool "objdump-dwarf" "${r2}/objdump-dwarf.txt" 180 \
        objdump --dwarf=decodedline,info,abbrev "$target"
}
