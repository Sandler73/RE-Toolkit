#!/usr/bin/env bash
# =============================================================================
# stages/static/54-wasm.sh
# =============================================================================
#
# Synopsis:
#     WebAssembly module validation, disassembly, and decompilation.
#
# Description:
#     Tool: WABT (apt: wabt) - WebAssembly Binary Toolkit.
#     - Wasm2wat: binary -> text format (.wat)
#     - Wasm-objdump: structural dump similar to objdump
#     - Wasm-decompile: C-like pseudocode reconstruction
#     - Wasm-validate: spec validation
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
#     stage_wasm()
#
# Output subtrees:
#     ${outdir}/54-wasm/
#
# Skip controls:
#     SKIP_WASM
#
# Tools invoked (run_tool labels):
#     wasm-decompile, wasm-objdump, wasm-objdump-disasm, wasm-validate,
#     wasm2wat
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_wasm() {
    local target="$1" outdir="$2"
    local ws="${outdir}/54-wasm"

    if [[ ${SKIP_WASM:-0} -eq 1 ]]; then
        log_step "WASM: skipped (SKIP_WASM=1)"
        return 0
    fi

    if ! command -v wasm2wat >/dev/null 2>&1; then
        log_warn "WASM: wabt suite not installed - skipping (install via: apt install wabt)"
        return 0
    fi

    mkdir -p "$ws"

    # wasm2wat: binary -> WebAssembly text format. The .wat file is human
    # readable s-expressions.
    run_tool "wasm2wat" "${ws}/module.wat" 120 \
        wasm2wat "$target" -o "${ws}/module.wat"
    # run_tool's log capture wraps stdout/stderr; the actual .wat lands at the path above

    # wasm-objdump: structural dump. -x flag = full details (sections,
    # function signatures, imports, exports, custom sections, ...).
    run_tool "wasm-objdump" "${ws}/objdump.txt" 60 \
        wasm-objdump -x "$target"

    # wasm-objdump -d: disassembly per function
    run_tool "wasm-objdump-disasm" "${ws}/disasm.txt" "${TOOL_TIMEOUT:-600}" \
        wasm-objdump -d "$target"

    # wasm-decompile: C-like pseudocode. Useful for human review of
    # whole-module behavior beyond the s-expression text format.
    run_tool "wasm-decompile" "${ws}/decompile.dcmp" "${TOOL_TIMEOUT:-600}" \
        wasm-decompile "$target" -o "${ws}/decompile.dcmp"

    # wasm-validate: spec compliance check. Non-zero exit means the
    # binary doesn't validate per the WebAssembly spec; the output goes
    # to stderr (captured by run_tool).
    run_tool "wasm-validate" "${ws}/validate.txt" 60 \
        wasm-validate "$target" || \
        log_step "wasm-validate: module did not validate (see validate.txt)"
}
