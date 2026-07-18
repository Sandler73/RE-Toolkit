#!/usr/bin/env bash
# =============================================================================
# stages/static/42-rizin.sh
# =============================================================================
#
# Synopsis:
#     rizin deep analysis providing an independent second opinion to radare2.
#
# Description:
#     Rizin is the rizin-labs fork of r2. Functionally similar CLI (aaa/aaaa),
#     but the rz-bin tool is substantially richer than rabin2 for format-level
#     metadata -- worth running BOTH r2 and rizin for cross-verification.
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
#     stage_rizin_deep()
#
# Output subtrees:
#     ${outdir}/42-rizin/
#
# Skip controls:
#     SKIP_R2
#
# Tools invoked (run_tool labels):
#     rz-bin-all, rz-bin-json
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_rizin_deep() {
    local target="$1" outdir="$2"
    [[ $SKIP_R2 -eq 1 ]] && return 0   # shared toggle: --no-r2 skips both
    command -v rizin >/dev/null 2>&1 || return 0

    local rz="${outdir}/42-rizin"
    mkdir -p "$rz"

    local anal_cmd
    if [[ $DEEP_ANALYSIS -eq 1 ]]; then anal_cmd='aaaa'; else anal_cmd='aaa'; fi

    # rz-bin: exhaustive format metadata
    if command -v rz-bin >/dev/null 2>&1; then
        run_tool "rz-bin-all"  "${rz}/rz-bin-all.txt"  180 rz-bin -AIeilrRsSzzh "$target"
        run_tool "rz-bin-json" "${rz}/rz-bin-full.json" 180 rz-bin -j -AIeilrRsSzzh "$target"
    fi

    # rizin itself: deep analysis + commands
    local rzscript
    rzscript="
e anal.depth=256
${anal_cmd}
afl | > ${rz}/funcs.txt
afll | > ${rz}/funcs-detailed.txt
iI | > ${rz}/info.txt
izz | > ${rz}/strings-deep.txt
axl | > ${rz}/xrefs.txt
pdf @@f | > ${rz}/all-functions-disasm.txt
q
"
    local t=$TOOL_TIMEOUT
    [[ $DEEP_ANALYSIS -eq 1 ]] && t=1200
    run_shell "rizin-deep-${anal_cmd}" "${rz}/rizin-driver.log" "$t" \
        "rizin -2 -q -c \"$rzscript\" '$target'"

    log_step "rizin deep (${anal_cmd}): → ${rz}/"
}
