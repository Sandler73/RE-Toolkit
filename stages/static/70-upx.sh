#!/usr/bin/env bash
# =============================================================================
# stages/static/70-upx.sh
# =============================================================================
#
# Synopsis:
#     UPX detection, unpacking, and re-analysis of the unpacked image.
#
# Description:
#     UPX detection, unpacking, and re-analysis of the unpacked image.
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
#     stage_upx()
#
# Output subtrees:
#     ${outdir}/70-upx-unpacked/
#
# Skip controls:
#     SKIP_GHIDRA_DOTNET
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_upx() {
    local target="$1" outdir="$2"
    local up="${outdir}/70-upx-unpacked"
    mkdir -p "$up"

    if ! command -v upx >/dev/null 2>&1; then
        log_step "upx: not installed, cannot unpack"
        return
    fi

    local unpacked
    unpacked="${up}/$(basename "$target").unpacked"
    cp "$target" "$unpacked"
    if upx -d "$unpacked" > "${up}/upx.log" 2>&1; then
        log_step "upx: successfully unpacked to ${unpacked}"
        log_step "upx: rerunning pipeline on unpacked version…"
        local inner_type
        inner_type=$(detect_type "$unpacked")
        log_step "upx: unpacked type = $inner_type"
        case "$inner_type" in
            pe-native)  stage_pe "$unpacked" "$up"; stage_ghidra "$unpacked" "$up" full; stage_alternative "$unpacked" "$up" ;;
            pe-dotnet)  stage_pe "$unpacked" "$up"; stage_dotnet "$unpacked" "$up"
                        [[ $SKIP_GHIDRA_DOTNET -eq 0 ]] && stage_ghidra "$unpacked" "$up" light ;;
            elf)        stage_elf "$unpacked" "$up"; stage_ghidra "$unpacked" "$up" full; stage_alternative "$unpacked" "$up" ;;
        esac
    else
        log_step "upx: unpack failed -- probably not UPX-packed or multi-layered"
    fi
}
