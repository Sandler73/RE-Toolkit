#!/usr/bin/env bash
# =============================================================================
# stages/static/26-retdec.sh
# =============================================================================
#
# Synopsis:
#     RetDec decompiler pass (opt-in, installed via --with-retdec).
#
# Description:
#     Not directly executable. Defines: stage_retdec
#
#     V3.0.2 additions (audit-6):
#     - Retdec: Avast's open-source machine-code decompiler. Provides a
#
#     Parallel decompilation perspective alongside Ghidra and r2/rizin for
#     native binaries.
#
#     Why retdec is opt-in (--with-retdec at install time): Retdec is
#     Docker-based by upstream. Pulling the image is ~2GB and a decompile run
#     takes 30s-5min depending on binary size. The historical v2.x decision was
#     to exclude retdec entirely on the no-Docker constraint. v3.0.0 introduced
#     Docker for the dynamic-analysis tier (LAYER 9), and v3.0.2 (audit-6, D64)
#     revisits the calculus: Docker is now an acceptable runtime dep, so retdec
#     joins as opt-in alongside cuckoo.
#
#     Activation:
#     - Installer must have run with --with-retdec (LAYER 11 pulls Docker image
#
#     And installs /opt/retdec/decompile.sh wrapper).
#     - Stage applies to native binaries (PE, ELF, Mach-O). Skipped for
#
#     Managed (.NET) targets which have ilspycmd/dnSpyEx instead.
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
#     stage_retdec()
#
# Output subtrees:
#     ${outdir}/26-retdec/
#
# Skip controls:
#     SKIP_RETDEC
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_retdec() {
    local target="$1" outdir="$2"
    local rd="${outdir}/26-retdec"

    if [[ ${SKIP_RETDEC:-0} -eq 1 ]]; then
        log_step "stage_retdec: SKIP (SKIP_RETDEC=1)"
        return 0
    fi

    # Wrapper must be present (created by LAYER 11 install with --with-retdec)
    if [[ ! -x /opt/retdec/decompile.sh ]]; then
        log_step "stage_retdec: skipping (--with-retdec not used at install time)"
        return 0
    fi

    if ! command -v docker >/dev/null 2>&1; then
        log_warn "stage_retdec: docker not on PATH; skipping"
        return 0
    fi

    # Skip managed (.NET) targets; ilspycmd/dnSpyEx handle those.
    if file "$target" 2>/dev/null | grep -qE "Mono/\.Net|\.NET (assembly|module)"; then
        log_step "stage_retdec: skipping managed (.NET) target; use stage_dotnet output"
        return 0
    fi

    # Apply to native binary types only.
    if ! file "$target" 2>/dev/null | grep -qE "ELF|PE32|Mach-O"; then
        log_step "stage_retdec: skipping non-native target"
        return 0
    fi

    mkdir -p "$rd"
    log_step "stage_retdec: invoking RetDec via Docker (this may take 1-5 minutes)"

    # The wrapper script bind-mounts target ro and outdir rw, then runs
    # retdec-decompiler. Cap with timeout so a pathological binary doesn't
    # stall the pipeline.
    if timeout 600 /opt/retdec/decompile.sh "$target" "$rd" >>"${rd}/retdec.log" 2>&1; then
        log_step "stage_retdec: complete ($(ls "$rd" | wc -l) output files)"
    else
        local rc=$?
        if [[ $rc -eq 124 ]]; then
            log_warn "stage_retdec: timed out after 600s (target too large?)"
        else
            log_warn "stage_retdec: exited $rc (see ${rd}/retdec.log)"
        fi
    fi
    return 0
}
