#!/usr/bin/env bash
# =============================================================================
# stages/static/88-yargen.sh
# =============================================================================
#
# Synopsis:
#     yarGen YARA rule generation from target strings (opt-in).
#
# Description:
#     OPT-IN by default. yarGen extracts strings from a malware sample, filters
#     them against a goodware database, and emits a YARA rule containing the
#     most distinctive non-goodware strings.
#
#     YarGen takes a directory of malware samples, not a single file. We create
#     a single-file directory shim and pass it. yarGen writes yargen_rules.yar
#     in the cwd we run it from.
#
#     Quality of generated rules depends on the goodware database. Without a
#     goodware DB, yarGen still emits rules but they're noisier (no filtering
#     against legit-software strings). Install with --with-yargen-db at install
#     time to download the ~913MB DB once.
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
#     stage_yargen()
#
# Output subtrees:
#     ${outdir}/88-yargen/
#
# Skip controls:
#     ENABLE_YARGEN
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_yargen() {
    local target="$1" outdir="$2"
    local yg="${outdir}/88-yargen"

    if [[ ${ENABLE_YARGEN:-0} -ne 1 ]]; then
        log_step "yargen: skipped (opt-in via --enable-yargen)"
        return 0
    fi

    if [[ ! -f "/opt/yarGen/yarGen.py" ]]; then
        log_warn "yargen: /opt/yarGen/yarGen.py not found; install via installer LAYER 2F"
        return 0
    fi

    if [[ -z "$VENV_PY" ]]; then
        log_warn "yargen: venv Python unavailable; skipping"
        return 0
    fi

    mkdir -p "$yg"

    # yarGen expects a directory of samples. Create a shim directory
    # with a single file (a copy or symlink of the target).
    local shim_dir="${yg}/.shim"
    mkdir -p "$shim_dir"
    rm -f "${shim_dir}"/*
    ln -sf "$(readlink -f "$target")" "${shim_dir}/$(basename "$target")"

    # Check for goodware DB. yarGen looks in /opt/yarGen/dbs/ for
    # good-strings*.db files.
    local goodware_msg="(no goodware DB detected; rules will be noisier)"
    if ls /opt/yarGen/dbs/good-strings*.db >/dev/null 2>&1; then
        goodware_msg="(goodware DB present at /opt/yarGen/dbs/)"
    fi
    log_step "yargen: $goodware_msg"

    # Run yarGen. It writes yargen_rules.yar to the current directory.
    # We run it from the per-binary 88-yargen/ output dir so the rule
    # file lands there.
    pushd "$yg" >/dev/null
    timeout "${YARGEN_TIMEOUT:-600}" "$VENV_PY" /opt/yarGen/yarGen.py \
        -m "$shim_dir" \
        -o yargen_rules.yar \
        -a "retoolkit auto-generated (v2.7.0)" \
        -r "https://github.com/Sandler73/retoolkit" \
        -p "Auto-generated rule from $(basename "$target")" \
        > yargen.log 2>&1 || true
    popd >/dev/null

    if [[ -s "${yg}/yargen_rules.yar" ]]; then
        local rule_count
        rule_count=$(grep -c "^rule " "${yg}/yargen_rules.yar")
        log_step "yargen: generated ${rule_count} YARA rule(s)"
    else
        log_warn "yargen: no rules generated (check yargen.log)"
    fi

    # Clean up shim
    rm -rf "$shim_dir"
}
