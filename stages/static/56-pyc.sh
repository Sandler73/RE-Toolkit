#!/usr/bin/env bash
# =============================================================================
# stages/static/56-pyc.sh
# =============================================================================
#
# Synopsis:
#     Python bytecode analysis and multi-decompiler recovery.
#
# Description:
#     Tool stack (multiple decompilers because each has version coverage gaps):
#     - Pycdc / pycdas (C++, zrax/pycdc): broad version coverage 1.x-3.13 but
#       Python 3.11+ partial. Source-built into /usr/local/bin/.
#     - Python -m dis: built-in disassembler. Covers any version the host
#       Python supports.
#     - Uncompyle6: pip-installed; works for Python <= 3.8.
#     - Decompyle3: pip-installed; works for Python 3.7-3.8.
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
#     stage_pyc()
#
# Output subtrees:
#     ${outdir}/56-pyc/
#
# Skip controls:
#     SKIP_PYC
#
# Tools invoked (run_tool labels):
#     decompyle3, pycdas, pycdc, python-dis, uncompyle6
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_pyc() {
    local target="$1" outdir="$2"
    local pc="${outdir}/56-pyc"

    if [[ ${SKIP_PYC:-0} -eq 1 ]]; then
        log_step "PYC: skipped (SKIP_PYC=1)"
        return 0
    fi

    mkdir -p "$pc"

    # First 16 bytes are the .pyc header: magic(4) + flags(4) + timestamp(4)
    # + size(4). The magic identifies the Python version.
    {
        echo "=== Header bytes (first 16) ==="
        xxd -l 16 "$target" 2>/dev/null
        echo ""
        echo "=== Magic interpretation ==="
        local magic_hex
        magic_hex=$(head -c 2 "$target" 2>/dev/null | xxd -p 2>/dev/null)
        # Selection of well-known magic prefixes (LSB first; full table
        # in CPython source). This is informational only; actual decompile
        # works regardless.
        case "$magic_hex" in
            420d) echo "  Python 3.11 magic family" ;;
            6f0d) echo "  Python 3.10 magic family" ;;
            550d) echo "  Python 3.9 magic family" ;;
            420d) echo "  Python 3.8 magic family" ;;
            330d) echo "  Python 3.7 magic family" ;;
            160d) echo "  Python 3.6 magic family" ;;
            *)    echo "  Magic $magic_hex (lookup against CPython source)" ;;
        esac
    } > "${pc}/header.txt"

    # pycdc - the C++ decompiler. Broad version coverage.
    if command -v pycdc >/dev/null 2>&1; then
        run_tool "pycdc" "${pc}/pycdc.py" "${TOOL_TIMEOUT:-600}" \
            pycdc "$target"
    else
        log_step "pycdc not installed - skipping (install via source build)"
    fi

    # pycdas - the disassembler companion to pycdc
    if command -v pycdas >/dev/null 2>&1; then
        run_tool "pycdas" "${pc}/pycdas.txt" "${TOOL_TIMEOUT:-600}" \
            pycdas "$target"
    fi

    # python3 -m dis - the built-in. Works for whatever Python the venv
    # has; if the .pyc magic doesn't match, this fails clean.
    if [[ -n "$VENV_PY" ]]; then
        run_tool "python-dis" "${pc}/dis.txt" "${TOOL_TIMEOUT:-600}" \
            "$VENV_PY" -m dis "$target"
    fi

    # uncompyle6 - pip-installed decompiler. Wide coverage up to 3.8.
    if [[ -n "$VENV_BIN" ]] && [[ -x "${VENV_BIN}/uncompyle6" ]]; then
        run_tool "uncompyle6" "${pc}/uncompyle6.py" "${TOOL_TIMEOUT:-600}" \
            "${VENV_BIN}/uncompyle6" "$target"
    fi

    # decompyle3 - works for 3.7-3.8 specifically
    if [[ -n "$VENV_BIN" ]] && [[ -x "${VENV_BIN}/decompyle3" ]]; then
        run_tool "decompyle3" "${pc}/decompyle3.py" "${TOOL_TIMEOUT:-600}" \
            "${VENV_BIN}/decompyle3" "$target"
    fi
}
