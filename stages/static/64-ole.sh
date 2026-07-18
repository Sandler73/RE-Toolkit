#!/usr/bin/env bash
# =============================================================================
# stages/static/64-ole.sh
# =============================================================================
#
# Synopsis:
#     OLE and OOXML Office document analysis including macro extraction.
#
# Description:
#     Two flavors share this stage:
#     - Legacy OLE: .doc, .xls, .ppt, .msg (Composite Document File V2 magic)
#     - OOXML: .docx, .xlsx, .pptx (ZIP container with [Content_Types].xml)
#
#     Oletools (already in venv) handles both flavors via its individual tools:
#     oleid (heuristic), olevba (macro extraction), oleobj (embedded OLE
#     objects), mraptor (malicious-macro classifier), msodde (DDE link
#     extraction). For OOXML, 7z provides container-level inspection.
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
#     stage_ole()
#
# Output subtrees:
#     ${outdir}/64-ole/
#
# Skip controls:
#     SKIP_OLE
#
# Tools invoked (run_tool labels):
#     7z-listing, mraptor, msodde, oledump, oleid, oleobj, olevba, olevba-json
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_ole() {
    local target="$1" outdir="$2"
    local ol="${outdir}/64-ole"

    if [[ ${SKIP_OLE:-0} -eq 1 ]]; then
        log_step "OLE: skipped (SKIP_OLE=1)"
        return 0
    fi

    mkdir -p "$ol"

    # OOXML container listing via 7z (only useful when target is a ZIP)
    if [[ -n "$VENV_BIN" ]] || command -v 7z >/dev/null 2>&1; then
        local zipmagic
        zipmagic=$(head -c 4 "$target" 2>/dev/null | xxd -p 2>/dev/null)
        if [[ "$zipmagic" == "504b0304" ]] && command -v 7z >/dev/null 2>&1; then
            run_tool "7z-listing" "${ol}/7z-listing.txt" 30 \
                7z l "$target"
        fi
    fi

    # oleid - heuristic risk indicators
    if [[ -n "$VENV_BIN" ]] && [[ -x "${VENV_BIN}/oleid" ]]; then
        run_tool "oleid" "${ol}/oleid.txt" 60 \
            "${VENV_BIN}/oleid" "$target"
    fi

    # olevba - VBA macro extraction (text + JSON for parsing)
    if [[ -n "$VENV_BIN" ]] && [[ -x "${VENV_BIN}/olevba" ]]; then
        run_tool "olevba" "${ol}/olevba.txt" "${TOOL_TIMEOUT:-600}" \
            "${VENV_BIN}/olevba" "$target"
        run_tool "olevba-json" "${ol}/olevba.json" "${TOOL_TIMEOUT:-600}" \
            "${VENV_BIN}/olevba" --json "$target"
    fi

    # oleobj - embedded OLE objects (e.g., suspicious linked spreadsheets)
    if [[ -n "$VENV_BIN" ]] && [[ -x "${VENV_BIN}/oleobj" ]]; then
        run_tool "oleobj" "${ol}/oleobj.txt" 120 \
            "${VENV_BIN}/oleobj" "$target"
    fi

    # mraptor - malicious-macro classifier (lightweight heuristic)
    if [[ -n "$VENV_BIN" ]] && [[ -x "${VENV_BIN}/mraptor" ]]; then
        run_tool "mraptor" "${ol}/mraptor.txt" 60 \
            "${VENV_BIN}/mraptor" "$target"
        if grep -q "SUSPICIOUS" "${ol}/mraptor.txt" 2>/dev/null; then
            log_step "mraptor: SUSPICIOUS verdict"
        fi
    fi

    # msodde - DDE / MS Office DDE-link extraction
    if [[ -n "$VENV_BIN" ]] && [[ -x "${VENV_BIN}/msodde" ]]; then
        run_tool "msodde" "${ol}/msodde.txt" 60 \
            "${VENV_BIN}/msodde" "$target"
    fi

    # oledump (Didier Stevens) - object-level dumper
    if [[ -x "/opt/DidierStevensSuite/oledump.py" ]] && [[ -n "$VENV_PY" ]]; then
        run_tool "oledump" "${ol}/oledump.txt" 120 \
            "$VENV_PY" /opt/DidierStevensSuite/oledump.py "$target"
    fi
}
