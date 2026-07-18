#!/usr/bin/env bash
# =============================================================================
# stages/static/62-pdf.sh
# =============================================================================
#
# Synopsis:
#     PDF document structural and active-content analysis.
#
# Description:
#     Tool stack (Didier Stevens + community + mupdf):
#     - Pdfid : keyword counter for /JavaScript, /OpenAction, /JS, /AA,
#       /Launch, /EmbeddedFile, /AcroForm, /XFA, etc. Fast first-pass triage
#       indicator.
#     - Pdf-parser : object-level walker. Extracts indirect objects, resolves
#       references, dumps streams.
#     - Peepdf : combines pdfid + pdf-parser plus JavaScript decoder.
#     - Mutool : mupdf's command-line tool. Authoritative parser for the PDF
#       format itself.
#     - Qpdf : structural validator and round-trip-er. --check flag reports
#       object-level errors.
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
#     stage_pdf()
#
# Output subtrees:
#     ${outdir}/62-pdf/
#
# Skip controls:
#     SKIP_PDF
#
# Tools invoked (run_tool labels):
#     mutool-info, mutool-show-trailer, pdf-parser-js, pdf-parser-openaction,
#     pdf-parser-stats, pdfid, peepdf, qpdf-check
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_pdf() {
    local target="$1" outdir="$2"
    local pd="${outdir}/62-pdf"

    if [[ ${SKIP_PDF:-0} -eq 1 ]]; then
        log_step "PDF: skipped (SKIP_PDF=1)"
        return 0
    fi

    mkdir -p "$pd"

    # pdfid - fast keyword counter
    local pdfid_cmd=""
    if command -v pdfid >/dev/null 2>&1; then
        pdfid_cmd="pdfid"
    elif command -v pdfid.py >/dev/null 2>&1; then
        pdfid_cmd="pdfid.py"
    elif [[ -x "/opt/DidierStevensSuite/pdfid.py" ]]; then
        pdfid_cmd="python3 /opt/DidierStevensSuite/pdfid.py"
    fi
    if [[ -n "$pdfid_cmd" ]]; then
        run_tool "pdfid" "${pd}/pdfid.txt" 60 \
            $pdfid_cmd -a "$target"
        # Parse hits for high-risk keywords for the verdict
        if grep -qE "/JavaScript|/JS|/OpenAction|/AA|/Launch|/EmbeddedFile" "${pd}/pdfid.txt" 2>/dev/null; then
            log_step "pdfid: high-risk PDF keywords present"
        fi
    fi

    # pdf-parser - object walker
    local pdfparser_cmd=""
    if command -v pdf-parser >/dev/null 2>&1; then
        pdfparser_cmd="pdf-parser"
    elif command -v pdf-parser.py >/dev/null 2>&1; then
        pdfparser_cmd="pdf-parser.py"
    elif [[ -x "/opt/DidierStevensSuite/pdf-parser.py" ]]; then
        pdfparser_cmd="python3 /opt/DidierStevensSuite/pdf-parser.py"
    fi
    if [[ -n "$pdfparser_cmd" ]]; then
        # -a = stats; show object types and counts
        run_tool "pdf-parser-stats" "${pd}/pdf-parser-stats.txt" 120 \
            $pdfparser_cmd -a "$target"
        # JavaScript-specific search
        run_tool "pdf-parser-js" "${pd}/pdf-parser-js.txt" 120 \
            $pdfparser_cmd -s javascript "$target"
        # OpenAction-specific search
        run_tool "pdf-parser-openaction" "${pd}/pdf-parser-openaction.txt" 60 \
            $pdfparser_cmd -s openaction "$target"
    fi

    # peepdf
    if [[ -n "$VENV_BIN" ]] && [[ -x "${VENV_BIN}/peepdf" ]]; then
        run_tool "peepdf" "${pd}/peepdf.txt" "${TOOL_TIMEOUT:-600}" \
            "${VENV_BIN}/peepdf" -f "$target"
    elif command -v peepdf >/dev/null 2>&1; then
        run_tool "peepdf" "${pd}/peepdf.txt" "${TOOL_TIMEOUT:-600}" \
            peepdf -f "$target"
    fi

    # mutool - authoritative PDF parser
    if command -v mutool >/dev/null 2>&1; then
        run_tool "mutool-info" "${pd}/mutool-info.txt" 60 \
            mutool info "$target"
        # mutool show: dump page tree and metadata trailer
        run_tool "mutool-show-trailer" "${pd}/mutool-trailer.txt" 60 \
            mutool show "$target" trailer
    fi

    # qpdf structural check
    if command -v qpdf >/dev/null 2>&1; then
        run_tool "qpdf-check" "${pd}/qpdf-check.txt" 60 \
            qpdf --check "$target"
    fi
}
