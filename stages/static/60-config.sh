#!/usr/bin/env bash
# =============================================================================
# stages/static/60-config.sh
# =============================================================================
#
# Synopsis:
#     Configuration and XML inspection for adjacent application metadata.
#
# Description:
#     Configuration and XML inspection for adjacent application metadata.
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
#     stage_config()
#
# Output subtrees:
#     ${outdir}/60-config/
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_config() {
    local target="$1" outdir="$2"
    local cfg="${outdir}/60-config"
    mkdir -p "$cfg"

    if command -v xmllint >/dev/null 2>&1; then
        xmllint --format "$target" > "${cfg}/formatted.xml" 2>"${cfg}/xmllint-errors.txt" || true
        log_step "xmllint: formatted output written"
    fi

    {
        echo "=== Credential / secret pattern search ==="
        echo ""
        echo "--- Connection strings ---"
        grep -iE "(connection\s*string|connectionstring|data\s*source|server\s*=)" "$target" 2>/dev/null || echo "(none)"
        echo ""
        echo "--- Password / key patterns ---"
        grep -iE "(password\s*=|pwd\s*=|secret\s*=|api[_-]?key|token\s*=)" "$target" 2>/dev/null || echo "(none)"
        echo ""
        echo "--- URLs ---"
        grep -oE "https?://[^ \"'<>]+" "$target" 2>/dev/null | sort -u | head -50 || echo "(none)"
        echo ""
        echo "--- File paths ---"
        grep -oE "(C:\\\\[A-Za-z]|/[a-z/]+)[^ \"'<>]*" "$target" 2>/dev/null | sort -u | head -50 || echo "(none)"
    } > "${cfg}/secrets-scan.txt"
    log_step "secrets-scan written"
}
