#!/usr/bin/env bash
# =============================================================================
# stages/static/14-pev.sh
# =============================================================================
#
# Synopsis:
#     pev suite analysis (readpe, pedis, pehash, pescan, pesec, pestr).
#
# Description:
#     Per-utility invocation for PE binaries. Each output is a plain text file
#     at the deepest verbosity the tool offers. All of these tools exit
#     non-zero on malformed PE; we capture regardless.
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
#     stage_pev()
#
# Output subtrees:
#     ${outdir}/14-pev/
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_pev() {
    local target="$1" outdir="$2"
    local ft; ft=$(file -b "$target" 2>/dev/null)
    if [[ "$ft" != *"PE32"* && "$ft" != *"MS-DOS"* && "$ft" != *"Mono/.Net"* ]]; then
        return 0  # not a PE -- skip quietly
    fi
    local pv="${outdir}/14-pev"
    mkdir -p "$pv"

    # pedis -- full disassembly (all functions, all sections)
    # v3.0.10 (audit-14 A1) - CLI flag corrections per pev manpage:
    #   `-F` does NOT exist; correct is `-f text` (lowercase)
    #   `-m` takes 16/32/64 only; AT&T syntax is `--att` (NOT `-m att`)
    #   `--n` long form does NOT exist; only `-n` short form
    # v3.0.11 (audit-15 A2) - audit-14 fix used `--offset 0` which is
    # technically valid per the manpage but offset 0 is the DOS header
    # (MZ magic) - not executable code. pedis returns to help when no
    # disassemblable input is found at the requested offset. Operator
    # reported pedis output was just help text after audit-14 fix.
    #
    # Fix: use the manpage's documented invocation patterns:
    #   `pedis -e <file>`           (entrypoint disassembly)
    #   `pedis -s ".text" <file>`   (named section disassembly)
    # Both have working examples in the Debian/Ubuntu pedis(1) manpage.
    # Concatenate both into pedis.txt with section headers so operators
    # see entrypoint analysis AND complete .text section in one file.
    #
    # `-n` is removed: it limits bytes-disassembled within a chosen
    # range, but `-e` (entrypoint) and `-s` (named section) already
    # define their own scope. Keeping `-n 200000` truncated long
    # functions / large sections.
    if command -v pedis >/dev/null 2>&1; then
        {
            echo "=== pedis (entrypoint disasm, AT&T syntax) ==="
            pedis --att -e "$target" 2>&1 || true
            echo ""
            echo "=== pedis (.text section disasm, AT&T syntax) ==="
            pedis --att -s ".text" "$target" 2>&1 || true
        } > "${pv}/pedis.txt"
    fi

    # pehash -- imphash, rich-hash, ssdeep, per-section hashes
    # v3.0.10 (audit-14 F1) - add -a flag to get FULL output. Per pev
    # manpage: "-a, --all  Hash file, sections and headers with md5,
    # sha1, sha256, ssdeep and imphash." Without -a, pehash only emits
    # the file-content hash (md5/sha1/sha256 of the file bytes) and
    # NOTHING about imphash, per-header hashes, or per-section hashes.
    # Pre-v3.0.10 invocation produced minimal output and 85-summary.sh
    # never read the file at all.
    if command -v pehash >/dev/null 2>&1; then
        {
            echo "=== pehash (-a; all hashes: file + headers + sections) ==="
            pehash -a "$target" 2>&1 || true
        } > "${pv}/pehash.txt"
    fi

    # pescan -- anomaly detection (packed, suspicious entry, TLS, headers)
    if command -v pescan >/dev/null 2>&1; then
        {
            echo "=== pescan -v (verbose) ==="
            pescan -v -f text "$target" 2>&1 || true
        } > "${pv}/pescan.txt"
    fi

    # pesec -- security characteristics
    if command -v pesec >/dev/null 2>&1; then
        {
            echo "=== pesec -f text ==="
            pesec -f text "$target" 2>&1 || true
        } > "${pv}/pesec.txt"
    fi

    # pestr -- PE-aware string extraction
    if command -v pestr >/dev/null 2>&1; then
        {
            echo "=== pestr (PE-aware strings) ==="
            pestr -s "$target" 2>&1 || true
        } > "${pv}/pestr.txt"
    fi

    log_step "pev: suite run → ${pv}/"
}
