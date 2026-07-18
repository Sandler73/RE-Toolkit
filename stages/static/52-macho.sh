#!/usr/bin/env bash
# =============================================================================
# stages/static/52-macho.sh
# =============================================================================
#
# Synopsis:
#     Mach-O structural analysis via the LLVM object tooling.
#
# Description:
#     On Linux there's no native otool. llvm-objdump --macho provides
#     equivalent output for the load commands, sections, segments, indirect
#     symbol table, and disassembly. LIEF (already in the venv) provides a
#     Python-based deep parser that complements llvm-objdump.
#
#     Ghidra is dispatched separately by lib/dispatch.sh and handles full
#     Mach-O analysis including the auto-analyzer and decompiler. This stage
#     focuses on structural inspection.
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
#     stage_macho()
#
# Output subtrees:
#     ${outdir}/52-macho/
#
# Skip controls:
#     SKIP_MACHO
#
# Tools invoked (run_tool labels):
#     llvm-objdump-macho-disasm, llvm-objdump-macho-dylibs,
#     llvm-objdump-macho-headers, llvm-objdump-macho-sections,
#     llvm-objdump-macho-symbols
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_macho() {
    local target="$1" outdir="$2"
    local mh="${outdir}/52-macho"

    if [[ ${SKIP_MACHO:-0} -eq 1 ]]; then
        log_step "Mach-O: skipped (SKIP_MACHO=1)"
        return 0
    fi

    mkdir -p "$mh"

    # llvm-objdump --macho: load commands, dylib list, sections
    if command -v llvm-objdump >/dev/null 2>&1; then
        run_tool "llvm-objdump-macho-headers" "${mh}/load-commands.txt" 60 \
            llvm-objdump --macho --private-headers "$target"
        run_tool "llvm-objdump-macho-sections" "${mh}/sections.txt" 60 \
            llvm-objdump --macho --section-headers "$target"
        run_tool "llvm-objdump-macho-symbols" "${mh}/symbols.txt" 60 \
            llvm-objdump --macho --syms "$target"
        run_tool "llvm-objdump-macho-disasm" "${mh}/disasm.txt" "${TOOL_TIMEOUT:-600}" \
            llvm-objdump --macho -d "$target"
        run_tool "llvm-objdump-macho-dylibs" "${mh}/dylibs.txt" 60 \
            llvm-objdump --macho --dylibs-used "$target"
    fi

    # LIEF Python deep parse
    if [[ -n "$VENV_PY" ]]; then
        "$VENV_PY" - "$target" > "${mh}/lief-macho.txt" 2>&1 <<'PYEOF' || true
import sys
try:
    import lief
except ImportError:
    print("LIEF not available"); sys.exit(0)

binary = lief.parse(sys.argv[1])
if not binary or binary.format != lief.EXE_FORMATS.MACHO:
    print("Not a Mach-O binary (LIEF format=%s)" % binary.format if binary else "Could not parse"); sys.exit(0)

print("=== Mach-O Header ===")
hdr = binary.header
print(f"Magic:          0x{int(hdr.magic):x}")
print(f"CPU type:       {hdr.cpu_type}")
print(f"CPU subtype:    {hdr.cpu_subtype}")
print(f"File type:      {hdr.file_type}")
print(f"Flags:          {hdr.flags}")
print(f"Reserved:       {getattr(hdr, 'reserved', 'N/A')}")

print("\n=== Load commands ===")
for i, cmd in enumerate(binary.commands):
    print(f"  [{i}] {cmd.command} - size {cmd.size}")

print("\n=== Sections ===")
for s in binary.sections:
    seg = s.segment_name if hasattr(s, 'segment_name') else ""
    print(f"  {seg:<16} {s.name:<24} addr=0x{s.virtual_address:x} size={s.size} entropy={s.entropy:.3f}")

print("\n=== Imported libraries ===")
for lib in binary.libraries:
    print(f"  {lib.name}  (compat={lib.compatibility_version}, current={lib.current_version})")

print("\n=== Imported symbols (first 100) ===")
for i, sym in enumerate(binary.imported_symbols):
    if i >= 100: break
    print(f"  {sym.name}")

print("\n=== Exported symbols (first 100) ===")
for i, sym in enumerate(binary.exported_symbols):
    if i >= 100: break
    print(f"  {sym.name}")

print("\n=== Code signature ===")
if binary.has_code_signature:
    cs = binary.code_signature
    print(f"  Present: yes; data offset 0x{cs.data_offset:x}, size {cs.data_size}")
else:
    print("  Present: no")
PYEOF
        log_step "macho LIEF parse: $(wc -l < "${mh}/lief-macho.txt" 2>/dev/null || echo 0) lines"
    fi
}
