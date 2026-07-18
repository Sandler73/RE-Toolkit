#!/usr/bin/env bash
# =============================================================================
# stages/static/10-pe.sh
# =============================================================================
#
# Synopsis:
#     PE-specific analysis shared by native and .NET Portable Executables.
#
# Description:
#     PE-specific analysis shared by native and .NET Portable Executables.
#     - Bloaty (PE section-level size breakdown via -d sections)
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
#     stage_pe()
#
# Output subtrees:
#     ${outdir}/10-pe/
#     ${outdir}/55-go/
#     ${outdir}/57-rust/
#
# Skip controls:
#     SKIP_BLOATY
#     SKIP_GO_DETECT
#     SKIP_RUST_DETECT
#
# Tools invoked (run_tool labels):
#     bloaty-sections, floss, readpe, redress-info, redress-moduledata,
#     redress-packages, redress-source, redress-types
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_pe() {
    local target="$1" outdir="$2"
    local pe="${outdir}/10-pe"
    mkdir -p "$pe"

    if command -v readpe >/dev/null 2>&1; then
        run_tool "readpe" "${pe}/readpe.txt" 60 readpe "$target"
    fi

    if [[ -n "$VENV_PY" ]]; then
        "$VENV_PY" - "$target" > "${pe}/pefile.txt" 2>&1 <<'PYEOF' || true
import sys
try:
    import pefile
except ImportError:
    print("pefile not available in this Python venv"); sys.exit(0)

pe = pefile.PE(sys.argv[1], fast_load=False)
print("=== DOS_HEADER ==="); print(pe.DOS_HEADER)
print("\n=== NT_HEADERS ==="); print(pe.NT_HEADERS)
print("\n=== FILE_HEADER ==="); print(pe.FILE_HEADER)
print("\n=== OPTIONAL_HEADER ==="); print(pe.OPTIONAL_HEADER)

print("\n=== SECTIONS ===")
for s in pe.sections:
    print("%-10s vaddr=%-10x vsize=%-8x rsize=%-8x flags=%-10x" %
          (s.Name.decode(errors='replace').rstrip('\x00'),
           s.VirtualAddress, s.Misc_VirtualSize, s.SizeOfRawData, s.Characteristics))

print("\n=== IMPORTS ===")
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print("Lib: %s" % entry.dll.decode(errors='replace'))
        for imp in entry.imports:
            name = imp.name.decode(errors='replace') if imp.name else "(ord %d)" % imp.ordinal
            print("  %s" % name)

# v3.0.10 (audit-14 D1) - emit delay-loaded imports. Pre-v3.0.10 only
# DIRECTORY_ENTRY_IMPORT was processed; delay-loaded imports were
# silently dropped from the report. The "Lib (delay):" prefix lets
# the parser distinguish delay vs static imports for the report's
# Imports/Exports tab subdivision.
if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        try:
            dll_name = entry.dll.decode(errors='replace')
        except Exception:
            dll_name = "(unknown)"
        print("Lib (delay): %s" % dll_name)
        for imp in (getattr(entry, 'imports', None) or []):
            name = imp.name.decode(errors='replace') if imp.name else "(ord %d)" % imp.ordinal
            print("  %s" % name)

# v3.0.10 (audit-14 D1) - emit bound imports. These are import bindings
# resolved at link time (rare on modern PE but used in some legacy
# Windows DLLs). Bound imports don't have function names per-entry; we
# just list the libraries.
if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
        try:
            dll_name = entry.name.decode(errors='replace') if hasattr(entry, 'name') else str(entry)
        except Exception:
            dll_name = "(unknown)"
        print("Lib (bound): %s" % dll_name)

print("\n=== EXPORTS ===")
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode(errors='replace') if exp.name else "(none)"
        print("  ord=%d rva=0x%x %s" % (exp.ordinal, exp.address, name))

print("\n=== RESOURCES ===")
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        name = str(entry.name) if entry.name else "(type %d)" % entry.id
        print("  Type: %s" % name)

print("\n=== RICH HEADER ===")
try:
    rich = pe.parse_rich_header()
    if rich:
        for e in rich['values']:
            print("  %s" % e)
except Exception as e:
    print("  (not available: %s)" % e)

print("\n=== CLR HEADER ===")
try:
    clr = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct
    print(clr)
except Exception:
    print("  (no CLR header -- not .NET)")

# v3.0.10 (audit-14 D2) - for .NET assemblies, surface the AssemblyRef
# table. .NET assemblies typically have only a single native import
# (mscoree.dll!_CorExeMain or _CorDllMain) - the rich "import" data
# lives in the CLR metadata's AssemblyRef table, which lists every
# referenced .NET assembly (mscorlib, System, System.Core, etc.).
# Without surfacing this, the report under-counts dependencies for
# .NET binaries. Use dnfile (already in venv per LAYER 5) to parse
# the metadata.
print("\n=== ASSEMBLYREF ===")
try:
    import dnfile
    dn = dnfile.dnPE(target)
    if not getattr(dn, 'net', None) or not getattr(dn.net, 'mdtables', None):
        print("  (no .NET metadata)")
    else:
        ar = getattr(dn.net.mdtables, 'AssemblyRef', None)
        if ar is None or not getattr(ar, 'rows', None):
            print("  (no AssemblyRef rows)")
        else:
            for row in ar.rows:
                try:
                    name = row.Name if hasattr(row, 'Name') else "(unknown)"
                    ver_parts = []
                    for f in ('MajorVersion', 'MinorVersion', 'BuildNumber', 'RevisionNumber'):
                        if hasattr(row, f):
                            ver_parts.append(str(getattr(row, f)))
                    version = ".".join(ver_parts) if ver_parts else "(unknown)"
                    print("Ref: %s v%s" % (name, version))
                except Exception as _re:
                    print("  (row parse error: %s)" % _re)
except ImportError:
    print("  (dnfile not available; cannot parse .NET metadata)")
except Exception as _ce:
    print("  (CLR parse error: %s)" % _ce)

print("\n=== CERTIFICATE ===")
try:
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if sec.VirtualAddress and sec.Size:
        print("  Cert directory at 0x%x, size %d bytes" % (sec.VirtualAddress, sec.Size))
    else:
        print("  (no certificate)")
except Exception:
    pass
PYEOF
        log_step "pefile: $(wc -l < "${pe}/pefile.txt" 2>/dev/null || echo 0) lines"
    fi

    if [[ -n "$FLOSS_CMD" ]]; then
        # FLOSS 3.x removed `--no-filter` (default behavior extracts all
        # string types: static, stack, tight, decoded). `--disable-progress`
        # stops the progress bar from garbaging up the per-tool log file,
        # which isn't a TTY.
        # v3.0.11 (audit-15 B3) - `--verbose` flag added: emits diagnostic
        # info per emulation step (tight loops detected, stack-string
        # heuristics, decoded-string identification reasoning). Increases
        # output by ~30% but provides traceability for the decoded
        # strings (operators can see WHY FLOSS believes a string is
        # decoded vs static).
        run_tool "floss" "${pe}/floss.txt" "$TOOL_TIMEOUT" \
            "$FLOSS_CMD" --disable-progress --verbose "$target"
    fi

    # v2.5.0: bloaty for PE - section-level size breakdown.
    # v3.0.11 (audit-15 B2) - expanded data-source coverage. Pre-v3.0.11
    # only `-d sections` ran. Operator finding F5 (audit-15) asks why
    # `-vvv` and additional sources ("symbols", "fullsymbols",
    # "segments") aren't leveraged. Per bloaty/src/bloaty.cc the
    # available data sources are: sections, segments, symbols,
    # rawsymbols, fullsymbols, shortsymbols, compileunits, inlines,
    # inputfiles. The two debug-info-dependent sources (compileunits,
    # inlines) usually produce useful output ONLY for binaries built
    # with debug info (gcc -g, clang -g, MSVC /Z7+/Zi); for stripped
    # PEs they degrade to "[None]" entries. We invoke them anyway
    # because if debug info IS embedded, the breakdown is high-value.
    #
    # Three invocations:
    #   bloaty-sections.txt  - sections + segments only (works on
    #                          stripped binaries; baseline coverage)
    #   bloaty-symbols.txt   - symbols + fullsymbols + shortsymbols
    #                          (separate file; demangled C++ symbols
    #                          are noisy in the main breakdown)
    #   bloaty-debug.txt     - compileunits + inlines (succeeds only
    #                          with debug info; preserved for analyst)
    #
    # `-n 0` means unlimited rows (default truncates to 20). For
    # comprehensive analysis we want every entry. `-v` is bloaty's
    # ONLY verbose flag per upstream doc/using.md and src/bloaty.cc:
    # there is NO `--verbose` long-form. Audit-15 B2 incorrectly used
    # `--verbose` (a pure L55 violation by me - cited docs, didn't
    # verify against the binary). That broke ALL bloaty execution
    # in v3.0.11. Audit-16 A3 reverts to the correct `-v`. L60
    # mandates flag-runtime smoke-tests after every flag change.
    #
    # v3.0.13 (audit-17 D1) - operator F5 (CRITICAL): bloaty PE
    # support is preliminary per upstream blog post (Aug 2018):
    # "PE/COFF support is on the wishlist". The bloaty PE parser
    # supports ONLY -d sections,segments. Any other data source
    # (symbols, fullsymbols, shortsymbols, compileunits, inlines)
    # exits with "bloaty: PE doesn't support this data source".
    # Audit-15 B2's design that ran all 3 invocations for both PE
    # and ELF was wrong for PE.
    #
    # 10-pe.sh now runs ONLY the sections+segments invocation for
    # PE binaries. The symbols and debug invocations are not
    # attempted. Operators see one clean output file, not 2 error
    # outputs and 1 success. ELF + Mach-O continue to run all 3
    # in 50-elf.sh.
    #
    # Lesson L61: Tools that support multiple binary formats may
    # have asymmetric feature support per format. Stage authors
    # must verify each data-source/format combination works for
    # the format being analyzed.
    if [[ ${SKIP_BLOATY:-0} -eq 0 ]] && command -v bloaty >/dev/null 2>&1; then
        run_tool "bloaty-sections" "${pe}/bloaty-sections.txt" 120 \
            bloaty -d sections,segments -n 0 -v "$target"
        # PE format does not support symbols/compileunits/inlines
        # data sources. Document the limitation in the output dir
        # so analysts don't expect those files to exist for PE.
        cat > "${pe}/bloaty-PE-LIMITATION.txt" <<'BLOATY_PE_LIMIT'
bloaty PE format limitation
============================

bloaty's PE/COFF support is preliminary (per upstream blog 2018).
The PE parser supports ONLY:
  -d sections,segments    (in bloaty-sections.txt)

The following data sources are NOT supported for PE binaries:
  -d symbols,fullsymbols,shortsymbols
  -d compileunits,inlines

These data sources are run for ELF and Mach-O binaries (see
50-elf.sh) but skipped for PE because bloaty exits with
"PE doesn't support this data source" if attempted.

For PE-specific symbol-level analysis, see:
  - 10-pe/floss.txt           (decoded strings + emulation hits)
  - 10-pe/objdump-dis.txt     (disassembly via llvm-objdump)
  - 10-pe/readpe-imports.txt  (import table)
  - 10-pe/pedis.txt           (entrypoint + .text disassembly)
  - 30-ghidra/dump.txt        (Ghidra full decompilation)

For PE-specific compile-unit analysis, debug-info needs to be
present in the binary (PDB sidecar). bloaty doesn't yet parse
PDB; that's an unimplemented bloaty feature.
BLOATY_PE_LIMIT
    fi

    # v2.6.0: Go runtime sub-detection (PE-flavored). Go binaries can be
    # cross-compiled to Windows; .gopclntab still appears in the .text
    # or .gopclntab section. redress handles PE-format Go binaries the
    # same way as ELF-format.
    if [[ ${SKIP_GO_DETECT:-0} -eq 0 ]]; then
        if [[ "$(detect_go_runtime "$target")" == "go" ]]; then
            local goroot="${outdir}/55-go"
            mkdir -p "$goroot"
            log_step "Go runtime detected (PE) - running redress"
            if command -v redress >/dev/null 2>&1; then
                run_tool "redress-info" "${goroot}/info.txt" 60 \
                    redress info "$target"
                run_tool "redress-packages" "${goroot}/packages.txt" 120 \
                    redress packages "$target"
                run_tool "redress-types" "${goroot}/types.txt" 120 \
                    redress types "$target"
                run_tool "redress-source" "${goroot}/source.txt" 180 \
                    redress source "$target"
                run_tool "redress-moduledata" "${goroot}/moduledata.txt" 60 \
                    redress moduledata "$target"
                redress gomod "$target" > "${goroot}/gomod.txt" 2>&1 || true
            else
                log_warn "redress not installed - skipping Go-specific analysis"
                echo "redress was not installed at toolkit setup time" > "${goroot}/_NOT-RUN.txt"
            fi
        fi
    fi

    # v2.6.0: Rust runtime sub-detection (PE-flavored)
    if [[ ${SKIP_RUST_DETECT:-0} -eq 0 ]]; then
        if [[ "$(detect_rust_runtime "$target")" == "rust" ]]; then
            local rustroot="${outdir}/57-rust"
            mkdir -p "$rustroot"
            log_step "Rust runtime detected (PE)"
            strings -n 12 "$target" 2>/dev/null | \
                grep -oE "/rustc/[0-9a-f]{8,}[^\"']*" | sort -u | head -50 > \
                "${rustroot}/rustc-paths.txt"
            log_step "Rust: $(wc -l < "${rustroot}/rustc-paths.txt") rustc paths captured"
        fi
    fi
}
