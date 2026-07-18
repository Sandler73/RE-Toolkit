#!/usr/bin/env bash
# =============================================================================
# stages/static/50-elf.sh
# =============================================================================
#
# Synopsis:
#     ELF-specific analysis: sections, symbols, hardening posture, and DWARF.
#
# Description:
#     ELF-specific analysis: sections, symbols, hardening posture, and DWARF.
#     - Checksec (ELF security flags: NX, PIE, RELRO, Stack Canary, Fortify)
#     - Scanelf (ELF security characteristics, runtime markings)
#     - Dumpelf (C-struct-style PE/ELF header dump)
#     - Pahole (DWARF struct layout when debug info present)
#     - Bloaty (section/segment size breakdown)
#     - Nm -DC (demangled dynamic symbol list; previously plain -D)
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
#     stage_elf()
#
# Output subtrees:
#     ${outdir}/50-elf/
#     ${outdir}/55-go/
#     ${outdir}/57-rust/
#
# Skip controls:
#     SKIP_BLOATY
#     SKIP_CHECKSEC
#     SKIP_DUMPELF
#     SKIP_GO_DETECT
#     SKIP_NM_DEMANGLED
#     SKIP_PAHOLE
#     SKIP_RUST_DETECT
#     SKIP_SCANELF
#
# Tools invoked (run_tool labels):
#     bloaty-debug, bloaty-sections, bloaty-symbols, checksec, checksec-pwn,
#     dumpelf, nm, nm-demangled, pahole, readelf, redress-info,
#     redress-moduledata, redress-packages, redress-source, redress-types,
#     scanelf
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_elf() {
    local target="$1" outdir="$2"
    local elf="${outdir}/50-elf"
    mkdir -p "$elf"

    # Original v2.4.0 tools - preserved verbatim for parity
    command -v readelf >/dev/null 2>&1 && \
        run_tool "readelf" "${elf}/readelf.txt" 60 readelf -a "$target"
    command -v nm >/dev/null 2>&1 && \
        run_tool "nm" "${elf}/nm.txt" 60 nm -D "$target"

    # v2.5.0: nm with C++ name demangling. Complementary to plain -D.
    if [[ ${SKIP_NM_DEMANGLED:-0} -eq 0 ]]; then
        command -v nm >/dev/null 2>&1 && \
            run_tool "nm-demangled" "${elf}/nm-demangled.txt" 60 \
                nm -DC "$target"
    fi

    # v2.5.0: checksec - ELF security mitigations (NX, PIE, RELRO, Canary, ...)
    # Two backends supported: the standalone `checksec` (from apt: checksec) and
    # pwntools' `pwn checksec`. Standalone first; fall back to pwntools.
    if [[ ${SKIP_CHECKSEC:-0} -eq 0 ]]; then
        if command -v checksec >/dev/null 2>&1; then
            run_tool "checksec" "${elf}/checksec.txt" 60 \
                checksec --file="$target"
        elif command -v pwn >/dev/null 2>&1; then
            run_tool "checksec-pwn" "${elf}/checksec.txt" 60 \
                pwn checksec "$target"
        else
            log_warn "checksec/pwn not available - skipping ELF mitigation summary"
        fi
    fi

    # v2.5.0: scanelf - PaX-utils ELF security/runtime markings
    # `-aBT` shows all flags + bind-now + textrels in a single pass.
    if [[ ${SKIP_SCANELF:-0} -eq 0 ]]; then
        command -v scanelf >/dev/null 2>&1 && \
            run_tool "scanelf" "${elf}/scanelf.txt" 60 \
                scanelf -aBT "$target"
    fi

    # v2.5.0: dumpelf - C-struct-style ELF header dump (PaX-utils companion)
    if [[ ${SKIP_DUMPELF:-0} -eq 0 ]]; then
        command -v dumpelf >/dev/null 2>&1 && \
            run_tool "dumpelf" "${elf}/dumpelf.txt" 60 \
                dumpelf "$target"
    fi

    # v2.5.0: pahole - DWARF struct layout (only meaningful when debug info present)
    # Returns non-zero if no DWARF info; treat as soft-fail (logged, not error).
    if [[ ${SKIP_PAHOLE:-0} -eq 0 ]]; then
        if command -v pahole >/dev/null 2>&1; then
            run_tool "pahole" "${elf}/pahole.txt" 120 pahole "$target" || \
                log_step "pahole returned non-zero (typical for stripped binaries)"
        fi
    fi

    # v2.5.0: bloaty - section/segment size breakdown
    # v3.0.11 (audit-15 B2) - expanded to match the PE bloaty audit-15
    # change: three invocations covering sections+segments, symbol
    # tables, and debug-info sources separately. ELF binaries from
    # gcc/clang typically retain debug info, so the compileunits +
    # inlines breakdown often yields rich per-source-file data.
    if [[ ${SKIP_BLOATY:-0} -eq 0 ]] && command -v bloaty >/dev/null 2>&1; then
        run_tool "bloaty-sections" "${elf}/bloaty-sections.txt" 120 \
            bloaty -d sections,segments -n 0 -v "$target"
        run_tool "bloaty-symbols" "${elf}/bloaty-symbols.txt" 120 \
            bloaty -d symbols,fullsymbols,shortsymbols -n 0 -v "$target"
        run_tool "bloaty-debug" "${elf}/bloaty-debug.txt" 120 \
            bloaty -d compileunits,inlines -n 0 -v "$target"
    fi

    # v2.6.0: Go runtime sub-detection. If the binary is Go-compiled,
    # run redress to extract package list, types, and source-tree
    # reconstruction. redress is purpose-built for stripped Go binaries
    # and recovers far more than nm + readelf.
    if [[ ${SKIP_GO_DETECT:-0} -eq 0 ]]; then
        if [[ "$(detect_go_runtime "$target")" == "go" ]]; then
            local goroot="${outdir}/55-go"
            mkdir -p "$goroot"
            log_step "Go runtime detected - running redress"
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
                # gomod info is only available for binaries built with modules
                redress gomod "$target" > "${goroot}/gomod.txt" 2>&1 || true
            else
                log_warn "redress not installed - skipping Go-specific analysis"
                echo "redress was not installed at toolkit setup time" > "${goroot}/_NOT-RUN.txt"
            fi
        fi
    fi

    # v2.6.0: Rust runtime sub-detection. Run rustfilt to demangle any
    # Rust-mangled symbols that nm picked up. Output is a parallel file
    # to nm.txt with demangled names.
    if [[ ${SKIP_RUST_DETECT:-0} -eq 0 ]]; then
        if [[ "$(detect_rust_runtime "$target")" == "rust" ]]; then
            local rustroot="${outdir}/57-rust"
            mkdir -p "$rustroot"
            log_step "Rust runtime detected"
            # Capture rustc path strings (these reveal the rust version
            # used to compile the binary)
            strings -n 12 "$target" 2>/dev/null | \
                grep -oE "/rustc/[0-9a-f]{8,}[^\"']*" | sort -u | head -50 > \
                "${rustroot}/rustc-paths.txt"
            log_step "Rust: $(wc -l < "${rustroot}/rustc-paths.txt") rustc paths captured"
            # Demangle nm output via rustfilt if available
            if command -v rustfilt >/dev/null 2>&1 && [[ -f "${elf}/nm.txt" ]]; then
                rustfilt -i "${elf}/nm.txt" -o "${rustroot}/nm-rust-demangled.txt" 2>&1 || \
                    log_warn "rustfilt: demangle pass failed (see nm-rust-demangled.txt)"
            fi
        fi
    fi
}
