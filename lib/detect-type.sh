#!/usr/bin/env bash
# =============================================================================
# lib/detect-type.sh
# =============================================================================
#
# Synopsis:
#     Binary type detection and runtime sub-classification.
#
# Description:
#     Classifies a target file into exactly one primary type, which the
#     dispatcher uses to select the analysis pipeline. Detection is ordered so
#     that more specific signatures win: UPX-packed images are recognized
#     before the generic PE match, because a packed PE matches both.
#
#     Primary types, in dispatch priority order:
#         pe-native, pe-dotnet, elf, macho, wasm, pyc, jar, pdf, ole,
#         upx-packed, config-xml, unknown
#
#     Runtime sub-classifications are returned by separate helpers and compose
#     with the primary type rather than replacing it. The dispatcher consults
#     both: the primary type drives stage selection, while the detected runtime
#     drives any specialized sub-stage.
#
#     Sourced by analyze-binaries.sh; not directly executable.
#
# Provides:
#     detect_type <file>          Prints the primary type token.
#     detect_go_runtime <file>    Prints "go" or empty. Valid for elf,
#                                 pe-native, and macho targets.
#     detect_rust_runtime <file>  Prints "rust" or empty. Valid for elf,
#                                 pe-native, and macho targets.
#
# Notes:
#     Type-to-stage routing is documented in the wiki (Architecture-and-Design,
#     Stage-Reference). Release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

detect_type() {
    local f="$1"
    local file_out
    file_out=$(file -b "$f" 2>/dev/null)

    # Order matters: UPX must come before pe-native because UPX-packed
    # PE binaries also match the PE signature.
    if echo "$file_out" | grep -qi "UPX compressed"; then
        echo "upx-packed"; return
    fi
    if strings "$f" 2>/dev/null | head -100 | grep -q "UPX!"; then
        echo "upx-packed"; return
    fi

    if echo "$file_out" | grep -q "Mono/.Net assembly"; then
        echo "pe-dotnet"; return
    fi

    if echo "$file_out" | grep -qE "PE32[+]? executable|MS-DOS executable"; then
        echo "pe-native"; return
    fi

    if echo "$file_out" | grep -q "ELF"; then
        echo "elf"; return
    fi

    # v2.6.0: Mach-O detection. file(1) on Linux says "Mach-O" for both
    # 32-bit and 64-bit and "Mach-O universal binary" for fat binaries.
    if echo "$file_out" | grep -qE "Mach-O|Apple binary"; then
        echo "macho"; return
    fi

    # v2.6.0: WASM detection via magic bytes (\x00asm followed by version).
    # file(1) on older systems may not recognize WASM; magic is more reliable.
    local magic
    magic=$(head -c 4 "$f" 2>/dev/null | xxd -p 2>/dev/null)
    if [[ "$magic" == "0061736d" ]]; then
        echo "wasm"; return
    fi
    if echo "$file_out" | grep -qi "WebAssembly"; then
        echo "wasm"; return
    fi

    # v2.6.0: Python bytecode (.pyc / .pyo). file(1) says
    # "python.*byte-compiled" and there's a known magic-byte table per
    # Python version, but that table changes. Defer to the file(1) string
    # match plus extension fallback.
    if echo "$file_out" | grep -qiE "python.*byte-compiled|python bytecode"; then
        echo "pyc"; return
    fi
    case "${f,,}" in
        *.pyc|*.pyo)
            # Even if file(1) doesn't recognize it, the extension is
            # near-definitive in practice.
            echo "pyc"; return ;;
    esac

    # v2.6.0: PDF detection via "%PDF-" signature in first 5 bytes.
    local first5
    first5=$(head -c 5 "$f" 2>/dev/null)
    if [[ "$first5" == "%PDF-" ]]; then
        echo "pdf"; return
    fi
    if echo "$file_out" | grep -qi "PDF document"; then
        echo "pdf"; return
    fi

    # v2.8.0: standalone DEX (Dalvik Executable). Magic bytes are
    #   64 65 78 0a 30 33 35 00  ("dex\n035\0") for standard DEX
    #   64 65 79 0a 30 33 36 00  ("dey\n036\0") for optimized DEX
    # Distinct from APK because a standalone classes.dex from a forensics
    # extraction or a malware sample should be analyzed without an
    # enclosing APK container. Two-path detection: file(1) string match
    # (universally available) plus xxd-based magic check (matches v2.6.0
    # pattern; Kali always has xxd via vim-common).
    if echo "$file_out" | grep -qiE "Dalvik dex file|^dex$"; then
        echo "dex"; return
    fi
    local dex_magic=""
    if command -v xxd >/dev/null 2>&1; then
        dex_magic=$(head -c 8 "$f" 2>/dev/null | xxd -p 2>/dev/null)
    elif command -v od >/dev/null 2>&1; then
        dex_magic=$(head -c 8 "$f" 2>/dev/null | od -An -tx1 -N8 2>/dev/null | tr -d ' \n')
    fi
    if [[ "$dex_magic" == "6465780a30333500"* || \
          "$dex_magic" == "6465790a30333600"* ]]; then
        echo "dex"; return
    fi

    # v2.8.0: Android APK / AAB / XAPK / APKM. All are ZIP files; the
    # distinguisher is presence of an AndroidManifest.xml entry. APK
    # detection MUST come BEFORE jar detection (both are ZIP-based; a
    # bare extension check would misclassify .jar that happen to be
    # Android-related, and vice-versa).
    case "${f,,}" in
        *.apk|*.aab|*.xapk|*.apkm)
            local zipmagic=""
            if command -v xxd >/dev/null 2>&1; then
                zipmagic=$(head -c 4 "$f" 2>/dev/null | xxd -p 2>/dev/null)
            elif command -v od >/dev/null 2>&1; then
                zipmagic=$(head -c 4 "$f" 2>/dev/null | od -An -tx1 -N4 2>/dev/null | tr -d ' \n')
            fi
            if [[ "$zipmagic" == "504b0304" || "$zipmagic" == "504b0506" ]]; then
                echo "apk"; return
            fi
            ;;
    esac
    # Extension-less APK detection: ZIP magic + AndroidManifest.xml entry.
    # This handles cases where the analyst dropped a renamed APK or a
    # forensics-extracted APK without its original extension.
    local zipmagic_for_apk=""
    if command -v xxd >/dev/null 2>&1; then
        zipmagic_for_apk=$(head -c 4 "$f" 2>/dev/null | xxd -p 2>/dev/null)
    elif command -v od >/dev/null 2>&1; then
        zipmagic_for_apk=$(head -c 4 "$f" 2>/dev/null | od -An -tx1 -N4 2>/dev/null | tr -d ' \n')
    fi
    if [[ "$zipmagic_for_apk" == "504b0304" ]] && command -v unzip >/dev/null 2>&1; then
        if unzip -l "$f" 2>/dev/null | grep -qE "[[:space:]]AndroidManifest\.xml$"; then
            echo "apk"; return
        fi
    fi

    # v2.6.0: Java archives (.jar/.war/.ear). All are ZIPs with a
    # META-INF/MANIFEST.MF entry. We check the extension first because
    # it's near-definitive, then verify ZIP magic + manifest entry.
    # v2.8.0: hardened with od fallback for consistency with new APK
    # branch (xxd may be missing on minimal Debian).
    case "${f,,}" in
        *.jar|*.war|*.ear)
            local zipmagic=""
            if command -v xxd >/dev/null 2>&1; then
                zipmagic=$(head -c 4 "$f" 2>/dev/null | xxd -p 2>/dev/null)
            elif command -v od >/dev/null 2>&1; then
                zipmagic=$(head -c 4 "$f" 2>/dev/null | od -An -tx1 -N4 2>/dev/null | tr -d ' \n')
            fi
            if [[ "$zipmagic" == "504b0304" || "$zipmagic" == "504b0506" ]]; then
                echo "jar"; return
            fi
            ;;
    esac

    # v2.6.0: OLE documents. Two flavors:
    #   1. Legacy OLE (DOC, XLS, PPT, MSG) - "Composite Document File V2"
    #   2. OOXML (DOCX, XLSX, PPTX) - actually ZIP files with [Content_Types].xml
    if echo "$file_out" | grep -qi "Composite Document File V2"; then
        echo "ole"; return
    fi
    case "${f,,}" in
        *.docx|*.xlsx|*.pptx|*.docm|*.xlsm|*.pptm|*.doc|*.xls|*.ppt|*.msg)
            local zipmagic=""
            if command -v xxd >/dev/null 2>&1; then
                zipmagic=$(head -c 4 "$f" 2>/dev/null | xxd -p 2>/dev/null)
            elif command -v od >/dev/null 2>&1; then
                zipmagic=$(head -c 4 "$f" 2>/dev/null | od -An -tx1 -N4 2>/dev/null | tr -d ' \n')
            fi
            if [[ "$zipmagic" == "504b0304" ]]; then
                # Verify it looks like OOXML by checking for [Content_Types].xml
                # via unzip -l. Fall back to extension-only if unzip fails.
                if command -v unzip >/dev/null 2>&1; then
                    if unzip -l "$f" 2>/dev/null | grep -q "\[Content_Types\]\.xml"; then
                        echo "ole"; return
                    fi
                fi
                # Extension is strong evidence even without unzip verification
                echo "ole"; return
            elif [[ "$zipmagic" == "d0cf11e0" ]]; then
                # OLE2 / Composite Document File magic
                echo "ole"; return
            fi
            ;;
    esac

    case "${f,,}" in
        *.config|*.xml|*.nlog|*.manifest|*.nuspec)
            echo "config-xml"; return ;;
    esac

    local firstline
    firstline=$(head -c 200 "$f" 2>/dev/null | tr -d '\r')
    if echo "$firstline" | grep -qE '^<\?xml|^<configuration|^<\!'; then
        echo "config-xml"; return
    fi

    echo "unknown"
}

# v2.6.0: Go-runtime sub-detection. Returns "go" if the binary is
# Go-compiled, empty otherwise. Works on elf, pe-native, and macho.
# Detection method: look for the .gopclntab section header magic
# (fb ff ff ff for Go 1.16+, fa ff ff ff for older) anywhere in the
# binary, OR look for the "Go build ID:" string. Either is conclusive
# because non-Go binaries don't have these markers.
detect_go_runtime() {
    local f="$1"

    # Check for "Go build ID:" near the top (cheap)
    if head -c 65536 "$f" 2>/dev/null | grep -aq "Go build ID:"; then
        echo "go"; return
    fi

    # Check for Go pclntab magic in the binary (slightly more expensive
    # but conclusive). Magic bytes vary by Go version:
    #   fbffffff  - Go 1.16-1.17
    #   faffffff  - Go 1.2-1.15
    #   f0ffffff  - Go 1.18+
    if grep -aq -E $'\xfb\xff\xff\xff|\xfa\xff\xff\xff|\xf0\xff\xff\xff' "$f" 2>/dev/null; then
        # False-positive guard: also require evidence of Go runtime via
        # strings - the four-byte sequence alone is too short for safety.
        if strings -n 12 "$f" 2>/dev/null | head -2000 | \
            grep -qE "runtime\.|go\.buildid|go:itab\.|^go1\.[0-9]+"; then
            echo "go"; return
        fi
    fi

    echo ""
}

# v2.6.0: Rust-runtime sub-detection. Returns "rust" if the binary
# contains Rust runtime markers, empty otherwise.
# Detection method: look for distinctive Rust panic strings or
# standard-library paths. Rust binaries always contain panic-related
# strings like "src/libcore/panicking.rs" or
# "/rustc/.../library/std/src/panicking.rs" because they're embedded
# by the panic infrastructure even in release builds.
detect_rust_runtime() {
    local f="$1"

    if strings -n 12 "$f" 2>/dev/null | head -5000 | grep -qE \
        "src/libcore/panicking\.rs|library/core/src/panicking\.rs|library/std/src/panicking\.rs|library/alloc/src/raw_vec\.rs|/rustc/[0-9a-f]{8,}/"; then
        echo "rust"; return
    fi

    echo ""
}
