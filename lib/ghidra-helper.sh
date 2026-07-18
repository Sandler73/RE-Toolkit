#!/usr/bin/env bash
# =============================================================================
# lib/ghidra-helper.sh
# =============================================================================
#
# Synopsis:
#     Ghidra installation discovery and toolkit version recording.
#
# Description:
#     Locates a usable Ghidra installation and records the versions of the
#     tools the run depends on, so that every analysis output is reproducible
#     against a known toolchain.
#
#     Runtime tool discovery and pyghidra helper-script generation live in the
#     driver (analyze-binaries.sh) rather than here, because they reference
#     argument-parsing globals owned by the driver.
#
#     Sourced by analyze-binaries.sh; not directly executable.
#
# Provides:
#     find_ghidra
#         Discovers the Ghidra installation directory. Prints the absolute
#         path on stdout and returns 0 on success; returns 1 when no
#         installation is found. Search order:
#             $GHIDRA_INSTALL, $GHIDRA_INSTALL_DIR, /opt/ghidra,
#             /opt/ghidra_*_PUBLIC, /usr/share/ghidra
#     write_toolkit_versions
#         Records resolved tool versions into the run metadata.
#
# Notes:
#     Ghidra provisioning is handled by install-retoolkit.sh. Release history
#     is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

find_ghidra() {
    local -a candidates=(
        "$GHIDRA_INSTALL"
        "$(expand_tilde "${GHIDRA_INSTALL_DIR:-}")"
        "/opt/ghidra"
    )
    for c in "${candidates[@]}"; do
        [[ -z "$c" ]] && continue
        local real="$c"
        [[ -L "$c" ]] && real=$(readlink -f "$c")
        if [[ -d "$real" && -x "$real/support/analyzeHeadless" ]]; then
            echo "$real"
            return 0
        fi
    done
    for d in /opt/ghidra_*_PUBLIC /usr/share/ghidra; do
        if [[ -d "$d" && -x "$d/support/analyzeHeadless" ]]; then
            echo "$d"
            return 0
        fi
    done
    return 1
}

# write_toolkit_versions: records the version of every tool RE-Toolkit
# uses into ${OUTPUT_ROOT}/_toolkit-versions.txt for run reproducibility.
write_toolkit_versions() {
    local vf="${OUTPUT_ROOT}/_toolkit-versions.txt"
    {
        echo "=== RE Toolkit Versions ==="
        echo "Generated: $(date -Iseconds)"
        echo "Driver:    analyze-binaries.sh v2.3.0"
        echo ""

        get_ver() {
            local name="$1"; shift
            local cmd=("$@")
            if command -v "${cmd[0]}" >/dev/null 2>&1 || [[ -x "${cmd[0]}" ]]; then
                local v
                v=$("${cmd[@]}" 2>&1 | head -2 | tr '\n' ' ' | cut -c1-120)
                printf "  %-18s %s\n" "$name" "$v"
            fi
        }

        get_ver "bash"        bash --version
        [[ -n "$ANALYZE_HEADLESS" ]] && get_ver "ghidra" "$ANALYZE_HEADLESS" -help
        get_ver "radare2"     radare2 -v
        get_ver "rizin"       rizin -v
        get_ver "objdump"     objdump --version
        get_ver "readelf"     readelf --version
        get_ver "nm"          nm --version
        get_ver "file"        file --version
        get_ver "strings"     strings --version
        get_ver "binwalk"     binwalk --version
        get_ver "yara"        yara --version
        get_ver "clamscan"    clamscan --version
        get_ver "exiftool"    exiftool -ver
        get_ver "upx"         upx --version
        [[ -n "$CAPA_CMD"  ]] && get_ver "capa"    "$CAPA_CMD" --version
        [[ -n "$FLOSS_CMD" ]] && get_ver "floss"   "$FLOSS_CMD" --version
        get_ver "monodis"     monodis --help
        get_ver "ikdasm"      ikdasm --help
        [[ -n "$ILSPYCMD" ]] && get_ver "ilspycmd" "$ILSPYCMD" --version
        get_ver "dotnet"      dotnet --version
        get_ver "xmllint"     xmllint --version

        echo ""
        echo "=== Rules inventory ==="
        if [[ -n "$CAPA_RULES" && -d "$CAPA_RULES" ]]; then
            echo "capa rules : $(find "$CAPA_RULES" -name '*.yml' | wc -l) .yml files at $CAPA_RULES"
        fi
        if [[ -n "$YARA_RULES" ]]; then
            if [[ -f "$YARA_RULES" ]]; then
                echo "yara rules : $(grep -c '^include' "$YARA_RULES" 2>/dev/null) includes in $YARA_RULES"
            else
                echo "yara rules : $(find "$YARA_RULES" -type f \( -name '*.yar' -o -name '*.yara' \) | wc -l) files at $YARA_RULES"
            fi
        fi

        echo ""
        echo "=== Python venv packages (${RETOOLS_VENV}) ==="
        if [[ -x "${VENV_BIN}/pip" ]]; then
            "${VENV_BIN}/pip" list 2>/dev/null
        fi
    } > "$vf"
    log_ok "Toolkit versions: $vf"
}
