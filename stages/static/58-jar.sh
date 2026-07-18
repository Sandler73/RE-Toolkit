#!/usr/bin/env bash
# =============================================================================
# stages/static/58-jar.sh
# =============================================================================
#
# Synopsis:
#     Java JAR, WAR, and EAR archive analysis and decompilation.
#
# Description:
#     Tools (independent - each gives a different decompilation perspective):
#     - Unzip -l : entry listing
#     - Unzip extraction of MANIFEST.MF: build metadata
#     - CFR : C# decompiler (highest fidelity for modern Java including Java
#       12+)
#     - Procyon-decompiler : alternative Java decompiler with different
#       heuristics; useful for cross-checking CFR output
#     - Javap (JDK) : authoritative bytecode disassembler (run on a
#       representative subset of classes since processing every class can be
#       expensive)
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
#     stage_jar()
#
# Output subtrees:
#     ${outdir}/58-jar/
#
# Skip controls:
#     SKIP_JAR
#
# Tools invoked (run_tool labels):
#     cfr, procyon, unzip-listing
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_jar() {
    local target="$1" outdir="$2"
    local jr="${outdir}/58-jar"

    if [[ ${SKIP_JAR:-0} -eq 1 ]]; then
        log_step "JAR: skipped (SKIP_JAR=1)"
        return 0
    fi

    mkdir -p "$jr"

    # Entry listing - gives a quick view of package structure
    if command -v unzip >/dev/null 2>&1; then
        run_tool "unzip-listing" "${jr}/listing.txt" 30 \
            unzip -l "$target"

        # Manifest extraction
        unzip -p "$target" "META-INF/MANIFEST.MF" 2>/dev/null \
            > "${jr}/MANIFEST.MF" || true
        if [[ -s "${jr}/MANIFEST.MF" ]]; then
            log_step "MANIFEST.MF extracted: $(wc -l < "${jr}/MANIFEST.MF") lines"
        fi

        # Class count for sizing the analysis
        local class_count
        class_count=$(unzip -l "$target" 2>/dev/null | grep -cE '\.class$' | head -1 | tr -dc '0-9')
        class_count="${class_count:-0}"
        log_step "JAR contains ${class_count} class files"
    fi

    # CFR decompiler - takes a JAR directly
    if [[ -f "/opt/cfr/cfr.jar" ]] && command -v java >/dev/null 2>&1; then
        mkdir -p "${jr}/cfr"
        run_tool "cfr" "${jr}/cfr.log" "${TOOL_TIMEOUT:-1200}" \
            java -jar /opt/cfr/cfr.jar "$target" --outputdir "${jr}/cfr"
        local cfr_java_count
        cfr_java_count=$(find "${jr}/cfr" -name '*.java' 2>/dev/null | wc -l)
        log_step "CFR produced ${cfr_java_count} .java files"
    else
        log_step "CFR: skipped (jar missing or java unavailable)"
    fi

    # procyon decompiler - alternative perspective
    if [[ -f "/opt/procyon/procyon.jar" ]] && command -v java >/dev/null 2>&1; then
        mkdir -p "${jr}/procyon"
        run_tool "procyon" "${jr}/procyon.log" "${TOOL_TIMEOUT:-1200}" \
            java -jar /opt/procyon/procyon.jar -jar "$target" -o "${jr}/procyon"
        local proc_java_count
        proc_java_count=$(find "${jr}/procyon" -name '*.java' 2>/dev/null | wc -l)
        log_step "procyon produced ${proc_java_count} .java files"
    else
        log_step "procyon: skipped (jar missing or java unavailable)"
    fi

    # javap - bytecode disassembly. Running it on every class would be
    # expensive for large JARs. Sample the first 20 .class entries.
    if command -v javap >/dev/null 2>&1; then
        mkdir -p "${jr}/javap"
        local extract_dir="${jr}/.classes"
        mkdir -p "$extract_dir"
        # Extract only the first 20 .class files to limit cost
        local entries
        entries=$(unzip -l "$target" 2>/dev/null | awk '/\.class$/ {print $NF}' | head -20)
        if [[ -n "$entries" ]]; then
            (cd "$extract_dir" && unzip -o -q "$target" $entries 2>/dev/null) || true
            {
                echo "=== javap -p -c -v on first 20 classes ==="
                while IFS= read -r class_path; do
                    [[ -z "$class_path" ]] && continue
                    local cls_file="${extract_dir}/${class_path}"
                    if [[ -f "$cls_file" ]]; then
                        echo ""; echo "--- $class_path ---"
                        timeout 30 javap -p -c -v "$cls_file" 2>&1 || true
                    fi
                done <<< "$entries"
            } > "${jr}/javap-sample.txt"
            log_step "javap sampled $(wc -l < "${jr}/javap-sample.txt") output lines"
        fi
        rm -rf "$extract_dir"
    fi
}
