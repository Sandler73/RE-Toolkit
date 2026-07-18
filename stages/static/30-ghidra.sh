#!/usr/bin/env bash
# =============================================================================
# stages/static/30-ghidra.sh
# =============================================================================
#
# Synopsis:
#     Ghidra headless analysis driving the GhidraDump.py postscript.
#
# Description:
#     Launches plain analyzeHeadless (Jython) by default. Ghidra 12's
#     PyGhidraScriptProvider does NOT automatically shadow Jython in headless
#     mode -- that only happens when Ghidra is bootstrapped via
#     pyghidra_launcher.py. So for Jython-compatible postscripts (like
#     GhidraDump.py), analyzeHeadless is the simpler, more reliable path.
#
#     Pass --use-pyghidra to launch via pyghidra_launcher.py instead. This is
#     an opt-in for scripts that need Python 3-only features. Args: $1 target
#     binary, $2 per-binary output dir, $3 optional: "light" to use minimal
#     analyzer set (used for .NET)
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
#     stage_ghidra()
#
# Output subtrees:
#     ${outdir}/30-ghidra/
#
# Skip controls:
#     SKIP_GHIDRA
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_ghidra() {
    local target="$1" outdir="$2" mode="${3:-full}"
    [[ $SKIP_GHIDRA -eq 1 ]] && return 0
    [[ -z "$SCRIPT_PATH" ]] && { log_step "Ghidra: skipped (GhidraDump.py not found)"; return 0; }

    local gd="${outdir}/30-ghidra"
    local proj="${gd}/project"
    local fname
    fname=$(basename "$target")
    local dump="${gd}/${fname}.ghidra-dump.txt"
    local logf="${gd}/ghidra.log"
    mkdir -p "$gd" "$proj"

    # Properties file location: distinct files for full vs light mode so a
    # rerun with a different mode uses the right settings.
    local propfile
    if [[ "$mode" == "light" ]]; then
        propfile="${OUTPUT_ROOT}/ghidra-analysis-light.properties"
        if [[ ! -f "$propfile" ]]; then
            # LIGHT mode: only the analyzers that make sense for a .NET
            # native stub. Disables aggressive decomp-based analyzers that
            # generate hundreds of "pcode error" / "Unable to resolve
            # constructor" warnings on CIL bytecode.
            cat > "$propfile" <<'PROPEOF'
Aggressive Instruction Finder=false
ASCII Strings=true
Create Address Tables=false
Decompiler Parameter ID=false
Decompiler Switch Analysis=false
Demangler Microsoft=true
Embedded Media=true
Function Start Search=true
Non-Returning Functions - Known=true
PDB Universal=true
Reference=true
Stack=false
Subroutine References=false
PROPEOF
        fi
    else
        propfile="${OUTPUT_ROOT}/ghidra-analysis.properties"
        if [[ ! -f "$propfile" ]]; then
            cat > "$propfile" <<'PROPEOF'
Aggressive Instruction Finder=true
ASCII Strings=true
Create Address Tables=true
Decompiler Parameter ID=true
Decompiler Switch Analysis=true
Demangler GNU=true
Demangler Microsoft=true
Embedded Media=true
Function ID=true
Function Start Search=true
Non-Returning Functions - Discovered=true
Non-Returning Functions - Known=true
PDB Universal=true
Reference=true
Scalar Operand References=true
Shared Return Calls=true
Stack=true
Subroutine References=true
WindowsPE x86 Propagate External Parameters=true
WindowsPE RTTI Analyzer=true
DWARF=true
Decompiler Parameter ID.Commit Data Types=true
Decompiler Parameter ID.Commit Void Return Values=true
PROPEOF
        fi
    fi

    local args=(
        "$proj" "auto-${fname}"
        -import "$target"
        -overwrite
        -analysisTimeoutPerFile "$GHIDRA_TIMEOUT"
        -propertiesPath "$OUTPUT_ROOT"
        -scriptPath "$(dirname "$SCRIPT_PATH")"
        -postScript "$(basename "$SCRIPT_PATH")" "dump-path=${dump}"
        -log "${gd}/${fname}.analysis.log"
        -scriptlog "${gd}/${fname}.script.log"
    )
    [[ $KEEP_PROJECT -eq 0 ]] && args+=(-deleteProject)

    # Build the environment. PyGhidra requires GHIDRA_INSTALL_DIR + a
    # CPython 3 with the pyghidra module importable.
    local saved_jto="${JAVA_TOOL_OPTIONS:-}"
    export JAVA_TOOL_OPTIONS="-Xmx${JVM_HEAP} -XX:+UseG1GC -Dfile.encoding=UTF-8"
    export GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL"

    # v2.1.7: tell GhidraDump.py where to drop its execution-stage trace
    # file. The script will write ghidra-dump-<pid>.trace there at every
    # major stage (module-top, imports, main-entered, writer-created,
    # etc.). If the dump ends up missing, the trace file tells us
    # exactly which stage failed.
    local sentinel_dir="${gd}/trace"
    mkdir -p "$sentinel_dir"
    local saved_sentinel="${RETOOLKIT_SENTINEL_DIR:-}"
    export RETOOLKIT_SENTINEL_DIR="$sentinel_dir"

    local start=$SECONDS
    local rc=0
    {
        echo "=== Ghidra analyzeHeadless (mode=$mode) ==="
        echo "Started: $(date -Iseconds)"
        if [[ $FORCE_JYTHON -eq 0 && $PYGHIDRA_AVAILABLE -eq 1 && -x "$PYGHIDRA_HELPER" ]]; then
            echo "Launcher: pyghidra-headless helper (CPython 3 + pyghidra, $PYGHIDRA_PY)"
            echo "Helper:   $PYGHIDRA_HELPER"
            echo "Trace:    $sentinel_dir (GhidraDump stage sentinels)"
        else
            echo "Launcher: analyzeHeadless (Jython 2.7) -- only works on Ghidra 11/older"
        fi
    } > "$logf"

    # Launch strategy (v2.1.3):
    #   - Ghidra 12+ (pyghidra_launcher.py exists in install): go via the
    #     helper `$PYGHIDRA_HELPER`, which pyghidra.start()s and calls
    #     AnalyzeHeadless.main() directly. This is the only path where .py
    #     postscripts actually run on Ghidra 12; analyzeHeadless alone
    #     errors with "Ghidra was not started with PyGhidra".
    #   - Ghidra 11 or older: plain analyzeHeadless (Jython) works fine
    #     and we use it.
    #   - `--force-jython`: override -- use analyzeHeadless even on G12+.
    #     Will fail on G12 but useful for debugging.
    #
    # v2.1.4: the PyGhidra path now calls pyghidra.run_script() via our
    # helper with POSITIONAL args, not the analyzeHeadless-style flags
    # from `$args[@]`. The Jython path still uses the flag form.
    local use_helper=0
    if [[ $FORCE_JYTHON -eq 0 && $PYGHIDRA_AVAILABLE -eq 1 && -x "$PYGHIDRA_HELPER" ]]; then
        use_helper=1
    fi

    if [[ $use_helper -eq 1 ]]; then
        # Positional call for pyghidra.run_script() wrapper.
        # Features deferred from the analyzeHeadless path:
        #   - -propertiesPath: no analyzer profile override. All analyzers
        #     run on all binaries. .NET gets noisy pcode warnings in the
        #     log but the dump still produces correctly.
        #   - -scriptlog: no dedicated script log file. The script's
        #     println() / print() output goes to our ghidra.log via the
        #     captured stderr.
        #   - -deleteProject: handled manually below.
        # v3.7.2 (audit-30 A6): hand the analysis budget to the helper so it can
        # bound Ghidra's auto-analysis (best-effort; see helper for the guarded
        # signature check). The outer `timeout` remains the hard wall-clock stop.
        export GHIDRA_ANALYSIS_TIMEOUT="$GHIDRA_TIMEOUT"
        if ! timeout --kill-after=30 "$((GHIDRA_TIMEOUT + 300))" \
            "$PYGHIDRA_PY" "$PYGHIDRA_HELPER" \
            "$GHIDRA_INSTALL" \
            "$target" \
            "$SCRIPT_PATH" \
            "$proj" \
            "auto-${fname}" \
            "dump-path=${dump}" >> "$logf" 2>&1; then
            rc=$?
        fi
        # Manual project cleanup (equivalent of analyzeHeadless -deleteProject)
        if [[ $KEEP_PROJECT -eq 0 && -d "$proj" ]]; then
            rm -rf "$proj" 2>/dev/null || true
        fi
    else
        # Jython path -- unchanged analyzeHeadless invocation
        if ! timeout --kill-after=30 "$((GHIDRA_TIMEOUT + 300))" \
            "$ANALYZE_HEADLESS" "${args[@]}" >> "$logf" 2>&1; then
            rc=$?
        fi
    fi

    local elapsed=$((SECONDS - start))
    echo "Exit: $rc  Elapsed: ${elapsed}s" >> "$logf"

    if [[ -z "$saved_jto" ]]; then unset JAVA_TOOL_OPTIONS; else export JAVA_TOOL_OPTIONS="$saved_jto"; fi
    if [[ -z "$saved_sentinel" ]]; then unset RETOOLKIT_SENTINEL_DIR; else export RETOOLKIT_SENTINEL_DIR="$saved_sentinel"; fi

    # v2.1.7: append trace file contents to ghidra.log BEFORE we decide
    # success/failure, so the stage trace is always preserved alongside
    # the rest of the log. Only on failure do we ALSO print it to the
    # user's console.
    local trace_files
    trace_files=$(find "$sentinel_dir" -name 'ghidra-dump-*.trace' -type f 2>/dev/null | head -5)
    if [[ -n "$trace_files" ]]; then
        {
            echo ""
            echo "=== GhidraDump.py stage trace ==="
            for tf in $trace_files; do
                echo "# File: $tf"
                cat "$tf"
            done
        } >> "$logf"
    fi

    # Validate the dump was produced. Ghidra's own exit code is 0 even when
    # the postscript fails -- the 2.0.0 bug. We verify the dump file exists
    # AND has non-trivial size.
    local dump_kb=0
    if [[ -f "$dump" ]]; then
        dump_kb=$(du -k "$dump" | cut -f1)
    fi

    if [[ $rc -eq 0 && -f "$dump" && $dump_kb -gt 0 ]]; then
        log_step "Ghidra: OK -- ${dump_kb} KB dump in ${elapsed}s (mode=$mode)"
    elif [[ $rc -eq 124 || $rc -eq 137 ]]; then
        log_step "Ghidra: ${C_WARN}TIMEOUT${C_OFF} after ${elapsed}s"
    elif [[ ! -f "$dump" || $dump_kb -eq 0 ]]; then
        log_step "Ghidra: ${C_ERR}NO DUMP PRODUCED${C_OFF} (${elapsed}s) -- script did not execute?"

        # v2.1.7: show the stage trace inline so the user sees exactly
        # where GhidraDump.py stopped. This is the most useful single
        # piece of diagnostic info for any future "dump missing" case.
        if [[ -n "$trace_files" ]]; then
            log_step "   ${C_BOLD}GhidraDump.py stage trace:${C_OFF}"
            for tf in $trace_files; do
                while IFS= read -r tline; do
                    log_step "     $tline"
                done < "$tf"
            done
        else
            log_step "   ${C_WARN}No trace file written -- GhidraDump.py module-top was never reached${C_OFF}"
            log_step "   This means pyghidra never actually executed the script file."
            # v3.7.2 (audit-30 A6): distinguish the "auto-analysis exceeded the
            # budget" case. When the script never started AND the run consumed
            # most of the wall-clock budget, Ghidra's auto-analysis (not the
            # dump script) is what ran out of time -- typical for large managed
            # /.NET assemblies, whose CIL analyzers are slow and whose decompiler
            # output Ghidra cannot meaningfully produce anyway. RE-Toolkit's
            # dedicated .NET stages (20-dotnet: ilspy / dnSpyEx / de4dot / dnfile
            # / monodis) cover managed code far better, so a missing Ghidra dump
            # here is not a loss of coverage.
            if [[ $elapsed -ge $((GHIDRA_TIMEOUT)) ]]; then
                log_step "   ${C_WARN}Ghidra auto-analysis exceeded the ${GHIDRA_TIMEOUT}s budget before the dump script ran.${C_OFF}"
                log_step "   Common for large or managed (.NET/Mono) assemblies. Managed-code"
                log_step "   analysis is provided by the 20-dotnet stages; raise --ghidra-timeout"
                log_step "   to allow a full native pass if a Ghidra dump is specifically needed."
            fi
        fi

        # Defense in depth: hunt for the file by basename.
        local dbase
        dbase=$(basename "$dump")
        local found
        found=$(find "$OUTPUT_ROOT" "$(dirname "$PYGHIDRA_HELPER" 2>/dev/null)" "$HOME" \
                    "$GHIDRA_INSTALL" -maxdepth 8 -name "$dbase" -type f 2>/dev/null \
                | head -5)
        if [[ -n "$found" ]]; then
            log_step "   ${C_WARN}Found dump at unexpected location(s):${C_OFF}"
            while IFS= read -r line; do
                local sz
                sz=$(du -k "$line" 2>/dev/null | cut -f1)
                log_step "     $line (${sz}KB)"
            done <<< "$found"
            log_step "   Relative-path bug in pyghidra/GhidraDump flow?"
        fi
        log_step "   Check: grep -iE 'error|traceback|missing' $logf"
        log_step "   Check: tail -60 ${gd}/${fname}.script.log"
        if [[ $FORCE_JYTHON -eq 1 ]]; then
            log_step "   Note: --force-jython is active; remove for Ghidra 12+"
        fi
        if [[ $PYGHIDRA_AVAILABLE -eq 0 ]] && [[ -f "${GHIDRA_INSTALL}/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py" ]]; then
            log_step "   Note: Ghidra 12+ detected but pyghidra module not importable"
            log_step "         Run: /opt/retools/venv/bin/pip install pyghidra"
        fi
    else
        log_step "Ghidra: ${C_WARN}exit $rc${C_OFF} (${elapsed}s) -- see $logf"
    fi
}
