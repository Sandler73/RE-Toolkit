#!/usr/bin/env bash
# =============================================================================
# Synopsis:
#     Bisect which v3.0.13 stage script breaks Stage 30.
# Description:
#     Runs analyze-binaries.sh 3 times against v3.0.13, each time swapping
#     in v3.0.12's version of one of the two suspect stage files. The
#     result tells us definitively whether 00-triage.sh, 10-pe.sh, or both
#     are responsible for Stage 30 breaking.
# Notes:
#     Per L28, this is the smallest test that gives definitive evidence.
#     Run from a fresh state (delete prior analyzer output dirs) so each
#     run is independent. Each run takes 5-15 minutes depending on binary
#     and tool count.
# Execution Parameters:
#     Argument 1: path to v3.0.12 RE-Toolkit dir
#     Argument 2: path to v3.0.13 RE-Toolkit dir (will be modified in-place; backed up first)
#     Argument 3: binary path
# Examples:
#     sudo bash v13-bisect.sh \
#         /path/to/retoolkit \
#         /path/to/retoolkit \
#         /path/to/samples/Sample.Shared.dll
# Version:
#     1.0 - 2026-05-03 - audit-19 follow-up
# =============================================================================

set -u

if [[ $# -lt 3 ]]; then
    echo "usage: $0 <v12-dir> <v13-dir> <binary>" >&2
    exit 2
fi

V12="$1"
V13="$2"
BIN="$3"

for f in "$V12/stages/static/00-triage.sh" \
         "$V12/stages/static/10-pe.sh"     \
         "$V13/stages/static/00-triage.sh" \
         "$V13/stages/static/10-pe.sh"     \
         "$V13/analyze-binaries.sh"        \
         "$BIN"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: missing required file: $f" >&2
        exit 2
    fi
done

# Snapshot v13's stage files so we can restore them between runs
BACKUP_DIR=$(mktemp -d -t v13-bisect-backup-XXXXXX)
cp "$V13/stages/static/00-triage.sh" "$BACKUP_DIR/00-triage.sh.v13"
cp "$V13/stages/static/10-pe.sh"     "$BACKUP_DIR/10-pe.sh.v13"
echo "Backed up v13 originals to $BACKUP_DIR"

restore_v13() {
    cp "$BACKUP_DIR/00-triage.sh.v13" "$V13/stages/static/00-triage.sh"
    cp "$BACKUP_DIR/10-pe.sh.v13"     "$V13/stages/static/10-pe.sh"
}
trap restore_v13 EXIT

# Output dir naming
OUT_BASE="/tmp/v13-bisect-$(date +%s)"
mkdir -p "$OUT_BASE"

# ---------------------------------------------------------------------------
# Helper: run one configuration and report stage-30 result
# ---------------------------------------------------------------------------
run_config() {
    local label="$1"
    local outdir="$OUT_BASE/$label"
    mkdir -p "$outdir"

    echo ""
    echo "================================================================"
    echo " RUN: $label"
    echo "================================================================"
    echo "  v13 00-triage.sh sha256: $(sha256sum "$V13/stages/static/00-triage.sh" | awk '{print $1}')"
    echo "  v13 10-pe.sh     sha256: $(sha256sum "$V13/stages/static/10-pe.sh"     | awk '{print $1}')"
    echo "  output dir            : $outdir"
    echo ""

    cd "$V13" || return 2

    # Run analyzer; capture full stdout+stderr in case Stage 30 fails early
    local run_log="$outdir/run.log"
    if "$V13/analyze-binaries.sh" --no-dotnet -o "$outdir/out" "$BIN" > "$run_log" 2>&1; then
        echo "  analyze-binaries.sh exit: 0"
    else
        echo "  analyze-binaries.sh exit: $?"
    fi

    # Look for the Ghidra dump file
    local dump
    dump=$(find "$outdir/out" -name '*.ghidra-dump.txt' -type f 2>/dev/null | head -1)
    local kb=0
    if [[ -n "$dump" && -f "$dump" ]]; then
        kb=$(du -k "$dump" | cut -f1)
    fi

    if [[ $kb -gt 0 ]]; then
        echo "  --> STAGE 30 RESULT: SUCCESS  ($kb KB dump at $dump)"
        echo "PASS"
        return 0
    else
        echo "  --> STAGE 30 RESULT: NO DUMP"
        # Show the ghidra.log if it exists
        local ghidra_log
        ghidra_log=$(find "$outdir/out" -path '*30-ghidra*ghidra.log' -type f 2>/dev/null | head -1)
        if [[ -n "$ghidra_log" ]]; then
            echo "  --- ghidra.log contents (last 30 lines) ---"
            tail -30 "$ghidra_log" | sed 's/^/  | /'
            echo "  ---"
        fi
        echo "FAIL"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Configuration 1: full v3.0.13 (control -- expected to fail per user report)
# ---------------------------------------------------------------------------
restore_v13
RESULT_1=$(run_config "1-full-v13" 2>&1)
echo "$RESULT_1"
RC1=$(echo "$RESULT_1" | tail -1)

# ---------------------------------------------------------------------------
# Configuration 2: v3.0.13 with v3.0.12's 00-triage.sh
# ---------------------------------------------------------------------------
restore_v13
cp "$V12/stages/static/00-triage.sh" "$V13/stages/static/00-triage.sh"
RESULT_2=$(run_config "2-v13-with-v12-triage" 2>&1)
echo "$RESULT_2"
RC2=$(echo "$RESULT_2" | tail -1)

# ---------------------------------------------------------------------------
# Configuration 3: v3.0.13 with v3.0.12's 10-pe.sh
# ---------------------------------------------------------------------------
restore_v13
cp "$V12/stages/static/10-pe.sh" "$V13/stages/static/10-pe.sh"
RESULT_3=$(run_config "3-v13-with-v12-pe" 2>&1)
echo "$RESULT_3"
RC3=$(echo "$RESULT_3" | tail -1)

# ---------------------------------------------------------------------------
# Final restoration + verdict
# ---------------------------------------------------------------------------
restore_v13

echo ""
echo "================================================================"
echo " BISECTION VERDICT"
echo "================================================================"
echo "  Config 1 (full v3.0.13)                : $RC1"
echo "  Config 2 (v13 + v12 00-triage.sh)      : $RC2"
echo "  Config 3 (v13 + v12 10-pe.sh)          : $RC3"
echo ""

if [[ "$RC1" == "FAIL" && "$RC2" == "PASS" && "$RC3" == "FAIL" ]]; then
    echo "  --> 00-triage.sh changes are responsible."
elif [[ "$RC1" == "FAIL" && "$RC3" == "PASS" && "$RC2" == "FAIL" ]]; then
    echo "  --> 10-pe.sh changes are responsible."
elif [[ "$RC1" == "FAIL" && "$RC2" == "PASS" && "$RC3" == "PASS" ]]; then
    echo "  --> Either change alone is sufficient to break Stage 30."
    echo "      Both files contribute. Look for shared resource interaction."
elif [[ "$RC1" == "PASS" ]]; then
    echo "  --> Cannot reproduce -- v3.0.13 succeeded in Config 1."
    echo "      Failure may be environment-specific. Check ghidra.log files."
else
    echo "  --> All configs failed including Config 2 and Config 3."
    echo "      Cause is NOT in 00-triage.sh or 10-pe.sh."
    echo "      Check the run.log files for the actual error:"
    echo "        $OUT_BASE/1-full-v13/run.log"
    echo "        $OUT_BASE/2-v13-with-v12-triage/run.log"
    echo "        $OUT_BASE/3-v13-with-v12-pe/run.log"
fi

echo ""
echo "All output preserved at: $OUT_BASE"
echo "v13 originals restored from: $BACKUP_DIR"
echo "================================================================"
