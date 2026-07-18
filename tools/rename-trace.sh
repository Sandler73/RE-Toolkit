#!/usr/bin/env bash
# =============================================================================
# Synopsis:
#     Pinpoint exactly which RE-Toolkit stage (and which tool within that stage)
#     creates the duplicated-extension file (e.g. sample.exe.exe).
# Description:
#     Runs analyze-binaries.sh under a watcher that logs every filesystem
#     event in the binary's parent directory with timestamps. The watcher
#     output is correlated with RE-Toolkit's stage timestamps so we can
#     pinpoint which stage's tool creates <target>.<ext>.
# Notes:
#     Uses inotifywait (apt install inotify-tools, very small).
#     If inotify-tools isn't installed, falls back to a polling loop using
#     find with -newer.
# Execution Parameters:
#     Argument 1: path to RE-Toolkit dir
#     Argument 2: binary path
# Examples:
#     sudo bash rename-trace.sh \
#         /path/to/retoolkit \
#         /path/to/samples/Sample.Shared.dll
# Version:
#     1.0 - 2026-05-03 - audit-19 follow-up
# =============================================================================

set -u

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <retoolkit-dir> <binary>" >&2
    exit 2
fi

RETOOLKIT_DIR="$1"
BIN="$2"
BIN=$(readlink -f "$BIN")
BIN_DIR=$(dirname "$BIN")
BIN_NAME=$(basename "$BIN")

if [[ ! -f "$BIN" ]]; then
    echo "ERROR: binary not found: $BIN" >&2
    exit 2
fi
if [[ ! -x "$RETOOLKIT_DIR/analyze-binaries.sh" ]]; then
    echo "ERROR: analyze-binaries.sh not found at $RETOOLKIT_DIR" >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Pre-run baseline snapshot of bin dir
# -----------------------------------------------------------------------------
LOG_DIR="/tmp/rename-trace-$(date +%s)"
mkdir -p "$LOG_DIR"

echo "============================================================"
echo " RE-Toolkit rename-trace v1.0"
echo "============================================================"
echo "  retoolkit_dir = $RETOOLKIT_DIR"
echo "  binary        = $BIN"
echo "  binary_dir    = $BIN_DIR"
echo "  binary_name   = $BIN_NAME"
echo "  log_dir       = $LOG_DIR"
echo ""

ls -la "$BIN_DIR" > "$LOG_DIR/before.txt"
echo "Pre-run dir listing saved: $LOG_DIR/before.txt"

# -----------------------------------------------------------------------------
# Start watcher
# -----------------------------------------------------------------------------
INOTIFY_LOG="$LOG_DIR/inotify.log"
WATCHER_PID=""
if command -v inotifywait >/dev/null 2>&1; then
    echo "Starting inotifywait on $BIN_DIR..."
    inotifywait -m -r --timefmt '%H:%M:%S' \
        --format '%T %e %w%f' \
        -e create -e modify -e moved_to -e moved_from -e delete -e attrib \
        "$BIN_DIR" > "$INOTIFY_LOG" 2>&1 &
    WATCHER_PID=$!
    sleep 1
else
    echo "WARNING: inotifywait not installed (apt install inotify-tools)"
    echo "         Falling back to before/after diff only."
fi

# -----------------------------------------------------------------------------
# Run RE-Toolkit
# -----------------------------------------------------------------------------
RUN_LOG="$LOG_DIR/run.log"
echo ""
echo "Running analyze-binaries.sh..."
echo "  (full output goes to $RUN_LOG; this terminal will show stage markers)"
echo ""

cd "$RETOOLKIT_DIR" || exit 2
START_TS=$(date +%s)
"$RETOOLKIT_DIR/analyze-binaries.sh" "$BIN" 2>&1 | tee "$RUN_LOG" \
    | grep -E '^=== STAGE|stage_|Stage [0-9]' &
RUN_PID=$!
wait $RUN_PID
END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))

# Stop the watcher
if [[ -n "$WATCHER_PID" ]] && kill -0 "$WATCHER_PID" 2>/dev/null; then
    kill "$WATCHER_PID" 2>/dev/null
    wait "$WATCHER_PID" 2>/dev/null
fi

echo ""
echo "============================================================"
echo " Analysis"
echo "============================================================"

# -----------------------------------------------------------------------------
# Post-run dir listing
# -----------------------------------------------------------------------------
ls -la "$BIN_DIR" > "$LOG_DIR/after.txt"

echo "Diff of binary's parent directory (before -> after):"
echo "----------------------------------------------------"
diff "$LOG_DIR/before.txt" "$LOG_DIR/after.txt" | head -40
echo ""

# -----------------------------------------------------------------------------
# Find the rename culprit in inotify log
# -----------------------------------------------------------------------------
if [[ -f "$INOTIFY_LOG" ]]; then
    echo "All inotify events involving '${BIN_NAME}' (any modification):"
    echo "------------------------------------------------------------"
    grep -F "$BIN_NAME" "$INOTIFY_LOG" | head -30
    echo ""

    echo "Specifically searching for '${BIN_NAME}.<extension>' creation events:"
    echo "------------------------------------------------------------"
    # Match "BIN_NAME.something" but not the original BIN_NAME exactly
    grep -E "${BIN_NAME//./\\.}\.[a-zA-Z0-9]+" "$INOTIFY_LOG" | head -10
    echo ""

    echo "First 5 'CREATE' events on files matching '${BIN_NAME}*' (timestamped):"
    echo "------------------------------------------------------------"
    grep -E "(CREATE|MOVED_TO).*${BIN_NAME}" "$INOTIFY_LOG" | head -5
fi

# -----------------------------------------------------------------------------
# Correlate with RE-Toolkit stages
# -----------------------------------------------------------------------------
echo ""
echo "RE-Toolkit stage start times (correlate against inotify timestamps):"
echo "-------------------------------------------------------------------"
grep -nE 'STAGE [0-9]+|stage_[a-z]+ ' "$RUN_LOG" | head -25

# -----------------------------------------------------------------------------
# Verdict
# -----------------------------------------------------------------------------
echo ""
echo "============================================================"
DUPE_FILES=$(find "$BIN_DIR" -maxdepth 1 -name "${BIN_NAME}.*" -type f 2>/dev/null)
if [[ -n "$DUPE_FILES" ]]; then
    echo "REPRODUCED: duplicate-extension file(s) created:"
    for df in $DUPE_FILES; do
        echo "  $df ($(stat -c%s "$df") bytes, sha256=$(sha256sum "$df" | cut -d' ' -f1 | cut -c1-12)...)"
    done
    echo ""
    echo "Original sha256 (from $LOG_DIR/before.txt context):"
    sha256sum "$BIN" | cut -c1-72
    echo ""
    echo "If sha256 matches, it's a COPY of the original (some tool created it)."
    echo "If different, the original was MODIFIED then renamed."
else
    echo "NO REPRODUCTION: no duplicate-extension files found in $BIN_DIR"
fi
echo ""
echo "Full log dir: $LOG_DIR"
echo "============================================================"
