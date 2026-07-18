#!/usr/bin/env bash
# =============================================================================
# Synopsis:
#     Identify the EXACT process that deletes/renames the target binary file
#     during RE-Toolkit execution. Uses Linux audit subsystem to capture every
#     unlink, rename, link, and modify operation on the file.
# Description:
#     Sets up auditd watch rules on the target file (parent dir + file itself),
#     runs analyze-binaries.sh, and post-processes ausearch output to identify
#     the precise PID, command line, and parent process that triggered the
#     deletion. This succeeds where inotifywait failed because:
#     1. auditd captures path-based ops even when source/target both vanish
#        within microseconds (no race condition).
#     2. PID + comm + exe + cwd are captured for every event, even short-lived
#        processes lsof never sees.
#     3. Tool-by-tool process tree visibility (parent RE-Toolkit -> stage_*
#        function -> run_tool wrapper -> actual tool process).
# Notes:
#     Requires: auditd. Install with: sudo apt install -y auditd
#     This tool sets temporary audit rules and removes them on exit (trap).
#     Output may be voluminous; the verdict block at the end is the answer.
# Execution Parameters:
#     Argument 1: path to RE-Toolkit dir
#     Argument 2: binary path
# Examples:
#     sudo bash file-stalker.sh \
#         /path/to/retoolkit \
#         /path/to/samples/sample.exe
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

if ! command -v auditctl >/dev/null 2>&1 || ! command -v ausearch >/dev/null 2>&1; then
    echo "ERROR: auditd not installed. Install with: sudo apt install -y auditd" >&2
    exit 2
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (auditctl requires root)" >&2
    exit 2
fi

LOG_DIR="/tmp/file-stalker-$(date +%s)"
mkdir -p "$LOG_DIR"
TAG="RE-Toolkit-stalker-$$"

echo "============================================================"
echo " RE-Toolkit file-stalker v1.0"
echo "============================================================"
echo "  retoolkit_dir = $RETOOLKIT_DIR"
echo "  binary        = $BIN"
echo "  binary_dir    = $BIN_DIR"
echo "  binary_name   = $BIN_NAME"
echo "  log_dir       = $LOG_DIR"
echo "  audit_tag     = $TAG"
echo ""

# Cleanup function -- always remove rules on exit
cleanup_rules() {
    auditctl -W "$BIN"      2>/dev/null || true
    auditctl -W "$BIN_DIR"  2>/dev/null || true
    auditctl -d exit,always -F dir="$BIN_DIR" -F perm=wa -k "$TAG" 2>/dev/null || true
}
trap cleanup_rules EXIT

# Set up audit rules: watch the file + watch the parent directory for w/a ops
echo "Installing audit watches..."
auditctl -w "$BIN"      -p rwxa -k "$TAG"
auditctl -w "$BIN_DIR"  -p wa   -k "$TAG"

echo "Audit rules installed:"
auditctl -l | grep "$TAG" | sed 's/^/  /'
echo ""

# Capture timestamp before run
TS_START=$(date +%s)
echo "Starting analyze-binaries.sh at $(date -Iseconds)..."
echo ""

cd "$RETOOLKIT_DIR" || exit 2
"$RETOOLKIT_DIR/analyze-binaries.sh" "$BIN" >"$LOG_DIR/run.log" 2>&1 &
RUN_PID=$!

# Wait until the binary is gone (or run finishes)
while kill -0 "$RUN_PID" 2>/dev/null; do
    if [[ ! -f "$BIN" ]]; then
        TS_DELETED=$(date +%s)
        echo "Binary $BIN_NAME disappeared at $(date -Iseconds)"
        echo "  Killing analyze-binaries.sh to preserve audit log..."
        kill -TERM "$RUN_PID" 2>/dev/null
        sleep 2
        kill -KILL "$RUN_PID" 2>/dev/null
        break
    fi
    sleep 0.5
done
wait "$RUN_PID" 2>/dev/null
TS_END=$(date +%s)

# Pull all audit events for our tag in our window
echo ""
echo "============================================================"
echo " Audit events for $BIN_NAME during run"
echo "============================================================"

ausearch -k "$TAG" --start "$TS_START" --end "$TS_END" \
    > "$LOG_DIR/ausearch.txt" 2>&1

# Filter for the destructive operations
echo ""
echo "Destructive operations (rename, unlink, create with target name):"
echo "------------------------------------------------------------------"
ausearch -k "$TAG" --start "$TS_START" --end "$TS_END" -i 2>/dev/null \
    | awk '
        /^----/ { block=""; getline; }
        /type=SYSCALL/ {
            block_syscall=$0
        }
        /type=PATH/ {
            block_path=$0
            if (block_path ~ /'"$BIN_NAME"'/) {
                if (block_syscall ~ /(unlink|rename|renameat|linkat)/) {
                    print "TIME=" gensub(/.*time->|\..*/,"","g",block_syscall)
                    print "  SYSCALL: " block_syscall
                    print "  PATH:    " block_path
                    print ""
                }
            }
        }
    ' | head -100

echo ""
echo "============================================================"
echo " Verdict"
echo "============================================================"

# Find the deletion event with full process info
DEL_EVENT=$(ausearch -k "$TAG" --start "$TS_START" --end "$TS_END" -i 2>/dev/null \
    | grep -B 5 "name=\"$BIN_NAME\"" \
    | grep -B 3 "DELETE\|RENAME\|nametype=DELETE" \
    | head -30)

if [[ -n "$DEL_EVENT" ]]; then
    echo "Found deletion/rename event(s):"
    echo "$DEL_EVENT"
else
    echo "No DELETE/RENAME events found explicitly. Check $LOG_DIR/ausearch.txt"
    echo "for the full audit trail."
fi

echo ""
echo "Latest stages reached in RE-Toolkit run.log:"
echo "------------------------------------------"
grep -nE 'STAGE [0-9]+|stage_[a-z]+ ' "$LOG_DIR/run.log" 2>/dev/null | tail -10

echo ""
echo "Final state of binary directory:"
echo "------------------------------------------"
ls -la "$BIN_DIR" 2>/dev/null

echo ""
echo "============================================================"
echo " Full audit log:  $LOG_DIR/ausearch.txt"
echo " Full run log:    $LOG_DIR/run.log"
echo "============================================================"
