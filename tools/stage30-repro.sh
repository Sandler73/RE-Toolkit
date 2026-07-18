#!/usr/bin/env bash
# =============================================================================
# Synopsis:
#     Manual reproducer for the v3.0.14 Stage-30 Ghidra failure.
# Description:
#     Invokes the exact same pyghidra helper RE-Toolkit's 30-ghidra.sh would,
#     with the exact same env vars, cwd, args, and `timeout` wrapper. Uses
#     the user's actual GhidraDump.py and .pyghidra-headless.py from the
#     installed RE-Toolkit. Writes to a /tmp project location so the actual
#     RE-Toolkit run output isn't disturbed.
# Notes:
#     If this reproduces the "File not found: file:///..." error, we have
#     a minimal repro and can iterate on the fix without re-running all 29
#     prior stages. If this works, the failure is something earlier in the
#     pipeline state, not in 30-ghidra.sh's invocation itself.
# Execution Parameters:
#     Argument 1: path to binary that fails Stage 30
#     Argument 2 (optional): path to RE-Toolkit install directory
#                            (default: /path/to/retoolkit)
# Examples:
#     sudo bash stage30-repro.sh ./samples/Sample.Shared.dll
# Version:
#     1.0 - 2026-05-03 - audit-19 follow-up
# =============================================================================

set -u
# Note: NOT using `set -e` -- we want to see the failure, not abort on it.

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <binary-path> [<RE-Toolkit-install-dir>]" >&2
    exit 2
fi

BIN="$1"
RETOOLKIT_DIR="${2:-/path/to/retoolkit}"

# Resolve binary to absolute path
if [[ ! -f "$BIN" ]]; then
    echo "ERROR: binary not found: $BIN" >&2
    exit 2
fi
BIN=$(readlink -f "$BIN")

# Locate Ghidra (mirror find_ghidra logic from lib/ghidra-helper.sh)
GHIDRA_INSTALL=""
for cand in /opt/ghidra_*_PUBLIC; do
    [[ -d "$cand" ]] && GHIDRA_INSTALL="$cand"
done
if [[ -z "$GHIDRA_INSTALL" ]]; then
    echo "ERROR: cannot find Ghidra install under /opt/ghidra_*_PUBLIC" >&2
    exit 2
fi

# Locate RE-Toolkit pieces
PYGHIDRA_HELPER="${RETOOLKIT_DIR}/rca64test/.pyghidra-headless.py"
GHIDRA_DUMP_PY="${RETOOLKIT_DIR}/GhidraDump.py"
PYGHIDRA_PY="/opt/retools/venv/bin/python"

for f in "$PYGHIDRA_HELPER" "$GHIDRA_DUMP_PY" "$PYGHIDRA_PY"; do
    if [[ ! -e "$f" ]]; then
        echo "ERROR: missing required file: $f" >&2
        echo "  (run RE-Toolkit at least once so it generates the helper)" >&2
        exit 2
    fi
done

# Build a /tmp project location -- avoids disturbing the actual RE-Toolkit run.
FNAME=$(basename "$BIN")
WORKDIR=$(mktemp -d -t stage30-repro-XXXXXX)
PROJ_ROOT="${WORKDIR}/rca64test/${FNAME}/30-ghidra"
PROJ="${PROJ_ROOT}/project"
DUMP="${PROJ_ROOT}/${FNAME}.ghidra-dump.txt"
SENTINEL_DIR="${PROJ_ROOT}/trace"
LOG="${PROJ_ROOT}/ghidra.log"
mkdir -p "$PROJ" "$SENTINEL_DIR"

echo "============================================================"
echo " Stage-30 reproducer v1.0"
echo "============================================================"
echo "  binary           = $BIN"
echo "  retoolkit_dir    = $RETOOLKIT_DIR"
echo "  ghidra_install   = $GHIDRA_INSTALL"
echo "  helper           = $PYGHIDRA_HELPER"
echo "  GhidraDump.py    = $GHIDRA_DUMP_PY"
echo "  pyghidra_python  = $PYGHIDRA_PY"
echo "  project_root     = $PROJ"
echo "  expected_dump    = $DUMP"
echo "  sentinel_dir     = $SENTINEL_DIR"
echo "  log              = $LOG"
echo "  GHIDRA_TIMEOUT   = 600 (sim)"
echo ""

# ---------------------------------------------------------------------------
# Mirror 30-ghidra.sh's environment setup EXACTLY (lines 113-125)
# ---------------------------------------------------------------------------
export JAVA_TOOL_OPTIONS="-Xmx4G -XX:+UseG1GC -Dfile.encoding=UTF-8"
export GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL"
export RETOOLKIT_SENTINEL_DIR="$SENTINEL_DIR"

# Mirror 30-ghidra.sh's cwd (the user's RE-Toolkit dir)
cd "$RETOOLKIT_DIR" || { echo "cannot cd to $RETOOLKIT_DIR"; exit 2; }

# ---------------------------------------------------------------------------
# Invocation that EXACTLY mirrors 30-ghidra.sh lines 170-179
# ---------------------------------------------------------------------------
echo "============================================================"
echo " Invoking helper..."
echo " (same `timeout` wrapper, same env, same cwd, same args)"
echo "============================================================"
echo ""

# Capture into log AND show on stdout
{
    echo "=== Ghidra analyzeHeadless (mode=stage30-repro) ==="
    echo "Started: $(date -Iseconds)"
    echo "Launcher: pyghidra-headless helper (CPython 3 + pyghidra, $PYGHIDRA_PY)"
    echo "Helper:   $PYGHIDRA_HELPER"
    echo "Trace:    $SENTINEL_DIR (GhidraDump stage sentinels)"
} | tee "$LOG"

START=$SECONDS
RC=0
timeout --kill-after=30 900 \
    "$PYGHIDRA_PY" "$PYGHIDRA_HELPER" \
    "$GHIDRA_INSTALL" \
    "$BIN" \
    "$GHIDRA_DUMP_PY" \
    "$PROJ" \
    "auto-${FNAME}" \
    "dump-path=${DUMP}" 2>&1 | tee -a "$LOG"
RC=${PIPESTATUS[0]}
ELAPSED=$((SECONDS - START))
echo "Exit: $RC  Elapsed: ${ELAPSED}s" | tee -a "$LOG"

# ---------------------------------------------------------------------------
# Append trace files (mirroring 30-ghidra.sh lines 202-213)
# ---------------------------------------------------------------------------
TRACE_FILES=$(find "$SENTINEL_DIR" -name 'ghidra-dump-*.trace' -type f 2>/dev/null | head -5)
if [[ -n "$TRACE_FILES" ]]; then
    {
        echo ""
        echo "=== GhidraDump.py stage trace ==="
        for tf in $TRACE_FILES; do
            echo "# File: $tf"
            cat "$tf"
        done
    } | tee -a "$LOG"
fi

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
DUMP_KB=0
[[ -f "$DUMP" ]] && DUMP_KB=$(du -k "$DUMP" 2>/dev/null | cut -f1)

if [[ $RC -eq 0 && -f "$DUMP" && $DUMP_KB -gt 0 ]]; then
    echo "RESULT: SUCCESS -- Ghidra produced a ${DUMP_KB} KB dump in ${ELAPSED}s"
    echo ""
    echo "  This is unexpected: this reproducer mirrors 30-ghidra.sh exactly."
    echo "  If RE-Toolkit Stage 30 still fails for you with the same VM and"
    echo "  same binary, the failure must be caused by something one of"
    echo "  the prior 29 stages does to system state."
    echo ""
    echo "  Suggested next test: run RE-Toolkit with most stages skipped:"
    echo "    /path/to/retoolkit/analyze-binaries.sh \\"
    echo "        --skip-stages='0,1,2,5,7,8,10,15,20,25,28,29' \\"
    echo "        $BIN"
elif [[ $RC -eq 124 || $RC -eq 137 ]]; then
    echo "RESULT: TIMEOUT after ${ELAPSED}s"
elif [[ ! -f "$DUMP" || $DUMP_KB -eq 0 ]]; then
    echo "RESULT: REPRODUCED -- no dump produced"
    echo ""
    echo "  Helper exited rc=$RC in ${ELAPSED}s without writing a dump."
    echo "  The full helper output is in: $LOG"
    echo ""
    echo "  Most relevant lines (errors/tracebacks):"
    grep -iE 'error|traceback|exception|file not found' "$LOG" | head -20
else
    echo "RESULT: UNCLEAR -- helper exit=$RC, dump_kb=$DUMP_KB"
fi

echo ""
echo "  Full log saved at: $LOG"
echo "  Workdir (preserved for inspection): $WORKDIR"
echo "============================================================"
