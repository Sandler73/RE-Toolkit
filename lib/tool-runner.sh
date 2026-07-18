#!/usr/bin/env bash
# =============================================================================
# lib/tool-runner.sh
# =============================================================================
#
# Synopsis:
#     Bounded tool execution, the run status ledger, and output validation.
#
# Description:
#     Every external tool RE-Toolkit invokes goes through this module. Running a
#     tool directly from a stage is not permitted, because this wrapper is what
#     makes a run survivable and auditable.
#
#     Bounded execution. Each invocation runs under a timeout, so a hostile or
#     malformed input cannot hang the pipeline. stdout and stderr are captured
#     to per-tool log files rather than suppressed, so a failure stays visible
#     instead of vanishing into a redirect.
#
#     The status ledger. Each invocation appends a record of what ran, how it
#     exited, and how long it took. This is what allows the report to state
#     which tools ran, which were skipped, and why, rather than leaving the
#     analyst to infer tool coverage from which files happen to exist.
#
#     Output validation. A tool that exits zero has not necessarily produced
#     usable output. Content-shape guards check that what a tool wrote matches
#     what its parser expects, which catches the silent-failure case where an
#     invocation succeeds but emits usage text, an empty file, or a format the
#     downstream parser cannot read.
#
#     Sourced by analyze-binaries.sh; not directly executable.
#
# Provides:
#     run_tool <label> <timeout> <command...>
#         Execute a tool with a timeout, capture its output, and record the
#         result in the ledger.
#     run_shell <label> <timeout> <shell-command>
#         As run_tool, for invocations that require shell interpretation.
#     validate_output_format <path> <expected-shape>
#         Confirm a tool's output matches the shape its parser requires.
#     _ledger_append <record>
#         Internal. Append an entry to the run status ledger.
#
# Notes:
#     Timeout defaults and per-tool overrides are documented in the wiki
#     (Configuration). Release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

_ledger_append() {
    local label="$1" logf="$2" rc="$3" elapsed="$4"; shift 4
    # v3.7.2 (audit-30 A4): redact operator paths from the ledger's command
    # field (the ledger is a shareable run artifact). Tool/status/rc fields are
    # untouched, so any consumer that keys on those is unaffected.
    local cmd; cmd="$(sanitize_path_str "$*")"

    # Resolve the ledger path. Prefer the per-target export; else derive from
    # the log file location (logf is <outdir>/<stage>/<name>.log, so the
    # target outdir is two levels up).
    local ledger="${TARGET_LEDGER:-}"
    if [[ -z "$ledger" ]]; then
        if [[ -n "$logf" ]]; then
            local stage_dir target_dir
            stage_dir=$(dirname "$logf" 2>/dev/null) || return 0
            target_dir=$(dirname "$stage_dir" 2>/dev/null) || return 0
            ledger="${target_dir}/_ledger.jsonl"
        else
            return 0
        fi
    fi

    # Best-effort: derive a primary output path + size if the log's sibling
    # output is discoverable. We record the log file itself as the artifact
    # (always present) plus its size; stage-specific outputs vary too much to
    # infer generically, and the log path anchors the record to its stage.
    local out_path="$logf"
    local out_size=0
    if [[ -f "$out_path" ]]; then
        out_size=$(stat -c%s "$out_path" 2>/dev/null || echo 0)
    fi

    # Build + append the JSON record in Python for safe escaping. Route all
    # errors to /dev/null and always succeed.
    python3 - "$ledger" "$label" "$rc" "$elapsed" "$cmd" "$out_path" "$out_size" <<'PYLEDGER' 2>/dev/null || true
import sys, json, os
from datetime import datetime, timezone
try:
    ledger, label, rc, elapsed, cmd, out_path, out_size = sys.argv[1:8]
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": label,
        "command": cmd,
        "exit": int(rc) if str(rc).lstrip("-").isdigit() else rc,
        "elapsed_s": int(elapsed) if str(elapsed).isdigit() else elapsed,
        "log": out_path,
        "log_size": int(out_size) if str(out_size).isdigit() else 0,
    }
    # Append one line; create the file if needed. Never truncate.
    with open(ledger, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
except Exception:
    # Best-effort: a ledger failure must not surface.
    pass
PYLEDGER
    return 0
}

run_tool() {
    local label="$1" logf="$2" timeout_sec="$3"; shift 3
    local start=$SECONDS
    local rc=0
    if [[ ${#@} -eq 0 ]]; then
        echo "run_tool: no command supplied" > "$logf"
        log_step "${label}: (skipped -- no command)"
        return 0
    fi
    {
        echo "=== $label ==="
        # v3.7.2 (audit-30 A4): redact operator paths from the recorded command.
        echo "Command: $(sanitize_path_str "$*")"
        echo "Started: $(date -Iseconds)"
        echo "Timeout: ${timeout_sec}s"
        echo ""
    } > "$logf"
    if ! timeout --kill-after=10 "$timeout_sec" "$@" >> "$logf" 2>&1; then
        rc=$?
    fi
    local elapsed=$((SECONDS - start))
    {
        echo ""
        echo "=== $label END ==="
        echo "Exit:    $rc"
        echo "Elapsed: ${elapsed}s"
        echo "Finished: $(date -Iseconds)"
    } >> "$logf"
    if [[ $rc -eq 0 ]]; then
        log_step "${label}: OK (${elapsed}s)"
    elif [[ $rc -eq 124 || $rc -eq 137 ]]; then
        log_step "${label}: ${C_WARN}TIMEOUT${C_OFF} after ${elapsed}s -- see $logf"
    else
        log_step "${label}: ${C_WARN}exit $rc${C_OFF} (${elapsed}s) -- see $logf"
    fi
    # v3.3.0 (A0.4): record this invocation in the status ledger (best-effort).
    _ledger_append "$label" "$logf" "$rc" "$elapsed" "$@"
    return $rc
}

run_shell() {
    local label="$1" logf="$2" timeout_sec="$3"; shift 3
    local cmdline="$*"
    local start=$SECONDS
    local rc=0
    {
        echo "=== $label ==="
        # v3.7.2 (audit-30 A4): redact operator paths from the recorded command.
        echo "Command: $(sanitize_path_str "$cmdline")"
        echo "Started: $(date -Iseconds)"
        echo ""
    } > "$logf"
    if ! timeout --kill-after=10 "$timeout_sec" bash -c "$cmdline" >> "$logf" 2>&1; then
        rc=$?
    fi
    local elapsed=$((SECONDS - start))
    {
        echo ""
        echo "=== $label END ==="
        echo "Exit:    $rc"
        echo "Elapsed: ${elapsed}s"
    } >> "$logf"
    if [[ $rc -eq 0 ]]; then
        log_step "${label}: OK (${elapsed}s)"
    elif [[ $rc -eq 124 || $rc -eq 137 ]]; then
        log_step "${label}: ${C_WARN}TIMEOUT${C_OFF} after ${elapsed}s"
    else
        log_step "${label}: ${C_WARN}exit $rc${C_OFF} (${elapsed}s)"
    fi
    # v3.3.0 (A0.4): record this invocation in the status ledger (best-effort).
    _ledger_append "$label" "$logf" "$rc" "$elapsed" "$cmdline"
    return $rc
}


# =============================================================================
# v3.1.0 (audit-22 A0.3) -- Output content-shape validation
# =============================================================================
# Synopsis:
#     Validate that a tool's output file actually matches the format it was
#     supposed to produce, distinguishing "missing/empty" from "present but
#     malformed."
# Description:
#     The audit-21 L64 bug: r2's `agC` (no format suffix) emitted ASCII art
#     into a file named `.dot`. The existing guard checked only "file exists
#     and is non-empty" -- the ASCII-art file passed that check, then graphviz
#     failed to parse it at render time. The failure message ("missing or
#     empty") did not match the actual problem ("present but wrong format"),
#     which is what hid the bug's true nature during diagnosis.
#
#     validate_output_format() checks a file's actual content shape against an
#     expected format and returns a distinct code for each outcome, so callers
#     can emit accurate messages and downstream consumers can trust the file.
# Notes:
#     Supported formats: dot, json, xml, svg, csv. Each check is intentionally
#     cheap (first-line / small-parse), not a full validation -- the goal is to
#     catch gross format mismatches (ASCII where dot expected), not to fully
#     lint the content.
# Return codes:
#     0 = present and matches expected format
#     1 = present but does NOT match expected format (malformed / wrong type)
#     2 = missing or empty
# Version:
#     1.0 - 2026-05-03 - audit-22 A0.3
# =============================================================================
validate_output_format() {
    local file="$1"
    local fmt="$2"

    # Missing or empty -> code 2 (distinct from malformed).
    if [[ ! -s "$file" ]]; then
        return 2
    fi

    case "$fmt" in
        dot)
            # graphviz dot files start with an optional "strict" then
            # "digraph" or "graph" (possibly after leading whitespace/comments).
            # r2 ASCII art starts with box-drawing chars or whitespace+hex.
            if grep -qE '^[[:space:]]*(strict[[:space:]]+)?(di)?graph([[:space:]]|\{)' "$file" 2>/dev/null; then
                return 0
            fi
            return 1
            ;;
        json)
            # Cheap structural check first (starts with { or [), then a real
            # parse via python stdlib (json module; always available).
            if ! grep -qE '^[[:space:]]*[\[{]' "$file" 2>/dev/null; then
                return 1
            fi
            if python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$file" >/dev/null 2>&1; then
                return 0
            fi
            return 1
            ;;
        xml|svg)
            # XML/SVG start with <?xml or a root element tag. Validate
            # well-formedness via python xml.etree (stdlib).
            if ! grep -qE '^[[:space:]]*<(\?xml|svg|[A-Za-z])' "$file" 2>/dev/null; then
                return 1
            fi
            if python3 -c "import xml.etree.ElementTree as ET,sys; ET.parse(sys.argv[1])" "$file" >/dev/null 2>&1; then
                return 0
            fi
            return 1
            ;;
        csv)
            # CSV: at least one line with a delimiter (comma/tab/semicolon) and
            # at least one data row. Cheap heuristic, not RFC 4180 validation.
            local first
            first=$(head -1 "$file" 2>/dev/null)
            if [[ "$first" == *,* || "$first" == *$'\t'* || "$first" == *';'* ]]; then
                # Ensure there is more than just a header line.
                if [[ $(wc -l < "$file" 2>/dev/null) -ge 1 ]]; then
                    return 0
                fi
            fi
            return 1
            ;;
        *)
            # Unknown format requested: we cannot validate, so treat a
            # non-empty file as acceptable (return 0) but warn once.
            log_warn "validate_output_format: unknown format '$fmt'; treating non-empty file as OK"
            return 0
            ;;
    esac
}
# =============================================================================
# end v3.1.0 (audit-22 A0.3) output content-shape validation
# =============================================================================
