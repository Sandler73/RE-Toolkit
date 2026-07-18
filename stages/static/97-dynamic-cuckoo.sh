#!/usr/bin/env bash
# =============================================================================
# stages/static/97-dynamic-cuckoo.sh
# =============================================================================
#
# Synopsis:
#     Dynamic analysis Tier 4: cuckoo sandbox detonation.
#
# Description:
#     Tier 4 of v3.0.0 dynamic analysis: cuckoo sandbox.
#     Hardware-virtualization barrier; defeats kernel exploits. Heaviest tier;
#     requires --with-cuckoo at install time AND a working cuckoo deployment
#     (hypervisor + analyst-VM + agent setup; not automated by this toolkit).
#
#     This stage submits the target to a running cuckoo daemon, polls for
#     completion, retrieves the report, and synthesizes the uniform schema from
#     cuckoo's behavioral analysis. If cuckoo is not running or not reachable,
#     the stage logs a warning and writes ran=false; the rest of the pipeline
#     continues (per the graceful-degradation pattern of the other dynamic
#     stages).
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
#     stage_dynamic_cuckoo()
#
# Output subtrees:
#     ${outdir}/97-dynamic-cuckoo/
#
# Skip controls:
#     DYNAMIC_MODE
#     SKIP_DYNAMIC_CUCKOO
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_dynamic_cuckoo() {
    local target="$1" outdir="$2"
    local dc="${outdir}/97-dynamic-cuckoo"

    if [[ ${DYNAMIC:-0} -eq 0 ]]; then
        log_step "dynamic-cuckoo: skipped (--dynamic not enabled)"
        return 0
    fi
    if [[ ${SKIP_DYNAMIC_CUCKOO:-0} -eq 1 ]]; then
        log_step "dynamic-cuckoo: skipped (SKIP_DYNAMIC_CUCKOO=1)"
        return 0
    fi
    # v3.0.9 (audit-13 A2) - in auto-tier mode, this tier runs when prereqs
    # (cuckoo binary present, --allow-real-execution) are met. In legacy mode,
    # only run when DYNAMIC_MODE=cuckoo.
    if [[ ${DYNAMIC_AUTO:-0} -eq 0 ]] && [[ "${DYNAMIC_MODE:-qiling}" != "cuckoo" ]]; then
        log_step "dynamic-cuckoo: skipped (DYNAMIC_MODE=${DYNAMIC_MODE:-qiling}, auto-tier off)"
        return 0
    fi

    if [[ ${ALLOW_REAL_EXECUTION:-0} -ne 1 ]]; then
        if [[ ${DYNAMIC_AUTO:-0} -eq 1 ]]; then
            log_step "dynamic-cuckoo: skipped (auto-tier; --allow-real-execution required)"
            mkdir -p "$dc"
            echo '{"ran": false, "tier": "cuckoo", "reason": "--allow-real-execution not set"}' > "${dc}/_dynamic.json"
            return 0
        fi
        log_err "dynamic-cuckoo: ALLOW_REAL_EXECUTION=0; refusing to run"
        log_err "         (this should have been caught at driver startup)"
        return 0
    fi

    mkdir -p "$dc"

    # Locate cuckoo binary (PATH or /opt/cuckoo)
    local cuckoo_bin=""
    if command -v cuckoo >/dev/null 2>&1; then
        cuckoo_bin=$(command -v cuckoo)
    elif [[ -x /opt/cuckoo/bin/cuckoo ]]; then
        cuckoo_bin=/opt/cuckoo/bin/cuckoo
    fi
    if [[ -z "$cuckoo_bin" ]]; then
        log_warn "dynamic-cuckoo: cuckoo binary not found. Install per:"
        log_warn "         https://cuckoo.readthedocs.io/en/latest/installation/"
        echo '{"ran": false, "reason": "cuckoo binary not found"}' > "${dc}/_dynamic.json"
        return 0
    fi

    # Verify cuckoo daemon is reachable. cuckoo uses an HTTP API at
    # http://localhost:1337 by default (configurable). We do a brief
    # health check without requiring extra tools.
    local cuckoo_api="${CUCKOO_API:-http://localhost:1337}"
    if ! curl -sSf --max-time 5 "${cuckoo_api}/cuckoo/status" >/dev/null 2>&1; then
        log_warn "dynamic-cuckoo: cuckoo API at $cuckoo_api not reachable"
        log_warn "         start the cuckoo daemon first: cuckoo -d"
        echo '{"ran": false, "reason": "cuckoo API not reachable"}' > "${dc}/_dynamic.json"
        return 0
    fi

    log_step "dynamic-cuckoo: submitting target to cuckoo (timeout=${DYNAMIC_TIMEOUT:-60}s)"

    local start_time end_time duration
    start_time=$(date +%s.%N 2>/dev/null || date +%s)

    # Submit target via REST API. Cuckoo's task creation endpoint accepts
    # a multipart upload with the target file plus task options.
    local task_create_resp
    task_create_resp=$(curl -sS --max-time 30 \
        -F "file=@${target}" \
        -F "timeout=${DYNAMIC_TIMEOUT:-60}" \
        -F "enforce_timeout=1" \
        "${cuckoo_api}/tasks/create/file" 2>&1) || {
        log_warn "dynamic-cuckoo: task submission failed"
        echo '{"ran": false, "reason": "task submission failed"}' > "${dc}/_dynamic.json"
        return 0
    }
    echo "$task_create_resp" > "${dc}/cuckoo-task.json"

    # Extract task_id from JSON response
    local task_id
    task_id=$(echo "$task_create_resp" | "$VENV_PY" -c "
import sys, json
try:
    j = json.loads(sys.stdin.read())
    print(j.get('task_id') or j.get('task', {}).get('id') or '')
except Exception:
    pass
" 2>/dev/null)

    if [[ -z "$task_id" ]]; then
        log_warn "dynamic-cuckoo: could not extract task_id from response"
        echo '{"ran": false, "reason": "no task_id in response"}' > "${dc}/_dynamic.json"
        return 0
    fi

    log_step "dynamic-cuckoo: polling task $task_id for completion"

    # Poll for task completion. Hard cap at DYNAMIC_TIMEOUT * 3 (analysis +
    # VM cleanup + report generation overhead).
    local poll_cap=$(( ${DYNAMIC_TIMEOUT:-60} * 3 ))
    local poll_elapsed=0
    local poll_interval=5
    local task_status="pending"
    while [[ $poll_elapsed -lt $poll_cap ]]; do
        sleep $poll_interval
        poll_elapsed=$((poll_elapsed + poll_interval))
        task_status=$(curl -sSf --max-time 5 \
            "${cuckoo_api}/tasks/view/${task_id}" 2>/dev/null \
            | "$VENV_PY" -c "
import sys, json
try:
    j = json.loads(sys.stdin.read())
    print(j.get('task', {}).get('status') or j.get('status') or 'unknown')
except Exception:
    print('unknown')
" 2>/dev/null) || task_status="unknown"
        if [[ "$task_status" == "reported" || "$task_status" == "completed" ]]; then
            break
        fi
    done

    end_time=$(date +%s.%N 2>/dev/null || date +%s)
    duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "0")

    if [[ "$task_status" != "reported" && "$task_status" != "completed" ]]; then
        log_warn "dynamic-cuckoo: task did not complete (status=$task_status after ${poll_elapsed}s)"
        cat > "${dc}/_dynamic.json" <<JSON
{
  "ran": true, "tier": "cuckoo", "tool": "cuckoo",
  "real_execution": true, "exit_status": null,
  "duration_sec": $duration,
  "syscall_count": 0, "api_call_count": 0,
  "file_writes": [], "registry_writes": [],
  "network_attempts": [], "spawned_processes": [],
  "syscalls": [], "api_calls": [],
  "errors": ["cuckoo task did not complete: status=$task_status"]
}
JSON
        return 0
    fi

    # Retrieve full report
    if curl -sSf --max-time 30 \
        "${cuckoo_api}/tasks/report/${task_id}/json" \
        > "${dc}/report.json" 2>/dev/null; then
        log_ok "dynamic-cuckoo: report retrieved ($(wc -c < ${dc}/report.json) bytes)"
    else
        log_warn "dynamic-cuckoo: report retrieval failed"
        echo '{"ran": false, "reason": "report retrieval failed"}' > "${dc}/_dynamic.json"
        return 0
    fi

    # Synthesize uniform _dynamic.json from cuckoo report
    "$VENV_PY" - "$dc" "$duration" > "${dc}/_synth.log" 2>&1 <<'PYEOF' || true
"""Synthesize cuckoo report into uniform _dynamic.json schema.

Cuckoo report structure (top-level keys we care about):
  - info: task metadata (timestamps, machine, etc.)
  - target: target file metadata
  - behavior:
      processes: [{pid, parent_id, process_name, calls: [{api, arguments, ...}]}]
      summary: {files, regkeys, mutexes, ...}
  - network:
      hosts: [{ip, hostname}]
      tcp: [{src, dst, sport, dport}]
      http: [{host, port, uri, ...}]
      dns: [{request, answers}]
"""
import sys
import os
import json

dc = sys.argv[1]
try: duration = float(sys.argv[2])
except (ValueError, IndexError): duration = 0.0

errors = []
report_path = os.path.join(dc, "report.json")
if not os.path.exists(report_path):
    errors.append("report.json not present")
    report = {}
else:
    try:
        with open(report_path) as f: report = json.load(f)
    except Exception as e:
        errors.append(f"report parse: {type(e).__name__}: {e}")
        report = {}

api_calls = []
syscalls = []
file_writes = []
registry_writes = []
network_attempts = []
spawned_processes = []

# Behavior - processes and their API calls
behavior = report.get("behavior") or {}
for proc in (behavior.get("processes") or []):
    if not isinstance(proc, dict): continue
    pname = proc.get("process_name") or "?"
    ppid = proc.get("parent_id")
    pid = proc.get("pid")
    if ppid:  # not the root process; counts as spawn
        spawned_processes.append({
            "argv": pname,
            "pid": pid,
            "parent_id": ppid,
            "tier": "cuckoo",
        })
    for call in (proc.get("calls") or [])[:200]:
        if not isinstance(call, dict): continue
        api = call.get("api") or "?"
        args = call.get("arguments") or {}
        api_calls.append({
            "name": api,
            "process": pname,
            "args": str(args)[:200],
            "tier": "cuckoo",
        })
        # Categorize for uniform schema
        api_lower = api.lower()
        if any(k in api_lower for k in ("writefile", "ntwritefile", "createfile")):
            path_a = args.get("FileName") or args.get("filepath") or ""
            if path_a:
                file_writes.append({"path": str(path_a), "api": api, "tier": "cuckoo"})
        if any(k in api_lower for k in ("regsetvalue", "regcreatekey")):
            key_a = args.get("FullName") or args.get("KeyHandle") or args.get("HKey") or ""
            registry_writes.append({"key": str(key_a), "api": api, "tier": "cuckoo"})
        if any(k in api_lower for k in ("connect", "send", "wsasend", "internetopen", "httpopen")):
            host_a = args.get("hostname") or args.get("ip") or ""
            port_a = 0
            try:
                port_a = int(args.get("port") or args.get("server_port") or 0)
            except (ValueError, TypeError):
                pass
            network_attempts.append({
                "protocol": "tcp", "host": str(host_a), "port": port_a,
                "api": api, "tier": "cuckoo",
            })

# Behavior summary - file/regkey aggregate lists
summary = behavior.get("summary") or {}
for f in (summary.get("file_written") or summary.get("write_files") or []):
    file_writes.append({"path": str(f), "tier": "cuckoo"})
for k in (summary.get("regkey_written") or summary.get("write_keys") or []):
    registry_writes.append({"key": str(k), "tier": "cuckoo"})

# Network - explicit network section
network = report.get("network") or {}
for tcp in (network.get("tcp") or []):
    if isinstance(tcp, dict):
        network_attempts.append({
            "protocol": "tcp",
            "host": str(tcp.get("dst") or "?"),
            "port": int(tcp.get("dport") or 0),
            "tier": "cuckoo",
        })
for http in (network.get("http") or []):
    if isinstance(http, dict):
        network_attempts.append({
            "protocol": "http",
            "host": str(http.get("host") or "?"),
            "port": int(http.get("port") or 80),
            "uri": str(http.get("uri") or ""),
            "tier": "cuckoo",
        })
for dns in (network.get("dns") or []):
    if isinstance(dns, dict):
        network_attempts.append({
            "protocol": "dns",
            "host": str(dns.get("request") or "?"),
            "port": 53,
            "tier": "cuckoo",
        })

uniform = {
    "ran": True,
    "tier": "cuckoo",
    "tool": "cuckoo",
    "real_execution": True,
    "exit_status": (report.get("info") or {}).get("score"),  # cuckoo's malice score 0-10
    "duration_sec": round(duration, 3),
    "syscall_count": len(syscalls),
    "api_call_count": len(api_calls),
    "file_writes": file_writes[:200],
    "registry_writes": registry_writes[:200],
    "network_attempts": network_attempts[:200],
    "spawned_processes": spawned_processes[:100],
    "syscalls": syscalls[:300],
    "api_calls": api_calls[:300],
    "errors": errors,
}
with open(os.path.join(dc, "_dynamic.json"), "w") as f:
    json.dump(uniform, f, indent=2, default=str)

print(f"cuckoo: api_calls={len(api_calls)}, file_writes={len(file_writes)}, "
      f"network={len(network_attempts)}, spawned={len(spawned_processes)}")
PYEOF

    log_step "dynamic-cuckoo: $(grep -m1 '^cuckoo:' "${dc}/_synth.log" 2>/dev/null || echo 'completed')"
}
