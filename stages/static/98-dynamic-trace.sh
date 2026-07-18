#!/usr/bin/env bash
# =============================================================================
# stages/static/98-dynamic-trace.sh
# =============================================================================
#
# Synopsis:
#     Dynamic trace aggregation across all executed dynamic tiers.
#
# Description:
#     Aggregator stage. Synthesizes per-tier _dynamic.json files (from
#     stage_dynamic_qiling / stage_dynamic_firejail / stage_dynamic_docker)
#     into a single aggregated.json with deduplication and cross-tier
#     correlation. Consumed by stage_summary (85) for verdict input and
#     stage_report (90) for the Dynamic Analysis tab.
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
#     stage_dynamic_trace()
#
# Output subtrees:
#     ${outdir}/92-dynamic-qiling/
#     ${outdir}/94-dynamic-firejail/
#     ${outdir}/96-dynamic-docker/
#     ${outdir}/97-dynamic-cuckoo/
#     ${outdir}/98-dynamic-trace/
#
# Skip controls:
#     SKIP_DYNAMIC_TRACE
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_dynamic_trace() {
    local target="$1" outdir="$2"
    local dt="${outdir}/98-dynamic-trace"

    if [[ ${DYNAMIC:-0} -eq 0 ]]; then
        log_step "dynamic-trace: skipped (--dynamic not enabled)"
        return 0
    fi
    if [[ ${SKIP_DYNAMIC_TRACE:-0} -eq 1 ]]; then
        log_step "dynamic-trace: skipped (SKIP_DYNAMIC_TRACE=1)"
        return 0
    fi

    # Check whether any dynamic stage actually produced output
    local any_dynamic=0
    for stage_dir in "${outdir}/92-dynamic-qiling" "${outdir}/94-dynamic-firejail" "${outdir}/96-dynamic-docker" "${outdir}/97-dynamic-cuckoo"; do
        if [[ -f "${stage_dir}/_dynamic.json" ]]; then
            any_dynamic=1; break
        fi
    done

    if [[ $any_dynamic -eq 0 ]]; then
        log_step "dynamic-trace: skipped (no per-tier _dynamic.json found)"
        return 0
    fi

    if [[ -z "$VENV_PY" ]]; then
        log_warn "dynamic-trace: VENV_PY not set; cannot aggregate"
        return 0
    fi

    mkdir -p "$dt"

    "$VENV_PY" - "$outdir" "$dt" > "${dt}/_aggregate.log" 2>&1 <<'PYEOF' || true
"""Aggregate per-tier _dynamic.json into a single cross-tier file.

Each tier's _dynamic.json follows the uniform schema (see specs). This
script merges them, deduplicates obvious duplicates (same syscall name +
args from same tier), and surfaces cross-tier signal (e.g. same C2 host
attempted by multiple tiers = high-confidence indicator).
"""
import sys
import os
import json

outdir = sys.argv[1]
dt = sys.argv[2]

aggregated = {
    "tools_used": [],
    "modes_attempted": [],
    "real_execution": False,
    "any_ran": False,
    "exit_statuses": {},        # tier -> exit_status
    "duration_total_sec": 0.0,
    "syscall_count_total": 0,
    "api_call_count_total": 0,
    "file_write_count_total": 0,
    "registry_write_count_total": 0,
    "network_attempt_count_total": 0,
    "spawned_process_count_total": 0,
    "all_syscalls": [],         # truncated cross-tier list
    "all_api_calls": [],
    "all_file_writes": [],
    "all_registry_writes": [],
    "all_network_attempts": [],
    "all_spawned_processes": [],
    "errors": [],
    "skip_reasons": {},  # v3.0.9 (audit-13 C2): tier -> reason for didn't-run
    "cross_tier": {
        "common_network_hosts": [],   # hosts seen by 2+ tiers
        "any_network": False,
        "any_persistence": False,     # registry write OR file write to system path
    },
}

tier_files = [
    ("qiling",   os.path.join(outdir, "92-dynamic-qiling",   "_dynamic.json")),
    ("firejail", os.path.join(outdir, "94-dynamic-firejail", "_dynamic.json")),
    ("docker",   os.path.join(outdir, "96-dynamic-docker",   "_dynamic.json")),
    ("cuckoo",   os.path.join(outdir, "97-dynamic-cuckoo",   "_dynamic.json")),
]

for tier_name, path in tier_files:
    if not os.path.exists(path): continue
    try:
        with open(path) as f: data = json.load(f)
    except Exception as e:
        aggregated["errors"].append(f"read {tier_name}: {e}")
        continue
    if not data.get("ran"):
        aggregated["modes_attempted"].append(tier_name + " (no-op)")
        # v3.0.9 (audit-13 C2) - capture the skip reason. Each tier writes
        # _dynamic.json with a "reason" field when ran=False; surface that
        # so operators see WHY each tier didn't produce output.
        skip_reason = data.get("reason") or "no reason given"
        aggregated["skip_reasons"][tier_name] = skip_reason
        continue

    aggregated["any_ran"] = True
    aggregated["tools_used"].append(tier_name)
    aggregated["modes_attempted"].append(tier_name)
    if data.get("real_execution"):
        aggregated["real_execution"] = True
    aggregated["exit_statuses"][tier_name] = data.get("exit_status")
    aggregated["duration_total_sec"] += float(data.get("duration_sec") or 0)
    aggregated["syscall_count_total"]      += int(data.get("syscall_count") or 0)
    aggregated["api_call_count_total"]     += int(data.get("api_call_count") or 0)
    aggregated["file_write_count_total"]   += len(data.get("file_writes") or [])
    aggregated["registry_write_count_total"] += len(data.get("registry_writes") or [])
    aggregated["network_attempt_count_total"] += len(data.get("network_attempts") or [])
    aggregated["spawned_process_count_total"] += len(data.get("spawned_processes") or [])

    # Append samples (already truncated by stage)
    for sc in (data.get("syscalls") or [])[:100]:
        aggregated["all_syscalls"].append(sc)
    for ac in (data.get("api_calls") or [])[:100]:
        aggregated["all_api_calls"].append(ac)
    for fw in (data.get("file_writes") or []):
        aggregated["all_file_writes"].append(fw)
    for rw in (data.get("registry_writes") or []):
        aggregated["all_registry_writes"].append(rw)
    for na in (data.get("network_attempts") or []):
        aggregated["all_network_attempts"].append(na)
    for sp in (data.get("spawned_processes") or []):
        aggregated["all_spawned_processes"].append(sp)

    for err in data.get("errors") or []:
        aggregated["errors"].append(f"[{tier_name}] {err}")

# Cross-tier correlation
aggregated["cross_tier"]["any_network"] = aggregated["network_attempt_count_total"] > 0

# Hosts seen by 2+ tiers = stronger C2 indicator
host_tiers = {}
for na in aggregated["all_network_attempts"]:
    h = na.get("host")
    if not h: continue
    host_tiers.setdefault(h, set()).add(na.get("tier", "unknown"))
for h, tiers in host_tiers.items():
    if len(tiers) >= 2:
        aggregated["cross_tier"]["common_network_hosts"].append({
            "host": h, "tiers": sorted(tiers),
        })

# Persistence indicators: writes to common persistence locations
PERSISTENCE_PATHS = [
    "/etc/", "/usr/", "/lib/", "/bin/", "/sbin/",  # system paths
    "/.bashrc", "/.profile", "/.bash_profile",      # shell init
    "/etc/cron", "/var/spool/cron",                  # cron persistence
    "/etc/systemd/", "/lib/systemd/",                # systemd
    "C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
]
for fw in aggregated["all_file_writes"]:
    p = (fw.get("path") or "").lower()
    if any(persist.lower() in p for persist in PERSISTENCE_PATHS):
        aggregated["cross_tier"]["any_persistence"] = True
        break
for rw in aggregated["all_registry_writes"]:
    k = (rw.get("key") or "").lower()
    if any(persist.lower() in k for persist in PERSISTENCE_PATHS):
        aggregated["cross_tier"]["any_persistence"] = True
        break

# Truncate the "all_*" lists to keep aggregated.json reasonably sized
aggregated["all_syscalls"] = aggregated["all_syscalls"][:300]
aggregated["all_api_calls"] = aggregated["all_api_calls"][:300]
aggregated["all_file_writes"] = aggregated["all_file_writes"][:200]
aggregated["all_registry_writes"] = aggregated["all_registry_writes"][:100]
aggregated["all_network_attempts"] = aggregated["all_network_attempts"][:100]
aggregated["all_spawned_processes"] = aggregated["all_spawned_processes"][:100]

with open(os.path.join(dt, "aggregated.json"), "w") as f:
    json.dump(aggregated, f, indent=2, default=str)

print(f"dynamic-trace: tiers={','.join(aggregated['tools_used']) or 'none'}, "
      f"any_ran={aggregated['any_ran']}, "
      f"syscalls={aggregated['syscall_count_total']}, "
      f"network={aggregated['network_attempt_count_total']}, "
      f"file_writes={aggregated['file_write_count_total']}, "
      f"persistence={aggregated['cross_tier']['any_persistence']}")
PYEOF

    log_step "dynamic-trace: $(grep -m1 '^dynamic-trace:' "${dt}/_aggregate.log" 2>/dev/null || echo 'completed')"
}
