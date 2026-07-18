#!/usr/bin/env bash
# =============================================================================
# stages/static/94-dynamic-firejail.sh
# =============================================================================
#
# Synopsis:
#     Dynamic analysis Tier 2: firejail namespace-sandboxed execution.
#
# Description:
#     Tier 2 of v3.0.0 dynamic analysis: firejail namespace-sandboxed real
#     execution. ELF only (we refuse non-ELF inputs - Wine inside firejail
#     without a container is not robust enough for unknown samples).
#
#     REQUIRES --allow-real-execution. Driver-level safety gate refuses to
#     start the run if DYNAMIC_MODE=firejail and ALLOW_REAL_EXECUTION != 1, so
#     by the time this stage is reached the consent gate has been passed. We
#     re-check inside the stage as defense-in-depth.
#
#     Network defaults to OFF (--net=none). --dynamic-network=tap or =host can
#     override.
#
#     Firejail flags chosen for maximum isolation: --noprofile --noroot
#     --net=none --private-tmp --private-dev --seccomp --caps.drop=all
#     --shell=none --nogroups --quiet --timeout=00:01:00 --trace=<path>
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
#     stage_dynamic_firejail()
#
# Output subtrees:
#     ${outdir}/94-dynamic-firejail/
#
# Skip controls:
#     DYNAMIC_MODE
#     SKIP_DYNAMIC_FIREJAIL
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_dynamic_firejail() {
    local target="$1" outdir="$2"
    local df="${outdir}/94-dynamic-firejail"

    # Skip checks
    if [[ ${DYNAMIC:-0} -eq 0 ]]; then
        log_step "dynamic-firejail: skipped (--dynamic not enabled)"
        return 0
    fi
    if [[ ${SKIP_DYNAMIC_FIREJAIL:-0} -eq 1 ]]; then
        log_step "dynamic-firejail: skipped (SKIP_DYNAMIC_FIREJAIL=1)"
        return 0
    fi
    # v3.0.9 (audit-13 A2) - in auto-tier mode (DYNAMIC_AUTO=1), this tier
    # runs when prereqs (firejail installed, ELF target, --allow-real-execution)
    # are met. In legacy mode (DYNAMIC_AUTO=0), only run when DYNAMIC_MODE=
    # firejail. The downstream checks (firejail availability, ELF type,
    # ALLOW_REAL_EXECUTION) still gate the actual execution.
    if [[ ${DYNAMIC_AUTO:-0} -eq 0 ]] && [[ "${DYNAMIC_MODE:-qiling}" != "firejail" ]]; then
        log_step "dynamic-firejail: skipped (DYNAMIC_MODE=${DYNAMIC_MODE:-qiling}, auto-tier off)"
        return 0
    fi

    # Defense-in-depth safety gate (driver does the primary check in legacy mode).
    # v3.0.9 (audit-13 A2) - In auto-tier mode, missing --allow-real-execution is
    # not an error; it just means "this tier can't run in this configuration".
    # Skip cleanly with informative message so operator knows what's missing.
    if [[ ${ALLOW_REAL_EXECUTION:-0} -ne 1 ]]; then
        if [[ ${DYNAMIC_AUTO:-0} -eq 1 ]]; then
            log_step "dynamic-firejail: skipped (auto-tier; --allow-real-execution required for real-execution tiers)"
            mkdir -p "$df"
            echo '{"ran": false, "tier": "firejail", "reason": "--allow-real-execution not set"}' > "${df}/_dynamic.json"
            return 0
        fi
        log_err "dynamic-firejail: ALLOW_REAL_EXECUTION=0; refusing to run"
        log_err "         (this should have been caught at driver startup)"
        return 0
    fi

    if ! command -v firejail >/dev/null 2>&1; then
        log_warn "dynamic-firejail: firejail not installed; skipping"
        echo '{"ran": false, "reason": "firejail not installed"}' > "${df}/_dynamic.json"
        return 0
    fi

    # Type check: ELF only. Refuse PE/Mach-O/etc.
    local btype
    btype=$(detect_type "$target" 2>/dev/null || echo "unknown")
    if [[ "$btype" != "elf" ]]; then
        if [[ ${DYNAMIC_AUTO:-0} -eq 1 ]]; then
            log_step "dynamic-firejail: skipped (auto-tier; target type=$btype, firejail tier is ELF-only; docker tier handles non-ELF)"
        else
            log_warn "dynamic-firejail: target type=$btype; firejail tier is ELF-only. Use docker tier for non-ELF."
        fi
        mkdir -p "$df"
        echo "{\"ran\": false, \"tier\": \"firejail\", \"reason\": \"non-ELF target (type=$btype)\"}" > "${df}/_dynamic.json"
        return 0
    fi

    mkdir -p "$df"

    # Network mode mapping
    local net_flag
    case "${DYNAMIC_NETWORK:-none}" in
        none)  net_flag="--net=none" ;;
        host)  net_flag="" ;;  # firejail without --net= retains host network
        tap)   net_flag="--net=lo" ;;  # local loopback only as a safer "tap"
        *)     net_flag="--net=none" ;;
    esac

    # Network must be off when --allow-real-execution alone wasn't enough
    # to imply network consent
    if [[ "$net_flag" != "--net=none" && ${ALLOW_REAL_EXECUTION:-0} -eq 1 ]]; then
        log_warn "dynamic-firejail: NETWORK ENABLED (--dynamic-network=${DYNAMIC_NETWORK:-none}). Sample can attempt outbound traffic."
    fi

    local timeout_min
    timeout_min=$(( (${DYNAMIC_TIMEOUT:-60} + 59) / 60 ))  # round up
    [[ $timeout_min -lt 1 ]] && timeout_min=1
    local timeout_str
    timeout_str=$(printf "00:%02d:00" "$timeout_min")

    log_step "dynamic-firejail: running ELF in firejail (timeout=$timeout_str, net=${DYNAMIC_NETWORK:-none})"

    local start_time end_time duration exit_code
    start_time=$(date +%s.%N 2>/dev/null || date +%s)

    # Execute via firejail. Each tool path captured separately because
    # firejail --trace isn't a substitute for full strace; ltrace adds
    # library-level resolution.
    local fj_args=(
        --noprofile --noroot $net_flag
        --private-tmp --private-dev --seccomp --caps.drop=all
        --shell=none --nogroups --quiet
        --timeout="$timeout_str"
        --trace="${df}/firejail-trace.log"
    )

    # Run target under firejail with strace wrapping where possible.
    # We invoke strace OUTSIDE firejail because firejail's seccomp filter
    # may interfere with strace ptrace attach. The compromise: run inside
    # firejail with --trace, plus a separate run with strace captured by
    # firejail's --output= when available.
    set +e
    firejail "${fj_args[@]}" "$target" \
        > "${df}/stdout.log" 2> "${df}/stderr.log"
    exit_code=$?
    set -e

    end_time=$(date +%s.%N 2>/dev/null || date +%s)
    duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "0")

    echo "$exit_code" > "${df}/exit-status.txt"

    # Optional ltrace pass (best-effort; many binaries strip needed symbols)
    if command -v ltrace >/dev/null 2>&1; then
        set +e
        timeout "${DYNAMIC_TIMEOUT:-60}" \
            firejail "${fj_args[@]}" \
                ltrace -o "${df}/ltrace.log" -f "$target" \
                > /dev/null 2>&1
        set -e
    fi

    # Synthesize uniform _dynamic.json
    if [[ -n "$VENV_PY" ]]; then
        "$VENV_PY" - "$df" "$exit_code" "$duration" > "${df}/_synth.log" 2>&1 <<'PYEOF' || true
"""Synthesize firejail trace logs into uniform _dynamic.json schema."""
import sys
import os
import re
import json

df = sys.argv[1]
exit_code = int(sys.argv[2])
try: duration = float(sys.argv[3])
except ValueError: duration = 0.0

syscalls = []
file_writes = []
network_attempts = []
spawned_processes = []
errors = []

# Parse firejail-trace.log
# Format: "<depth>:<binary>:<syscall> <args>"
trace_path = os.path.join(df, "firejail-trace.log")
if os.path.exists(trace_path):
    with open(trace_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = re.match(r"^(\d+):([^:]+):(\w+)\s*(.*)$", line)
            if not m: continue
            depth, binary, op, args = m.groups()
            entry = {"name": op, "binary": binary, "args": args[:200], "tier": "firejail"}
            syscalls.append(entry)
            if op in ("connect", "sendto", "send"):
                # Parse host/port from args if present
                hp = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)", args)
                if hp:
                    network_attempts.append({
                        "protocol": "tcp" if op == "connect" else "udp",
                        "host": hp.group(1), "port": int(hp.group(2)),
                        "tier": "firejail",
                    })
            if op in ("openat", "open", "creat", "fopen", "fopen64") and "O_WRONLY" in args.upper():
                pm = re.search(r'"([^"]+)"', args)
                if pm:
                    file_writes.append({"path": pm.group(1), "tier": "firejail"})
            if op in ("execve", "fork", "vfork", "clone"):
                spawned_processes.append({"argv": args[:200], "tier": "firejail"})

# Parse strace.log if present (more detail than firejail --trace)
strace_path = os.path.join(df, "strace.log")
if os.path.exists(strace_path):
    with open(strace_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"^(?:\[pid \d+\]\s+)?(\w+)\((.*?)\)\s*=\s*(-?\d+|\?)", line)
            if not m: continue
            name, args_str, retval = m.groups()
            entry = {"name": name, "args": args_str[:200], "result": retval, "tier": "firejail-strace"}
            syscalls.append(entry)

uniform = {
    "ran": True,
    "tier": "firejail",
    "tool": "firejail",
    "real_execution": True,
    "exit_status": exit_code,
    "duration_sec": round(duration, 3),
    "syscall_count": len(syscalls),
    "api_call_count": 0,
    "file_writes": file_writes[:100],
    "registry_writes": [],
    "network_attempts": network_attempts[:100],
    "spawned_processes": spawned_processes[:50],
    "syscalls": syscalls[:300],
    "api_calls": [],
    "errors": errors,
}
with open(os.path.join(df, "_dynamic.json"), "w") as f:
    json.dump(uniform, f, indent=2, default=str)

print(f"firejail: exit={exit_code}, duration={duration:.1f}s, "
      f"syscalls={len(syscalls)}, "
      f"network_attempts={len(network_attempts)}, "
      f"file_writes={len(file_writes)}, "
      f"spawned={len(spawned_processes)}")
PYEOF
    fi

    log_step "dynamic-firejail: $(grep -m1 '^firejail:' "${df}/_synth.log" 2>/dev/null || echo 'completed')"
}
