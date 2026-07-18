#!/usr/bin/env bash
# =============================================================================
# stages/static/92-dynamic-qiling.sh
# =============================================================================
#
# Synopsis:
#     Dynamic analysis Tier 1: qiling emulation over the Unicorn engine.
#
# Description:
#     Tier 1 (safest) of v3.0.0 dynamic analysis: qiling emulator. Pure CPython
#     emulator over Unicorn engine; no real syscalls hit the host kernel.
#     Cross-architecture: emulates Windows PE on Linux, Linux ELF, Mach-O. Does
#     NOT require --allow-real-execution because no real execution occurs.
#
#     Qiling needs an OS rootfs (Win10 system DLLs, Linux libc, etc.) to
#     emulate properly. The installer (LAYER 8) clones the qiling rootfs into
#     /opt/qiling-rootfs/. For Windows PE: rootfs at .../x86_windows or
#     x8664_windows; for Linux: x86_linux or x8664_linux; for Mach-O:
#     x8664_macos. Architecture is auto-detected from the binary type.
#
#     Hard timeout enforced via signal alarm in the Python heredoc; default
#     60s, configurable via --dynamic-timeout.
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
#     stage_dynamic_qiling()
#
# Output subtrees:
#     ${outdir}/92-dynamic-qiling/
#
# Skip controls:
#     DYNAMIC_MODE
#     SKIP_DYNAMIC_QILING
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_dynamic_qiling() {
    local target="$1" outdir="$2"
    local dq="${outdir}/92-dynamic-qiling"

    # Multi-condition skip check
    if [[ ${DYNAMIC:-0} -eq 0 ]]; then
        log_step "dynamic-qiling: skipped (--dynamic not enabled)"
        return 0
    fi
    if [[ ${SKIP_DYNAMIC_QILING:-0} -eq 1 ]]; then
        log_step "dynamic-qiling: skipped (SKIP_DYNAMIC_QILING=1)"
        return 0
    fi
    # v3.0.9 (audit-13 A2) - in auto-tier mode (DYNAMIC_AUTO=1), this tier
    # always runs (qiling has no real-execution risk). In legacy mode
    # (DYNAMIC_AUTO=0), only run when DYNAMIC_MODE=qiling.
    if [[ ${DYNAMIC_AUTO:-0} -eq 0 ]] && [[ "${DYNAMIC_MODE:-qiling}" != "qiling" ]]; then
        log_step "dynamic-qiling: skipped (DYNAMIC_MODE=${DYNAMIC_MODE:-qiling}, auto-tier off)"
        return 0
    fi

    if [[ -z "$VENV_PY" ]]; then
        log_warn "dynamic-qiling: VENV_PY not set; cannot run qiling"
        return 0
    fi

    mkdir -p "$dq"

    # Detect rootfs based on binary type. Default to /opt/qiling-rootfs/.
    local rootfs_root="${QILING_ROOTFS:-/opt/qiling-rootfs}"
    local rootfs_path=""
    local btype=""
    btype=$(detect_type "$target" 2>/dev/null || echo "unknown")
    case "$btype" in
        pe-native|pe-dotnet)
            # Default to x8664; PE-32 falls back to x86 via heuristic in heredoc
            if [[ -d "${rootfs_root}/x8664_windows" ]]; then
                rootfs_path="${rootfs_root}/x8664_windows"
            elif [[ -d "${rootfs_root}/x86_windows" ]]; then
                rootfs_path="${rootfs_root}/x86_windows"
            fi
            ;;
        elf)
            if [[ -d "${rootfs_root}/x8664_linux" ]]; then
                rootfs_path="${rootfs_root}/x8664_linux"
            fi
            ;;
        macho)
            if [[ -d "${rootfs_root}/x8664_macos" ]]; then
                rootfs_path="${rootfs_root}/x8664_macos"
            fi
            ;;
    esac

    if [[ -z "$rootfs_path" ]]; then
        log_warn "dynamic-qiling: no rootfs at ${rootfs_root} for type=$btype; skipping"
        echo '{"ran": false, "reason": "no rootfs available"}' > "${dq}/_dynamic.json"
        return 0
    fi

    # v3.0.9 (audit-13 E1) - empty Windows rootfs check.
    # The qiling-rootfs/x8664_windows directory exists after install (LAYER 8
    # creates it during the clone) but Microsoft Windows DLLs are NOT bundled
    # per Microsoft EULA. Without DLLs, qiling cannot resolve Windows API
    # imports and emulation fails immediately on the first import lookup.
    # Detect this case and emit a clear actionable message rather than
    # letting qiling fail with an opaque traceback.
    if [[ "$btype" =~ ^pe ]]; then
        local dll_count
        dll_count=$(find "$rootfs_path" -maxdepth 4 -iname '*.dll' 2>/dev/null | head -10 | wc -l)
        if [[ $dll_count -eq 0 ]]; then
            log_warn "dynamic-qiling: Windows rootfs at ${rootfs_path} contains 0 DLLs."
            log_warn "         Microsoft Windows DLLs are NOT bundled per Microsoft EULA."
            log_warn "         qiling cannot emulate Windows PE binaries without system DLLs."
            log_warn "         Recommendations:"
            log_warn "           1. Install Docker tier: re-run installer with --with-docker"
            log_warn "              and pass --dynamic-mode=docker --allow-real-execution at run time."
            log_warn "           2. OR manually populate ${rootfs_path}/Windows/System32/"
            log_warn "              with the required DLLs (advanced; license-restricted)."
            mkdir -p "$dq"
            cat > "${dq}/_dynamic.json" <<JSONEOF
{
  "ran": false,
  "tier": "qiling",
  "tool": "qiling",
  "real_execution": false,
  "reason": "Windows rootfs empty (Microsoft DLLs not bundled per EULA)",
  "recommendation": "Use --dynamic-mode=docker (requires --with-docker installer flag and --allow-real-execution at run time) for real Wine-based PE execution."
}
JSONEOF
            return 0
        fi
    fi

    log_step "dynamic-qiling: emulating ($btype) with rootfs=$rootfs_path, timeout=${DYNAMIC_TIMEOUT:-60}s"

    "$VENV_PY" - "$target" "$rootfs_path" "$dq" "${DYNAMIC_TIMEOUT:-60}" \
        > "${dq}/emulation.log" 2>&1 <<'PYEOF' || true
"""qiling-based emulation with syscall + API call interception.

Args:
    sys.argv[1] = target binary path
    sys.argv[2] = qiling rootfs path
    sys.argv[3] = output dir for this stage
    sys.argv[4] = hard timeout in seconds (string-to-int)
"""
import sys
import os
import json
import signal
import time
import traceback

target = sys.argv[1]
rootfs = sys.argv[2]
outdir = sys.argv[3]
try:
    timeout_sec = int(sys.argv[4])
except (ValueError, IndexError):
    timeout_sec = 60

# Output buffers populated by hooks
syscalls = []
api_calls = []
file_writes = []
registry_writes = []
network_attempts = []
spawned_processes = []
errors = []

start_time = time.monotonic()
exit_status = None

# Hard timeout via SIGALRM. qiling can hang on anti-emulation tricks or
# infinite loops; SIGALRM is the only reliable kill since qiling's own
# instruction-count timeout doesn't always fire on Python-bound code.
def _timeout_handler(signum, frame):
    raise TimeoutError(f"qiling emulation exceeded {timeout_sec}s")

signal.signal(signal.SIGALRM, _timeout_handler)
signal.alarm(timeout_sec)

try:
    from qiling import Qiling
    try:
        from qiling.const import QL_VERBOSE
        verbose_off = QL_VERBOSE.OFF
    except ImportError:
        verbose_off = 0  # legacy qiling

    # Construct emulator
    ql = Qiling([target], rootfs, verbose=verbose_off)

    # ---- Syscall hook (Linux/POSIX) -----------------------------------------
    # qiling exposes ql.os.set_syscall(N, callback) for individual syscalls,
    # but that requires per-syscall registration. For broad capture we use
    # ql.hook_intno (interrupt) on Linux x86_64 (syscall via int 0x80 / syscall)
    # plus ql.os.fcall hooks for each registered syscall handler.
    try:
        # Hook the generic syscall dispatcher when available
        if hasattr(ql.os, "set_syscall_hook"):
            def _syscall_hook(ql, syscall_num, params, retval):
                try:
                    syscalls.append({
                        "syscall_num": int(syscall_num),
                        "params": [str(p) for p in (params or [])][:8],
                        "retval": str(retval) if retval is not None else None,
                    })
                except Exception:
                    pass
            ql.os.set_syscall_hook(_syscall_hook)
    except Exception as e:
        errors.append(f"syscall hook setup: {type(e).__name__}: {e}")

    # ---- API call hook (Windows PE) -----------------------------------------
    # For PE binaries, qiling intercepts WinAPI via its in-Python implementation.
    # We use ql.os.set_api when available to wrap call dispatch.
    try:
        if hasattr(ql.os, "set_api"):
            def _api_hook(ql, name, params=None):
                try:
                    entry = {
                        "name": str(name),
                        "params_count": len(params) if params else 0,
                    }
                    api_calls.append(entry)
                    # Derive uniform-schema fields from API name
                    sname = str(name)
                    # File writes: CreateFileA/W with write access OR WriteFile
                    if sname in ("WriteFile", "CreateFileA", "CreateFileW"):
                        path_param = ""
                        if params:
                            for p in params:
                                ps = str(p)
                                if ("\\" in ps or "/" in ps) and len(ps) < 260:
                                    path_param = ps; break
                        if path_param:
                            file_writes.append({"path": path_param, "tier": "qiling"})
                    # Registry writes: RegSetValueExA/W
                    if sname.startswith("RegSetValue") or sname.startswith("RegCreateKey"):
                        key_param = ""
                        if params:
                            for p in params:
                                ps = str(p)
                                if ("HKEY" in ps.upper() or "Software\\" in ps) and len(ps) < 260:
                                    key_param = ps; break
                        registry_writes.append({"key": key_param or "?", "tier": "qiling"})
                    # Network attempts: connect / send / WSAStartup / InternetOpen / InternetReadFile
                    if sname in ("connect", "send", "InternetReadFile", "InternetOpenA",
                                 "InternetOpenW", "InternetConnectA", "InternetConnectW",
                                 "WSAStartup"):
                        host_param = ""
                        port_param = 0
                        if params:
                            for p in params:
                                ps = str(p)
                                # Heuristic: look for hostname-like or IP-like strings
                                if ("." in ps and ps.count(".") >= 2 and len(ps) < 256
                                        and not ps.startswith("\\")):
                                    host_param = ps; break
                        network_attempts.append({
                            "protocol": "tcp",
                            "host": host_param or "?",
                            "port": port_param,
                            "api": sname,
                            "tier": "qiling",
                        })
                    # Process spawn: CreateProcessA/W / ShellExecuteA/W / WinExec
                    if sname.startswith("CreateProcess") or sname.startswith("ShellExecute") \
                            or sname == "WinExec":
                        argv = ""
                        if params:
                            for p in params:
                                ps = str(p)
                                if (".exe" in ps.lower() or "\\" in ps or "/" in ps) \
                                        and len(ps) < 1024:
                                    argv = ps; break
                        spawned_processes.append({"argv": argv or sname, "tier": "qiling"})
                except Exception:
                    pass
            # Hook a documented set of common Windows APIs. qiling's hook scope
            # varies by version; missing APIs simply don't fire (best-effort).
            for api_name in ("CreateFileA", "CreateFileW", "WriteFile",
                             "RegOpenKeyExA", "RegOpenKeyExW",
                             "RegSetValueExA", "RegSetValueExW",
                             "RegCreateKeyExA", "RegCreateKeyExW",
                             "InternetOpenA", "InternetOpenW",
                             "InternetConnectA", "InternetConnectW",
                             "InternetReadFile",
                             "WSAStartup", "connect", "send", "recv",
                             "CreateProcessA", "CreateProcessW",
                             "ShellExecuteA", "ShellExecuteW",
                             "WinExec"):
                try:
                    ql.os.set_api(api_name, _api_hook)
                except Exception:
                    pass
    except Exception as e:
        errors.append(f"API hook setup: {type(e).__name__}: {e}")

    # ---- Linux syscall enrichment -------------------------------------------
    # The set_syscall_hook above captures all syscalls generically. For
    # uniform-schema fields (file_writes / spawned_processes / network_attempts)
    # on Linux ELF targets, parse the captured syscalls list at end-of-run
    # rather than per-syscall (avoids hook ordering issues with set_syscall_hook).
    # This runs after ql.run() completes; see post-run enrichment block below.

    # ---- Run emulation ------------------------------------------------------
    try:
        ql.run()
        exit_status = 0
    except TimeoutError:
        exit_status = -1  # timed out
        errors.append(f"hard-timeout at {timeout_sec}s")
    except Exception as e:
        exit_status = -2
        errors.append(f"emulation error: {type(e).__name__}: {e}")
        # Truncated traceback for the log
        tb = traceback.format_exc().splitlines()
        for line in tb[-12:]:
            errors.append(f"  {line}")

    # ---- Post-run Linux syscall enrichment ----------------------------------
    # For Linux ELF targets, derive uniform-schema fields from the captured
    # syscall list. The Linux syscall numbers below are x86_64 ABI; Linux
    # x86_64 is qiling's most-tested architecture for ELF.
    LINUX_X86_64_SYSCALLS = {
        0:   "read",       1:   "write",      2:   "open",       257: "openat",
        85:  "creat",      42:  "connect",    44:  "sendto",     45:  "recvfrom",
        46:  "sendmsg",    47:  "recvmsg",    49:  "bind",       50:  "listen",
        59:  "execve",     56:  "clone",      57:  "fork",       58:  "vfork",
        322: "execveat",
    }
    O_WRONLY = 0x1
    O_RDWR = 0x2
    O_CREAT = 0x40
    try:
        for sc in syscalls:
            sc_num = sc.get("syscall_num")
            if sc_num is None: continue
            name = LINUX_X86_64_SYSCALLS.get(int(sc_num))
            if not name: continue
            params = sc.get("params") or []
            # File writes: write / openat with O_WRONLY|O_CREAT|O_RDWR / creat
            if name in ("write",):
                if params and len(params) >= 1:
                    file_writes.append({"fd": params[0], "tier": "qiling"})
            elif name in ("open", "openat", "creat"):
                # Look for path-like and flag-like params
                path_p = ""
                flags_p = 0
                for p in params:
                    ps = str(p)
                    if "/" in ps and len(ps) < 256:
                        path_p = ps; break
                for p in params:
                    try:
                        v = int(str(p), 0)
                        if v & (O_WRONLY | O_RDWR | O_CREAT):
                            flags_p = v; break
                    except (ValueError, TypeError):
                        continue
                if flags_p or name == "creat":
                    file_writes.append({"path": path_p or "?", "tier": "qiling"})
            # Network: connect / sendto / sendmsg / bind
            elif name in ("connect", "sendto", "sendmsg", "bind"):
                network_attempts.append({
                    "protocol": "tcp" if name in ("connect", "sendmsg") else "udp",
                    "host": "?", "port": 0,
                    "syscall": name, "tier": "qiling",
                })
            # Spawn: execve / execveat / clone / fork / vfork
            elif name in ("execve", "execveat", "clone", "fork", "vfork"):
                argv_p = ""
                for p in params:
                    ps = str(p)
                    if "/" in ps and len(ps) < 1024:
                        argv_p = ps; break
                spawned_processes.append({"argv": argv_p or name, "syscall": name, "tier": "qiling"})
    except Exception as e:
        errors.append(f"syscall enrichment: {type(e).__name__}: {e}")

except ImportError as e:
    errors.append(f"qiling import failed: {e}")
    exit_status = -3
except Exception as e:
    errors.append(f"setup error: {type(e).__name__}: {e}")
    exit_status = -4
finally:
    signal.alarm(0)

duration = time.monotonic() - start_time

# Write per-stage outputs
def _write_json(path, data):
    try:
        with open(path, "w") as f: json.dump(data, f, indent=2, default=str)
    except Exception as e:
        errors.append(f"write {path}: {e}")

_write_json(os.path.join(outdir, "syscalls.json"), syscalls)
_write_json(os.path.join(outdir, "api-calls.json"), api_calls)

# Uniform _dynamic.json schema (consumed by stage_dynamic_trace and
# stage_summary). All four dynamic stages emit this schema so summary
# parsing is tier-agnostic.
uniform = {
    "ran": exit_status is not None,
    "tier": "qiling",
    "tool": "qiling",
    "real_execution": False,
    "exit_status": exit_status,
    "duration_sec": round(duration, 3),
    "syscall_count": len(syscalls),
    "api_call_count": len(api_calls),
    "file_writes": file_writes,
    "registry_writes": registry_writes,
    "network_attempts": network_attempts,
    "spawned_processes": spawned_processes,
    "syscalls": syscalls[:200],  # first 200 only
    "api_calls": api_calls[:200],
    "errors": errors,
}
_write_json(os.path.join(outdir, "_dynamic.json"), uniform)

print(f"qiling: ran={uniform['ran']}, exit={exit_status}, "
      f"duration={duration:.1f}s, syscalls={len(syscalls)}, "
      f"apis={len(api_calls)}, errors={len(errors)}")
PYEOF

    log_step "dynamic-qiling: $(grep -m1 '^qiling:' "${dq}/emulation.log" 2>/dev/null || echo 'completed')"
}
