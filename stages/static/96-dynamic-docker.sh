#!/usr/bin/env bash
# =============================================================================
# stages/static/96-dynamic-docker.sh
# =============================================================================
#
# Synopsis:
#     Dynamic analysis Tier 3: Docker container-isolated execution.
#
# Description:
#     Tier 3 of v3.0.0 dynamic analysis: full container isolation. Wine inside
#     container for PE binaries. Heaviest tier; requires --with-docker at
#     install time AND --allow-real-execution at run time.
#
#     Container image retoolkit-dynamic:latest is built by the installer when
#     --with-docker is passed (LAYER 9). Image bundles strace, ltrace, Wine,
#     and a /entrypoint.sh that detects target type, selects the right runner,
#     and writes outputs to /out (volume-mounted from $outdir).
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
#     stage_dynamic_docker()
#
# Output subtrees:
#     ${outdir}/96-dynamic-docker/
#
# Skip controls:
#     DYNAMIC_MODE
#     SKIP_DYNAMIC_DOCKER
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_dynamic_docker() {
    local target="$1" outdir="$2"
    local dd="${outdir}/96-dynamic-docker"

    if [[ ${DYNAMIC:-0} -eq 0 ]]; then
        log_step "dynamic-docker: skipped (--dynamic not enabled)"
        return 0
    fi
    if [[ ${SKIP_DYNAMIC_DOCKER:-0} -eq 1 ]]; then
        log_step "dynamic-docker: skipped (SKIP_DYNAMIC_DOCKER=1)"
        return 0
    fi
    # v3.0.9 (audit-13 A2) - in auto-tier mode (DYNAMIC_AUTO=1), this tier
    # runs when prereqs (docker installed, image built, --allow-real-execution)
    # are met. In legacy mode (DYNAMIC_AUTO=0), only run when DYNAMIC_MODE=docker.
    if [[ ${DYNAMIC_AUTO:-0} -eq 0 ]] && [[ "${DYNAMIC_MODE:-qiling}" != "docker" ]]; then
        log_step "dynamic-docker: skipped (DYNAMIC_MODE=${DYNAMIC_MODE:-qiling}, auto-tier off)"
        return 0
    fi

    if [[ ${ALLOW_REAL_EXECUTION:-0} -ne 1 ]]; then
        if [[ ${DYNAMIC_AUTO:-0} -eq 1 ]]; then
            log_step "dynamic-docker: skipped (auto-tier; --allow-real-execution required)"
            mkdir -p "$dd"
            echo '{"ran": false, "tier": "docker", "reason": "--allow-real-execution not set"}' > "${dd}/_dynamic.json"
            return 0
        fi
        log_err "dynamic-docker: ALLOW_REAL_EXECUTION=0; refusing to run"
        return 0
    fi

    if ! command -v docker >/dev/null 2>&1; then
        log_warn "dynamic-docker: docker not installed; install with --with-docker"
        mkdir -p "$dd"
        echo '{"ran": false, "reason": "docker not installed"}' > "${dd}/_dynamic.json"
        return 0
    fi

    # Verify our image is present
    if ! docker image inspect retoolkit-dynamic:latest >/dev/null 2>&1; then
        log_warn "dynamic-docker: retoolkit-dynamic:latest image not built. Re-run installer with --with-docker."
        mkdir -p "$dd"
        echo '{"ran": false, "reason": "container image not built"}' > "${dd}/_dynamic.json"
        return 0
    fi

    mkdir -p "$dd"

    # Network mode mapping
    local docker_net
    case "${DYNAMIC_NETWORK:-none}" in
        none)  docker_net="none" ;;
        host)  docker_net="host" ;;
        tap)   docker_net="bridge" ;;  # docker bridge with NAT; safer than host
        *)     docker_net="none" ;;
    esac

    if [[ "$docker_net" != "none" ]]; then
        log_warn "dynamic-docker: NETWORK ENABLED (--dynamic-network=$docker_net). Outbound traffic possible."
    fi

    log_step "dynamic-docker: running in retoolkit-dynamic container (timeout=${DYNAMIC_TIMEOUT:-60}s, net=$docker_net)"

    local start_time end_time duration exit_code
    start_time=$(date +%s.%N 2>/dev/null || date +%s)

    # Resolve target absolute path for bind mount
    local target_abs
    target_abs=$(readlink -f "$target")
    local target_basename
    target_basename=$(basename "$target_abs")

    # Defense against path/argument injection in docker -v: refuse target
    # filenames containing characters that have meaning to docker volume
    # syntax (`:` separates source/dest/options) or shell metachars.
    # detect_type already rejects most pathological inputs, but this is
    # defense-in-depth for the case where a user passes a sample with
    # adversarial filename.
    if [[ "$target_basename" =~ [\:\;\|\&\$\`\"\'\\\(\)\<\>] ]]; then
        log_err "dynamic-docker: target basename contains unsafe characters; refusing"
        log_err "         basename was: $target_basename"
        log_err "         rename the sample to a path-safe filename and re-run"
        echo '{"ran": false, "reason": "target basename contains unsafe characters"}' > "${dd}/_dynamic.json"
        return 0
    fi
    if [[ "$target_abs" =~ [\:\;\|\&\$\`\"\'] ]]; then
        log_err "dynamic-docker: target absolute path contains unsafe characters; refusing"
        echo '{"ran": false, "reason": "target absolute path contains unsafe characters"}' > "${dd}/_dynamic.json"
        return 0
    fi

    # Run with strict resource limits + read-only root + tmpfs /tmp
    set +e
    timeout "$((${DYNAMIC_TIMEOUT:-60} + 10))" \
        docker run --rm \
            --network="$docker_net" \
            --memory=512m \
            --cpus=1.0 \
            --read-only \
            --tmpfs /tmp:rw,size=64m,mode=1777 \
            --tmpfs /run:rw,size=16m \
            --security-opt=no-new-privileges \
            --cap-drop=ALL \
            -v "${target_abs}:/sample/${target_basename}:ro" \
            -v "${dd}:/out:rw" \
            -e "RT_TIMEOUT=${DYNAMIC_TIMEOUT:-60}" \
            -e "RT_TARGET=/sample/${target_basename}" \
            retoolkit-dynamic:latest \
            > "${dd}/container.log" 2>&1
    exit_code=$?
    set -e

    end_time=$(date +%s.%N 2>/dev/null || date +%s)
    duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "0")

    echo "$exit_code" > "${dd}/exit-status.txt"

    # The container's entrypoint is expected to write /out/_dynamic.json with
    # the uniform schema. If it didn't (image misbuilt or container errored),
    # we synthesize a minimal one.
    if [[ ! -f "${dd}/_dynamic.json" ]]; then
        cat > "${dd}/_dynamic.json" <<JSON
{
  "ran": true,
  "tier": "docker",
  "tool": "docker",
  "real_execution": true,
  "exit_status": $exit_code,
  "duration_sec": $duration,
  "syscall_count": 0,
  "api_call_count": 0,
  "file_writes": [],
  "registry_writes": [],
  "network_attempts": [],
  "spawned_processes": [],
  "syscalls": [],
  "api_calls": [],
  "errors": ["container did not emit _dynamic.json; check container.log"]
}
JSON
    fi

    log_step "dynamic-docker: container exited with code $exit_code"
}
