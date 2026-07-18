#!/usr/bin/env bash
# =============================================================================
# stages/static/81-fuzzyhash.sh
# =============================================================================
#
# Synopsis:
#     Fuzzy hashing via ssdeep and sdhash for similarity clustering.
#
# Description:
#     Three fuzzy hashing algorithms covering the same need from different
#     angles:
#     - Ssdeep: context-triggered piecewise hash. Fast. Good for "near
#       duplicates with insertions/deletions". De-facto standard (used by
#       VirusTotal).
#     - TLSH: trend locality sensitive hash. More resistant to single-byte
#       changes than ssdeep. Used by STIX 2.1.
#     - Sdhash: similarity digest hash (Roussev). Optional; only included when
#       the apt package is available.
#
#     All three feed into the codebase-level _similarity-matrix.json built by
#     lib/aggregate.sh's write_similarity_matrix at the end of the run.
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
#     stage_fuzzyhash()
#
# Output subtrees:
#     ${outdir}/81-fuzzyhash/
#
# Skip controls:
#     SKIP_FUZZYHASH
#
# Tools invoked (run_tool labels):
#     sdhash, ssdeep
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_fuzzyhash() {
    local target="$1" outdir="$2"
    local fh="${outdir}/81-fuzzyhash"

    if [[ ${SKIP_FUZZYHASH:-0} -eq 1 ]]; then
        log_step "fuzzyhash: skipped (SKIP_FUZZYHASH=1)"
        return 0
    fi

    mkdir -p "$fh"

    # ssdeep CLI - fast and universal
    if command -v ssdeep >/dev/null 2>&1; then
        run_tool "ssdeep" "${fh}/ssdeep.txt" 30 \
            ssdeep -b "$target"
    fi

    # All-in-one Python heredoc: ssdeep + tlsh + emit unified JSON
    if [[ -n "$VENV_PY" ]]; then
        "$VENV_PY" - "$target" "$fh" > "${fh}/_compute.log" 2>&1 <<'PYEOF' || true
"""Compute ssdeep and tlsh fuzzy hashes; emit hashes.json."""
import sys
import os
import json

target = sys.argv[1]
outdir = sys.argv[2]

result = {
    "target": target,
    "size": os.path.getsize(target) if os.path.exists(target) else 0,
    "ssdeep": None,
    "tlsh": None,
    "ssdeep_error": None,
    "tlsh_error": None,
}

# ssdeep
try:
    import ssdeep
    result["ssdeep"] = ssdeep.hash_from_file(target)
except ImportError:
    result["ssdeep_error"] = "python-ssdeep not installed in venv"
except Exception as e:
    result["ssdeep_error"] = f"ssdeep: {type(e).__name__}: {e}"

# tlsh - requires minimum 50 bytes of input AND minimum entropy
try:
    import tlsh
    with open(target, "rb") as f:
        data = f.read()
    if len(data) < 50:
        result["tlsh_error"] = f"file too small ({len(data)} bytes; tlsh needs >= 50)"
    else:
        h = tlsh.hash(data)
        # tlsh returns "TNULL" for files that don't have enough entropy
        if h == "TNULL" or h == "":
            result["tlsh_error"] = "tlsh: insufficient entropy (TNULL)"
        else:
            result["tlsh"] = h
except ImportError:
    result["tlsh_error"] = "python-tlsh not installed in venv"
except Exception as e:
    result["tlsh_error"] = f"tlsh: {type(e).__name__}: {e}"

# Write JSON for downstream parsers
out_path = os.path.join(outdir, "hashes.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
print(f"ssdeep={result['ssdeep']}, tlsh={result['tlsh']}")
PYEOF
    fi

    # sdhash - optional. Only if the binary is available.
    if command -v sdhash >/dev/null 2>&1; then
        run_tool "sdhash" "${fh}/sdhash.txt" 60 \
            sdhash "$target"
    fi

    log_step "fuzzyhash: $(test -f "${fh}/hashes.json" && echo "hashes.json written" || echo "no hashes computed")"
}
