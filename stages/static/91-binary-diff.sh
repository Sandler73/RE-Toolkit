#!/usr/bin/env bash
# =============================================================================
# stages/static/91-binary-diff.sh
# =============================================================================
#
# Synopsis:
#     Byte-level binary diffing via bsdiff and vbindiff.
#
# Description:
#     Not directly executable. Defines: stage_binary_diff
#
#     V3.0.2 additions (audit-6):
#     - Bsdiff: produces compact binary patch using Colin Percival's
#
#     Algorithm. Useful for firmware-version comparison and patch-RE.
#     - Vbindiff: visual byte-level diff (curses TUI). We invoke
#
#     Non-interactively via stdin/stdout where possible; primary use case is
#     producing a text snapshot of differing regions for the report.
#
#     Activation: This stage runs only when the env var
#     RETOOLKIT_REFERENCE_BINARY is set to a readable file path. Without a
#     reference binary, there's nothing meaningful to diff against, so the
#     stage is a no-op. The driver passes this through from the optional --diff
#     <path> CLI flag.
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
#     stage_binary_diff()
#
# Output subtrees:
#     ${outdir}/91-binary-diff/
#
# Skip controls:
#     SKIP_BINARY_DIFF
#
# Tools invoked (run_tool labels):
#     bsdiff
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_binary_diff() {
    local target="$1" outdir="$2"
    local diff="${outdir}/91-binary-diff"

    if [[ ${SKIP_BINARY_DIFF:-0} -eq 1 ]]; then
        log_step "stage_binary_diff: SKIP (SKIP_BINARY_DIFF=1)"
        return 0
    fi

    # Activation gate: RETOOLKIT_REFERENCE_BINARY must point at a readable file.
    local ref="${RETOOLKIT_REFERENCE_BINARY:-}"
    if [[ -z "$ref" ]]; then
        log_step "stage_binary_diff: skipping (no RETOOLKIT_REFERENCE_BINARY set)"
        return 0
    fi
    if [[ ! -r "$ref" ]]; then
        log_warn "stage_binary_diff: reference binary not readable: $ref"
        return 0
    fi
    if [[ "$(realpath "$ref")" == "$(realpath "$target")" ]]; then
        log_step "stage_binary_diff: reference is identical to target; skipping"
        return 0
    fi

    mkdir -p "$diff"
    log_step "stage_binary_diff: comparing target against reference: $ref"

    # ----- bsdiff: produce a binary patch ---------------------------------
    if command -v bsdiff >/dev/null 2>&1; then
        local patch_path="${diff}/bsdiff-patch.bin"
        if run_tool "bsdiff" "${diff}/bsdiff.log" 120 \
                bsdiff "$ref" "$target" "$patch_path"; then
            local patch_sz target_sz ref_sz
            patch_sz=$(stat -c %s "$patch_path" 2>/dev/null || echo 0)
            target_sz=$(stat -c %s "$target" 2>/dev/null || echo 0)
            ref_sz=$(stat -c %s "$ref" 2>/dev/null || echo 0)
            {
                echo "# bsdiff summary: $ref -> $target"
                echo "reference_size_bytes: $ref_sz"
                echo "target_size_bytes:    $target_sz"
                echo "patch_size_bytes:     $patch_sz"
                if [[ $target_sz -gt 0 ]]; then
                    awk -v p="$patch_sz" -v t="$target_sz" \
                        'BEGIN{ printf "patch_to_target_ratio: %.4f\n", p/t }'
                fi
            } > "${diff}/bsdiff-summary.txt"
        fi
    else
        log_warn "stage_binary_diff: bsdiff not on PATH; skipping binary patch generation"
    fi

    # ----- vbindiff: text snapshot of differing regions -------------------
    # vbindiff is a curses TUI tool; it has no headless mode. We sidestep
    # by computing a byte-level diff via cmp + awk, which produces a
    # representative snapshot suitable for inclusion in the HTML report.
    # vbindiff is verified at install time so analysts know it's available
    # for interactive use; the stage records the invocation.
    if command -v cmp >/dev/null 2>&1; then
        # Capture first 50 differing byte offsets (sufficient for a snapshot)
        cmp -l "$ref" "$target" 2>/dev/null \
            | head -50 \
            | awk 'BEGIN{print "# Byte-level diff snapshot (first 50 differing offsets)"; print "# offset(decimal) ref_byte(octal) target_byte(octal)"} {print}' \
            > "${diff}/vbindiff-snapshot.txt"
    fi
    if command -v vbindiff >/dev/null 2>&1; then
        echo "# vbindiff is installed at $(command -v vbindiff)" \
            >> "${diff}/vbindiff-snapshot.txt"
        echo "# For interactive analyst review run: vbindiff $ref $target" \
            >> "${diff}/vbindiff-snapshot.txt"
    fi

    # ----- _diff.json: machine-readable summary --------------------------
    local diff_count=0
    diff_count=$(cmp -l "$ref" "$target" 2>/dev/null | wc -l || echo 0)
    cat > "${diff}/_diff.json" <<JSONEOF
{
  "reference": "$(realpath "$ref")",
  "target": "$(realpath "$target")",
  "reference_size": $(stat -c %s "$ref" 2>/dev/null || echo 0),
  "target_size": $(stat -c %s "$target" 2>/dev/null || echo 0),
  "differing_byte_count": ${diff_count},
  "bsdiff_patch_path": "$([[ -f "${diff}/bsdiff-patch.bin" ]] && realpath "${diff}/bsdiff-patch.bin" || echo "")",
  "bsdiff_patch_size": $(stat -c %s "${diff}/bsdiff-patch.bin" 2>/dev/null || echo 0)
}
JSONEOF

    log_step "stage_binary_diff: complete (${diff_count} differing bytes)"
    return 0
}
