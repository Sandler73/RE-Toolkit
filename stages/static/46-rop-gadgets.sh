#!/usr/bin/env bash
# =============================================================================
# stages/static/46-rop-gadgets.sh
# =============================================================================
#
# Synopsis:
#     ROP gadget enumeration via pwntools.
#
# Description:
#     Not directly executable. Defines: stage_rop_gadgets
#
#     V3.0.2 additions (audit-6):
#     - Pwntools ROP class for gadget enumeration on ELF binaries.
#
#     Complements ROPgadget which is a separate analyzer; pwntools' ROP emits
#     the same gadget concept but with pwntools-specific metadata (pivot
#     points, syscall gadgets, magic-gadget detection, etc.).
#
#     Why a separate stage from stage_elf:
#     - ROP enumeration on a large ELF can take minutes (>1 min wall-clock
#
#     On binaries with many code segments). Keeping it in a dedicated stage
#     lets analysts skip it cheaply via SKIP_ROP_GADGETS=1.
#     - Output volume can be large (10K+ gadgets on a typical glibc-linked
#
#     Binary). Separate output dir avoids polluting 50-elf/.
#
#     Dependencies:
#     - Pwntools is in the LAYER 3 venv at $RETOOLS_VENV/bin/python.
#
#     Driver exports VENV_PY for stages to use.
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
#     stage_rop_gadgets()
#
# Output subtrees:
#     ${outdir}/46-rop-gadgets/
#
# Skip controls:
#     SKIP_ROP_GADGETS
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_rop_gadgets() {
    local target="$1" outdir="$2"
    local rop="${outdir}/46-rop-gadgets"
    mkdir -p "$rop"

    if [[ ${SKIP_ROP_GADGETS:-0} -eq 1 ]]; then
        log_step "stage_rop_gadgets: SKIP (SKIP_ROP_GADGETS=1)"
        return 0
    fi

    # Stage applies to ELF only. Caller should restrict via dispatch, but
    # double-check here for safety.
    if ! file "$target" 2>/dev/null | grep -q "ELF"; then
        log_step "stage_rop_gadgets: skipping (target is not ELF)"
        return 0
    fi

    # pwntools must be importable. VENV_PY is set by the driver.
    if [[ -z "${VENV_PY:-}" ]] || ! "$VENV_PY" -c "from pwn import ROP, ELF" 2>/dev/null; then
        log_warn "stage_rop_gadgets: pwntools ROP unavailable in venv; skipping"
        return 0
    fi

    log_step "stage_rop_gadgets: enumerating gadgets via pwntools ROP class"

    # Use a Python heredoc to invoke pwntools. Wrap in timeout so a
    # pathological binary doesn't hang the pipeline.
    timeout 120 "$VENV_PY" - "$target" "$rop" <<'PYEOF' 2>&1 | tee "${rop}/_pwntools.log" >/dev/null
import json
import sys
import os
from collections import Counter

target_path, out_dir = sys.argv[1], sys.argv[2]

# Silence pwntools' progress chatter -- we want machine-readable output.
os.environ.setdefault("PWNLIB_NOTERM", "1")
os.environ.setdefault("PWNLIB_SILENT", "1")

try:
    from pwn import context, ELF, ROP
except Exception as e:
    print(f"FATAL: pwntools import failed: {e}", file=sys.stderr)
    sys.exit(2)

context.log_level = "error"

try:
    elf = ELF(target_path, checksec=False)
except Exception as e:
    print(f"FATAL: ELF parse failed: {e}", file=sys.stderr)
    sys.exit(3)

try:
    rop = ROP(elf)
except Exception as e:
    print(f"FATAL: ROP construction failed: {e}", file=sys.stderr)
    sys.exit(4)

# pwntools ROP exposes .gadgets (dict: addr -> Gadget object) once gadgets
# have been enumerated. Iterate executable segments to populate.
gadgets = []
try:
    # Use the lower-level ROPGadget-style enumeration. pwntools loads
    # gadgets lazily; force enumeration by accessing rop.gadgets which
    # parses on demand from .text-equivalent segments.
    for addr, gadget in (rop.gadgets or {}).items():
        # Each gadget is a pwntools Gadget(address, insns, regs, move).
        gadgets.append({
            "address": f"0x{addr:x}",
            "insns": list(gadget.insns) if gadget.insns else [],
            "regs": list(gadget.regs) if gadget.regs else [],
            "move": gadget.move,
        })
except Exception as e:
    print(f"WARN: gadget iteration failed: {e}", file=sys.stderr)

# Write text view (one gadget per line, address + insns)
text_path = os.path.join(out_dir, "gadgets.txt")
with open(text_path, "w", encoding="utf-8", errors="replace") as fh:
    fh.write(f"# pwntools ROP enumeration for {target_path}\n")
    fh.write(f"# total gadgets: {len(gadgets)}\n\n")
    for g in gadgets:
        insns = "; ".join(g["insns"]) if g["insns"] else "(no insns)"
        fh.write(f"{g['address']}: {insns}\n")

# Write JSON view (full structure for downstream programmatic use)
json_path = os.path.join(out_dir, "gadgets.json")
with open(json_path, "w", encoding="utf-8") as fh:
    json.dump({
        "target": target_path,
        "total_gadgets": len(gadgets),
        "gadgets": gadgets,
    }, fh, indent=2)

# Summary stats: histogram of first instruction
summary_path = os.path.join(out_dir, "summary.txt")
first_insn_counts = Counter()
for g in gadgets:
    if g["insns"]:
        first = g["insns"][0].split()[0] if g["insns"][0].split() else "?"
        first_insn_counts[first] += 1
with open(summary_path, "w", encoding="utf-8") as fh:
    fh.write(f"# pwntools ROP gadget summary for {target_path}\n")
    fh.write(f"Total gadgets: {len(gadgets)}\n")
    fh.write("\nTop-20 first-instruction histogram:\n")
    for insn, count in first_insn_counts.most_common(20):
        fh.write(f"  {count:6d}  {insn}\n")

print(f"OK: {len(gadgets)} gadgets written to {out_dir}/")
PYEOF

    local rc=$?
    if [[ $rc -eq 0 ]]; then
        log_step "stage_rop_gadgets: complete ($(wc -l < "${rop}/gadgets.txt" 2>/dev/null || echo 0) lines)"
    elif [[ $rc -eq 124 ]]; then
        log_warn "stage_rop_gadgets: pwntools ROP timed out after 120s (target too large?)"
    else
        log_warn "stage_rop_gadgets: pwntools ROP exited $rc (see ${rop}/_pwntools.log)"
    fi
    return 0
}
