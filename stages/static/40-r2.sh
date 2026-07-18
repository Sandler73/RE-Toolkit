#!/usr/bin/env bash
# =============================================================================
# stages/static/40-r2.sh
# =============================================================================
#
# Synopsis:
#     radare2 deep analysis and string-to-function mapping.
#
# Description:
#     Invokes r2 at maximum analysis depth and emits one text file per
#     informational command to 40-r2/. Analysis level is `aaa` by default;
#     --deep-analysis unlocks `aaaa` (5-10x slower, full propagation).
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
#     stage_r2_deep()
#     _r2_string_to_function()
#
# Output subtrees:
#     ${outdir}/40-r2/
#
# Skip controls:
#     SKIP_R2
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_r2_deep() {
    local target="$1" outdir="$2"
    [[ $SKIP_R2 -eq 1 ]] && return 0
    command -v radare2 >/dev/null 2>&1 || return 0

    local r2="${outdir}/40-r2"
    mkdir -p "$r2"

    # Analysis level
    local anal_cmd
    if [[ $DEEP_ANALYSIS -eq 1 ]]; then
        anal_cmd='aaaa'
    else
        anal_cmd='aaa'
    fi

    # Build a single r2 script that emits many output files at once. The
    # `|>` pipe form writes the preceding command's output to the named
    # file from within r2; doing it this way is ~3x faster than running
    # radare2 repeatedly (we amortize the aaa analysis pass).
    local r2script
    r2script="
e anal.depth=256
e anal.vars=true
e bin.cache=true
${anal_cmd}
iz | > ${r2}/strings.txt
izzz | > ${r2}/strings-deep.txt
afl | > ${r2}/funcs.txt
afll | > ${r2}/funcs-detailed.txt
axl | > ${r2}/xrefs.txt
is | > ${r2}/symbols.txt
iS | > ${r2}/sections.txt
ii | > ${r2}/imports.txt
iE | > ${r2}/exports.txt
ih | > ${r2}/header.txt
ie | > ${r2}/entries.txt
ir | > ${r2}/relocs.txt
iz~~[3] | > ${r2}/string-section-map.txt
pdf @@f | > ${r2}/all-functions-disasm.txt
agCd | > ${r2}/global-call-graph.dot
izj | > ${r2}/strings.json
aflj | > ${r2}/funcs.json
q
"
    local t=$TOOL_TIMEOUT
    [[ $DEEP_ANALYSIS -eq 1 ]] && t=1200  # cap at 20min for aaaa; default is faster
    run_shell "radare2-deep-${anal_cmd}" "${r2}/r2-driver.log" "$t" \
        "radare2 -2 -q -c \"$r2script\" '$target'"

    local fcount
    fcount=$(wc -l < "${r2}/funcs.txt" 2>/dev/null | awk '{print $1}')
    [[ -z "$fcount" ]] && fcount=0
    log_step "r2 deep (${anal_cmd}): $fcount functions analyzed → ${r2}/"

    # v3.0.6 (audit-10 B1+B2+B3) - render global call graph to SVG.
    #
    # r2 emits global-call-graph.dot above (line ~59 via `agCd`). Pre-v3.0.6
    # this .dot file was just dropped on the filesystem; nothing rendered or
    # consumed it. v3.0.6 adds a render step so stage 89-viz / stage 90-report
    # can embed the call graph inline.
    #
    # v3.0.17 (audit-21) fix: command was `agC` which emits ASCII art --
    # NOT graphviz dot format. Per r2 official docs:
    #     agC[format]   Global callgraph
    # Output formats:
    #     <blank>   ascii art       (agC alone -> ASCII art)
    #     d         graphviz dot    (agCd -> .dot format)
    # The bug: `agC | > .dot` redirected ASCII art into a file with .dot
    # extension. Graphviz `dot` then refused to render the ASCII content,
    # producing operator-visible ".dot missing or empty; skipping render".
    # Fix: append `d` format suffix -> `agCd`. This is the same class of
    # bug as L60 (flag verification): the format suffix wasn't checked
    # against the file extension we were writing to.
    #
    # Guards (v3.0.6, hardened v3.1.0 audit-22 A0.3):
    #   (1) .dot must exist, be non-empty, AND be valid graphviz syntax
    #       (v3.1.0: validate_output_format distinguishes "missing/empty"
    #       from "present but malformed" -- the exact distinction that hid
    #       the L64 agC-vs-agCd bug, where ASCII art passed a bare non-empty
    #       check then failed graphviz at render time).
    #   (2) graphviz must be installed (`dot` on PATH); skip cleanly if not
    #   (3) Node-count cap to avoid hanging `dot` on very large binaries:
    #       graphviz layout is O(V*E) worst case. Caps at 5000 nodes
    #       (counted as DOT lines containing '->'). Beyond cap, emit
    #       a placeholder note instead of trying to render.
    local cg_dot="${r2}/global-call-graph.dot"
    local cg_svg="${r2}/global-call-graph.svg"
    validate_output_format "$cg_dot" dot
    local cg_fmt_rc=$?
    if [[ $cg_fmt_rc -eq 2 ]]; then
        log_step "r2 call graph: .dot missing or empty; skipping render"
    elif [[ $cg_fmt_rc -eq 1 ]]; then
        # Present but NOT valid graphviz -- this is the L64 signature. If it
        # ever recurs (e.g. a future r2 version changes agCd output, or the
        # command regresses to bare agC), we now report it accurately instead
        # of the misleading "missing or empty."
        log_step "r2 call graph: .dot present but not valid graphviz syntax; skipping render"
        log_step "  (expected 'digraph'/'graph'; got other content -- check agCd invocation)"
    elif ! command -v dot >/dev/null 2>&1; then
        log_step "r2 call graph: graphviz 'dot' not installed; .dot kept but not rendered"
        log_step "  (install graphviz to enable: sudo apt install graphviz)"
    else
        # Count edges (lines containing ' -> ') as a cheap node-count proxy.
        # head -200000 caps the count operation itself for pathological cases.
        local edge_count
        edge_count=$(grep -c ' -> ' "$cg_dot" 2>/dev/null | head -1 | tr -dc '0-9')
        edge_count="${edge_count:-0}"
        if [[ "$edge_count" -gt 5000 ]]; then
            # Too large to render reasonably; emit placeholder.
            cat > "$cg_svg" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 200" width="800" height="200">
<rect width="800" height="200" fill="#1a1a1a"/>
<text x="400" y="80" font-family="Garamond,serif" font-size="20" fill="#e6e6e6"
      text-anchor="middle">Call graph too large to render inline</text>
<text x="400" y="120" font-family="Garamond,serif" font-size="14" fill="#a8a8a8"
      text-anchor="middle">${edge_count} edges (cap: 5000). See global-call-graph.dot for raw data.</text>
<text x="400" y="150" font-family="Garamond,serif" font-size="12" fill="#888"
      text-anchor="middle">Manual render: dot -Tsvg global-call-graph.dot -o output.svg</text>
</svg>
SVG
            log_step "r2 call graph: ${edge_count} edges exceeds 5000-edge cap; placeholder SVG written"
        else
            # Render via dot; cap at 60s wall time (large graphs can still
            # be slow even within the edge-count budget).
            if timeout 60 dot -Tsvg "$cg_dot" -o "$cg_svg" 2>>"${r2}/dot-render.log"; then
                log_step "r2 call graph: rendered ${edge_count} edges -> $(basename "$cg_svg")"
            else
                log_step "r2 call graph: dot render failed or timed out (see ${r2}/dot-render.log)"
                rm -f "$cg_svg"  # clean up partial output
            fi
        fi
    fi

    # =========================================================================
    # v3.6.0 (audit-27 F1) -- String-to-function mapping
    # =========================================================================
    # Global-RE deliverable: for each interesting string, which function(s)
    # reference it. Answers "who uses api.vendor.com?" -> "sub_8400 and main".
    # Technique adapted from the binary-re static-analysis skill
    # (github.com/2389-research/binary-re): izj (strings + vaddr) correlated
    # against per-string axtj (xrefs to the string, each carrying fcn_addr /
    # fcn_name). We drive a second focused r2 pass that emits axtj per string
    # address (the version-stable command), then correlate in Python.
    #
    # This runs only when the main pass produced strings.json + funcs.json.
    # It is best-effort: any failure logs and skips without breaking the stage.
    _r2_string_to_function "$target" "$r2"
}

# _r2_string_to_function <target> <r2_outdir>
# Builds ${r2_outdir}/string-to-function.json and _strfunc-summary.json.
_r2_string_to_function() {
    local target="$1" r2="$2"
    [[ -z "$VENV_PY" ]] && return 0
    [[ -f "${r2}/strings.json" && -f "${r2}/funcs.json" ]] || return 0

    # Step 1: collect the string virtual addresses from strings.json, then run
    # a focused r2 script emitting `axtj @ <vaddr>` for each. We cap the number
    # of strings we correlate (most-relevant first is not knowable pre-corr, so
    # we cap by count) to bound runtime on string-heavy binaries.
    local xref_script
    xref_script=$("$VENV_PY" - "${r2}/strings.json" <<'PYADDR' 2>/dev/null || true
import sys, json
try:
    with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    # izj may be a bare list or {"strings":[...]} depending on r2 version.
    strings = data.get("strings", data) if isinstance(data, dict) else data
    MAX = 2000  # bound the per-string xref pass
    lines = []
    for s in strings[:MAX]:
        va = s.get("vaddr")
        if isinstance(va, int) and va > 0:
            # Emit an axtj at this address, prefixed with a marker line so the
            # correlator can associate the output block with the string vaddr.
            lines.append(f'?e ===STRVA {va}===')
            lines.append(f'axtj @ {va}')
    print("\n".join(lines))
except Exception:
    pass
PYADDR
)
    if [[ -z "$xref_script" ]]; then
        return 0
    fi
    # Run the focused xref pass (light: reuse cached analysis via project is
    # overkill; a fresh `aa` is enough to resolve function membership).
    printf 'aa\n%s\nq\n' "$xref_script" > "${r2}/.strfunc-script.r2"
    run_shell "radare2-strfunc" "${r2}/strfunc-r2.log" "$TOOL_TIMEOUT" \
        "radare2 -2 -q -i '${r2}/.strfunc-script.r2' '$target' > '${r2}/string-xrefs.raw' 2>/dev/null"

    # Step 2: correlate strings <-> functions in Python.
    "$VENV_PY" - "${r2}/strings.json" "${r2}/funcs.json" "${r2}/string-xrefs.raw" \
                  "${r2}/string-to-function.json" "${r2}/_strfunc-summary.json" \
                  <<'PYCORR' > "${r2}/strfunc-correlate.log" 2>&1 || true
import sys, json, re

strings_path, funcs_path, xref_raw_path, out_path, summary_path = sys.argv[1:6]

def load(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None

sdata = load(strings_path)
strings = sdata.get("strings", sdata) if isinstance(sdata, dict) else (sdata or [])
fdata = load(funcs_path)
funcs = fdata if isinstance(fdata, list) else (fdata.get("functions", []) if isinstance(fdata, dict) else [])

# Build function address ranges for fallback membership resolution:
# each function covers [offset, offset+size).
franges = []
for fn in funcs:
    off = fn.get("offset")
    size = fn.get("size", 0) or 0
    name = fn.get("name", "")
    if isinstance(off, int):
        franges.append((off, off + size, name, off))
franges.sort()

def fcn_for_addr(addr):
    """Resolve which function contains addr via ranges (fallback path)."""
    for start, end, name, foff in franges:
        if start <= addr < end:
            return name, foff
    return None, None

# vaddr -> string value
va_to_str = {}
for s in strings:
    va = s.get("vaddr")
    val = s.get("string", "")
    if isinstance(va, int):
        va_to_str[va] = val

# Parse the raw axtj output. It is a sequence of:
#   ===STRVA <vaddr>===
#   <axtj JSON line>   (a JSON array; may be empty [])
# for each string we queried.
mapping = {}  # vaddr -> set of (fcn_name, fcn_addr)
cur_va = None
marker_re = re.compile(r'^===STRVA\s+(\d+)===\s*$')
try:
    with open(xref_raw_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = marker_re.match(line.strip())
            if m:
                cur_va = int(m.group(1))
                mapping.setdefault(cur_va, set())
                continue
            if cur_va is None:
                continue
            ls = line.strip()
            if not ls.startswith("["):
                continue
            try:
                refs = json.loads(ls)
            except Exception:
                continue
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                # r2 axtj carries fcn_addr / fcn_name directly (preferred).
                fname = ref.get("fcn_name")
                faddr = ref.get("fcn_addr")
                if not fname:
                    # Fallback: resolve the referencing address to a function.
                    frm = ref.get("from")
                    if isinstance(frm, int):
                        fname, faddr = fcn_for_addr(frm)
                if fname:
                    mapping[cur_va].add((fname, faddr if isinstance(faddr, int) else -1))
except Exception:
    pass

# Build the output: one record per string that has at least one referencing
# function, sorted by number of referencing functions (most-referenced first).
records = []
for va, fset in mapping.items():
    if not fset:
        continue
    sval = va_to_str.get(va, "")
    fns = sorted(
        ({"name": n, "addr": hex(a) if a >= 0 else ""} for n, a in fset),
        key=lambda d: d["name"],
    )
    records.append({
        "string": sval,
        "vaddr": hex(va),
        "ref_count": len(fns),
        "functions": fns,
    })
records.sort(key=lambda r: r["ref_count"], reverse=True)

with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"strings": records, "total_mapped": len(records)}, f, indent=2, ensure_ascii=False)

with open(summary_path, "w", encoding="utf-8") as f:
    json.dump({
        "strings_scanned": len(strings),
        "functions_known": len(franges),
        "strings_mapped_to_functions": len(records),
    }, f, indent=2)

print(f"string-to-function: {len(records)} strings mapped to functions "
      f"(of {len(strings)} scanned)")
PYCORR

    if [[ -f "${r2}/string-to-function.json" ]]; then
        local mapped
        mapped=$(grep -m1 '^string-to-function:' "${r2}/strfunc-correlate.log" 2>/dev/null || echo "string-to-function: done")
        log_step "strfunc: ${mapped#string-to-function: }"
    fi
    rm -f "${r2}/.strfunc-script.r2"
}
