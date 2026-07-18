#!/usr/bin/env bash
# =============================================================================
# stages/static/86-angr.sh
# =============================================================================
#
# Synopsis:
#     angr CFGFast control-flow graph recovery (opt-in).
#
# Description:
#     OPT-IN by default. angr's CFGFast can recover control flow that static
#     disassemblers miss (indirect calls, computed jumps). Cost is high: 30
#     seconds for small binaries, several minutes for large/stripped ones. Hard
#     timeout protects against runaway analyses on adversarial inputs.
#
#     We only run CFGFast (not CFGEmulated). CFGEmulated is much more accurate
#     but takes orders of magnitude longer; analysts who need it should invoke
#     angr interactively from the venv.
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
#     stage_angr()
#
# Output subtrees:
#     ${outdir}/86-angr/
#
# Skip controls:
#     ENABLE_ANGR
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_angr() {
    local target="$1" outdir="$2"
    local an="${outdir}/86-angr"

    if [[ ${ENABLE_ANGR:-0} -ne 1 ]]; then
        log_step "angr: skipped (opt-in via --enable-angr)"
        return 0
    fi

    if [[ -z "$VENV_PY" ]]; then
        log_warn "angr: venv Python unavailable; skipping"
        return 0
    fi

    mkdir -p "$an"

    local angr_timeout="${ANGR_TIMEOUT:-600}"
    log_step "angr: starting CFGFast (timeout ${angr_timeout}s)"

    timeout "$angr_timeout" "$VENV_PY" - "$target" "$an" \
        > "${an}/_angr.log" 2>&1 <<'PYEOF' || true
"""angr CFGFast recovery. Emits cfg-summary.json with function/edge counts,
indirect jumps, and high-level metrics. Does NOT do full symbolic exploration -
that's left to the analyst to do interactively if needed.
"""
import sys
import os
import json
import traceback

target_path = sys.argv[1]
outdir = sys.argv[2]

result = {
    "target": target_path,
    "loaded": False,
    "arch": None,
    "entry_point": None,
    "load_error": None,
    "cfg_error": None,
    "function_count": 0,
    "node_count": 0,
    "edge_count": 0,
    "indirect_jumps_resolved": 0,
    "indirect_jumps_unresolved": 0,
    "function_samples": [],  # first 50 functions by address
}

try:
    # Suppress angr's verbose logging
    import logging
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('cle').setLevel(logging.ERROR)
    logging.getLogger('claripy').setLevel(logging.ERROR)
    logging.getLogger('pyvex').setLevel(logging.ERROR)

    import angr

    proj = angr.Project(
        target_path,
        load_options={"auto_load_libs": False},
    )
    result["loaded"] = True
    result["arch"] = str(proj.arch)
    result["entry_point"] = hex(proj.entry) if proj.entry is not None else None

    try:
        cfg = proj.analyses.CFGFast(
            normalize=True,
            data_references=False,
            cross_references=False,
            show_progressbar=False,
        )
        result["function_count"] = len(cfg.kb.functions)
        # v3.0.10 (audit-14 A5) - networkx graph node/edge views may
        # return iterators (not sized containers) on some versions.
        # Pre-v3.0.10 used `len(cfg.graph.nodes())` which raised
        # "TypeError: object of type 'generator' has no len()" on the
        # operator's networkx version. The networkx-canonical APIs are
        # `g.number_of_nodes()` and `g.number_of_edges()`, which return
        # int directly across all versions.
        result["node_count"] = cfg.graph.number_of_nodes()
        result["edge_count"] = cfg.graph.number_of_edges()

        # v3.0.6 (audit-10 C1): export the CFG as a Graphviz .dot file.
        # Pre-v3.0.6 the cfg.graph was held in memory only; we wrote
        # node/edge COUNTS to JSON but never dumped the structure.
        #
        # Strategy:
        #  - Build a compact NetworkX MultiDiGraph from cfg.graph (its native
        #    type is a NetworkX DiGraph; we copy to ensure we have full
        #    control over the export form).
        #  - Each node is labeled with its block-start address (hex);
        #    optionally annotated with the containing function name when
        #    we can resolve it cheaply.
        #  - Cap at 5000 edges in the .dot output to match the r2/dot
        #    pipeline's render cap. Beyond cap, we emit a 'too-large'
        #    marker file so the renderer skips and writes a placeholder.
        #
        # Skip cleanly if networkx or pydot is unavailable (some installs
        # may have angr without optional deps); we don't fail the stage.
        try:
            import networkx as _nx  # angr already depends on networkx
            _CFG_DOT_PATH = os.path.join(outdir, "cfg.dot")
            _CFG_DOT_TOO_LARGE = os.path.join(outdir, "cfg.dot.too-large")
            _edge_cap = 5000
            _g = cfg.graph
            _edge_count = _g.number_of_edges()
            if _edge_count > _edge_cap:
                # Write marker file so the bash post-step knows to emit a placeholder.
                with open(_CFG_DOT_TOO_LARGE, "w") as _fh:
                    _fh.write(f"edges={_edge_count}\ncap={_edge_cap}\n")
                result["cfg_dot_skipped_reason"] = f"too-large:{_edge_count}>{_edge_cap}"
            else:
                # Build a compact graph for export. cfg.graph's nodes are
                # CFGNode objects; their str() is verbose. Re-label by
                # block address as a hex string for readability.
                _h = _nx.DiGraph()
                _addr_of = {}
                for _node in _g.nodes():
                    try:
                        _addr = getattr(_node, "addr", None)
                        if _addr is None:
                            continue
                        _label = hex(_addr)
                        # Try to attribute the block to a function for color/grouping.
                        _func_addr = getattr(_node, "function_address", None)
                        _func_name = ""
                        if _func_addr is not None and _func_addr in cfg.kb.functions:
                            _func_name = cfg.kb.functions[_func_addr].name or ""
                        _h.add_node(_label,
                                    addr=_label,
                                    function=_func_name)
                        _addr_of[id(_node)] = _label
                    except Exception:
                        continue
                for _src, _dst in _g.edges():
                    _s = _addr_of.get(id(_src))
                    _d = _addr_of.get(id(_dst))
                    if _s and _d:
                        _h.add_edge(_s, _d)

                # Try pydot first (cleaner output); fall back to nx_agraph
                # (which uses pygraphviz) or to manual .dot writing.
                _wrote = False
                try:
                    from networkx.drawing.nx_pydot import write_dot as _write_dot
                    _write_dot(_h, _CFG_DOT_PATH)
                    _wrote = True
                except Exception:
                    pass
                if not _wrote:
                    # Manual minimal .dot writer (no external deps).
                    with open(_CFG_DOT_PATH, "w") as _fh:
                        _fh.write('digraph cfg {\n')
                        _fh.write('  rankdir=LR;\n')
                        _fh.write('  node [shape=box, fontname="monospace", fontsize=8];\n')
                        for _n, _attrs in _h.nodes(data=True):
                            _func = _attrs.get("function", "").replace('"', "'")
                            _label = f'{_n}\\n{_func}' if _func else _n
                            _fh.write(f'  "{_n}" [label="{_label}"];\n')
                        for _u, _v in _h.edges():
                            _fh.write(f'  "{_u}" -> "{_v}";\n')
                        _fh.write('}\n')
                    _wrote = True
                result["cfg_dot_written"] = bool(_wrote)
                result["cfg_dot_path"] = _CFG_DOT_PATH if _wrote else None
        except ImportError as _e:
            result["cfg_dot_skipped_reason"] = f"networkx-unavailable:{_e}"
        except Exception as _e:
            result["cfg_dot_skipped_reason"] = f"{type(_e).__name__}:{_e}"

        # Indirect jump resolution stats (angr exposes this on the cfg)
        try:
            ij = getattr(cfg, "indirect_jumps", None)
            if ij is not None:
                resolved = sum(1 for j in ij.values() if getattr(j, "resolved", False))
                result["indirect_jumps_resolved"] = resolved
                result["indirect_jumps_unresolved"] = len(ij) - resolved
        except Exception:
            pass

        # Function samples - first 50 by address
        for i, (addr, func) in enumerate(sorted(cfg.kb.functions.items())):
            if i >= 50: break
            try:
                result["function_samples"].append({
                    "addr": hex(addr),
                    "name": func.name or "",
                    "size": func.size or 0,
                    "block_count": len(list(func.blocks)),
                    "is_syscall": bool(func.is_syscall),
                    "is_simprocedure": bool(func.is_simprocedure),
                    "returning": bool(func.returning) if func.returning is not None else None,
                })
            except Exception:
                continue
    except Exception as e:
        result["cfg_error"] = f"{type(e).__name__}: {e}"
        traceback.print_exc()

except Exception as e:
    result["load_error"] = f"{type(e).__name__}: {e}"
    traceback.print_exc()

with open(os.path.join(outdir, "cfg-summary.json"), "w") as f:
    json.dump(result, f, indent=2)
print(f"angr: loaded={result['loaded']}, "
      f"functions={result['function_count']}, "
      f"nodes={result['node_count']}, "
      f"edges={result['edge_count']}, "
      f"indirect_resolved={result['indirect_jumps_resolved']}, "
      f"unresolved={result['indirect_jumps_unresolved']}")
PYEOF
    rc=$?
    if [[ $rc -eq 124 ]]; then
        log_warn "angr: TIMEOUT after ${angr_timeout}s; partial output may be present"
        echo "TIMEOUT after ${angr_timeout}s" > "${an}/_TIMEOUT.txt"
    elif [[ $rc -ne 0 ]]; then
        log_warn "angr: exit code $rc; see _angr.log"
    fi

    # v3.0.6 (audit-10 C2+C3) - render cfg.dot to SVG via graphviz.
    #
    # The Python block above writes cfg.dot when angr's CFG was successfully
    # built and the graph fits within the 5000-edge cap. We render here in
    # bash so the rendering pipeline matches stage 40-r2.sh's pattern.
    #
    # Three guards:
    #   (1) cfg.dot.too-large marker means the Python block already decided
    #       the graph is too big; emit placeholder SVG and skip
    #   (2) graphviz must be installed (`dot` on PATH); skip cleanly if not
    #   (3) cfg.dot must exist and be non-empty; skip cleanly if not
    local cfg_dot="${an}/cfg.dot"
    local cfg_svg="${an}/cfg.svg"
    local cfg_too_large="${an}/cfg.dot.too-large"

    if [[ -f "$cfg_too_large" ]]; then
        local edges_info
        edges_info=$(cat "$cfg_too_large" 2>/dev/null | head -1)
        cat > "$cfg_svg" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 200" width="800" height="200">
<rect width="800" height="200" fill="#1a1a1a"/>
<text x="400" y="80" font-family="Garamond,serif" font-size="20" fill="#e6e6e6"
      text-anchor="middle">CFG too large to render inline</text>
<text x="400" y="120" font-family="Garamond,serif" font-size="14" fill="#a8a8a8"
      text-anchor="middle">${edges_info} (cap: 5000)</text>
<text x="400" y="150" font-family="Garamond,serif" font-size="12" fill="#888"
      text-anchor="middle">See cfg-summary.json for graph metrics; raw graph not exported.</text>
</svg>
SVG
        log_step "angr CFG: graph too large; placeholder SVG written"
    elif [[ ! -s "$cfg_dot" ]]; then
        log_step "angr CFG: cfg.dot missing or empty; skipping render"
    elif ! command -v dot >/dev/null 2>&1; then
        log_step "angr CFG: graphviz 'dot' not installed; .dot kept but not rendered"
        log_step "  (install graphviz to enable: sudo apt install graphviz)"
    else
        # Render via dot; cap at 60s wall time (matches r2 stage).
        if timeout 60 dot -Tsvg "$cfg_dot" -o "$cfg_svg" 2>>"${an}/dot-render.log"; then
            local edge_count
            edge_count=$(grep -c ' -> ' "$cfg_dot" 2>/dev/null | head -1 | tr -dc '0-9')
            edge_count="${edge_count:-0}"
            log_step "angr CFG: rendered ${edge_count} edges -> $(basename "$cfg_svg")"
        else
            log_step "angr CFG: dot render failed or timed out (see ${an}/dot-render.log)"
            rm -f "$cfg_svg"  # clean up partial output
        fi
    fi
}
