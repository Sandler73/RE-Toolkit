#!/usr/bin/env bash
# =============================================================================
# stages/static/89-viz.sh
# =============================================================================
#
# Synopsis:
#     Visualization rendering: treemaps, heatmaps, charts, and graphs.
#
# Description:
#     Generates SELF-CONTAINED inline SVG visualizations from already-collected
#     stage data. No external CDN, no JS libraries, no internet fetch. Each
#     HTML file is openable offline and embeddable inline in the 90-report
#     Visualizations tab.
#
#     Reads (best-effort; missing inputs result in empty viz with explanatory
#     text):
#     - ${outdir}/_summary.json (canonical aggregated data)
#     - Capa per-rule output (parsed from _summary.json's capa_data)
#     - ${outdir}/12-lief/* (sections, imports)
#     - ${outdir}/50-elf/* (ELF section data)
#     - ${outdir}/52-macho/* (Mach-O segment data)
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
#     stage_viz()
#
# Output subtrees:
#     ${outdir}/12-lief/
#     ${outdir}/50-elf/
#     ${outdir}/52-macho/
#     ${outdir}/89-viz/
#
# Skip controls:
#     SKIP_VIZ
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_viz() {
    local target="$1" outdir="$2"
    local viz="${outdir}/89-viz"

    if [[ ${SKIP_VIZ:-0} -eq 1 ]]; then
        log_step "viz: skipped (SKIP_VIZ=1)"
        return 0
    fi

    mkdir -p "$viz"

    if [[ -z "$VENV_PY" ]]; then
        log_warn "viz: VENV_PY not set; cannot generate visualizations"
        return 0
    fi

    # Concatenate viz-helper Python primitives + main viz logic into a single
    # Python invocation. This keeps the helper functions DRY between
    # stage_viz and aggregate.sh::write_cluster_graph.
    "$VENV_PY" - "$outdir" "$viz" "$target" > "${viz}/_viz.log" 2>&1 <<PYEOF || true
import sys
import os
import json
import re   # v3.0.6 (audit-10 D1): used by viz_graphs() to strip XML/DOCTYPE
            # declarations from graphviz-emitted SVG before inline embedding.

OUTDIR = sys.argv[1]
VIZ_DIR = sys.argv[2]
TARGET = sys.argv[3]

$(viz_helper_emit_svg_chrome_py)
$(viz_helper_emit_color_scale_py)
$(viz_helper_emit_treemap_py)
$(viz_helper_emit_force_layout_py)


# ---- Read aggregated summary -----------------------------------------------
SUMMARY = {}
sum_path = os.path.join(OUTDIR, "_summary.json")
if os.path.exists(sum_path):
    try:
        with open(sum_path) as f:
            SUMMARY = json.load(f)
    except Exception as e:
        SUMMARY = {"_error": str(e)}

viz_meta = {"generated": [], "skipped": [], "errors": []}


# ============================================================================
# Visualization 1: Section/segment treemap
# ============================================================================
def viz_sections():
    """Generate section/segment treemap from PE/ELF/Mach-O section data.

    v3.0.8 (audit-12 A1) - schema-correct read.
    Pre-v3.0.8 read pe.sections[].virtual_size / size / entropy / executable
    / characteristics. ACTUAL summary schema (see 85-summary.sh line 340 +
    line 1362-1366):
      SUMMARY["pe"]["sections"]      = [{name, vaddr, vsize, rsize, flags}]
      SUMMARY["entropy"]["sections"] = [{name, vsize, rsize, entropy, flag}]
    Section structural data is in pe.sections; entropy is in entropy.sections;
    they're merged by name. None of the keys read pre-v3.0.8 exist in the
    actual JSON, so every PE binary fell into the "no data available" path.
    """
    sections = []
    # Build entropy lookup by section name
    entropy_data = SUMMARY.get("entropy", {}) or {}
    entropy_by_name = {}
    for e in entropy_data.get("sections") or []:
        if isinstance(e, dict):
            entropy_by_name[e.get("name") or "?"] = float(e.get("entropy") or 0.0)

    # PE: sections under pe.sections - actual schema {name, vaddr, vsize, rsize, flags}
    pe_data = SUMMARY.get("pe", {}) or {}
    pe_sections = pe_data.get("sections") or []
    for s in pe_sections:
        if not isinstance(s, dict): continue
        name = s.get("name") or "?"
        # vsize/rsize may be hex strings (e.g., "0x1234") or decimal
        size = 0
        for key in ("vsize", "rsize"):
            v = s.get(key)
            if v is None: continue
            try:
                size = int(str(v), 0) if isinstance(v, str) and v.startswith(("0x","0X")) else int(v)
                if size > 0: break
            except (ValueError, TypeError):
                continue
        # flags string contains 'X' or 'IMAGE_SCN_MEM_EXECUTE' for executable
        flags_str = str(s.get("flags") or "")
        is_exec = ("X" in flags_str or "MEM_EXECUTE" in flags_str.upper())
        sections.append({
            "name": name,
            "size": size,
            "entropy": entropy_by_name.get(name, 0.0),
            "executable": is_exec,
        })

    # ELF: try elf section data (kept; verify schema matches what 50-elf emits)
    if not sections:
        elf_data = SUMMARY.get("elf", {}) or {}
        elf_sections = elf_data.get("sections") or []
        for s in elf_sections:
            if isinstance(s, dict):
                name = s.get("name") or "?"
                size = 0
                v = s.get("size")
                if v is not None:
                    try: size = int(str(v), 0) if isinstance(v, str) and v.startswith(("0x","0X")) else int(v)
                    except (ValueError, TypeError): pass
                sections.append({
                    "name": name,
                    "size": size,
                    "entropy": entropy_by_name.get(name, 0.0),
                    "executable": "X" in str(s.get("flags", "")),
                })
    # Mach-O: try macho segment data (kept as fallback)
    if not sections:
        macho_data = SUMMARY.get("macho", {}) or {}
        for s in macho_data.get("segments") or []:
            if isinstance(s, dict):
                name = s.get("name") or "?"
                size = 0
                v = s.get("size")
                if v is not None:
                    try: size = int(str(v), 0) if isinstance(v, str) and v.startswith(("0x","0X")) else int(v)
                    except (ValueError, TypeError): pass
                sections.append({
                    "name": name,
                    "size": size,
                    "entropy": entropy_by_name.get(name, 0.0),
                    "executable": "x" in str(s.get("permissions", "")).lower(),
                })

    if not sections:
        body = (
            '<p style="color:var(--text-secondary);text-align:center;padding:40px">'
            'No section/segment data available.<br>'
            '<small>This visualization populates when PE/ELF/Mach-O section'
            ' data is in _summary.json. For binaries without parseable'
            ' section structure (e.g., raw firmware blobs), this view is'
            ' skipped.</small></p>'
        )
        viz_meta["skipped"].append("01-sections (no section data)")
    else:
        # Filter zero-size and sort
        sections = [s for s in sections if s["size"] > 0]
        sections.sort(key=lambda s: -s["size"])

        VIZ_W, VIZ_H = 1100, 600
        sizes = [s["size"] for s in sections]
        rects = squarify(sizes, 10, 10, VIZ_W - 20, VIZ_H - 20)

        rect_svgs = []
        for s, (rx, ry, rw, rh) in zip(sections, rects):
            if rw < 1 or rh < 1: continue
            fill = color_entropy(s["entropy"])
            stroke = "#f87171" if s["executable"] else "#2a3346"
            stroke_w = 2 if s["executable"] else 1
            label = html_escape(s["name"])
            size_kb = s["size"] / 1024
            tooltip = f'{label}: {size_kb:.1f} KB, entropy {s["entropy"]:.2f}{", X" if s["executable"] else ""}'
            rect_svgs.append(
                f'<rect class="tooltip-trigger" x="{rx:.1f}" y="{ry:.1f}" '
                f'width="{rw:.1f}" height="{rh:.1f}" '
                f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_w}">'
                f'<title>{html_escape(tooltip)}</title></rect>'
            )
            # Inline label if rect is big enough
            if rw > 60 and rh > 20:
                text_color = "#0a0e1a" if s["entropy"] < 5.0 else "#e5e7eb"
                rect_svgs.append(
                    f'<text x="{rx + 4:.1f}" y="{ry + 14:.1f}" '
                    f'fill="{text_color}" font-size="11" font-weight="bold">'
                    f'{label}</text>'
                )
                if rh > 40:
                    rect_svgs.append(
                        f'<text x="{rx + 4:.1f}" y="{ry + 28:.1f}" '
                        f'fill="{text_color}" font-size="10">'
                        f'{size_kb:.1f}KB e={s["entropy"]:.2f}</text>'
                    )

        legend = (
            '<g transform="translate(10, ' + str(VIZ_H + 10) + ')">'
            '<rect width="20" height="14" fill="#4ade80"/>'
            '<text x="26" y="11" fill="#e5e7eb" font-size="11">low entropy (text/code)</text>'
            '<rect x="200" width="20" height="14" fill="#facc15"/>'
            '<text x="226" y="11" fill="#e5e7eb" font-size="11">medium entropy</text>'
            '<rect x="380" width="20" height="14" fill="#f87171"/>'
            '<text x="406" y="11" fill="#e5e7eb" font-size="11">high entropy (compressed/encrypted)</text>'
            '<rect x="640" width="20" height="14" fill="none" stroke="#f87171" stroke-width="2"/>'
            '<text x="666" y="11" fill="#e5e7eb" font-size="11">red border = executable</text>'
            '</g>'
        )
        body = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {VIZ_W} {VIZ_H + 40}" '
            f'preserveAspectRatio="xMidYMid meet">'
            f'{"".join(rect_svgs)}{legend}</svg>'
        )
        viz_meta["generated"].append("01-sections")

    out_path = os.path.join(VIZ_DIR, "01-sections.html")
    with open(out_path, "w") as f:
        f.write(svg_chrome_html(
            body,
            title="Section / Segment Treemap",
            subtitle="Area = size; color = Shannon entropy; red border = executable.",
        ))


# ============================================================================
# Visualization 2: Imports sunburst (DLL -> API hierarchy)
# ============================================================================
def viz_imports():
    """Hierarchical bar chart of imports grouped by DLL/library.

    v3.0.8 (audit-12 A2) - schema-correct read.
    Pre-v3.0.8 read pe.imports as flat list of {dll, function} entries.
    ACTUAL summary schema (see 85-summary.sh line 309-329):
      SUMMARY["pe"]["imports"] = [{"lib": "kernel32.dll",
                                    "funcs": ["CreateFileA", "WriteFile", ...]},
                                   ...]
    Each entry IS a library with its functions nested in 'funcs'. Pre-v3.0.8
    read .dll and .function (which don't exist), so by_dll always ended up
    empty and the viz fell into "no import data available" placeholder.
    """
    pe_data = SUMMARY.get("pe", {}) or {}
    imports = pe_data.get("imports") or []
    by_dll = {}
    for entry in imports:
        if isinstance(entry, dict):
            # Actual schema: {"lib": "kernel32.dll", "funcs": [...]}
            dll = (entry.get("lib") or entry.get("dll") or entry.get("library") or "?").lower()
            funcs = entry.get("funcs") or entry.get("functions") or []
            if isinstance(funcs, list):
                for fn in funcs:
                    by_dll.setdefault(dll, []).append(str(fn))
            else:
                # Single-function legacy shape (kept as fallback)
                fn = entry.get("function") or entry.get("name") or "?"
                by_dll.setdefault(dll, []).append(str(fn))
        elif isinstance(entry, str) and "!" in entry:
            dll, fn = entry.split("!", 1)
            by_dll.setdefault(dll.lower(), []).append(fn)

    # ELF: dynamic symbols / needed libs
    if not by_dll:
        elf_data = SUMMARY.get("elf", {}) or {}
        for need in (elf_data.get("dt_needed") or [])[:30]:
            by_dll.setdefault(str(need).lower(), [])

    if not by_dll:
        body = (
            '<p style="color:var(--text-secondary);text-align:center;padding:40px">'
            'No import data available.</p>'
        )
        viz_meta["skipped"].append("02-imports (no import data)")
    else:
        # Sort DLLs by API count, take top 20
        sorted_dlls = sorted(by_dll.items(), key=lambda kv: -len(kv[1]))[:20]

        VIZ_W = 1100
        BAR_H = 32; BAR_GAP = 8
        max_count = max(len(fns) for _, fns in sorted_dlls) or 1
        VIZ_H = len(sorted_dlls) * (BAR_H + BAR_GAP) + 40

        rows = []
        rows.append(
            '<text x="10" y="20" fill="#e5e7eb" font-size="14" font-weight="bold">'
            f'Top {len(sorted_dlls)} imported libraries by API count</text>'
        )
        for i, (dll, fns) in enumerate(sorted_dlls):
            y = 40 + i * (BAR_H + BAR_GAP)
            count = len(fns)
            bar_w = int((count / max_count) * (VIZ_W - 380))
            # Highlight suspicious DLLs (commonly used by malware)
            suspicious = any(s in dll.lower() for s in [
                "wininet", "urlmon", "ws2_32", "wsock32", "advapi32",
                "shell32", "ntdll", "psapi", "iphlpapi"
            ])
            color = "#f87171" if suspicious else "#60a5fa"
            tooltip_apis = ", ".join(fns[:8]) + (f" (+{count-8} more)" if count > 8 else "")
            rows.append(
                f'<g class="tooltip-trigger">'
                f'<text x="10" y="{y + 20}" fill="#e5e7eb" font-size="13" '
                f'text-anchor="start">{html_escape(dll[:35])}</text>'
                f'<rect x="180" y="{y}" width="{bar_w}" height="{BAR_H}" '
                f'fill="{color}" rx="2">'
                f'<title>{html_escape(tooltip_apis)}</title></rect>'
                f'<text x="{180 + bar_w + 8}" y="{y + 20}" fill="#9ca3af" '
                f'font-size="12">{count}</text>'
                f'</g>'
            )

        body = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {VIZ_W} {VIZ_H}" '
            f'preserveAspectRatio="xMidYMid meet">{"".join(rows)}</svg>'
        )
        viz_meta["generated"].append("02-imports")

    out_path = os.path.join(VIZ_DIR, "02-imports.html")
    with open(out_path, "w") as f:
        f.write(svg_chrome_html(
            body,
            title="Imports / External Dependencies",
            subtitle="API count per imported library; red bars highlight network/registry/process libraries commonly used by malware.",
        ))


# ============================================================================
# Visualization 3: capa-MITRE ATT&CK heatmap
# ============================================================================
# MITRE ATT&CK tactic ordering (kill-chain)
MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

def viz_capa_mitre():
    """Heatmap of capa rule matches grouped by MITRE ATT&CK tactic.

    v3.0.8 (audit-12 A4) - schema-correct read.
    Pre-v3.0.8 read rule.attack[] for each rule entry. ACTUAL summary schema
    (see 85-summary.sh line 255-297):
      capa["rules"]  = [{name, namespace, scope}]    (NO attack list per rule)
      capa["attack"] = [{id: "T1059", technique, tactic}, ...]  (top-level)
      capa["mbc"]    = [{id, behavior}, ...]                    (top-level)
    Pre-v3.0.8 read .attack on each rule (which is always None / empty),
    so by_tactic always summed to 0 and the viz showed an all-zero heatmap.
    """
    capa = SUMMARY.get("capa", {}) or {}
    rules = capa.get("rules") or []
    attack_entries = capa.get("attack") or []  # top-level, not per-rule
    by_tactic = {t: 0 for t in MITRE_TACTICS}
    rules_by_tactic = {t: [] for t in MITRE_TACTICS}

    # Walk the top-level attack list (proper schema)
    for atk in attack_entries:
        if not isinstance(atk, dict): continue
        tactic = (atk.get("tactic") or "").strip()
        technique = (atk.get("technique") or atk.get("id") or "").strip()
        # Match by tactic name (case-insensitive)
        for mt in MITRE_TACTICS:
            if tactic.lower() == mt.lower() or mt.lower() in tactic.lower():
                by_tactic[mt] += 1
                if technique:
                    rules_by_tactic[mt].append(technique)
                break

    # Legacy fallback: also walk per-rule .attack if present (older summaries)
    for rule in rules:
        if not isinstance(rule, dict): continue
        attack_list = rule.get("attack") or []
        rname = rule.get("name") or "?"
        for atk in attack_list:
            atk_str = str(atk)
            for tactic in MITRE_TACTICS:
                if tactic.lower() in atk_str.lower():
                    by_tactic[tactic] += 1
                    rules_by_tactic[tactic].append(rname)
                    break

    if all(v == 0 for v in by_tactic.values()):
        body = (
            '<p style="color:var(--text-secondary);text-align:center;padding:40px">'
            'No capa-MITRE ATT&amp;CK data available.<br>'
            '<small>capa rule data with MITRE ATT&amp;CK tactic mappings is'
            ' required. capa rule namespaces include attack annotations'
            ' that this visualization extracts.</small></p>'
        )
        viz_meta["skipped"].append("03-capa-mitre (no capa data)")
    else:
        VIZ_W = 1100
        CELL_W = 75; CELL_H = 70; PADDING = 6
        max_count = max(by_tactic.values()) or 1
        VIZ_H = CELL_H + 80

        cells = []
        cells.append(
            '<text x="10" y="20" fill="#e5e7eb" font-size="14" font-weight="bold">'
            f'capa rule matches per MITRE ATT&amp;CK tactic ({sum(by_tactic.values())} total)</text>'
        )
        for i, tactic in enumerate(MITRE_TACTICS):
            count = by_tactic[tactic]
            x = 10 + i * (CELL_W + PADDING)
            y = 40
            # Color intensity proportional to count
            t = count / max_count if max_count > 0 else 0
            color = color_blend("#1c2333", "#f87171", t) if count > 0 else "#0a0e1a"
            tooltip_rules = "; ".join(rules_by_tactic[tactic][:5]) + \
                (f" (+{count-5} more)" if count > 5 else "")
            text_color = "#0a0e1a" if t > 0.5 else "#e5e7eb"
            cells.append(
                f'<g class="tooltip-trigger">'
                f'<rect x="{x}" y="{y}" width="{CELL_W}" height="{CELL_H}" '
                f'fill="{color}" stroke="#2a3346" stroke-width="1" rx="3">'
                f'<title>{html_escape(tactic)}: {count} match(es). {html_escape(tooltip_rules)}</title>'
                f'</rect>'
                f'<text x="{x + CELL_W/2}" y="{y + CELL_H/2 - 4}" '
                f'fill="{text_color}" font-size="9" text-anchor="middle">'
                f'{html_escape(tactic[:11])}</text>'
                f'<text x="{x + CELL_W/2}" y="{y + CELL_H/2 + 14}" '
                f'fill="{text_color}" font-size="20" font-weight="bold" text-anchor="middle">'
                f'{count}</text>'
                f'</g>'
            )

        body = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {VIZ_W} {VIZ_H}" '
            f'preserveAspectRatio="xMidYMid meet">{"".join(cells)}</svg>'
        )
        viz_meta["generated"].append("03-capa-mitre")

    out_path = os.path.join(VIZ_DIR, "03-capa-mitre.html")
    with open(out_path, "w") as f:
        f.write(svg_chrome_html(
            body,
            title="capa-MITRE ATT&CK Heatmap",
            subtitle="Tactics ordered along the kill-chain; cell intensity = capa rule match count.",
        ))


# ============================================================================
# Visualization 4: IOC distribution bar chart
# ============================================================================
def viz_iocs():
    """Bar chart of IOC counts by category.

    v3.0.8 (audit-12 A3) - schema-correct read.
    Pre-v3.0.8 read SUMMARY["iocs"]["urls"] / domains / ipv4 / ... directly.
    ACTUAL summary schema (see 85-summary.sh line 1384-1387):
      SUMMARY["iocs"] = {"totals": {"urls": N, "ipv4": N, ...}, "total": M}
    Per-category counts are nested under 'totals'. Pre-v3.0.8 reads against
    the top-level returned 0 for every category, and total summed to 0,
    so the viz fell into "No IOCs extracted" placeholder.
    """
    ioc = SUMMARY.get("iocs", {}) or {}
    # The actual per-category counts are nested under "totals"
    ioc_totals = ioc.get("totals") or {}
    # Fall back to direct ioc dict for very old summaries (pre-v3.0.8 schema)
    src = ioc_totals if ioc_totals else ioc
    categories = [
        ("URLs",            int(src.get("urls", 0) or 0)),
        ("Domains",         int(src.get("domains", 0) or 0)),
        ("IP addresses",    int(src.get("ipv4", 0) or 0) + int(src.get("ipv6", 0) or 0)),
        ("Email addresses", int(src.get("emails", 0) or 0)),
        ("File paths",      int(src.get("paths", 0) or 0) + int(src.get("filepaths", 0) or 0)),
        ("Registry keys",   int(src.get("registry_keys", 0) or 0) + int(src.get("registry", 0) or 0)),
        ("Bitcoin addrs",   int(src.get("bitcoin", 0) or 0)),
        ("MAC addresses",   int(src.get("mac_addresses", 0) or 0) + int(src.get("macs", 0) or 0)),
    ]
    total = sum(c[1] for c in categories)

    if total == 0:
        body = (
            '<p style="color:var(--text-secondary);text-align:center;padding:40px">'
            'No IOCs extracted.</p>'
        )
        viz_meta["skipped"].append("04-iocs (no IOCs)")
    else:
        VIZ_W = 1100
        BAR_H = 40; BAR_GAP = 12
        max_v = max(c[1] for c in categories) or 1
        VIZ_H = len(categories) * (BAR_H + BAR_GAP) + 40

        rows = []
        rows.append(
            '<text x="10" y="20" fill="#e5e7eb" font-size="14" font-weight="bold">'
            f'IOC distribution ({total} total)</text>'
        )
        # Suspicious categories get red; others get accent blue
        suspicious_cats = {"URLs", "Domains", "IP addresses", "Bitcoin addrs"}
        for i, (cat, v) in enumerate(categories):
            y = 40 + i * (BAR_H + BAR_GAP)
            bar_w = int((v / max_v) * (VIZ_W - 320)) if v > 0 else 0
            color = "#f87171" if cat in suspicious_cats and v > 0 else "#60a5fa"
            if v == 0: color = "#374151"
            rows.append(
                f'<text x="10" y="{y + 25}" fill="#e5e7eb" font-size="13">'
                f'{html_escape(cat)}</text>'
                f'<rect x="180" y="{y}" width="{max(bar_w, 1)}" height="{BAR_H}" '
                f'fill="{color}" rx="2"/>'
                f'<text x="{180 + max(bar_w, 1) + 8}" y="{y + 25}" '
                f'fill="#9ca3af" font-size="13">{v}</text>'
            )

        body = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {VIZ_W} {VIZ_H}" '
            f'preserveAspectRatio="xMidYMid meet">{"".join(rows)}</svg>'
        )
        viz_meta["generated"].append("04-iocs")

    out_path = os.path.join(VIZ_DIR, "04-iocs.html")
    with open(out_path, "w") as f:
        f.write(svg_chrome_html(
            body,
            title="IOC Distribution",
            subtitle="Indicators of Compromise extracted by stage_iocs (80-iocs.sh); red bars highlight network-pivotable IOCs.",
        ))


# ============================================================================
# Visualization 5: Severity contribution stacked bar
# ============================================================================
def viz_severity():
    """Show how the final severity decomposes across signal sources.

    v3.0.8 (audit-12 A4) - schema-correct read.
    Pre-v3.0.8 read verdict.severity_reasons. ACTUAL summary schema
    (see 85-summary.sh line 1423-1430):
      SUMMARY["verdict"] = {line, severity, reasons, is_packed, is_signed,
                            has_suspicious_imports}
    The field is "reasons" not "severity_reasons". Pre-v3.0.8 reads against
    .severity_reasons returned empty list so the viz showed an empty
    decomposition. Severity stripe at top still rendered (hardcoded).
    """
    verdict = SUMMARY.get("verdict", {}) or {}
    severity = verdict.get("severity") or "low"
    # Actual key is "reasons", not "severity_reasons"
    reasons = verdict.get("reasons") or verdict.get("severity_reasons") or []

    # Categorize each reason (keyword match against reason text)
    categories = {
        "Capabilities (capa)": [],
        "Signatures (yara/signsrch)": [],
        "Vulnerabilities (cwe_checker)": [],
        "Crypto / Auth": [],
        "IOCs / Network": [],
        "Mobile (manifest/apksig)": [],
        "Other": [],
    }
    for r in reasons:
        rl = str(r).lower()
        if any(k in rl for k in ["capa", "capability", "rule"]):
            categories["Capabilities (capa)"].append(r)
        elif any(k in rl for k in ["yara", "signsrch"]):
            categories["Signatures (yara/signsrch)"].append(r)
        elif any(k in rl for k in ["cwe", "vulner", "buffer"]):
            categories["Vulnerabilities (cwe_checker)"].append(r)
        elif any(k in rl for k in ["crypto", "key", "authenticode", "cert", "signing"]):
            categories["Crypto / Auth"].append(r)
        elif any(k in rl for k in ["url", "domain", "ip", "ioc", "network"]):
            categories["IOCs / Network"].append(r)
        elif any(k in rl for k in ["permission", "exported", "janus", "apk"]):
            categories["Mobile (manifest/apksig)"].append(r)
        else:
            categories["Other"].append(r)

    total_reasons = sum(len(v) for v in categories.values())

    VIZ_W = 1100
    VIZ_H = 380

    if total_reasons == 0:
        body = (
            '<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {VIZ_W} 200">'
            '<text x="' + str(VIZ_W//2) + '" y="100" fill="#9ca3af" font-size="16" '
            'text-anchor="middle">'
            f'Severity: {html_escape(severity)} (no contributing reasons recorded).</text>'
            '</svg>'
        )
        viz_meta["generated"].append("05-severity (empty)")
    else:
        sev_color = color_severity(severity)
        # Build a stacked horizontal bar showing contribution share per category
        BAR_X = 50; BAR_Y = 80; BAR_W = VIZ_W - 100; BAR_H = 80
        cat_palette = {
            "Capabilities (capa)":          "#60a5fa",
            "Signatures (yara/signsrch)":   "#a78bfa",
            "Vulnerabilities (cwe_checker)":"#f87171",
            "Crypto / Auth":                "#facc15",
            "IOCs / Network":               "#fb923c",
            "Mobile (manifest/apksig)":     "#34d399",
            "Other":                        "#6b7280",
        }
        rects = []
        legend_items = []
        cur_x = BAR_X
        for cat, items in categories.items():
            if not items: continue
            share = len(items) / total_reasons
            seg_w = share * BAR_W
            color = cat_palette.get(cat, "#6b7280")
            rects.append(
                f'<rect class="tooltip-trigger" x="{cur_x:.1f}" y="{BAR_Y}" '
                f'width="{seg_w:.1f}" height="{BAR_H}" fill="{color}">'
                f'<title>{html_escape(cat)}: {len(items)} reason(s). '
                f'{html_escape("; ".join(str(i) for i in items[:3]))}</title>'
                f'</rect>'
            )
            if seg_w > 50:
                rects.append(
                    f'<text x="{cur_x + seg_w/2:.1f}" y="{BAR_Y + BAR_H/2 + 5}" '
                    f'fill="#0a0e1a" font-size="14" font-weight="bold" '
                    f'text-anchor="middle">{len(items)}</text>'
                )
            cur_x += seg_w
            legend_items.append((cat, color, len(items)))

        # Legend
        leg_x = BAR_X
        leg_y = BAR_Y + BAR_H + 30
        legend_svg = []
        for cat, color, count in legend_items:
            legend_svg.append(
                f'<rect x="{leg_x}" y="{leg_y}" width="14" height="14" '
                f'fill="{color}" rx="2"/>'
                f'<text x="{leg_x + 22}" y="{leg_y + 12}" fill="#e5e7eb" '
                f'font-size="13">{html_escape(cat)} ({count})</text>'
            )
            leg_y += 22

        # Final severity badge
        sev_badge = (
            f'<rect x="{BAR_X}" y="20" width="200" height="40" rx="6" '
            f'fill="{sev_color}"/>'
            f'<text x="{BAR_X + 100}" y="46" fill="#0a0e1a" '
            f'font-size="20" font-weight="bold" text-anchor="middle">'
            f'severity: {html_escape(severity).upper()}</text>'
        )
        title_text = (
            f'<text x="{BAR_X + 220}" y="46" fill="#e5e7eb" font-size="14">'
            f'composed from {total_reasons} contributing reason(s) across '
            f'{len(legend_items)} categories</text>'
        )

        body = (
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {VIZ_W} {VIZ_H}" preserveAspectRatio="xMidYMid meet">'
            f'{sev_badge}{title_text}'
            f'{"".join(rects)}'
            f'{"".join(legend_svg)}'
            f'</svg>'
        )
        viz_meta["generated"].append("05-severity")

    out_path = os.path.join(VIZ_DIR, "05-severity.html")
    with open(out_path, "w") as f:
        f.write(svg_chrome_html(
            body,
            title="Severity Contribution",
            subtitle="Stacked decomposition of severity reasons by signal source.",
        ))


# ============================================================================
# Visualization 6: Dynamic analysis behavioral histogram (v3.0.0)
# ============================================================================
def viz_dynamic():
    """Bar chart of dynamic-analysis behavioral counts when dynamic ran."""
    dyn = SUMMARY.get("dynamic", {}) or {}
    if not dyn.get("ran"):
        # No dynamic data; emit a placeholder explaining
        body = (
            '<p style="color:var(--text-secondary);text-align:center;padding:40px">'
            'No dynamic analysis data. Re-run with <code>--dynamic</code> to '
            'populate this visualization.</p>'
        )
        viz_meta["skipped"].append("06-dynamic (no dynamic data)")
    else:
        # Behavioral count buckets
        buckets = [
            ("Syscalls",         int(dyn.get("syscall_count_total") or 0),         "#60a5fa"),
            ("API calls",        int(dyn.get("api_call_count_total") or 0),        "#a78bfa"),
            ("File writes",      int(dyn.get("file_write_count_total") or 0),      "#facc15"),
            ("Registry writes",  int(dyn.get("registry_write_count_total") or 0),  "#fb923c"),
            ("Network attempts", int(dyn.get("network_attempt_count_total") or 0), "#f87171"),
            ("Spawned procs",    int(dyn.get("spawned_process_count_total") or 0), "#f87171"),
        ]
        max_v = max((b[1] for b in buckets), default=0) or 1
        VIZ_W = 1100
        BAR_H = 38; BAR_GAP = 12
        VIZ_H = len(buckets) * (BAR_H + BAR_GAP) + 60

        tools_used = dyn.get("tools_used") or []
        cross_tier = dyn.get("cross_tier", {}) or {}

        rows = []
        rows.append(
            '<text x="10" y="20" fill="#e5e7eb" font-size="14" font-weight="bold">'
            f'Dynamic behavior across tier(s): {html_escape(", ".join(tools_used))} '
            f'(real_execution={html_escape(str(dyn.get("real_execution", False)))}, '
            f'duration={dyn.get("duration_total_sec", 0):.1f}s)</text>'
        )
        for i, (label, value, color) in enumerate(buckets):
            y = 50 + i * (BAR_H + BAR_GAP)
            bar_w = int((value / max_v) * (VIZ_W - 320)) if value > 0 else 1
            rows.append(
                f'<text x="10" y="{y + 24}" fill="#e5e7eb" font-size="13">'
                f'{html_escape(label)}</text>'
                f'<rect x="180" y="{y}" width="{bar_w}" height="{BAR_H}" '
                f'fill="{color if value > 0 else "#374151"}" rx="2"/>'
                f'<text x="{180 + bar_w + 8}" y="{y + 24}" fill="#9ca3af" '
                f'font-size="13">{value}</text>'
            )

        # Indicator badges
        badge_y = VIZ_H - 4
        badges = []
        if cross_tier.get("any_persistence"):
            badges.append(("PERSISTENCE", "#f87171"))
        if cross_tier.get("any_network"):
            badges.append(("NETWORK", "#facc15"))
        common = cross_tier.get("common_network_hosts") or []
        if common:
            badges.append((f"CROSS-TIER C2 ({len(common)})", "#f87171"))
        if not badges:
            badges.append(("CLEAN BEHAVIOR", "#4ade80"))

        bx = 10
        for badge, color in badges:
            text_w = len(badge) * 8 + 16
            rows.append(
                f'<rect x="{bx}" y="{badge_y - 24}" width="{text_w}" height="24" '
                f'rx="4" fill="{color}"/>'
                f'<text x="{bx + text_w/2}" y="{badge_y - 8}" fill="#0a0e1a" '
                f'font-size="11" font-weight="bold" text-anchor="middle">{html_escape(badge)}</text>'
            )
            bx += text_w + 8

        body = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {VIZ_W} {VIZ_H + 8}" '
            f'preserveAspectRatio="xMidYMid meet">{"".join(rows)}</svg>'
        )
        viz_meta["generated"].append("06-dynamic")

    out_path = os.path.join(VIZ_DIR, "06-dynamic.html")
    with open(out_path, "w") as f:
        f.write(svg_chrome_html(
            body,
            title="Dynamic Analysis Behavior",
            subtitle="Behavioral counts across dynamic tier(s); badges indicate cross-tier indicators.",
        ))


# v3.0.6 (audit-10 D1+D2) - Graphs viz: embed pre-rendered call graph + CFG.
#
# Stages 40-r2 and 86-angr now produce .svg files (rendered from .dot via
# graphviz, gated on graphviz being installed and graph size being under
# the 5000-edge cap). This function reads those pre-rendered SVGs and
# wraps them in the standard svg_chrome_html template so they appear as
# tabs in the per-binary report alongside the other visualizations.
#
# Graceful degradation: if neither file exists (graphviz not installed,
# or stages were skipped, or graphs too large), the tab still renders
# but shows a placeholder message indicating which graphs are missing
# and why.
def _parse_ghidra_dump():
    """Parse 30-ghidra/dump.txt into {function_inventory, call_graph, xrefs}.

    v3.3.0 (audit-24 A5.4). State machine over the dump's section markers
    ("  SECTION 11 - Function Inventory", etc). Robust to absent sections;
    returns empty lists that the panels render as graceful placeholders.
    Also writes 30-ghidra/dump-parsed.json for other consumers.
    """
    parsed = {"function_inventory": [], "call_graph": [], "xrefs": [],
              "decompilation": []}
    # v3.5.0 (audit-26): resolve the real Ghidra dump filename. The 30-ghidra
    # stage writes "<fname>.ghidra-dump.txt" (see 30-ghidra.sh), NOT a fixed
    # "dump.txt". The v3.3.0 parser hard-coded "dump.txt", which does not exist
    # on real runs -- so the viz panels always hit the "no data" path. Resolve
    # via glob (exactly one dump per binary dir); keep the legacy fixed name as
    # a fallback for synthetic callers.
    import glob as _glob
    gd = os.path.join(OUTDIR, "30-ghidra")
    dump_path = None
    hits = sorted(_glob.glob(os.path.join(gd, "*.ghidra-dump.txt")))
    if hits:
        dump_path = hits[0]
    else:
        legacy = os.path.join(gd, "dump.txt")
        if os.path.exists(legacy):
            dump_path = legacy
    if not dump_path or not os.path.exists(dump_path):
        return parsed
    try:
        with open(dump_path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except Exception:
        return parsed

    sec_re = re.compile(r'^\s*SECTION\s+(\d+)\s+-\s+(.*)$')
    current = None
    # v3.7.2 (audit-30 A1): GhidraDump.py's fmt_addr() emits BARE hex
    # ("00402051"), not "0x"-prefixed. The pre-v3.7.2 parsers required a "0x"
    # prefix everywhere, so on real dumps the decompilation header, function
    # inventory, call graph, and xref rows never matched -- dump-parsed.json
    # came out empty and every downstream consumer (viz panels, the report
    # decompilation panel, and the v3.7.0 summary features) showed "no data".
    # Accept an OPTIONAL "0x" prefix throughout. _ADDR is the reusable address
    # fragment; _addr_ok() gates inventory/xref rows (>=4 hex digits so plain
    # words never match).
    _ADDR = r'(?:0x)?[0-9a-fA-F]+'
    _addr_ok = re.compile(r'^(?:0x)?[0-9a-fA-F]{4,}$').match
    # v3.5.0 (audit-26 A4.4): Section 13 decompilation accumulation state.
    # Header:  "### funcname  @ ADDR  (N bytes)" (ADDR bare or 0x-prefixed)
    # Body:    4-space-indented C lines, or "    // decompile failed: ..." /
    #          "    // skipped: body N bytes ..." status markers.
    decomp_hdr = re.compile(r'^###\s+(\S.*?)\s+@\s+(' + _ADDR + r')\s+\((\d+)\s+bytes\)\s*$')
    cur_decomp = None  # the in-progress {name, addr, bytes, code_lines[], status}

    def _flush_decomp():
        if cur_decomp is not None:
            code = "\n".join(cur_decomp["code_lines"]).rstrip()
            status = cur_decomp["status"]
            if status == "ok" and not code.strip():
                status = "empty"
            parsed["decompilation"].append({
                "name": cur_decomp["name"],
                "addr": cur_decomp["addr"],
                "bytes": cur_decomp["bytes"],
                "code": code,
                "status": status,
            })

    for ln in lines:
        m = sec_re.match(ln)
        if m:
            # Leaving Section 13: flush any in-progress function.
            if current == 13:
                _flush_decomp()
                cur_decomp = None
            current = int(m.group(1))
            continue

        if current == 11:
            s = ln.rstrip()
            if not s or s.startswith("Name") or set(s) <= set("- ") or s.startswith("Total functions"):
                continue
            parts = ln.split()
            if len(parts) < 3:
                continue
            name = parts[0]
            entry = parts[1] if len(parts) > 1 else ""
            try:
                size = int(parts[2])
            except (ValueError, IndexError):
                size = 0
            if _addr_ok(entry):
                parsed["function_inventory"].append(
                    {"name": name, "addr": entry, "size": size}
                )

        elif current == 13:
            # Decompilation section.
            hm = decomp_hdr.match(ln)
            if hm:
                # New function: flush the previous, start this one.
                _flush_decomp()
                cur_decomp = {
                    "name": hm.group(1),
                    "addr": hm.group(2),
                    "bytes": int(hm.group(3)),
                    "code_lines": [],
                    "status": "ok",
                }
                continue
            if cur_decomp is None:
                continue
            # Body line: strip the leading 4-space indent Ghidra adds.
            body = ln[4:] if ln.startswith("    ") else ln
            stripped = body.strip()
            if stripped.startswith("// decompile failed") or stripped.startswith("// decompile exception"):
                cur_decomp["status"] = "failed"
                continue
            if stripped.startswith("// skipped:"):
                cur_decomp["status"] = "skipped"
                continue
            # Ignore the section's trailing summary line.
            if stripped.startswith("--- Decompilation complete"):
                continue
            cur_decomp["code_lines"].append(body)

        elif current == 14:
            s = ln.rstrip()
            if not s:
                continue
            mcaller = re.match(r'^(\S.*?)\s+\((' + _ADDR + r')\)\s+calls:\s*$', s)
            if mcaller:
                parsed["call_graph"].append({"caller": mcaller.group(1), "callees": []})
                continue
            mcallee = re.match(r'^\s+->\s+(\S.*?)\s+\((' + _ADDR + r')\)\s*$', s)
            if mcallee and parsed["call_graph"]:
                parsed["call_graph"][-1]["callees"].append(mcallee.group(1))

        elif current == 15:
            s = ln.rstrip()
            if not s or s.startswith("Target") or set(s) <= set("- "):
                continue
            parts = s.split()
            if len(parts) < 2:
                continue
            target = parts[0]
            if not _addr_ok(target):
                continue
            try:
                cnt = int(parts[1])
            except (ValueError, IndexError):
                continue
            parsed["xrefs"].append({"target": target, "ref_count": cnt})

    # Flush a trailing in-progress decompiled function (dump ended in S13).
    if current == 13:
        _flush_decomp()

    try:
        with open(os.path.join(OUTDIR, "30-ghidra", "dump-parsed.json"), "w",
                  encoding="utf-8") as jf:
            json.dump(parsed, jf, indent=2)
    except Exception:
        pass
    return parsed


def viz_call_graph():
    """08 - Directed call graph SVG from Ghidra Section 14."""
    data = _parse_ghidra_dump()
    cg = data.get("call_graph", [])
    if not cg:
        with open(os.path.join(VIZ_DIR, "08-call-graph.html"), "w") as f:
            f.write(svg_chrome_html(
                "<p><em>No call-graph data. Ghidra Section 14 was empty or "
                "the binary has no decompilable functions "
                "(dex/apk/jar skip Ghidra).</em></p>",
                title="Call Graph"))
        viz_meta["skipped"].append("08-call-graph")
        return

    MAX_NODES = 50
    cg_sorted = sorted(cg, key=lambda e: len(e.get("callees", [])), reverse=True)
    truncated = len(cg_sorted) > MAX_NODES
    cg_use = cg_sorted[:MAX_NODES]

    caller_names = {e["caller"] for e in cg_use}
    nodes_set = set(caller_names)
    edges = []
    for e in cg_use:
        for callee in e.get("callees", []):
            if callee in caller_names:
                edges.append((e["caller"], callee))
                nodes_set.add(callee)
    nodes = sorted(nodes_set)
    if not nodes:
        nodes = sorted(caller_names)

    outdeg = {n: 0 for n in nodes}
    for e in cg_use:
        if e["caller"] in outdeg:
            outdeg[e["caller"]] = len(e.get("callees", []))

    W, H = 900, 640
    node_idx = {n: i for i, n in enumerate(nodes)}
    edge_idx = [(node_idx[a], node_idx[b]) for a, b in edges if a in node_idx and b in node_idx]
    positions = force_directed_layout(list(range(len(nodes))), edge_idx, W, H)

    svg_parts = []
    for a, b in edge_idx:
        x1, y1 = positions[a]; x2, y2 = positions[b]
        svg_parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="#4a5568" stroke-width="1" opacity="0.5"/>'
        )
    for n in nodes:
        i = node_idx[n]
        x, y = positions[i]
        deg = outdeg.get(n, 0)
        if deg > 5:
            color = "#e67e22"
        elif deg > 0:
            color = "#5dade2"
        else:
            color = "#718096"
        r = 5 + min(deg, 10)
        label = n if len(n) <= 18 else n[:16] + ".."
        svg_parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{color}" '
            f'stroke="#1a1a1a" stroke-width="1"><title>{html_escape(n)} '
            f'({deg} callees)</title></circle>'
            f'<text x="{x:.1f}" y="{y - r - 3:.1f}" font-size="9" '
            f'fill="#b8b8b8" text-anchor="middle">{html_escape(label)}</text>'
        )

    legend = (
        '<text x="12" y="20" font-size="12" fill="#e67e22">&#9679; hub (&gt;5 callees)</text>'
        '<text x="150" y="20" font-size="12" fill="#5dade2">&#9679; caller</text>'
        '<text x="240" y="20" font-size="12" fill="#718096">&#9679; leaf</text>'
    )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
        f'preserveAspectRatio="xMidYMid meet">{legend}{"".join(svg_parts)}</svg>'
    )
    sub = f"Top {len(cg_use)} of {len(cg)} callers by out-degree." if truncated else \
          f"{len(cg)} callers with outgoing calls."
    with open(os.path.join(VIZ_DIR, "08-call-graph.html"), "w") as f:
        f.write(svg_chrome_html(svg, title="Call Graph", subtitle=sub))
    viz_meta["generated"].append("08-call-graph")


def viz_xrefs():
    """09 - Cross-reference heatmap (horizontal bars) from Ghidra Section 15."""
    data = _parse_ghidra_dump()
    xrefs = data.get("xrefs", [])
    if not xrefs:
        with open(os.path.join(VIZ_DIR, "09-xrefs.html"), "w") as f:
            f.write(svg_chrome_html(
                "<p><em>No cross-reference data. Ghidra Section 15 was empty "
                "or the binary has no decompilable code.</em></p>",
                title="Cross-References"))
        viz_meta["skipped"].append("09-xrefs")
        return

    TOP = 30
    xr = sorted(xrefs, key=lambda x: x.get("ref_count", 0), reverse=True)[:TOP]
    max_cnt = max((x["ref_count"] for x in xr), default=1) or 1

    W = 900
    row_h = 20
    H = row_h * len(xr) + 40
    bar_x = 130
    bar_max = W - bar_x - 60
    rows = []
    for i, x in enumerate(xr):
        y = 30 + i * row_h
        cnt = x["ref_count"]
        bw = int((cnt / max_cnt) * bar_max)
        rows.append(
            f'<text x="{bar_x - 6}" y="{y + 11}" font-size="10" '
            f'fill="#b8b8b8" text-anchor="end" font-family="Consolas,monospace">'
            f'{html_escape(x["target"])}</text>'
            f'<rect x="{bar_x}" y="{y + 2}" width="{bw}" height="{row_h - 6}" '
            f'fill="#5dade2" rx="2"><title>{html_escape(x["target"])}: {cnt} refs</title></rect>'
            f'<text x="{bar_x + bw + 6}" y="{y + 11}" font-size="10" '
            f'fill="#e8e8e8">{cnt}</text>'
        )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
        f'preserveAspectRatio="xMidYMid meet">{"".join(rows)}</svg>'
    )
    sub = f"Top {len(xr)} of {len(xrefs)} most-referenced targets (by inbound reference count)."
    with open(os.path.join(VIZ_DIR, "09-xrefs.html"), "w") as f:
        f.write(svg_chrome_html(svg, title="Cross-References", subtitle=sub))
    viz_meta["generated"].append("09-xrefs")


def viz_function_complexity():
    """10 - Function complexity bar chart from Ghidra Section 11."""
    data = _parse_ghidra_dump()
    fns = data.get("function_inventory", [])
    if not fns:
        with open(os.path.join(VIZ_DIR, "10-function-complexity.html"), "w") as f:
            f.write(svg_chrome_html(
                "<p><em>No function-inventory data. Ghidra Section 11 was "
                "empty or the binary has no decompilable functions.</em></p>",
                title="Function Complexity"))
        viz_meta["skipped"].append("10-function-complexity")
        return

    TOP = 40
    fl = sorted(fns, key=lambda f: f.get("size", 0), reverse=True)[:TOP]
    max_sz = max((f.get("size", 0) for f in fl), default=1) or 1

    W = 900
    row_h = 18
    H = row_h * len(fl) + 40
    bar_x = 180
    bar_max = W - bar_x - 70
    rows = []
    for i, fn in enumerate(fl):
        y = 30 + i * row_h
        sz = fn.get("size", 0)
        bw = int((sz / max_sz) * bar_max)
        color = "#e67e22" if sz >= max_sz * 0.75 else "#5dade2"
        name = fn["name"] if len(fn["name"]) <= 26 else fn["name"][:24] + ".."
        rows.append(
            f'<text x="{bar_x - 6}" y="{y + 11}" font-size="10" '
            f'fill="#b8b8b8" text-anchor="end" font-family="Consolas,monospace">'
            f'{html_escape(name)}</text>'
            f'<rect x="{bar_x}" y="{y + 2}" width="{bw}" height="{row_h - 6}" '
            f'fill="{color}" rx="2"><title>{html_escape(fn["name"])}: {sz} bytes '
            f'@ {html_escape(fn.get("addr",""))}</title></rect>'
            f'<text x="{bar_x + bw + 6}" y="{y + 11}" font-size="10" '
            f'fill="#e8e8e8">{sz}</text>'
        )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
        f'preserveAspectRatio="xMidYMid meet">{"".join(rows)}</svg>'
    )
    sub = (f"Top {len(fl)} of {len(fns)} functions by size (byte count). "
           f"Orange = largest quartile (candidate analysis targets).")
    with open(os.path.join(VIZ_DIR, "10-function-complexity.html"), "w") as f:
        f.write(svg_chrome_html(svg, title="Function Complexity", subtitle=sub))
    viz_meta["generated"].append("10-function-complexity")


def viz_graphs():
    cg_path = os.path.join(OUTDIR, "40-r2", "global-call-graph.svg")
    cfg_path = os.path.join(OUTDIR, "86-angr", "cfg.svg")

    has_cg = os.path.exists(cg_path) and os.path.getsize(cg_path) > 0
    has_cfg = os.path.exists(cfg_path) and os.path.getsize(cfg_path) > 0

    if not (has_cg or has_cfg):
        # Neither graph rendered. Diagnose why and emit placeholder.
        reasons = []
        # Stage 40 dot was emitted?
        if os.path.exists(os.path.join(OUTDIR, "40-r2", "global-call-graph.dot")):
            reasons.append("r2 .dot present but .svg missing (graphviz not installed?)")
        else:
            reasons.append("r2 stage skipped or did not produce .dot")
        # Stage 86 dot was emitted?
        if os.path.exists(os.path.join(OUTDIR, "86-angr", "cfg.dot")):
            reasons.append("angr .dot present but .svg missing (graphviz not installed?)")
        elif os.path.exists(os.path.join(OUTDIR, "86-angr", "cfg.dot.too-large")):
            reasons.append("angr CFG too large to render (>5000 edges)")
        else:
            reasons.append("angr stage skipped (use --enable-angr) or did not produce CFG")

        body = (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 280" '
            'width="800" height="280">'
            '<rect width="800" height="280" fill="#1a1a1a"/>'
            '<text x="400" y="60" font-family="Garamond,serif" font-size="22" '
            'fill="#e6e6e6" text-anchor="middle">No graphs available</text>'
            '<text x="400" y="100" font-family="Garamond,serif" font-size="14" '
            'fill="#a8a8a8" text-anchor="middle">'
            'Call graph and CFG are produced when r2 and/or angr stages run with</text>'
            '<text x="400" y="120" font-family="Garamond,serif" font-size="14" '
            'fill="#a8a8a8" text-anchor="middle">'
            'graphviz installed. Reasons:</text>'
        )
        for i, reason in enumerate(reasons):
            body += (
                f'<text x="400" y="{160 + i*22}" font-family="Garamond,serif" '
                f'font-size="13" fill="#888" text-anchor="middle">'
                f'- {html_escape(reason)}</text>'
            )
        body += '</svg>'
        viz_meta["generated"].append("07-graphs (placeholder)")
    else:
        # Build a body that embeds whichever SVGs are available. Each SVG
        # gets a section header + the inline content. We strip the outer
        # XML declaration and outer SVG tag tweaks if present so the
        # graphviz output drops in cleanly.
        sections = []

        if has_cg:
            try:
                with open(cg_path, "r") as _fh:
                    cg_svg = _fh.read()
                # Strip XML declaration and DOCTYPE (graphviz emits these);
                # the outer page already has a content-type and DOCTYPE.
                cg_svg = re.sub(r'<\?xml[^>]*\?>', '', cg_svg)
                cg_svg = re.sub(r'<!DOCTYPE[^>]*>', '', cg_svg)
                sections.append(
                    '<div style="margin-bottom:32px">'
                    '<h2 style="color:var(--accent);border-bottom:1px solid var(--border-color);'
                    'padding-bottom:6px">r2 Global Call Graph</h2>'
                    '<p class="viz-meta">Static call graph from radare2 (agC). '
                    'Each node is a function; edges are direct calls. '
                    'Indirect calls require deeper analysis (see CFG below).</p>'
                    f'<div style="overflow:auto;max-width:100%">{cg_svg}</div>'
                    '</div>'
                )
                viz_meta["generated"].append("07-graphs (r2 call graph)")
            except Exception as e:
                viz_meta["errors"].append(f"07-graphs r2: {type(e).__name__}: {e}")

        if has_cfg:
            try:
                with open(cfg_path, "r") as _fh:
                    cfg_svg = _fh.read()
                cfg_svg = re.sub(r'<\?xml[^>]*\?>', '', cfg_svg)
                cfg_svg = re.sub(r'<!DOCTYPE[^>]*>', '', cfg_svg)
                sections.append(
                    '<div>'
                    '<h2 style="color:var(--accent);border-bottom:1px solid var(--border-color);'
                    'padding-bottom:6px">angr Control Flow Graph</h2>'
                    '<p class="viz-meta">Per-binary CFG built via angr CFGFast. '
                    'Each node is a basic block (block-start address); edges '
                    'are control-flow transfers including direct calls, jumps, '
                    'and resolved indirect jumps.</p>'
                    f'<div style="overflow:auto;max-width:100%">{cfg_svg}</div>'
                    '</div>'
                )
                viz_meta["generated"].append("07-graphs (angr CFG)")
            except Exception as e:
                viz_meta["errors"].append(f"07-graphs angr: {type(e).__name__}: {e}")

        body = "".join(sections) if sections else (
            '<p class="viz-meta">Graphs were detected but could not be embedded.</p>'
        )

    out_path = os.path.join(VIZ_DIR, "07-graphs.html")
    with open(out_path, "w") as f:
        f.write(svg_chrome_html(
            body,
            title="Call Graph + CFG",
            subtitle="Pre-rendered graphs from radare2 (agC) and angr (CFGFast).",
        ))


# ---- Run all visualizations ----------------------------------------------
try: viz_sections()
except Exception as e: viz_meta["errors"].append(f"01-sections: {type(e).__name__}: {e}")
try: viz_imports()
except Exception as e: viz_meta["errors"].append(f"02-imports: {type(e).__name__}: {e}")
try: viz_capa_mitre()
except Exception as e: viz_meta["errors"].append(f"03-capa-mitre: {type(e).__name__}: {e}")
try: viz_iocs()
except Exception as e: viz_meta["errors"].append(f"04-iocs: {type(e).__name__}: {e}")
try: viz_severity()
except Exception as e: viz_meta["errors"].append(f"05-severity: {type(e).__name__}: {e}")
# v3.0.0: dynamic visualization. Conditionally generates content based on
# whether dynamic_data is present in _summary.json (else placeholder).
try: viz_dynamic()
except Exception as e: viz_meta["errors"].append(f"06-dynamic: {type(e).__name__}: {e}")
# v3.0.6 (audit-10): graphs visualization. Embeds pre-rendered SVG from
# stages 40-r2 and 86-angr; placeholder if graphviz not installed.
try: viz_graphs()
except Exception as e: viz_meta["errors"].append(f"07-graphs: {type(e).__name__}: {e}")
# v3.3.0 (audit-24 A5.4): GhidraDump-driven panels. Each parses
# 30-ghidra/dump.txt; render "no data" placeholders when Ghidra was skipped
# (dex/apk/jar) or produced no functions.
try: viz_call_graph()
except Exception as e: viz_meta["errors"].append(f"08-call-graph: {type(e).__name__}: {e}")
try: viz_xrefs()
except Exception as e: viz_meta["errors"].append(f"09-xrefs: {type(e).__name__}: {e}")
try: viz_function_complexity()
except Exception as e: viz_meta["errors"].append(f"10-function-complexity: {type(e).__name__}: {e}")


# ---- Index page linking all visualizations ----------------------------
links_html = ""
for fname, title in [
    ("01-sections.html", "Section / Segment Treemap"),
    ("02-imports.html",  "Imports / Dependencies"),
    ("03-capa-mitre.html", "capa-MITRE ATT&CK Heatmap"),
    ("04-iocs.html", "IOC Distribution"),
    ("05-severity.html", "Severity Contribution"),
    ("06-dynamic.html", "Dynamic Analysis Behavior"),
    ("07-graphs.html", "Call Graph + CFG"),
    ("08-call-graph.html", "Call Graph (Ghidra)"),
    ("09-xrefs.html", "Cross-References (Ghidra)"),
    ("10-function-complexity.html", "Function Complexity (Ghidra)"),
]:
    if os.path.exists(os.path.join(VIZ_DIR, fname)):
        links_html += (
            f'<li style="margin:8px 0"><a href="{fname}">{html_escape(title)}</a></li>'
        )

index_body = f"""
<ul style="list-style:none;padding:0">
{links_html}
</ul>
<p class="viz-meta">Each visualization is self-contained inline SVG. The Visualizations
tab in the parent HTML report embeds each of these inline.</p>
"""
with open(os.path.join(VIZ_DIR, "index.html"), "w") as f:
    f.write(svg_chrome_html(index_body, title="Visualizations"))


# ---- Write metadata for 85-summary.sh ----
with open(os.path.join(VIZ_DIR, "_viz-summary.json"), "w") as f:
    json.dump(viz_meta, f, indent=2)

print(f"viz: generated={len(viz_meta['generated'])}, "
      f"skipped={len(viz_meta['skipped'])}, "
      f"errors={len(viz_meta['errors'])}")
PYEOF
    log_step "viz: $(grep -m1 '^viz:' "${viz}/_viz.log" 2>/dev/null || echo 'completed')"
}
