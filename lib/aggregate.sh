#!/usr/bin/env bash
# =============================================================================
# lib/aggregate.sh
# =============================================================================
#
# Synopsis:
#     Codebase-level aggregation across every analyzed target.
#
# Description:
#     Per-target stages produce one _summary.json per binary. This module works
#     one level above that, synthesizing the whole run into artifacts that only
#     make sense in aggregate.
#
#     It writes the run manifest and the codebase index page, which together
#     answer what was analyzed, with which toolchain, and how each target
#     scored. It computes cross-target similarity from the fuzzy hashes each
#     target contributed, and renders the resulting clusters as a graph, which
#     is how related samples in a batch become visible. It also emits
#     threat-intelligence exports in portable formats so findings can leave
#     RE-Toolkit for a platform that consumes indicators.
#
#     All rendered output is self-contained: inline SVG and inline styling,
#     with no external CDN reference and no network fetch at view time.
#
#     Sourced by analyze-binaries.sh; not directly executable.
#
# Provides:
#     write_run_json_and_index    Run manifest (_run.json) plus index.html.
#     write_summary               Roll up per-target results for the run.
#     write_similarity_matrix     Pairwise similarity from fuzzy hashes.
#     write_cluster_graph         Render similarity clusters as a graph.
#     write_threat_intel_export   Export indicators in portable formats.
#     write_composite_intel       Combined cross-target intelligence view.
#
# Notes:
#     Output locations and schemas are documented in the wiki
#     (Output-and-Reports). Release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

write_run_json_and_index() {
    [[ -z "$VENV_PY" ]] && return 0
    "$VENV_PY" - "$OUTPUT_ROOT" "$TOTAL_ELAPSED" "$START_TS" <<'PYEOF' || true
"""Aggregate _run.json manifest + top-level index.html for RE-Toolkit v2.3.0.

Reads every per-binary _summary.json and builds:
  _run.json   -- machine-readable run manifest
  index.html  - codebase-wide landing page with per-binary verdict table

CSS/design matches the per-binary reports (and the reference report).
"""
import os, sys, json, html
from datetime import datetime, timezone

OUTPUT_ROOT = sys.argv[1]
total_elapsed = int(sys.argv[2])
start_ts = int(sys.argv[3])

def esc(x):
    return html.escape(str(x), quote=True)

def fmt_bytes(n):
    if not n: return "0 B"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}" if u != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TB"

# Gather per-binary summaries
binaries = []
for entry in sorted(os.listdir(OUTPUT_ROOT)):
    bdir = os.path.join(OUTPUT_ROOT, entry)
    if not os.path.isdir(bdir):
        continue
    sjson = os.path.join(bdir, "_summary.json")
    if not os.path.isfile(sjson):
        continue
    try:
        with open(sjson, encoding="utf-8") as f:
            S = json.load(f)
        binaries.append((entry, S))
    except Exception:
        continue

# Build codebase-at-a-glance
corpus = {
    "total_binaries": len(binaries),
    "total_size_bytes": 0,
    "signed_count": 0,
    "packed_count": 0,
    "total_iocs": 0,
    "total_capa_rules": 0,
    "total_yara_hits": 0,
    "total_attack": 0,
    "total_mbc": 0,
    "severity_counts": {"crit": 0, "high": 0, "med": 0, "low": 0, "info": 0},
}
unique_attack = set()
unique_mbc = set()

for _, S in binaries:
    corpus["total_size_bytes"] += S["file"]["size"] or 0
    if S["verdict"]["is_signed"]:
        corpus["signed_count"] += 1
    if S["verdict"]["is_packed"]:
        corpus["packed_count"] += 1
    corpus["total_iocs"] += S["iocs"]["total"]
    corpus["total_capa_rules"] += S["capa"]["rule_count"]
    corpus["total_yara_hits"] += len(S["yara_hits"])
    for a in S["capa"]["attack"]:
        if a.get("id"): unique_attack.add(a["id"])
    for b in S["capa"]["mbc"]:
        if b.get("id"): unique_mbc.add(b["id"])
    sev = S["verdict"]["severity"]
    if sev in corpus["severity_counts"]:
        corpus["severity_counts"][sev] += 1

corpus["total_attack"] = len(unique_attack)
corpus["total_mbc"] = len(unique_mbc)

# --- Write _run.json ---------------------------------------------------------
run_manifest = {
    "version": "2.3.0",
    "started": datetime.fromtimestamp(start_ts, timezone.utc).isoformat(),
    "ended": datetime.now(timezone.utc).isoformat(),
    "elapsed_seconds": total_elapsed,
    "output_root": OUTPUT_ROOT,
    "codebase": corpus,  # v3.0.7 (audit-11 D): JSON key renamed corpus->codebase; internal Python variable keeps the old name for code stability
    "binaries": [
        {
            "name": name,
            "path": S["file"]["path"],
            "size": S["file"]["size"],
            "file_type": S["file"]["file_type"],
            "hashes": S["file"]["hashes"],
            "verdict": S["verdict"],
            "metrics": {
                "capa_rule_count": S["capa"]["rule_count"],
                "attack_techniques": len(S["capa"]["attack"]),
                "mbc_behaviors": len(S["capa"]["mbc"]),
                "yara_hits": len(S["yara_hits"]),
                "clamav_hits": len(S["clamav_hits"]),
                "ioc_total": S["iocs"]["total"],
                "import_libs": len(S["pe"]["imports"]),
                "exports": len(S["pe"]["exports"]),
                "ghidra_dump_bytes": S["ghidra"]["dump_size_bytes"],
                "dotnet_cs_files": S["dotnet"]["cs_file_count"],
                "entropy_overall": S["entropy"]["overall"],
                "entropy_high_sections": S["entropy"]["high_count"],
            }
        }
        for name, S in binaries
    ],
}

with open(os.path.join(OUTPUT_ROOT, "_run.json"), "w", encoding="utf-8") as f:
    json.dump(run_manifest, f, indent=2, sort_keys=False)

# --- Write index.html --------------------------------------------------------
# Same CSS as per-binary reports; factored here for consistency.
CSS = """
:root {
  --bg-primary:#1a1a1a; --bg-secondary:#242424; --bg-tertiary:#2d2d2d; --bg-hover:#363636;
  --text-primary:#e8e8e8; --text-secondary:#b8b8b8; --text-muted:#888;
  --border-color:#3a3a3a; --header-bg:#0e1a26; --header-text:#e8e8e8;
  --accent:#5dade2; --accent-2:#2ecc71; --accent-3:#e67e22;
  --crit-bg:#7d2020; --high-bg:#8a4a14; --med-bg:#8a7616;
  --low-bg:#1d5c80;  --info-bg:#4a4f50;
  --crit-border:#a52a2a; --high-border:#b85f1a; --med-border:#b89e1a;
  --low-border:#2d7da8; --info-border:#6a6f70;
  --code-bg:#1f1f1f; --link-color:#5dade2;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { width: 100%; }
body {
  font-family: Garamond, "Times New Roman", serif;
  background: var(--bg-primary); color: var(--text-primary);
  line-height: 1.65; font-size: 16px;
}
a { color: var(--link-color); text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { font-size: 26px; color: var(--accent); margin: 28px 0 12px; padding-bottom: 8px; border-bottom: 2px solid var(--border-color); }
h2 { font-size: 20px; color: var(--accent-2); margin: 20px 0 10px; padding-bottom: 4px; border-bottom: 1px solid var(--border-color); }
code { background: var(--code-bg); padding: 2px 6px; border-radius: 3px; font-family: Consolas, "Courier New", monospace; font-size: 13px; color: #d8d8d8; }

.w {
  max-width: 1280px;
  margin: 0 auto;
  padding: 24px 32px 36px 32px;
  width: 100%;
}

.doc-header {
  border-bottom: 2px solid var(--border-color);
  padding-bottom: 18px; margin-bottom: 22px;
}
.doc-title {
  font-size: 28px; font-weight: bold; color: var(--accent);
  margin-bottom: 6px; line-height: 1.3;
}
.doc-subtitle { color: var(--text-secondary); font-size: 14px; line-height: 1.5; }

.summary-banner {
  background: var(--bg-secondary); border: 1px solid var(--border-color);
  padding: 18px 22px; border-radius: 8px; margin: 0 0 24px 0;
}
.summary-banner h3 { margin: 0 0 12px 0; color: var(--accent); font-size: 16px; }
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
}
.summary-cell {
  background: var(--bg-tertiary); border: 1px solid var(--border-color);
  border-radius: 6px; padding: 14px 10px; text-align: center; overflow: hidden;
}
.summary-cell .num {
  font-size: 24px; font-weight: bold; display: block; line-height: 1.1;
  color: var(--accent); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.summary-cell .lbl {
  font-size: 11px; color: var(--text-secondary); margin-top: 6px;
  text-transform: uppercase; letter-spacing: 0.05em; display: block;
}
.summary-cell.total .num { color: var(--accent-2); }
.summary-cell.crit  .num { color: #e74c3c; }
.summary-cell.high  .num { color: #e67e22; }
.summary-cell.med   .num { color: #f1c40f; }

.c {
  background: var(--bg-secondary); border: 1px solid var(--border-color);
  border-radius: 8px; padding: 20px 22px; margin: 0 0 20px 0; overflow-x: auto;
}
table {
  width: 100%; border-collapse: collapse; margin: 10px 0 14px 0; font-size: 14px;
}
th, td {
  padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border-color);
  vertical-align: top; overflow-wrap: anywhere;
}
th {
  background: var(--header-bg); color: var(--header-text);
  font-weight: bold; font-size: 13px; white-space: nowrap;
}
tbody tr:nth-child(even) { background: var(--bg-tertiary); }
tbody tr:hover { background: var(--bg-hover); }

.pill {
  display: inline-block; padding: 2px 8px; border-radius: 3px;
  font-size: 11px; font-weight: bold; letter-spacing: 0.06em; text-transform: uppercase;
  margin: 2px 4px 2px 0;
}
.pill.crit { background: var(--crit-bg); color: #fff; }
.pill.high { background: var(--high-bg); color: #fff; }
.pill.med  { background: var(--med-bg);  color: #fff; }
.pill.low  { background: var(--low-bg);  color: #fff; }
.pill.info { background: var(--info-bg); color: #fff; }

.footer {
  margin-top: 36px; padding-top: 18px; border-top: 2px solid var(--border-color);
  text-align: center; color: var(--text-secondary); font-size: 13px;
}
"""

# Per-binary table rows
rows = []
for name, S in binaries:
    sev = S["verdict"]["severity"]
    link = f"{name}/_report.html"
    ft_short = (S["file"]["file_type"] or "").split(",")[0][:40]
    rows.append(f"""
    <tr>
      <td><a href="{esc(link)}"><strong>{esc(name)}</strong></a></td>
      <td><span class="pill {sev}">{esc(sev)}</span></td>
      <td>{fmt_bytes(S["file"]["size"])}</td>
      <td><code>{esc(ft_short)}</code></td>
      <td style="text-align:center">{'✓' if S["verdict"]["is_signed"] else '✗'}</td>
      <td style="text-align:center">{'✓' if S["verdict"]["is_packed"] else '✗'}</td>
      <td>{S["capa"]["rule_count"]}</td>
      <td>{len(S["capa"]["attack"])}</td>
      <td>{len(S["yara_hits"])}</td>
      <td>{S["iocs"]["total"]}</td>
    </tr>
    """)

# Severity summary pills
sev_pills = "".join(
    f'<span class="pill {k}">{k.upper()}: {v}</span>'
    for k, v in corpus["severity_counts"].items() if v > 0
)

banner_cells = [
    ("total", f'{corpus["total_binaries"]}', "Binaries"),
    ("", fmt_bytes(corpus["total_size_bytes"]), "Total Size"),
    ("", f'{corpus["signed_count"]}/{corpus["total_binaries"]}', "Signed"),
    ("med", f'{corpus["packed_count"]}', "Packed"),
    ("", f'{corpus["total_capa_rules"]}', "capa Rules"),
    ("high", f'{corpus["total_attack"]}', "ATT&CK Techs"),
    ("med", f'{corpus["total_mbc"]}', "MBC Behaviors"),
    ("crit", f'{corpus["total_yara_hits"]}', "YARA Hits"),
    ("", f'{corpus["total_iocs"]}', "IOCs Extracted"),
    ("", f'{total_elapsed // 60}m {total_elapsed % 60}s', "Elapsed"),
]
banner_html = "".join(
    f'<div class="summary-cell {cls}"><span class="num">{esc(n)}</span><span class="lbl">{esc(l)}</span></div>'
    for cls, n, l in banner_cells
)

now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

out_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RE Codebase Index -- {corpus['total_binaries']} binaries</title>
<style>{CSS}</style>
</head>
<body>
<div class="w">
  <div class="doc-header">
    <div class="doc-title">Reverse Engineering Codebase Index</div>
    <div class="doc-subtitle">
      {corpus['total_binaries']} binaries analyzed in {total_elapsed // 60}m {total_elapsed % 60}s
      &middot; {now}
      &middot; {sev_pills}
    </div>
  </div>

  <div class="summary-banner">
    <h3>Codebase At A Glance</h3>
    <div class="summary-grid">{banner_html}</div>
  </div>

  <div class="c">
    <h2>Per-Binary Verdicts</h2>
    <table>
      <thead>
        <tr>
          <th>Binary</th><th>Severity</th><th>Size</th><th>Type</th>
          <th>Signed</th><th>Packed</th>
          <th>capa</th><th>ATT&amp;CK</th><th>YARA</th><th>IOCs</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows) or '<tr><td colspan=10><em>No binaries processed.</em></td></tr>'}
      </tbody>
    </table>
  </div>

  <div class="c">
    <h2>Codebase Intelligence</h2>
    <p>Cross-binary correlation and threat-intel export artifacts (generated
    when 2 or more binaries are analyzed):</p>
    <ul>
      <li><a href="_composite-intel.html"><strong>Composite Intelligence</strong></a>
        -- shared IOCs, common packers, shared imports, and a campaign
        ATT&amp;CK heatmap across all binaries (A5.5).</li>
      <li><a href="_similarity-matrix.html">Similarity Matrix</a>
        -- NxN fuzzy-hash similarity (ssdeep + TLSH).</li>
      <li><a href="_cluster.html">Cluster Graph</a>
        -- force-directed clustering by similarity.</li>
      <li>Threat-intel export (A5.6):
        <a href="_export-stix.json">STIX 2.1</a>,
        <a href="_export-misp.json">MISP event</a>,
        <a href="_export-findings.json">flat findings JSON</a>
        -- feed directly into a TIP.</li>
    </ul>
  </div>

  <div class="footer">
    Generated by RE-Toolkit v2.3.0 &middot; {now}
    &middot; Machine-readable manifest: <code>_run.json</code>
    &middot; Run log: <code>_run.log</code>
  </div>
</div>
</body>
</html>
"""

with open(os.path.join(OUTPUT_ROOT, "index.html"), "w", encoding="utf-8") as f:
    f.write(out_html)
print(f"Codebase index: {os.path.join(OUTPUT_ROOT, 'index.html')}")
print(f"Run manifest: {os.path.join(OUTPUT_ROOT, '_run.json')}")
PYEOF
}

# =============================================================================
# Aggregate summary
# =============================================================================
write_summary() {
    local sf="${OUTPUT_ROOT}/_summary.md"
    {
        echo "# RE Analysis Summary"
        echo ""
        echo "Generated: $(date -Iseconds)"
        echo "Elapsed:   ${TOTAL_ELAPSED}s ($((TOTAL_ELAPSED / 60))m)"
        echo "Targets:   ${#UNIQUE_TARGETS[@]}"
        echo "Driver:    analyze-binaries.sh v2.3.0"
        echo ""
        echo "## Per-binary verdicts"
        echo ""
        echo "| Binary | Severity | Type | Signed | Packed | capa | ATT&CK | YARA | IOCs | Dump KB | .cs |"
        echo "|---|---|---|:-:|:-:|---:|---:|---:|---:|---:|---:|"
        for t in "${UNIQUE_TARGETS[@]}"; do
            local fn
            fn=$(basename "$t")
            local dir="${OUTPUT_ROOT}/${fn}"
            local sjson="${dir}/_summary.json"

            if [[ -f "$sjson" && -n "$VENV_PY" ]]; then
                # v2.2.0: source of truth is _summary.json. Emit one markdown
                # row per binary by reading the structured data.
                "$VENV_PY" - "$sjson" "$fn" <<'PYEOF' 2>/dev/null || echo "| $fn | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |"
import json, sys, os
sp, fn = sys.argv[1], sys.argv[2]
with open(sp, encoding="utf-8") as f: S = json.load(f)
sev = S["verdict"]["severity"]
typ = (S["file"]["file_type"] or "").split(",")[0][:40]
signed = "✓" if S["verdict"]["is_signed"] else "✗"
packed = "✓" if S["verdict"]["is_packed"] else "✗"
capa_n = S["capa"]["rule_count"]
att_n  = len(S["capa"]["attack"])
yara_n = len(S["yara_hits"])
ioc_n  = S["iocs"]["total"]
dump_kb = S["ghidra"]["dump_size_bytes"] // 1024 if S["ghidra"]["dump_size_bytes"] else 0
cs_n   = S["dotnet"]["cs_file_count"] or "-"
print(f"| {fn} | {sev} | {typ} | {signed} | {packed} | {capa_n} | {att_n} | {yara_n} | {ioc_n} | {dump_kb or '-'} | {cs_n} |")
PYEOF
            else
                # Fallback for binaries where summary generation failed
                local status
                if [[ -f "${dir}/00-triage/hashes.txt" ]]; then status="(partial)"; else status="(failed)"; fi
                echo "| $fn | ? | $status | ? | ? | ? | ? | ? | ? | ? | ? |"
            fi
        done
        echo ""
        echo "## Output directory layout"
        echo ""
        echo "Each per-binary directory contains numbered subdirs:"
        echo "- \`00-triage/\` -- universal (file, hashes, strings, yara, capa, binwalk, clamav)"
        echo "- \`10-pe/\` -- PE structure (pefile, readpe, floss)"
        echo "- \`20-dotnet/\` -- .NET (ilspy/*.cs, monodis.il, dnfile-metadata.txt)"
        echo "- \`30-ghidra/\` -- Ghidra comprehensive 20-section dump"
        echo "- \`40-alternative/\` -- radare2, rizin, objdump"
        echo "- \`50-elf/\` -- ELF-specific (readelf, nm)"
        echo "- \`60-config/\` -- XML config inspection"
        echo "- \`70-upx-unpacked/\` -- unpacked binary (when UPX detected)"
        echo "- \`90-logs/\` -- per-tool stdout/stderr"
        echo ""
        echo "## Troubleshooting"
        echo ""
        echo "If Ghidra dump is \`0KB (empty!)\` or \`-\`:"
        echo "  - tail -40 \`30-ghidra/<binary>.script.log\` -- the postscript's own output"
        echo "  - grep -iE 'error|traceback' \`30-ghidra/ghidra.log\` -- launch + framework errors"
        echo "  - If you passed \`--use-pyghidra\`, try without it to use Jython"
        echo ""
        echo "If ilspy .cs count is 0 for a .NET binary:"
        echo "  - tail \`20-dotnet/ilspycmd.log\`"
        echo "  - confirm \`dotnet --version\` works"
    } > "$sf"
    log_ok "Summary written: $sf"
}

# =============================================================================
# v2.7.0 - Codebase-level similarity matrix from per-binary fuzzy hashes
# =============================================================================
write_similarity_matrix() {
    # Reads each per-binary 81-fuzzyhash/hashes.json and computes the
    # NxN similarity matrix using ssdeep.compare() and tlsh.diff().
    # Writes _similarity-matrix.json and _similarity-matrix.html to
    # OUTPUT_ROOT.
    local out_root="$1"

    if [[ -z "$VENV_PY" ]]; then
        log_warn "similarity-matrix: venv Python unavailable; skipping"
        return 0
    fi

    "$VENV_PY" - "$out_root" > "${out_root}/_similarity-matrix.log" 2>&1 <<'PYEOF' || true
"""Build codebase-level similarity matrix from per-binary fuzzy hashes."""
import sys
import os
import json
import glob

out_root = sys.argv[1]

# Collect (filename, ssdeep_hash, tlsh_hash) tuples
samples = []
for hashes_path in sorted(glob.glob(os.path.join(out_root, "*", "81-fuzzyhash", "hashes.json"))):
    try:
        with open(hashes_path) as f:
            data = json.load(f)
        binary_dir = os.path.basename(os.path.dirname(os.path.dirname(hashes_path)))
        samples.append({
            "name": binary_dir,
            "ssdeep": data.get("ssdeep"),
            "tlsh": data.get("tlsh"),
            "size": data.get("size", 0),
        })
    except Exception as e:
        print(f"  skip {hashes_path}: {e}")

if len(samples) < 2:
    print(f"similarity-matrix: only {len(samples)} sample(s); matrix not meaningful")
    matrix_data = {"sample_count": len(samples), "samples": samples, "ssdeep_matrix": [], "tlsh_matrix": []}
    with open(os.path.join(out_root, "_similarity-matrix.json"), "w") as f:
        json.dump(matrix_data, f, indent=2)
    sys.exit(0)

# Compute pairwise scores
ssdeep_matrix = []
tlsh_matrix = []

try:
    import ssdeep as _ssdeep
    have_ssdeep = True
except ImportError:
    have_ssdeep = False
    print("ssdeep not in venv; ssdeep matrix will be empty")

try:
    import tlsh as _tlsh
    have_tlsh = True
except ImportError:
    have_tlsh = False
    print("tlsh not in venv; tlsh matrix will be empty")

n = len(samples)
for i in range(n):
    ssdeep_row = []
    tlsh_row = []
    for j in range(n):
        # ssdeep similarity (0-100; higher = more similar)
        score = None
        if have_ssdeep and samples[i].get("ssdeep") and samples[j].get("ssdeep"):
            try:
                score = _ssdeep.compare(samples[i]["ssdeep"], samples[j]["ssdeep"])
            except Exception:
                score = None
        ssdeep_row.append(score)
        # tlsh distance (0+; LOWER = more similar; 0 = identical)
        # We invert by reporting "1000 - distance" capped to make it
        # consistent with ssdeep (higher = more similar)
        td = None
        if have_tlsh and samples[i].get("tlsh") and samples[j].get("tlsh"):
            try:
                d = _tlsh.diff(samples[i]["tlsh"], samples[j]["tlsh"])
                td = max(0, 1000 - d)  # higher = more similar
            except Exception:
                td = None
        tlsh_row.append(td)
    ssdeep_matrix.append(ssdeep_row)
    tlsh_matrix.append(tlsh_row)

matrix_data = {
    "sample_count": n,
    "samples": [{"name": s["name"], "size": s["size"]} for s in samples],
    "ssdeep_matrix": ssdeep_matrix,
    "tlsh_matrix": tlsh_matrix,
    "note": "ssdeep: 0-100, higher = more similar; tlsh: 0-1000+, higher = more similar (1000 - tlsh distance, floored at 0)",
}

with open(os.path.join(out_root, "_similarity-matrix.json"), "w") as f:
    json.dump(matrix_data, f, indent=2)

# Build a tiny HTML table renderer (Garamond, dark theme; matches v2.5.0 style)
html_parts = ["""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>RE-Toolkit codebase similarity matrix</title>
<style>
:root { --bg-primary: #1a1a1a; --bg-secondary: #2a2a2a; --text-primary: #e0e0e0;
        --text-secondary: #a0a0a0; --accent: #d4a55a; --border: #3a3a3a; }
body { font-family: Garamond, 'EB Garamond', serif; background: var(--bg-primary);
       color: var(--text-primary); margin: 24px; }
h1 { color: var(--accent); }
table { border-collapse: collapse; margin: 12px 0; font-size: 13px; }
th, td { border: 1px solid var(--border); padding: 4px 8px; text-align: center; }
th { background: var(--bg-secondary); color: var(--accent); }
.high { background: #4a3a1a; }
.med  { background: #3a3a2a; }
.low  { background: #2a2a3a; }
.dim  { color: var(--text-secondary); }
</style></head><body>
<h1>RE-Toolkit codebase similarity matrix</h1>"""]
html_parts.append(f"<p>{n} samples; ssdeep matrix below (top), tlsh-derived matrix below (bottom). Cell values: similarity (0-100 for ssdeep; 0-1000 for tlsh-derived where 1000=identical).</p>")

def render_matrix(m, label):
    parts = [f"<h2>{label}</h2><table><thead><tr><th></th>"]
    for s in samples:
        parts.append(f"<th>{s['name'][:24]}</th>")
    parts.append("</tr></thead><tbody>")
    for i, row in enumerate(m):
        parts.append(f"<tr><th>{samples[i]['name'][:24]}</th>")
        for v in row:
            if v is None:
                parts.append('<td class="dim">-</td>')
            else:
                cls = "high" if v >= 80 else ("med" if v >= 30 else "low")
                if i == row.index(v) and v in (100, 1000):
                    cls = ""  # diagonal; suppress highlight
                parts.append(f'<td class="{cls}">{v}</td>')
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)

if have_ssdeep:
    html_parts.append(render_matrix(ssdeep_matrix, "ssdeep similarity (0-100)"))
if have_tlsh:
    html_parts.append(render_matrix(tlsh_matrix, "tlsh-derived similarity (1000 - distance)"))

html_parts.append("</body></html>")

with open(os.path.join(out_root, "_similarity-matrix.html"), "w", encoding="utf-8") as f:
    f.write("".join(html_parts))

print(f"similarity-matrix: {n}x{n} written")
PYEOF

    if [[ -f "${out_root}/_similarity-matrix.json" ]]; then
        log_ok "Similarity matrix: ${out_root}/_similarity-matrix.html"
    fi
}

# =============================================================================
# write_cluster_graph (v2.9.0)
# =============================================================================
# Reads each per-binary 81-fuzzyhash/hashes.json under $out_root and renders
# a force-directed cluster graph. Edges connect binaries with ssdeep
# similarity > $CLUSTER_THRESHOLD (default 60). Nodes are sized by file
# size; node color by severity (from each per-binary _summary.json).
#
# Output: ${out_root}/_cluster.html (self-contained inline SVG; ~80 lines
# of embedded JS for pan/zoom).
#
# Args:
#     $1 = output root directory (contains per-binary subdirs)
# Skip: SKIP_FUZZYHASH=1 (same control as similarity matrix)
# =============================================================================
write_cluster_graph() {
    local out_root="$1"
    if [[ ${SKIP_FUZZYHASH:-0} -eq 1 ]]; then
        log_info "Cluster graph: skipped (SKIP_FUZZYHASH=1)"
        return 0
    fi
    if [[ -z "${VENV_PY:-}" ]]; then
        log_warn "Cluster graph: VENV_PY not set; skipping"
        return 0
    fi
    if [[ ! -d "$out_root" ]]; then
        log_warn "Cluster graph: out_root does not exist: $out_root"
        return 0
    fi

    local cluster_threshold="${CLUSTER_THRESHOLD:-60}"

    "$VENV_PY" - "$out_root" "$cluster_threshold" <<PYEOF || true
import sys
import os
import json

OUT_ROOT = sys.argv[1]
THRESHOLD = int(sys.argv[2])

$(viz_helper_emit_svg_chrome_py)
$(viz_helper_emit_color_scale_py)
$(viz_helper_emit_force_layout_py)


# ---- Discover per-binary fuzzy hash + summary data ------------------------
binaries = []
for entry in sorted(os.listdir(OUT_ROOT)):
    bin_dir = os.path.join(OUT_ROOT, entry)
    if not os.path.isdir(bin_dir):
        continue
    fz_path = os.path.join(bin_dir, "81-fuzzyhash", "hashes.json")
    if not os.path.exists(fz_path):
        continue
    try:
        with open(fz_path) as f:
            fz = json.load(f)
    except Exception:
        continue
    sum_path = os.path.join(bin_dir, "_summary.json")
    severity = "low"
    file_size = 0
    if os.path.exists(sum_path):
        try:
            with open(sum_path) as f:
                summary = json.load(f)
            severity = (summary.get("verdict", {}) or {}).get("severity") or "low"
            file_size = int(((summary.get("file") or {}).get("size") or 0))
        except Exception:
            pass
    binaries.append({
        "name": entry,
        "ssdeep": fz.get("ssdeep") or "",
        "tlsh":   fz.get("tlsh") or "",
        "severity": severity,
        "size": max(file_size, 1),
    })

if len(binaries) < 2:
    # Need at least 2 binaries for a meaningful cluster graph
    body = (
        '<p style="color:var(--text-secondary);text-align:center;padding:60px">'
        f'Need at least 2 binaries with fuzzy hashes to render a cluster graph; '
        f'found {len(binaries)}.</p>'
    )
    with open(os.path.join(OUT_ROOT, "_cluster.html"), "w") as f:
        f.write(svg_chrome_html(
            body,
            title="Codebase Cluster Graph",
            subtitle="Force-directed similarity cluster (requires 2+ binaries)."
        ))
    print(f"cluster-graph: {len(binaries)} binaries; cluster graph not rendered")
    sys.exit(0)


# ---- Compute ssdeep similarity edges via Python ssdeep wrapper ------------
edges = []
try:
    import ssdeep
    for i, a in enumerate(binaries):
        for j, b in enumerate(binaries[i+1:], start=i+1):
            if not a["ssdeep"] or not b["ssdeep"]:
                continue
            try:
                score = ssdeep.compare(a["ssdeep"], b["ssdeep"])
            except Exception:
                score = 0
            if score >= THRESHOLD:
                edges.append((a["name"], b["name"], score))
except ImportError:
    # Fallback: no ssdeep available; cluster cannot be computed
    edges = []


# ---- Compute force-directed layout ----------------------------------------
W, H = 1100, 700
node_names = [b["name"] for b in binaries]
edge_pairs = [(u, v) for (u, v, _score) in edges]
positions = force_directed_layout(node_names, edge_pairs, W, H, iterations=120)


# ---- Render SVG -----------------------------------------------------------
nodes_by_name = {b["name"]: b for b in binaries}
max_size = max(b["size"] for b in binaries) or 1

# Edges first (drawn behind nodes)
edge_svgs = []
for (u, v, score) in edges:
    if u not in positions or v not in positions:
        continue
    x1, y1 = positions[u]; x2, y2 = positions[v]
    # Higher score => more opaque
    alpha = max(0.15, min(1.0, score / 100.0))
    edge_svgs.append(
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
        f'stroke="#60a5fa" stroke-opacity="{alpha:.2f}" stroke-width="1.5">'
        f'<title>{html_escape(u)} <-> {html_escape(v)}: ssdeep similarity {score}</title>'
        f'</line>'
    )

# Nodes
node_svgs = []
import math as _math
for name, (x, y) in positions.items():
    b = nodes_by_name[name]
    # Node radius: log scale with size; min 8, max 28
    rel = b["size"] / max_size
    radius = max(8, min(28, 8 + _math.log1p(rel * 100) * 4))
    color = color_severity(b["severity"])
    short = name[:28] + ("..." if len(name) > 28 else "")
    node_svgs.append(
        f'<g class="tooltip-trigger">'
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius:.1f}" '
        f'fill="{color}" fill-opacity="0.7" stroke="#0a0e1a" stroke-width="2">'
        f'<title>{html_escape(name)}: severity {html_escape(b["severity"])}, '
        f'{b["size"] // 1024} KB</title>'
        f'</circle>'
        f'<text x="{x:.1f}" y="{y + radius + 12:.1f}" fill="#e5e7eb" '
        f'font-size="11" text-anchor="middle">{html_escape(short)}</text>'
        f'</g>'
    )

# Legend
legend_svg = (
    '<g transform="translate(10, ' + str(H - 60) + ')">'
    '<rect width="320" height="50" fill="#131826" stroke="#2a3346" rx="3"/>'
    '<circle cx="20" cy="18" r="8" fill="#4ade80" fill-opacity="0.7"/>'
    '<text x="32" y="22" fill="#e5e7eb" font-size="11">low</text>'
    '<circle cx="80" cy="18" r="8" fill="#facc15" fill-opacity="0.7"/>'
    '<text x="92" y="22" fill="#e5e7eb" font-size="11">medium</text>'
    '<circle cx="160" cy="18" r="8" fill="#f87171" fill-opacity="0.7"/>'
    '<text x="172" y="22" fill="#e5e7eb" font-size="11">high</text>'
    f'<text x="10" y="42" fill="#9ca3af" font-size="10">'
    f'edges: ssdeep similarity &ge; {THRESHOLD}; node size: file size; node color: severity</text>'
    '</g>'
)

svg_body = (
    f'<svg xmlns="http://www.w3.org/2000/svg" id="cluster-svg" '
    f'viewBox="0 0 {W} {H}" preserveAspectRatio="xMidYMid meet" '
    f'style="cursor:grab">'
    f'<g id="cluster-zoom-group">'
    f'{"".join(edge_svgs)}'
    f'{"".join(node_svgs)}'
    f'{legend_svg}'
    f'</g></svg>'
    # Minimal pan/zoom JS - under 80 lines
    '<script>'
    '(function(){'
    'var svg=document.getElementById("cluster-svg");'
    'var g=document.getElementById("cluster-zoom-group");'
    'if(!svg||!g)return;'
    'var s=1,tx=0,ty=0,dragging=false,sx=0,sy=0;'
    'function apply(){g.setAttribute("transform","translate("+tx+","+ty+") scale("+s+")");}'
    'svg.addEventListener("wheel",function(e){'
    'e.preventDefault();'
    'var f=e.deltaY<0?1.15:0.87;'
    'var pt=svg.createSVGPoint();pt.x=e.clientX;pt.y=e.clientY;'
    'var ctm=g.getScreenCTM().inverse();var lp=pt.matrixTransform(ctm);'
    's=Math.max(0.2,Math.min(8,s*f));apply();'
    '});'
    'svg.addEventListener("mousedown",function(e){dragging=true;sx=e.clientX-tx;sy=e.clientY-ty;svg.style.cursor="grabbing";});'
    'window.addEventListener("mouseup",function(){dragging=false;svg.style.cursor="grab";});'
    'window.addEventListener("mousemove",function(e){if(!dragging)return;tx=e.clientX-sx;ty=e.clientY-sy;apply();});'
    '})();'
    '</script>'
)

cluster_meta = {
    "n_binaries": len(binaries),
    "n_edges": len(edges),
    "threshold": THRESHOLD,
}
subtitle = (
    f'{len(binaries)} binaries, {len(edges)} similarity edge(s) '
    f'(ssdeep &ge; {THRESHOLD}). Drag to pan, scroll to zoom.'
)
with open(os.path.join(OUT_ROOT, "_cluster.html"), "w") as f:
    f.write(svg_chrome_html(
        svg_body,
        title="Codebase Cluster Graph",
        subtitle=subtitle,
    ))
with open(os.path.join(OUT_ROOT, "_cluster.json"), "w") as f:
    json.dump(cluster_meta, f, indent=2)

print(f"cluster-graph: {len(binaries)} binaries, {len(edges)} edges (threshold={THRESHOLD})")
PYEOF

    if [[ -f "${out_root}/_cluster.html" ]]; then
        log_ok "Cluster graph: ${out_root}/_cluster.html"
    fi
}

# =============================================================================
# v3.4.0 (audit-25 A5.6) -- Threat-intel export (STIX 2.1 / MISP / JSON)
# =============================================================================
# Synopsis:
#     Export the codebase-level findings and IOCs in machine-readable formats
#     that feed directly into threat-intel platforms.
# Description:
#     Reads every per-binary _summary.json and 80-iocs/_iocs.json under
#     OUTPUT_ROOT and emits three files:
#       _export-findings.json -- a clean, flat canonical set of all findings
#                                and IOCs across every analyzed target.
#       _export-stix.json     -- a STIX 2.1 bundle: an Indicator SDO per IOC,
#                                a Malware SDO per flagged binary, and
#                                Relationship SDOs linking indicators to the
#                                malware they were found in.
#       _export-misp.json     -- a MISP event: one event with an Attribute
#                                per IOC and a file Object per binary.
# Notes:
#     STIX/MISP IDs are derived deterministically (uuid5 over stable content)
#     so re-running on the same corpus produces the same IDs -- important for
#     idempotent ingestion into TIP platforms. IOC values are exported as-is
#     from the extraction stage (already length-capped + noise-filtered by
#     80-iocs). This is a reporting/export function: it reads finished
#     analysis output and never touches the operator's input.
# Execution Parameters:
#     $1 = OUTPUT_ROOT (codebase output directory containing per-binary dirs)
# Examples:
#     write_threat_intel_export "$OUTPUT_ROOT"
# Version:
#     1.0 - 2026-05-03 - audit-25 A5.6
# =============================================================================
write_threat_intel_export() {
    local out_root="$1"
    [[ -z "$VENV_PY" ]] && { log_warn "threat-intel-export: venv Python unavailable; skipping"; return 0; }

    "$VENV_PY" - "$out_root" > "${out_root}/_export.log" 2>&1 <<'PYEOF' || true
"""Emit STIX 2.1 / MISP / flat-JSON threat-intel export from a codebase run.

Reads every per-binary _summary.json + 80-iocs/_iocs.json under OUTPUT_ROOT.
Dependency-free (stdlib only). All IDs are deterministic (uuid5) for
idempotent TIP ingestion.
"""
import os, sys, json, uuid
from datetime import datetime, timezone

OUTPUT_ROOT = sys.argv[1]

# Stable namespace for deterministic uuid5 IDs (RE-Toolkit-specific).
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://retoolkit.local/threat-intel")

def _det_id(prefix, *parts):
    """Deterministic STIX-style id: <type>--<uuid5 over parts>."""
    return f"{prefix}--{uuid.uuid5(_NS, '|'.join(str(p) for p in parts))}"

def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# ---- Collect per-binary data ----------------------------------------------
# Map each IOC category to a STIX pattern property + MISP attribute type.
# category -> (stix_pattern_object_path, misp_type, misp_category)
IOC_MAP = {
    "urls":          ("url:value",           "url",       "Network activity"),
    "domains":       ("domain-name:value",   "domain",    "Network activity"),
    "ipv4":          ("ipv4-addr:value",     "ip-dst",    "Network activity"),
    "ipv6":          ("ipv6-addr:value",     "ip-dst",    "Network activity"),
    "emails":        ("email-addr:value",    "email-src", "Payload delivery"),
    "windows_paths": ("file:name",           "filename",  "Artifacts dropped"),
}

binaries = []   # list of dicts: {name, hashes, severity, risk_score, iocs:{cat:[vals]}}
for entry in sorted(os.listdir(OUTPUT_ROOT)):
    bdir = os.path.join(OUTPUT_ROOT, entry)
    if not os.path.isdir(bdir):
        continue
    sjson = read_json(os.path.join(bdir, "_summary.json"))
    if not sjson:
        continue
    verdict = sjson.get("verdict", {}) or {}
    file_info = sjson.get("file", {}) or {}
    hashes = file_info.get("hashes", {}) or {}

    # Raw IOC values live in 80-iocs/_iocs.json (summary only has counts).
    iocs_json = read_json(os.path.join(bdir, "80-iocs", "_iocs.json")) or {}
    iocs = {}
    for cat in IOC_MAP:
        vals = []
        for item in (iocs_json.get(cat) or []):
            v = item.get("value") if isinstance(item, dict) else item
            if v:
                vals.append(v)
        if vals:
            iocs[cat] = vals

    binaries.append({
        "name": file_info.get("name", entry),
        "hashes": hashes,
        "severity": verdict.get("severity", "info"),
        "risk_score": verdict.get("risk_score"),
        "verdict_line": verdict.get("line", ""),
        "iocs": iocs,
    })

now_iso = datetime.now(timezone.utc).isoformat()

# ---- 1. Flat canonical findings JSON --------------------------------------
findings = {
    "generated": now_iso,
    "tool": "retoolkit",
    "target_count": len(binaries),
    "binaries": binaries,
}
with open(os.path.join(OUTPUT_ROOT, "_export-findings.json"), "w", encoding="utf-8") as f:
    json.dump(findings, f, indent=2, ensure_ascii=False)

# ---- 2. STIX 2.1 bundle ----------------------------------------------------
stix_objects = []
for b in binaries:
    # Malware SDO per flagged binary (severity above info).
    mal_id = None
    if b["severity"] != "info":
        mal_id = _det_id("malware", b["name"], b["hashes"].get("sha256", ""))
        stix_objects.append({
            "type": "malware",
            "spec_version": "2.1",
            "id": mal_id,
            "created": now_iso,
            "modified": now_iso,
            "name": b["name"],
            "is_family": False,
            "description": b["verdict_line"],
        })
    # Indicator SDO per IOC; relationship to the malware when present.
    for cat, vals in b["iocs"].items():
        pattern_path, _, _ = IOC_MAP[cat]
        for v in vals:
            # STIX pattern: [url:value = 'http://...']
            esc_v = v.replace("\\", "\\\\").replace("'", "\\'")
            pattern = f"[{pattern_path} = '{esc_v}']"
            ind_id = _det_id("indicator", cat, v)
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"{cat}: {v[:80]}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_iso,
            })
            if mal_id:
                stix_objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _det_id("relationship", ind_id, mal_id),
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": mal_id,
                })

stix_bundle = {
    "type": "bundle",
    "id": _det_id("bundle", OUTPUT_ROOT, len(binaries)),
    "objects": stix_objects,
}
with open(os.path.join(OUTPUT_ROOT, "_export-stix.json"), "w", encoding="utf-8") as f:
    json.dump(stix_bundle, f, indent=2, ensure_ascii=False)

# ---- 3. MISP event ---------------------------------------------------------
misp_attributes = []
misp_objects = []
for b in binaries:
    # File object with hashes.
    obj_attrs = []
    for htype in ("md5", "sha1", "sha256"):
        if b["hashes"].get(htype):
            obj_attrs.append({
                "type": htype, "object_relation": htype,
                "value": b["hashes"][htype], "category": "Payload delivery",
            })
    obj_attrs.append({
        "type": "filename", "object_relation": "filename",
        "value": b["name"], "category": "Payload delivery",
    })
    misp_objects.append({
        "name": "file",
        "meta-category": "file",
        "comment": f"RE-Toolkit severity={b['severity']} score={b['risk_score']}",
        "Attribute": obj_attrs,
    })
    # IOC attributes at the event level.
    for cat, vals in b["iocs"].items():
        _, misp_type, misp_cat = IOC_MAP[cat]
        for v in vals:
            misp_attributes.append({
                "type": misp_type,
                "category": misp_cat,
                "value": v,
                "comment": f"from {b['name']}",
                "to_ids": True,
            })

misp_event = {
    "Event": {
        "info": f"RE-Toolkit analysis: {len(binaries)} binaries",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "threat_level_id": "2",
        "analysis": "2",
        "published": False,
        "Attribute": misp_attributes,
        "Object": misp_objects,
    }
}
with open(os.path.join(OUTPUT_ROOT, "_export-misp.json"), "w", encoding="utf-8") as f:
    json.dump(misp_event, f, indent=2, ensure_ascii=False)

n_ind = sum(1 for o in stix_objects if o["type"] == "indicator")
n_mal = sum(1 for o in stix_objects if o["type"] == "malware")
print(f"threat-intel-export: {len(binaries)} binaries, {n_ind} indicators, "
      f"{n_mal} malware SDOs, {len(misp_attributes)} MISP attributes")
PYEOF

    if [[ -f "${out_root}/_export-stix.json" ]]; then
        log_ok "Threat-intel export: ${out_root}/_export-{findings,stix,misp}.json"
    fi
}

# =============================================================================
# v3.4.0 (audit-25 A5.5) -- Composite intelligence view
# =============================================================================
# Synopsis:
#     Build a codebase-level intelligence picture across all analyzed targets:
#     shared IOCs, shared suspicious-import categories, common packers, a
#     severity distribution, and a campaign-level ATT&CK heatmap.
# Description:
#     Where the per-binary report answers "what is this file?", the composite
#     view answers "what does this SET of files tell us?" -- the question that
#     matters in a multi-sample investigation. It reads every per-binary
#     _summary.json and 80-iocs/_iocs.json under OUTPUT_ROOT and correlates:
#       - shared IOCs   : the same indicator value seen in 2+ binaries
#                         (a campaign link).
#       - shared imports: suspicious-import categories common across binaries.
#       - common packers: the same packer/protector across binaries.
#       - ATT&CK heatmap: union of capa ATT&CK techniques, counted across all
#                         binaries (which techniques define this campaign).
#     Emits _composite-intel.html (Garamond dark, inline SVG heatmap) and
#     _composite-intel.json (the raw correlation data).
# Notes:
#     Only meaningful for 2+ targets (like the similarity matrix). For a
#     single target it writes a short note and returns. Reporting function:
#     reads finished output only.
# Execution Parameters:
#     $1 = OUTPUT_ROOT (codebase output directory)
# Examples:
#     write_composite_intel "$OUTPUT_ROOT"
# Version:
#     1.0 - 2026-05-03 - audit-25 A5.5
# =============================================================================
write_composite_intel() {
    local out_root="$1"
    [[ -z "$VENV_PY" ]] && { log_warn "composite-intel: venv Python unavailable; skipping"; return 0; }

    "$VENV_PY" - "$out_root" > "${out_root}/_composite-intel.log" 2>&1 <<PYEOF || true
import os, sys, json, html as _html
from collections import defaultdict, Counter

OUTPUT_ROOT = sys.argv[1]

$(viz_helper_emit_svg_chrome_py)

def html_escape(s): return _html.escape(str(s))
def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# ---- Collect per-binary data ----------------------------------------------
IOC_CATS = ("urls", "domains", "ipv4", "ipv6", "emails", "windows_paths")
binaries = []
for entry in sorted(os.listdir(OUTPUT_ROOT)):
    bdir = os.path.join(OUTPUT_ROOT, entry)
    if not os.path.isdir(bdir):
        continue
    sjson = read_json(os.path.join(bdir, "_summary.json"))
    if not sjson:
        continue
    verdict = sjson.get("verdict", {}) or {}
    die = sjson.get("die", {}) or {}
    pe = sjson.get("pe", {}) or {}
    capa = sjson.get("capa", {}) or {}
    iocs_json = read_json(os.path.join(bdir, "80-iocs", "_iocs.json")) or {}
    ioc_values = set()
    for cat in IOC_CATS:
        for item in (iocs_json.get(cat) or []):
            v = item.get("value") if isinstance(item, dict) else item
            if v:
                ioc_values.add(v)
    binaries.append({
        "name": (sjson.get("file", {}) or {}).get("name", entry),
        "severity": verdict.get("severity", "info"),
        "packer": die.get("packer") or "",
        "protector": die.get("protector") or "",
        "suspicious_import_cats": sorted((pe.get("suspicious_imports") or {}).keys()),
        "attack": [a.get("id") for a in (capa.get("attack") or []) if a.get("id")],
        "attack_named": {a.get("id"): a.get("technique", "") for a in (capa.get("attack") or []) if a.get("id")},
        "iocs": ioc_values,
    })

n = len(binaries)

# ---- Single-target: skip with a note --------------------------------------
if n < 2:
    with open(os.path.join(OUTPUT_ROOT, "_composite-intel.html"), "w") as f:
        f.write(svg_chrome_html(
            "<p><em>Composite intelligence requires 2 or more analyzed "
            "binaries. Only " + str(n) + " present.</em></p>",
            title="Composite Intelligence"))
    with open(os.path.join(OUTPUT_ROOT, "_composite-intel.json"), "w") as f:
        json.dump({"target_count": n, "note": "needs 2+ targets"}, f, indent=2)
    print(f"composite-intel: only {n} target(s); not meaningful")
    sys.exit(0)

# ---- Correlate cross-binary ------------------------------------------------
# Shared IOCs: value -> [binary names] where it appears in 2+.
ioc_to_bins = defaultdict(list)
for b in binaries:
    for v in b["iocs"]:
        ioc_to_bins[v].append(b["name"])
shared_iocs = {v: names for v, names in ioc_to_bins.items() if len(names) >= 2}

# Common packers: packer -> [binary names].
packer_to_bins = defaultdict(list)
for b in binaries:
    if b["packer"]:
        packer_to_bins[b["packer"]].append(b["name"])
common_packers = {p: names for p, names in packer_to_bins.items() if len(names) >= 2}

# Shared suspicious-import categories: category -> [binary names].
impcat_to_bins = defaultdict(list)
for b in binaries:
    for c in b["suspicious_import_cats"]:
        impcat_to_bins[c].append(b["name"])
shared_import_cats = {c: names for c, names in impcat_to_bins.items() if len(names) >= 2}

# ATT&CK heatmap: technique id -> count across binaries.
attack_counter = Counter()
attack_names = {}
for b in binaries:
    for tid in set(b["attack"]):
        attack_counter[tid] += 1
        if tid in b["attack_named"] and b["attack_named"][tid]:
            attack_names[tid] = b["attack_named"][tid]

# Severity distribution.
sev_dist = Counter(b["severity"] for b in binaries)

composite = {
    "target_count": n,
    "shared_iocs": {v: names for v, names in sorted(shared_iocs.items())},
    "common_packers": {p: names for p, names in sorted(common_packers.items())},
    "shared_import_categories": {c: names for c, names in sorted(shared_import_cats.items())},
    "attack_heatmap": dict(attack_counter.most_common()),
    "severity_distribution": dict(sev_dist),
}
with open(os.path.join(OUTPUT_ROOT, "_composite-intel.json"), "w", encoding="utf-8") as f:
    json.dump(composite, f, indent=2, ensure_ascii=False)

# ---- Build the HTML view ---------------------------------------------------
parts = []

# Severity distribution summary.
sev_order = ["crit", "high", "med", "low", "info"]
sev_cells = "".join(
    f'<span style="margin-right:14px"><strong>{html_escape(s)}</strong>: '
    f'{sev_dist.get(s, 0)}</span>'
    for s in sev_order if sev_dist.get(s, 0)
)
parts.append(f'<div class="c"><h2>Corpus overview</h2>'
             f'<p>{n} binaries analyzed. Severity distribution: {sev_cells}</p></div>')

# Shared IOCs table (campaign links).
if shared_iocs:
    rows = "".join(
        f'<tr><td><code>{html_escape(v)}</code></td>'
        f'<td>{len(names)}</td>'
        f'<td style="color:var(--text-muted);font-size:12px">{html_escape(", ".join(names))}</td></tr>'
        for v, names in sorted(shared_iocs.items(), key=lambda kv: -len(kv[1]))
    )
    parts.append(
        '<div class="c"><h2>Shared IOCs (campaign links)</h2>'
        '<p>Indicators appearing in 2 or more binaries -- evidence the samples '
        'are related.</p><table><thead><tr><th>Indicator</th><th>Binaries</th>'
        '<th>Which</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
    )
else:
    parts.append('<div class="c"><h2>Shared IOCs</h2>'
                 '<p><em>No IOCs shared across binaries.</em></p></div>')

# Common packers.
if common_packers:
    rows = "".join(
        f'<tr><td>{html_escape(p)}</td><td>{len(names)}</td>'
        f'<td style="color:var(--text-muted);font-size:12px">{html_escape(", ".join(names))}</td></tr>'
        for p, names in sorted(common_packers.items(), key=lambda kv: -len(kv[1]))
    )
    parts.append(
        '<div class="c"><h2>Common packers</h2>'
        '<table><thead><tr><th>Packer</th><th>Binaries</th><th>Which</th></tr>'
        '</thead><tbody>' + rows + '</tbody></table></div>'
    )

# Shared suspicious-import categories.
if shared_import_cats:
    rows = "".join(
        f'<tr><td>{html_escape(c)}</td><td>{len(names)}</td>'
        f'<td style="color:var(--text-muted);font-size:12px">{html_escape(", ".join(names))}</td></tr>'
        for c, names in sorted(shared_import_cats.items(), key=lambda kv: -len(kv[1]))
    )
    parts.append(
        '<div class="c"><h2>Shared suspicious-import categories</h2>'
        '<table><thead><tr><th>Category</th><th>Binaries</th><th>Which</th></tr>'
        '</thead><tbody>' + rows + '</tbody></table></div>'
    )

# ATT&CK heatmap (horizontal bars: technique -> count across binaries).
if attack_counter:
    items = attack_counter.most_common(30)
    max_c = items[0][1] if items else 1
    W = 900; row_h = 22; Hh = row_h * len(items) + 40
    bar_x = 220; bar_max = W - bar_x - 60
    svg_rows = []
    for i, (tid, cnt) in enumerate(items):
        y = 30 + i * row_h
        bw = int((cnt / max_c) * bar_max)
        tname = attack_names.get(tid, "")
        label = f"{tid} {tname}"[:32]
        # Intensity = fraction of corpus exhibiting this technique.
        frac = cnt / n
        color = "#e74c3c" if frac >= 0.66 else ("#e67e22" if frac >= 0.33 else "#5dade2")
        svg_rows.append(
            f'<text x="{bar_x - 6}" y="{y + 13}" font-size="11" fill="#b8b8b8" '
            f'text-anchor="end">{html_escape(label)}</text>'
            f'<rect x="{bar_x}" y="{y + 3}" width="{bw}" height="{row_h - 8}" '
            f'fill="{color}" rx="2"><title>{html_escape(tid)} {html_escape(tname)}: '
            f'{cnt}/{n} binaries</title></rect>'
            f'<text x="{bar_x + bw + 6}" y="{y + 13}" font-size="11" fill="#e8e8e8">'
            f'{cnt}/{n}</text>'
        )
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {Hh}" '
           f'preserveAspectRatio="xMidYMid meet">{"".join(svg_rows)}</svg>')
    parts.append(
        '<div class="c"><h2>Campaign ATT&amp;CK heatmap</h2>'
        '<p>capa-derived ATT&amp;CK techniques across the corpus. Bar length '
        'and color = how many binaries exhibit each technique '
        '(red &ge; 2/3 of corpus, orange &ge; 1/3, blue below).</p>'
        + svg + '</div>'
    )

body = "".join(parts)
with open(os.path.join(OUTPUT_ROOT, "_composite-intel.html"), "w", encoding="utf-8") as f:
    f.write(svg_chrome_html(body, title="Composite Intelligence",
                            subtitle=f"{n} binaries correlated"))

print(f"composite-intel: {n} binaries, {len(shared_iocs)} shared IOCs, "
      f"{len(common_packers)} common packers, {len(attack_counter)} ATT&CK techniques")
PYEOF

    if [[ -f "${out_root}/_composite-intel.html" ]]; then
        log_ok "Composite intelligence: ${out_root}/_composite-intel.html"
    fi
}
