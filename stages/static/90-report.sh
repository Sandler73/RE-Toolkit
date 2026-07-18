#!/usr/bin/env bash
# =============================================================================
# stages/static/90-report.sh
# =============================================================================
#
# Synopsis:
#     Per-binary HTML report generation from _summary.json.
#
# Description:
#     Reads _summary.json and builds _report.html using the exact CSS design
#     from the reference report (dark theme, Garamond, 1280px .w
#     wrapper, tabbed layout). Doc-header and summary-banner are placed INSIDE
#     .w so they match content width.
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
#     stage_report()
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

stage_report() {
    local target="$1" outdir="$2"
    [[ -z "$VENV_PY" ]] && { log_step "report: skipped (no venv)"; return 0; }

    "$VENV_PY" - "$outdir" <<'PYEOF' || true
"""HTML report generator for RE-Toolkit v3.0.0.

Reads _summary.json from OUTDIR and writes _report.html.
CSS lifted verbatim from the reference RE report
Design constraints: dark theme only, Garamond serif, --accent:#5dade2,
.w wrapper at max-width 1280px, .doc-header and .summary-banner INSIDE .w.
"""
import os, sys, json, html
from datetime import datetime, timezone

OUTDIR = sys.argv[1]
summary_path = os.path.join(OUTDIR, "_summary.json")
if not os.path.isfile(summary_path):
    print("report: no _summary.json -- skipping")
    sys.exit(0)

with open(summary_path, encoding="utf-8") as f:
    S = json.load(f)

def esc(x):
    return html.escape(str(x), quote=True)

def fmt_bytes(n):
    if not n: return "0 B"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}" if u != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TB"

fname = S["file"]["name"]
verdict = S["verdict"]
sev = verdict["severity"]

# CSS -- lifted verbatim from the reference report, with the single
# structural change requested: .doc-header and .summary-banner sit INSIDE .w.
CSS = """
:root {
  --bg-primary:#1a1a1a; --bg-secondary:#242424; --bg-tertiary:#2d2d2d; --bg-hover:#363636;
  --text-primary:#e8e8e8; --text-secondary:#b8b8b8; --text-muted:#888;
  --border-color:#3a3a3a; --header-bg:#0e1a26; --header-text:#e8e8e8;
  --accent:#5dade2; --accent-2:#2ecc71; --accent-3:#e67e22;
  --crit-bg:#7d2020; --crit-text:#fff; --crit-border:#a52a2a;
  --high-bg:#8a4a14; --high-text:#fff; --high-border:#b85f1a;
  --med-bg:#8a7616;  --med-text:#fff;  --med-border:#b89e1a;
  --low-bg:#1d5c80;  --low-text:#fff;  --low-border:#2d7da8;
  --info-bg:#4a4f50; --info-text:#fff; --info-border:#6a6f70;
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
h3 { font-size: 17px; margin: 16px 0 8px; color: var(--text-primary); }
p { margin: 8px 0 12px; }
ul, ol { margin: 8px 0 12px 28px; }
li { margin: 4px 0; }
code { background: var(--code-bg); padding: 2px 6px; border-radius: 3px; font-family: Consolas, "Courier New", monospace; font-size: 13px; color: #d8d8d8; }
pre { background: var(--code-bg); padding: 12px; border-radius: 6px; border: 1px solid var(--border-color); overflow-x: auto; font-family: Consolas, "Courier New", monospace; font-size: 13px; line-height: 1.4; margin: 12px 0; color: #d8d8d8; max-height: 500px; }

/* Main wrapper -- single source of max-width */
.w {
  max-width: 1280px;
  margin: 0 auto;
  padding: 24px 32px 36px 32px;
  width: 100%;
}

/* Document header -- INSIDE .w per user requirement */
.doc-header {
  border-bottom: 2px solid var(--border-color);
  padding-bottom: 18px;
  margin-bottom: 22px;
}
.doc-title {
  font-size: 28px; font-weight: bold; color: var(--accent);
  margin-bottom: 6px; line-height: 1.3;
}
.doc-subtitle { color: var(--text-secondary); font-size: 14px; line-height: 1.5; }

/* Summary banner -- INSIDE .w per user requirement */
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

/* Tabs */
.tn {
  display: flex; flex-wrap: nowrap; gap: 2px;
  border-bottom: 2px solid var(--border-color);
  margin: 0 0 24px 0; overflow-x: auto; overflow-y: hidden;
  padding-bottom: 0; scrollbar-width: thin;
}
.tn::-webkit-scrollbar { height: 6px; }
.tn::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 3px; }
.tab {
  font-family: Garamond, "Times New Roman", serif; font-size: 14px;
  padding: 10px 16px; background: var(--bg-secondary); color: var(--text-secondary);
  cursor: pointer; border: 1px solid var(--border-color); border-bottom: none;
  border-radius: 6px 6px 0 0; transition: background 0.15s, color 0.15s;
  white-space: nowrap; flex: 0 0 auto; margin-bottom: -1px;
}
.tab:hover { background: var(--bg-hover); color: var(--text-primary); }
.tab.active {
  color: var(--accent); background: var(--bg-tertiary);
  border-color: var(--border-color); border-bottom-color: var(--bg-tertiary);
  font-weight: bold;
}
.tp { display: none; }
.tp.active { display: block; }

/* Panels */
.c {
  background: var(--bg-secondary); border: 1px solid var(--border-color);
  border-radius: 8px; padding: 20px 22px; margin: 0 0 20px 0;
  max-width: 100%; overflow-x: auto;
}
.c h2 { margin-top: 0; }
.c h3 { margin-top: 12px; }

/* Two-column grid */
.g2 { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
@media (max-width: 1000px) { .g2 { grid-template-columns: 1fr; } }

/* Tables */
table, .dt, .kv {
  width: 100%; border-collapse: collapse; margin: 10px 0 14px 0;
  font-size: 14px; table-layout: auto;
}
th, td {
  padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border-color);
  vertical-align: top; word-wrap: break-word; overflow-wrap: anywhere;
}
th {
  background: var(--header-bg); color: var(--header-text);
  font-weight: bold; font-size: 13px; white-space: nowrap;
}
tbody tr:nth-child(even) { background: var(--bg-tertiary); }
tbody tr:hover { background: var(--bg-hover); }

.kv td:first-child,
table.kv td:first-child {
  width: 30%; font-weight: bold; color: var(--text-secondary); white-space: nowrap;
}

/* Status badges */
.b { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
.b-g { background: var(--accent-2); color: var(--bg-primary); }
.b-y { background: #f1c40f; color: var(--bg-primary); }
.b-r { background: #e74c3c; color: #fff; }
.b-b { background: var(--accent); color: var(--bg-primary); }

/* Warnings/notes */
.warn { background: var(--bg-tertiary); border-left: 4px solid var(--high-border); padding: 12px 16px; margin: 14px 0; border-radius: 0 4px 4px 0; color: var(--text-primary); }
.note { background: var(--bg-tertiary); border-left: 4px solid var(--accent); padding: 12px 16px; margin: 14px 0; border-radius: 0 4px 4px 0; }
.ok   { background: var(--bg-tertiary); border-left: 4px solid var(--accent-2); padding: 12px 16px; margin: 14px 0; border-radius: 0 4px 4px 0; }

/* Pills */
.pill {
  display: inline-block; padding: 2px 8px; border-radius: 3px;
  font-size: 11px; font-weight: bold; letter-spacing: 0.06em; text-transform: uppercase;
  margin: 2px 4px 2px 0;
}
.pill.crit { background: var(--crit-bg); color: var(--crit-text); }
.pill.high { background: var(--high-bg); color: var(--high-text); }
.pill.med  { background: var(--med-bg);  color: var(--med-text); }
.pill.low  { background: var(--low-bg);  color: var(--low-text); }
.pill.info { background: var(--info-bg); color: var(--info-text); }

/* Footer */
.footer {
  margin-top: 36px; padding-top: 18px; border-top: 2px solid var(--border-color);
  text-align: center; color: var(--text-secondary); font-size: 13px;
}

/* Return to top */
.ret-top { text-align: right; margin: 14px 0 18px; font-size: 13px; }
.ret-top a {
  color: var(--text-secondary); padding: 4px 10px;
  border: 1px solid var(--border-color); border-radius: 3px;
}
.ret-top a:hover { background: var(--bg-tertiary); color: var(--accent); text-decoration: none; }

details { margin: 8px 0; }
details summary { cursor: pointer; padding: 8px 12px; background: var(--bg-tertiary); border-radius: 4px; color: var(--text-secondary); font-size: 13px; }
details[open] summary { color: var(--accent); }
"""

JS = """
function st(id){
  var tabs=document.querySelectorAll('.tab'),
      pgs=document.querySelectorAll('.tp');
  for(var i=0;i<tabs.length;i++){tabs[i].classList.remove('active');}
  for(var i=0;i<pgs.length;i++){pgs[i].classList.remove('active');}
  var el=document.getElementById('tab-'+id); if(el) el.classList.add('active');
  var pg=document.getElementById('pg-'+id);  if(pg) pg.classList.add('active');
}
"""

def build_kv_rows(pairs):
    out = []
    for k, v in pairs:
        if v in (None, ""): v = "<em style='color:var(--text-muted)'>--</em>"
        out.append(f"<tr><td>{esc(k)}</td><td>{v}</td></tr>")
    return "\n".join(out)

def pill(label, cls):
    return f'<span class="pill {cls}">{esc(label)}</span>'

# ---------------- Overview tab -----------------------------------------------
hashes = S["file"]["hashes"]
auth = S["authenticode"]
die = S["die"]
ent = S["entropy"]

auth_badge = ""
if auth.get("present"):
    if auth.get("valid"):
        auth_badge = '<span class="b b-g">SIGNED</span>'
    else:
        auth_badge = '<span class="b b-r">INVALID SIGNATURE</span>'
else:
    auth_badge = '<span class="b b-y">UNSIGNED</span>'

packed_badge = ""
if die.get("packer"):
    packed_badge = f'<span class="b b-r">PACKED: {esc(die["packer"])}</span>'
elif ent.get("high_count", 0) > 0:
    packed_badge = f'<span class="b b-y">{ent["high_count"]} HIGH-ENTROPY SECTIONS</span>'
else:
    packed_badge = '<span class="b b-g">NOT PACKED</span>'

signer = auth.get("signer") or ""

overview_rows = build_kv_rows([
    ("File Name", esc(fname)),
    ("Full Path", esc(S["file"]["path"])),
    ("Size", fmt_bytes(S["file"]["size"])),
    ("File Type", esc(S["file"]["file_type"])),
    ("SHA-256", f"<code>{esc(hashes.get('sha256', ''))}</code>"),
    ("SHA-1", f"<code>{esc(hashes.get('sha1', ''))}</code>"),
    ("MD5", f"<code>{esc(hashes.get('md5', ''))}</code>"),
    ("Signature", auth_badge + (f" &nbsp;<code>{esc(signer)}</code>" if signer else "")),
    ("Packing", packed_badge),
    ("Compiler (DIE)", esc(die.get("compiler") or "")),
    ("Protector (DIE)", esc(die.get("protector") or "")),
    ("Overall Entropy", f"{ent['overall']:.3f}" if ent.get("overall") else ""),
])

# v2.5.0: ELF security mitigations row from checksec parser
_mit = S.get("mitigations", {}) or {}
if _mit.get("ran"):
    _mit_parts = []
    for _label, _key, _good in [
        ("NX", "nx", "enabled"), ("PIE", "pie", "pie"),
        ("RELRO", "relro", "full"), ("Canary", "canary", "present"),
        ("Fortify", "fortify", "enabled"),
    ]:
        _val = _mit.get(_key)
        if _val is None:
            continue
        if _val == _good:
            _mit_parts.append(pill(_label, "low"))  # green-ish good badge
        elif _label == "RELRO" and _val == "partial":
            _mit_parts.append(pill(f"{_label}: partial", "med"))
        else:
            _mit_parts.append(pill(f"{_label}: {_val}", "high"))  # red bad badge
    if _mit_parts:
        overview_rows += (
            f'<tr><td>ELF Mitigations</td>'
            f'<td>{" ".join(_mit_parts)}</td></tr>'
        )

verdict_html = f"""
<div class="note" style="border-left-color: var(--{sev}-border);">
  <strong>Verdict:</strong> {esc(verdict['line'])}<br>
  <strong>Severity:</strong> {pill(sev, sev)}
  {"".join(f"<div style='margin-top:6px;color:var(--text-secondary);font-size:13px'>• {esc(r)}</div>" for r in verdict['reasons'])}
</div>
"""

# v3.2.0 (audit-23 A5.1) -- Explainable verdict panel.
# Renders the weighted-score breakdown from A2.1 so an analyst can see exactly
# why the binary scored as it did: the numeric risk score, the band it maps
# to, and each contributing signal with its weight and evidence. This turns
# the verdict from an assertion into an argument. Renders only when
# score_breakdown is present (v3.2.0+ summaries); older _summary.json without
# it falls through cleanly (backward compatible).
score_breakdown = verdict.get("score_breakdown", [])
risk_score = verdict.get("risk_score")
explainable_html = ""
if score_breakdown:
    # Band thresholds for the scale annotation (must match compute_score_band
    # in 85-summary.sh).
    _bands = [(100, "crit"), (60, "high"), (30, "med"), (10, "low"), (0, "info")]
    # Max weight among signals, for proportional bar widths (min 1 to avoid /0).
    _max_w = max((s.get("weight", 0) for s in score_breakdown), default=1) or 1
    _rows = []
    for s in score_breakdown:
        _w = s.get("weight", 0)
        _name = esc(s.get("name", ""))
        _ev = esc(s.get("evidence", ""))
        # Bar width proportional to this signal's weight vs the max.
        _pct = int((_w / _max_w) * 100)
        _rows.append(
            f"<tr>"
            f"<td style='white-space:nowrap;font-family:Consolas,monospace;font-size:12px'>{_name}</td>"
            f"<td style='text-align:right;font-weight:bold;width:48px'>+{_w}</td>"
            f"<td style='width:160px'>"
            f"<div style='background:var(--{sev}-border);height:12px;width:{_pct}%;"
            f"border-radius:3px;min-width:4px'></div></td>"
            f"<td style='color:var(--text-secondary);font-size:13px'>{_ev}</td>"
            f"</tr>"
        )
    _score_str = str(risk_score) if risk_score is not None else "n/a"
    explainable_html = f"""
<div class="note" style="margin-top:10px;border-left-color: var(--{sev}-border);">
  <strong>Risk score breakdown:</strong>
  <span style="font-size:20px;font-weight:bold;color:var(--{sev}-border);margin-left:8px">{_score_str}</span>
  <span style="color:var(--text-muted);font-size:13px">/ band: {esc(sev)}</span>
  <div style="color:var(--text-muted);font-size:12px;margin:4px 0 8px">
    Bands: info 0-9 &middot; low 10-29 &middot; med 30-59 &middot; high 60-99 &middot; crit 100+.
    Each signal below contributes additively; the total determines the band.
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead><tr>
      <th style="text-align:left;padding:4px 8px;border-bottom:1px solid var(--border-color)">Signal</th>
      <th style="text-align:right;padding:4px 8px;border-bottom:1px solid var(--border-color)">Weight</th>
      <th style="text-align:left;padding:4px 8px;border-bottom:1px solid var(--border-color)">Contribution</th>
      <th style="text-align:left;padding:4px 8px;border-bottom:1px solid var(--border-color)">Evidence</th>
    </tr></thead>
    <tbody>
      {"".join(_rows)}
    </tbody>
  </table>
</div>
"""

# v3.0.14 (audit-18 C1-C4) ===================================================
# Overview tab Triage panel additions surfacing audit-15/16/17 newly-captured
# signal. All panels render only when the underlying data is non-empty so a
# v3.0.13 _summary.json without the new fields still renders cleanly.
#
# C1: TrID full match table (top 10) -- audit-17 F1
# C2: binwalk-extract status -- audit-17 F2
# C3: die signature timing breakdown -- audit-16 F7
# C4: findaes -v context bytes -- audit-16 F13
# ============================================================================

# C1: TrID full match table (was previously top-3 only; audit-18 B1 schema
# bumped cap to 10. Also moved from PE-only tab to Overview since TrID
# applies to all binary formats not just PE).
trid_overview_html = ""
_trid_list = S.get("trid", []) or []
if _trid_list:
    _trid_rows = "".join(
        f'<tr>'
        f'<td style="text-align:right">{m.get("confidence", 0):.1f}%</td>'
        f'<td><code>.{esc(m.get("extension", ""))}</code></td>'
        f'<td>{esc(m.get("description", ""))}</td>'
        f'</tr>'
        for m in _trid_list
    )
    trid_overview_html = f"""
<div class="c">
  <h2>TrID File Identification ({len(_trid_list)} matches)</h2>
  <p style="color: var(--text-secondary); font-size: 13px;">
    Source: <code>00-triage/trid.txt</code>. TrID matches the file
    against ~17,000 file-format signatures from <a href="https://mark0.net" style="color: var(--accent);">mark0.net</a>.
    Higher confidence% = stronger format match. Multiple high-confidence
    matches usually indicate the file is a polyglot, dual-mode binary,
    or has been deliberately misformatted.
  </p>
  <table>
    <thead><tr><th>Confidence</th><th>Ext</th><th>Description</th></tr></thead>
    <tbody>{_trid_rows}</tbody>
  </table>
</div>
"""

# C2: binwalk-extract status panel (audit-17 F2 surfacing extension)
binwalk_overview_html = ""
_be = S.get("binwalk_extract", {}) or {}
if _be.get("ran"):
    _file_count = int(_be.get("file_count", 0))
    _partial = bool(_be.get("partial_success", False))
    _types = _be.get("extracted_types", []) or []
    _types_html = ""
    if _types:
        _types_html = (
            "<p>First extracted entries (first 10): "
            + ", ".join(f"<code>{esc(t)}</code>" for t in _types[:10])
            + "</p>"
        )
    if _partial and _file_count > 0:
        _be_status = pill(f"PARTIAL ({_file_count} files)", "med")
        _be_note = (
            "<p style='color:var(--text-secondary); font-size:13px;'>"
            "binwalk recognized embedded items beyond the extractable list. "
            "Items skipped have no Linux-side extractor utility installed (CAB, "
            "NSIS, MSI, custom firmware, etc.). The WARNING is expected partial-"
            "success behavior, not a complete failure.</p>"
        )
    elif _file_count > 0:
        _be_status = pill(f"OK ({_file_count} files)", "low")
        _be_note = ""
    elif _partial:
        _be_status = pill("0 files extracted", "med")
        _be_note = (
            "<p style='color:var(--text-secondary); font-size:13px;'>"
            "binwalk recognized embedded items but no extraction produced "
            "files. Likely cause: target has unusual formats with no available "
            "Linux extractor.</p>"
        )
    else:
        _be_status = pill("OK (no embedded)", "low")
        _be_note = ""
    binwalk_overview_html = f"""
<div class="c">
  <h2>binwalk Extraction</h2>
  <table class="kv"><tbody>
    <tr><td>Status</td><td>{_be_status}</td></tr>
    <tr><td>Files extracted</td><td>{_file_count}</td></tr>
    <tr><td>Partial success WARNING</td><td>{"yes" if _partial else "no"}</td></tr>
  </tbody></table>
  {_types_html}
  {_be_note}
  <p style="color: var(--text-secondary); font-size: 13px;">
    Source: <code>00-triage/binwalk-extract.txt</code> +
    <code>00-triage/binwalk-extracted/</code>.
  </p>
</div>
"""

# C3: die signature timing breakdown (audit-16 F7 -l flag)
die_timing_html = ""
_dt = S.get("die_timing", {}) or {}
if _dt.get("ran") and _dt.get("signatures"):
    _dt_rows = "".join(
        f'<tr><td>{esc(s.get("name", ""))}</td>'
        f'<td style="text-align:right">{s.get("ms", 0):.1f} ms</td></tr>'
        for s in _dt["signatures"][:20]
    )
    _total_html = ""
    _total = _dt.get("total_ms")
    if _total is not None:
        _total_html = f'<p>Total scan time: <strong>{_total:.1f} ms</strong></p>'
    die_timing_html = f"""
<div class="c">
  <h2>Detect-It-Easy Profiling</h2>
  {_total_html}
  <p style="color: var(--text-secondary); font-size: 13px;">
    Per-signature timing breakdown from <code>diec -l</code>. Slow
    signatures usually indicate either large file size or elaborate
    nested signature definitions; an outlier signature dominating
    time can be a hint that the binary triggered a complex match path.
  </p>
  <table>
    <thead><tr><th>Signature</th><th>Time (ms)</th></tr></thead>
    <tbody>{_dt_rows or '<tr><td colspan=2><em>No timing data.</em></td></tr>'}</tbody>
  </table>
</div>
"""

# C4: findaes -v context bytes (audit-16 F13)
findaes_html = ""
_fa = S.get("findaes", {}) or {}
if _fa.get("ran") and _fa.get("matches"):
    _fa_rows = "".join(
        f'<tr>'
        f'<td>AES-{esc(str(m.get("key_bits", "?")))}</td>'
        f'<td><code>{esc(m.get("offset", ""))}</code></td>'
        f'<td><code style="font-size:12px">{esc(m.get("context", ""))}</code></td>'
        f'</tr>'
        for m in _fa["matches"][:50]
    )
    findaes_html = f"""
<div class="c">
  <h2>findaes (AES Key Schedule Detection)</h2>
  <p style="color: var(--text-secondary); font-size: 13px;">
    findaes scans for AES key schedule patterns (the round-key
    expansion structure produced by AES key setup). Per-key context
    bytes shown for analyst verification. Source:
    <code>82-cryptokeys/findaes.txt</code>.
  </p>
  <table>
    <thead><tr><th>Key</th><th>Offset</th><th>Context bytes (first 16)</th></tr></thead>
    <tbody>{_fa_rows}</tbody>
  </table>
</div>
"""

# Aggregate v3.0.14 Overview-tab additions for splicing into the tab body.
overview_audit18_panels = (
    trid_overview_html + binwalk_overview_html
    + die_timing_html + findaes_html
)

# ---------------- PE/Structure tab --------------------------------------------
pe_section_rows = ""
if S["pe"]["sections"]:
    pe_section_rows = "".join(
        f"<tr><td><code>{esc(s['name'])}</code></td>"
        f"<td>{esc(s['vaddr'])}</td><td>{esc(s['vsize'])}</td>"
        f"<td>{esc(s['rsize'])}</td><td>{esc(s['flags'])}</td></tr>"
        for s in S["pe"]["sections"]
    )

entropy_rows = ""
for e in ent.get("sections", []):
    flag = ""
    if e["flag"] == "HIGH":
        flag = pill("HIGH", "high")
    elif e["flag"] == "LOW":
        flag = pill("LOW", "low")
    entropy_rows += (
        f"<tr><td><code>{esc(e['name'])}</code></td>"
        f"<td>{e['vsize']}</td><td>{e['rsize']}</td>"
        f"<td>{e['entropy']:.3f}</td><td>{flag}</td></tr>"
    )

# v3.0.7 (audit-11 C4) - PE Structure tab aggregation blocks.
# Pre-v3.0.7 the PE/Structure tab showed sections + entropy + TrID + pescan
# + LIEF only. The pev suite (readpe / pesec / pedis / pehash / pescan),
# Manalyze, peframe, and Authenticode chain validation each ran but their
# output was not aggregated into the report. Operators had to dig into
# individual stage directories to see those findings.
#
# These aggregation blocks read the per-tool output files and surface
# their KEY findings inline in the PE/Structure tab. Full output remains
# available under the per-tool subdirectories for deeper inspection.

import os as _os_pe

def _read_first_n(path, n=4000):
    """Read first n bytes of file, returning (content, full_size) or (None, 0)."""
    try:
        if not _os_pe.path.isfile(path):
            return None, 0
        sz = _os_pe.path.getsize(path)
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(n), sz
    except Exception:
        return None, 0

# --- pev aggregation: readpe + pesec + pehash ---
pev_aggregation_block = ""
pev_dir = _os_pe.path.join(OUTDIR, "14-pev")
if _os_pe.path.isdir(pev_dir):
    pev_files = []
    for fn in ("readpe.txt", "pesec.txt", "pehash.txt", "pedis.txt", "pescan.txt"):
        p = _os_pe.path.join(pev_dir, fn)
        if _os_pe.path.isfile(p):
            content, sz = _read_first_n(p, 3000)
            if content:
                pev_files.append((fn, content, sz))
    if pev_files:
        pev_blocks = "".join(
            f"<details><summary><code>14-pev/{esc(fn)}</code> -- "
            f"{fmt_bytes(sz)} (preview)</summary>"
            f"<pre>{esc(content)}</pre></details>"
            for fn, content, sz in pev_files
        )
        pev_aggregation_block = (
            f'<div class="c">'
            f'<h2>pev Suite ({len(pev_files)} output(s))</h2>'
            f'<p>The pev suite combines readpe (header dump), pesec (security '
            f'flags: ASLR/DEP/SEH/CFG), pehash (multiple hash algorithms), '
            f'pedis (disassembler), and pescan (anomaly detector). Click any '
            f'output to expand the first 3000 chars; full output in '
            f'<code>14-pev/</code>.</p>'
            f'{pev_blocks}'
            f'</div>'
        )

# --- Manalyze aggregation ---
manalyze_aggregation_block = ""
manalyze_dir = _os_pe.path.join(OUTDIR, "16-manalyze")
if _os_pe.path.isdir(manalyze_dir):
    # Manalyze writes manalyze.txt (text report) and optionally manalyze.json
    mz_txt_path = _os_pe.path.join(manalyze_dir, "manalyze.txt")
    content, sz = _read_first_n(mz_txt_path, 5000)
    if content:
        manalyze_aggregation_block = (
            f'<div class="c">'
            f'<h2>Manalyze (Heuristic PE Analyzer)</h2>'
            f'<p>Manalyze reports PE-level anomalies, suspicious imports, '
            f'packed-section heuristics, and resource-table oddities. First '
            f'5000 chars of <code>16-manalyze/manalyze.txt</code> '
            f'({fmt_bytes(sz)} total):</p>'
            f'<pre>{esc(content)}</pre>'
            f'</div>'
        )

# --- peframe aggregation ---
peframe_aggregation_block = ""
peframe_dir = _os_pe.path.join(OUTDIR, "17-peframe")
if _os_pe.path.isdir(peframe_dir):
    pf_txt_path = _os_pe.path.join(peframe_dir, "peframe.txt")
    pf_json_path = _os_pe.path.join(peframe_dir, "peframe.json")
    content, sz = _read_first_n(pf_txt_path, 5000)
    json_note = ""
    if _os_pe.path.isfile(pf_json_path):
        json_sz = _os_pe.path.getsize(pf_json_path)
        json_note = f' Structured JSON also available at <code>17-peframe/peframe.json</code> ({fmt_bytes(json_sz)}).'
    if content:
        peframe_aggregation_block = (
            f'<div class="c">'
            f'<h2>peframe (Behavioral PE Analyzer)</h2>'
            f'<p>peframe scans for behavioral indicators: API call patterns, '
            f'mutex / event names, registry-write signatures, file-write '
            f'targets, network indicators (URLs, IPs, domains).{json_note} '
            f'First 5000 chars of <code>17-peframe/peframe.txt</code> '
            f'({fmt_bytes(sz)} total):</p>'
            f'<pre>{esc(content)}</pre>'
            f'</div>'
        )

# --- Authenticode aggregation ---
authenticode_aggregation_block = ""
auth_dir = _os_pe.path.join(OUTDIR, "83-authenticode")
if _os_pe.path.isdir(auth_dir):
    auth_txt_path = _os_pe.path.join(auth_dir, "authenticode.txt")
    auth_json_path = _os_pe.path.join(auth_dir, "authenticode.json")
    # Try JSON first (structured); fall back to txt
    auth_summary_html = ""
    if _os_pe.path.isfile(auth_json_path):
        try:
            with open(auth_json_path, encoding="utf-8") as f:
                _auth = json.load(f)
            if isinstance(_auth, dict):
                signed = _auth.get("signed", False)
                signer = _auth.get("signer", _auth.get("issuer", "unknown"))
                valid = _auth.get("chain_valid", _auth.get("valid", None))
                expires = _auth.get("expires", _auth.get("not_after", "unknown"))
                signed_color = "var(--accent)" if signed else "#f87171"
                valid_color = ("var(--accent)" if valid is True else
                               "#f87171" if valid is False else "var(--text-secondary)")
                auth_summary_html = (
                    f'<table class="kv"><tbody>'
                    f'<tr><td>Signed</td><td><span style="color:{signed_color}">'
                    f'<b>{"yes" if signed else "no"}</b></span></td></tr>'
                    f'<tr><td>Signer</td><td><code>{esc(str(signer))}</code></td></tr>'
                    f'<tr><td>Chain valid</td><td><span style="color:{valid_color}">'
                    f'{"yes" if valid is True else "no" if valid is False else "unknown"}'
                    f'</span></td></tr>'
                    f'<tr><td>Expires</td><td><code>{esc(str(expires))}</code></td></tr>'
                    f'</tbody></table>'
                )
        except Exception:
            pass
    auth_txt_content, auth_sz = _read_first_n(auth_txt_path, 4000)
    if auth_summary_html or auth_txt_content:
        auth_body = auth_summary_html
        if auth_txt_content:
            auth_body += (
                f'<details><summary>Raw output (<code>83-authenticode/authenticode.txt</code>, '
                f'{fmt_bytes(auth_sz)})</summary><pre>{esc(auth_txt_content)}</pre></details>'
            )
        authenticode_aggregation_block = (
            f'<div class="c">'
            f'<h2>Authenticode Signature Chain</h2>'
            f'<p>Validation of the embedded Authenticode signature against the '
            f'system trust store. An "unsigned" or "chain invalid" verdict on '
            f'a sample claiming to be from a major vendor is a strong red flag.</p>'
            f'{auth_body}'
            f'</div>'
        )

# v3.0.14 (audit-18 C5-C8) ===================================================
# Structure tab bloaty panels. Audit-15 captured 3 bloaty data sources
# (sections+segments, symbols, compileunits) for ELF/Mach-O; audit-17 F5
# made it PE-aware (sections+segments only for PE). The 85-summary.sh
# audit-18 schema additions parse these into bloaty_data dict; this
# block renders them.
#
# C5: bloaty sections+segments table (PE OR ELF)
# C6: bloaty symbols table (ELF/Mach-O only)
# C7: bloaty compileunits table (ELF/Mach-O only)
# C8: bloaty PE limitation note (PE only)
# ============================================================================
_bloaty = S.get("bloaty", {}) or {}
_bloaty_html_block = ""
if _bloaty.get("ran"):
    _b_format = _bloaty.get("format_supported", "")
    # C5 -- sections+segments table
    _sec_rows = "".join(
        f'<tr>'
        f'<td><code>{esc(s.get("name", ""))}</code></td>'
        f'<td style="text-align:right">{s.get("file_pct", 0):.1f}%</td>'
        f'<td style="text-align:right"><code>{esc(s.get("file_size", ""))}</code></td>'
        f'<td style="text-align:right">{s.get("vm_pct", 0):.1f}%</td>'
        f'<td style="text-align:right"><code>{esc(s.get("vm_size", ""))}</code></td>'
        f'</tr>'
        for s in _bloaty.get("sections", []) or []
    )
    _sec_panel = f"""
<div class="c">
  <h2>bloaty Section/Segment Profile</h2>
  <p style="color: var(--text-secondary); font-size: 13px;">
    bloaty attributes every byte of the binary to a section + segment.
    Source: <code>10-pe/bloaty-sections.txt</code> or
    <code>50-elf/bloaty-sections.txt</code>. FILE SIZE = on-disk;
    VM SIZE = loaded into memory (sections like <code>.bss</code> have
    file=0 but vm&gt;0; debug sections are file&gt;0 vm=0).
  </p>
  <table>
    <thead><tr>
      <th>Name</th>
      <th>File %</th>
      <th>File Size</th>
      <th>VM %</th>
      <th>VM Size</th>
    </tr></thead>
    <tbody>{_sec_rows or '<tr><td colspan=5><em>No section data parsed.</em></td></tr>'}</tbody>
  </table>
</div>
"""
    # C6, C7 -- symbols + compileunits (ELF/Mach-O only)
    _sym_panel = ""
    if _bloaty.get("symbols"):
        _sym_rows = "".join(
            f'<tr>'
            f'<td><code style="font-size:12px">{esc(s.get("name", ""))}</code></td>'
            f'<td style="text-align:right">{s.get("file_pct", 0):.1f}%</td>'
            f'<td style="text-align:right"><code>{esc(s.get("file_size", ""))}</code></td>'
            f'<td style="text-align:right">{s.get("vm_pct", 0):.1f}%</td>'
            f'<td style="text-align:right"><code>{esc(s.get("vm_size", ""))}</code></td>'
            f'</tr>'
            for s in _bloaty["symbols"]
        )
        _sym_panel = f"""
<div class="c">
  <h2>bloaty Symbols Profile (top 30)</h2>
  <p style="color: var(--text-secondary); font-size: 13px;">
    Per-symbol size attribution from bloaty's deep DWARF/Mach-O parser.
    Symbols sorted by max(file, VM) size. ELF/Mach-O only; PE has
    preliminary bloaty support and doesn't expose symbol-level data
    (see PE-LIMITATION below). Source:
    <code>50-elf/bloaty-symbols.txt</code>.
  </p>
  <table>
    <thead><tr>
      <th>Symbol</th>
      <th>File %</th>
      <th>File Size</th>
      <th>VM %</th>
      <th>VM Size</th>
    </tr></thead>
    <tbody>{_sym_rows}</tbody>
  </table>
</div>
"""
    _cu_panel = ""
    if _bloaty.get("compileunits"):
        _cu_rows = "".join(
            f'<tr>'
            f'<td><code style="font-size:12px">{esc(s.get("name", ""))}</code></td>'
            f'<td style="text-align:right">{s.get("file_pct", 0):.1f}%</td>'
            f'<td style="text-align:right"><code>{esc(s.get("file_size", ""))}</code></td>'
            f'<td style="text-align:right">{s.get("vm_pct", 0):.1f}%</td>'
            f'<td style="text-align:right"><code>{esc(s.get("vm_size", ""))}</code></td>'
            f'</tr>'
            for s in _bloaty["compileunits"]
        )
        _cu_panel = f"""
<div class="c">
  <h2>bloaty Compile-Units / Inlines Profile (top 30)</h2>
  <p style="color: var(--text-secondary); font-size: 13px;">
    Per-compile-unit attribution from DWARF .debug_aranges. Each
    compile-unit corresponds to one source file in the linked binary.
    Useful for understanding which TUs contribute most to binary
    size, or which are unexpectedly large. Requires DWARF debug info
    (compile with -g or attach split debug file). Source:
    <code>50-elf/bloaty-debug.txt</code>.
  </p>
  <table>
    <thead><tr>
      <th>Compile Unit</th>
      <th>File %</th>
      <th>File Size</th>
      <th>VM %</th>
      <th>VM Size</th>
    </tr></thead>
    <tbody>{_cu_rows}</tbody>
  </table>
</div>
"""
    # C8 -- PE limitation explanatory note.
    # v3.7.3 (audit-31 C1): demoted from a full <h2> panel to a compact,
    # collapsed caveat. bloaty DOES run successfully on PE and the complete
    # supported profile (sections/segments) is rendered in the table above;
    # the prior full-panel note read as if bloaty had produced nothing but the
    # caveat. It is now a secondary, collapsible footnote so the data is the
    # focus.
    _pe_limit_panel = ""
    if _b_format == "pe-limited":
        _pe_limit_panel = f"""
<p style="color: var(--text-secondary); font-size: 12px; margin-top:-8px;">
  <details>
    <summary style="cursor:pointer;">Note: the profile above is bloaty's complete supported output for PE binaries
    (<code>-d sections,segments</code>). Why no symbol/compile-unit breakdown for PE?</summary>
    <div style="margin-top:6px;">
    Per upstream bloaty (Aug 2018), PE/COFF support is preliminary: only
    <code>sections,segments</code> is supported, while
    <code>symbols</code>/<code>compileunits</code>/<code>inlines</code> exit with
    "PE doesn't support this data source" (audit-17 F5 made the pipeline run only
    the supported invocation for PE). Symbol/compile-unit level analysis for PE is
    available elsewhere: <code>10-pe/floss.txt</code>,
    <code>10-pe/objdump-dis.txt</code>, <code>10-pe/readpe-imports.txt</code>,
    <code>10-pe/pedis.txt</code>, and the Ghidra decompilation. Full rationale:
    <code>10-pe/bloaty-PE-LIMITATION.txt</code>.
    </div>
  </details>
</p>
"""
    _bloaty_html_block = _sec_panel + _sym_panel + _cu_panel + _pe_limit_panel

pe_tab = f"""
<div class="c">
  <h2>PE Sections</h2>
  <p>Source: <code>10-pe/pefile.txt</code>. Cross-verifiable with
  <code>12-lief/lief-full.txt</code> and <code>14-pev/readpe.txt</code>.</p>
  <table>
    <thead><tr><th>Name</th><th>VAddr</th><th>VSize</th><th>RSize</th><th>Flags</th></tr></thead>
    <tbody>{pe_section_rows or '<tr><td colspan=5><em>Not a PE, or no section info extracted.</em></td></tr>'}</tbody>
  </table>
</div>
<div class="c">
  <h2>Section Entropy</h2>
  <table>
    <thead><tr><th>Section</th><th>VSize</th><th>RSize</th><th>Entropy</th><th>Flag</th></tr></thead>
    <tbody>{entropy_rows or '<tr><td colspan=5><em>No entropy data.</em></td></tr>'}</tbody>
  </table>
</div>
<div class="c">
  <h2>TrID File Identification</h2>
  {
      '<table><thead><tr><th>Confidence</th><th>Ext</th><th>Description</th></tr></thead><tbody>'
      + ''.join(
          f'<tr><td>{m["confidence"]:.1f}%</td>'
          f'<td><code>.{esc(m["extension"])}</code></td>'
          f'<td>{esc(m["description"])}</td></tr>'
          for m in S.get("trid", [])
      )
      + '</tbody></table>'
      if S.get("trid") else '<p><em>No TrID matches (database may be missing).</em></p>'
  }
</div>
<div class="c">
  <h2>pescan Anomalies</h2>
  {
      '<ul>' + ''.join(f'<li>{esc(a)}</li>' for a in S.get("pescan_anomalies", [])) + '</ul>'
      if S.get("pescan_anomalies")
      else '<p><em>No anomalies flagged by pescan.</em></p>'
  }
</div>
<div class="c">
  <h2>LIEF Supplementary</h2>
  {
      f'<p>Format parsed: <code>{esc(S["lief"].get("format", "?"))}</code></p>'
      f'<p>Embedded signatures (Authenticode chains): <b>{S["lief"]["signature_count"]}</b></p>'
      f'<p>TLS callbacks registered: <b>{S["lief"]["tls_callbacks"]}</b>'
      f'{" -- <span class=pill high>suspicious</span>" if S["lief"]["tls_callbacks"] > 0 else ""}</p>'
      f'<p>Full dump: <code>12-lief/lief-full.txt</code>, <code>12-lief/lief-full.json</code></p>'
      if S.get("lief", {}).get("parsed")
      else '<p><em>LIEF did not parse this file.</em></p>'
  }
</div>
{pev_aggregation_block}
{manalyze_aggregation_block}
{peframe_aggregation_block}
{authenticode_aggregation_block}
{_bloaty_html_block}
"""

# ---------------- Imports/Exports tab -----------------------------------------
# v3.0.7 (audit-11 C2) - reorder + enrich. Pre-v3.0.7 the tab led with
# "Suspicious Imports" (a filtered view) before showing the full Import
# Table. Operators looking for the COMPLETE import list had to scroll past
# the filter. Plus: no count summary at top showed totals, no DLL category
# breakdown, no exports count proportional to imports.
#
# v3.0.10 (audit-14 D4) - subdivide imports by kind. Each entry in
# S["pe"]["imports"] now has a "kind" field ("import"|"delay"|"bound").
# Pre-v3.0.10 the report rendered them in a single flat list; delay
# and bound imports were silently dropped at the parser level. Now we
# render three distinct sections so operators see every dependency.
# For .NET binaries, also render a separate AssemblyRef panel since
# the standard import table only contains mscoree.dll for managed
# code; the rich dependency picture lives in the CLR metadata.
_imps = S["pe"]["imports"] or []
_imps_static = [x for x in _imps if x.get("kind", "import") == "import"]
_imps_delay = [x for x in _imps if x.get("kind") == "delay"]
_imps_bound = [x for x in _imps if x.get("kind") == "bound"]
_arefs = S["pe"].get("assembly_refs", []) or []

def _render_imp_blocks(libs):
    """Render import library list as <details> blocks."""
    if not libs:
        return ""
    blocks = []
    for lib in libs:
        fnames = lib.get("funcs", []) or []
        if fnames:
            funcs = "".join(f"<li><code>{esc(fn)}</code></li>" for fn in fnames)
            block = (
                f'<details><summary>{esc(lib["lib"])} ({len(fnames)} functions)</summary>'
                f'<ul>{funcs}</ul></details>'
            )
        else:
            # Bound imports have no per-function names; just show DLL
            block = (
                f'<details><summary>{esc(lib["lib"])} (DLL only; no per-function names available)</summary>'
                f'<p><em>Bound imports do not enumerate function names per-entry.</em></p></details>'
            )
        blocks.append(block)
    return "\n".join(blocks)

_imps_static_html = _render_imp_blocks(_imps_static) or "<em>No standard imports extracted.</em>"
_imps_delay_html = _render_imp_blocks(_imps_delay)
_imps_bound_html = _render_imp_blocks(_imps_bound)
total_import_funcs = sum(len(lib.get("funcs", []) or []) for lib in _imps)

susp_blocks = ""
total_suspicious = 0
for cat, funcs in sorted(S["pe"]["suspicious_imports"].items()):
    pills = "".join(pill(fn, "high") for fn in sorted(set(funcs)))
    susp_blocks += f"<h3>{esc(cat.replace('_', ' ').title())}</h3><div>{pills}</div>"
    total_suspicious += len(set(funcs))

exp_rows = ""
for ex in S["pe"]["exports"][:500]:
    exp_rows += f"<tr><td>{ex['ord']}</td><td><code>{esc(ex['rva'])}</code></td><td><code>{esc(ex['name'])}</code></td></tr>"

# Build summary header showing totals at-a-glance
n_static = len(_imps_static)
n_delay = len(_imps_delay)
n_bound = len(_imps_bound)
n_arefs = len(_arefs)
n_dlls = len(_imps)
n_exports = len(S["pe"]["exports"])

# v3.0.10 (audit-14 D4) - summary line breaks down imports by kind so
# operators see the full picture, not just the static-import count.
_kind_breakdown_parts = [f"{n_static} standard"]
if n_delay > 0:
    _kind_breakdown_parts.append(f"{n_delay} delay-loaded")
if n_bound > 0:
    _kind_breakdown_parts.append(f"{n_bound} bound")
_kind_breakdown = ", ".join(_kind_breakdown_parts)

_aref_summary = ""
if n_arefs > 0:
    _aref_summary = (
        f' <b>.NET AssemblyRef:</b> {n_arefs} referenced .NET assembly/assemblies'
        f' (rich dependency data lives in the CLR metadata for managed code).'
    )

impexp_summary = (
    f'<p><b>Imports:</b> {total_import_funcs} function(s) across {n_dlls} '
    f'imported library/libraries ({_kind_breakdown}). <b>Exports:</b> {n_exports} '
    f'entry/entries. <b>Suspicious flagged:</b> {total_suspicious} function(s) '
    f'matched the built-in PEStudio-style triage list.{_aref_summary}</p>'
)

# Build the import sub-blocks. Always show the standard section; only
# show delay/bound/aref sections when they have content (don't clutter
# the report with empty panels for binaries that don't use them).
_static_block = (
    '<div class="c">'
    f'<h2>Standard Imports ({n_static} libraries / '
    f'{sum(len(x.get("funcs", []) or []) for x in _imps_static)} functions)</h2>'
    '<p>Imports resolved at load time from the standard import directory '
    '(<code>DIRECTORY_ENTRY_IMPORT</code>). For .NET assemblies, this is '
    'usually just <code>mscoree.dll</code>; see the AssemblyRef panel below '
    'for the .NET-level dependency graph.</p>'
    f'{_imps_static_html}'
    '</div>'
)

_delay_block = ""
if _imps_delay:
    _delay_block = (
        '<div class="c">'
        f'<h2>Delay-Loaded Imports ({n_delay} libraries / '
        f'{sum(len(x.get("funcs", []) or []) for x in _imps_delay)} functions)</h2>'
        '<p>Imports deferred until first call (<code>DIRECTORY_ENTRY_DELAY_IMPORT</code>). '
        'Common for optional dependencies the binary may not actually use; absent '
        'these, the binary still loads.</p>'
        f'{_imps_delay_html}'
        '</div>'
    )

_bound_block = ""
if _imps_bound:
    _bound_block = (
        '<div class="c">'
        f'<h2>Bound Imports ({n_bound} libraries)</h2>'
        '<p>Pre-resolved imports baked in at link time '
        '(<code>DIRECTORY_ENTRY_BOUND_IMPORT</code>). Rare on modern PE; common '
        'in legacy Windows DLLs.</p>'
        f'{_imps_bound_html}'
        '</div>'
    )

_aref_block = ""
if _arefs:
    _aref_rows = ""
    for ar in _arefs:
        _aref_rows += (
            f'<tr><td><code>{esc(ar.get("name", "(unknown)"))}</code></td>'
            f'<td><code>{esc(ar.get("version", "(unknown)"))}</code></td></tr>'
        )
    _aref_block = (
        '<div class="c">'
        f'<h2>.NET AssemblyRef ({n_arefs})</h2>'
        '<p>References to other .NET assemblies, parsed from the CLR metadata '
        '<code>AssemblyRef</code> table. This is the .NET-level analog of the '
        'native import table: every assembly listed here is a runtime dependency. '
        'Source: <code>10-pe/pefile.txt</code> (parsed via dnfile).</p>'
        '<table><thead><tr><th>Assembly Name</th><th>Version</th></tr></thead>'
        f'<tbody>{_aref_rows}</tbody></table>'
        '</div>'
    )

impexp_tab = f"""
<div class="c">
  <h2>Imports / Exports Overview</h2>
  {impexp_summary}
</div>
{_static_block}
{_delay_block}
{_bound_block}
{_aref_block}
<div class="c">
  <h2>Suspicious Imports ({total_suspicious})</h2>
  <p>Subset of imports flagged by the built-in PEStudio-style triage categories.
  This is a HEURISTIC filter and does not imply maliciousness; many legitimate
  applications use APIs in these categories.</p>
  {susp_blocks or '<p><em>No suspicious imports detected.</em></p>'}
</div>
<div class="c">
  <h2>Exports ({n_exports})</h2>
  <table>
    <thead><tr><th>Ord</th><th>RVA</th><th>Name</th></tr></thead>
    <tbody>{exp_rows or '<tr><td colspan=3><em>No exports.</em></td></tr>'}</tbody>
  </table>
</div>
"""

# ---------------- Strings tab -------------------------------------------------
ss = S["strings_stats"]

# v3.0.14 (audit-18 B7) ======================================================
# Strings tab signsrch hits-with-offsets panel. Audit-16 F8 fixed signsrch
# invocation (chdir to /tmp workaround for hardcoded path bug). Schema
# additions in audit-18 captured per-hit {offset, bytes, title}; this
# panel surfaces them. Pre-v3.0.14 the Capabilities tab had a signsrch
# section showing only top_titles list (no offsets). Now we have full
# hit_details with offsets so analysts can pivot to disasm/hexdump.
# ============================================================================
_signsrch_hits_panel = ""
_ss_panel_data = S.get("signsrch", {}) or {}
if _ss_panel_data.get("ran") and _ss_panel_data.get("hit_details"):
    _ss_hit_rows = "".join(
        f'<tr>'
        f'<td><code>{esc(h.get("offset", ""))}</code></td>'
        f'<td style="text-align:right">{int(h.get("bytes", 0))}</td>'
        f'<td>{esc(h.get("title", ""))}</td>'
        f'</tr>'
        for h in _ss_panel_data["hit_details"][:50]
    )
    _hits_total = int(_ss_panel_data.get("hits", 0))
    _shown = len(_ss_panel_data["hit_details"])
    _shown_label = f"showing first {_shown}" if _hits_total > _shown else f"all {_shown}"
    _signsrch_hits_panel = f"""
<div class="c">
  <h2>signsrch Constant/Algorithm Hits ({_hits_total} total, {_shown_label})</h2>
  <p style="color: var(--text-secondary); font-size: 13px;">
    signsrch identifies cryptographic constants, lookup tables, and well-known
    algorithm signatures (AES S-boxes, SHA-256 K constants, CRC tables, etc.)
    embedded in the binary. Pivot to <code>00-triage/signsrch.txt</code> for
    full hit list with bytes, or examine the offset in a hex viewer to
    understand the surrounding code/data.
  </p>
  <table>
    <thead><tr>
      <th>Offset (file)</th>
      <th>Bytes</th>
      <th>Algorithm / Constant</th>
    </tr></thead>
    <tbody>{_ss_hit_rows}</tbody>
  </table>
</div>
"""

# v3.6.0 (audit-27 F1): string-to-function mapping panel. Reads
# 40-r2/string-to-function.json (built by the r2 stage's correlator). Shows the
# most-referenced strings and which functions use them -- a core global-RE
# question ("who references api.vendor.com?"). Renders only when the mapping
# exists and is non-empty.
strfunc_panel = ""
try:
    _sf_path = os.path.join(OUTDIR, "40-r2", "string-to-function.json")
    if os.path.isfile(_sf_path):
        with open(_sf_path, encoding="utf-8") as _sf:
            _sf_data = json.load(_sf)
        _sf_records = _sf_data.get("strings", []) if isinstance(_sf_data, dict) else []
        if _sf_records:
            TOP_SF = 40
            _sf_rows = []
            for _r in _sf_records[:TOP_SF]:
                _fns = ", ".join(
                    f'{esc(f.get("name",""))}' + (f' <span style="color:var(--text-muted)">({esc(f["addr"])})</span>' if f.get("addr") else "")
                    for f in _r.get("functions", [])
                )
                _sf_rows.append(
                    f'<tr><td><code>{esc(_r.get("string","")[:80])}</code></td>'
                    f'<td><code>{esc(_r.get("vaddr",""))}</code></td>'
                    f'<td>{_r.get("ref_count",0)}</td>'
                    f'<td>{_fns}</td></tr>'
                )
            _sf_trunc = (f' (showing top {TOP_SF} of {len(_sf_records)})'
                         if len(_sf_records) > TOP_SF else "")
            strfunc_panel = (
                f'<div class="c"><h2>String-to-Function Mapping ({len(_sf_records)})</h2>'
                f'<p style="color:var(--text-secondary);font-size:13px">Which functions '
                f'reference each string, from radare2 cross-reference analysis{_sf_trunc}. '
                f'Sorted by number of referencing functions. This answers "who uses this '
                f'URL / path / key?" -- a starting point for tracing data flow to its use '
                f'sites.</p>'
                f'<table><thead><tr><th>String</th><th>Address</th><th>Refs</th>'
                f'<th>Referencing function(s)</th></tr></thead>'
                f'<tbody>{"".join(_sf_rows)}</tbody></table></div>'
            )
except Exception:
    strfunc_panel = ""

strings_tab = f"""
<div class="c">
  <h2>String Extraction Stats</h2>
  <table class="kv">
    <tbody>
      <tr><td>ASCII strings</td><td>{ss['ascii']:,}</td></tr>
      <tr><td>UTF-16LE strings</td><td>{ss['utf16le']:,}</td></tr>
      <tr><td>UTF-16BE strings</td><td>{ss['utf16be']:,}</td></tr>
    </tbody>
  </table>
  <p style="color: var(--text-secondary); font-size: 13px;">
    Full string lists: <code>00-triage/strings-ascii.txt</code>,
    <code>00-triage/strings-utf16le.txt</code>,
    <code>00-triage/strings-utf16be.txt</code>
    &middot; FLOSS decoded strings: <code>10-pe/floss.txt</code>
  </p>
</div>
{strfunc_panel}
{_signsrch_hits_panel}
"""

# ---------------- Capabilities tab --------------------------------------------
capa = S["capa"]
att_pills = "".join(
    pill(f"{a['id']} -- {a['technique'] or '?'}", "high")
    for a in capa["attack"][:50]
)
mbc_pills = "".join(
    pill(f"{b['id']} -- {b['behavior'] or '?'}", "med")
    for b in capa["mbc"][:50]
)
ns_rows = "".join(
    f"<tr><td><code>{esc(k)}</code></td><td>{v}</td></tr>"
    for k, v in sorted(capa["namespaces"].items(), key=lambda kv: -kv[1])
)
rule_rows = "".join(
    f"<tr><td><code>{esc(r['name'])}</code></td><td><code>{esc(r['namespace'])}</code></td><td>{esc(r['scope'])}</td></tr>"
    for r in capa["rules"][:500]
)

# v3.0.14 (audit-18 C9-C11) =================================================
# Capabilities tab additions: per-rule evidence dropdowns + ATT&CK and MBC
# aggregation tables. Surfaces audit-16 F4-F6 -vv rule evidence captured
# into capa.json -- the per-match function VAs and feature counts that the
# 85-summary.sh audit-18 schema additions parse out.
# ============================================================================

# C9: per-rule evidence dropdowns (collapsible). Each rule with match data
# becomes a <details> element showing top-20 match VAs + feature counts.
def _capa_rule_evidence_html(rule):
    _evidence = rule.get("evidence", []) or []
    _mc = int(rule.get("match_count", 0))
    if not _evidence and _mc == 0:
        return ""
    if not _evidence:
        return f'<span class="muted" style="font-size:12px">{_mc} match{"es" if _mc != 1 else ""} (locations not in JSON)</span>'
    _ev_rows = "".join(
        f'<tr><td><code>{esc(e.get("va", ""))}</code></td>'
        f'<td>{int(e.get("feature_count", 0))}</td></tr>'
        for e in _evidence
    )
    _mc_label = f"{_mc} match{'es' if _mc != 1 else ''}"
    if _mc > len(_evidence):
        _mc_label += f" (showing top {len(_evidence)})"
    return (
        f'<details><summary style="cursor:pointer">{_mc_label}</summary>'
        f'<table style="margin-top:6px">'
        f'<thead><tr><th>Address (VA)</th><th>Features</th></tr></thead>'
        f'<tbody>{_ev_rows}</tbody>'
        f'</table></details>'
    )

# Re-render rule_rows with evidence column when any rule has matches
_any_evidence = any(
    (r.get("match_count", 0) > 0) or r.get("evidence")
    for r in capa["rules"]
)
if _any_evidence:
    rule_rows = "".join(
        f"<tr>"
        f"<td><code>{esc(r['name'])}</code></td>"
        f"<td><code>{esc(r['namespace'])}</code></td>"
        f"<td>{esc(r['scope'])}</td>"
        f"<td>{_capa_rule_evidence_html(r)}</td>"
        f"</tr>"
        for r in capa["rules"][:500]
    )
    _rule_table_header = (
        '<thead><tr><th>Rule</th><th>Namespace</th>'
        '<th>Scope</th><th>Matches</th></tr></thead>'
    )
    _rule_table_colspan = 4
else:
    _rule_table_header = (
        '<thead><tr><th>Rule</th><th>Namespace</th>'
        '<th>Scope</th></tr></thead>'
    )
    _rule_table_colspan = 3

# C10: ATT&CK technique aggregation table (rule_count per technique)
_attack_rule_counts = capa.get("attack_rule_counts", {}) or {}
_attack_rows = ""
if _attack_rule_counts:
    # Pair technique IDs with names from capa["attack"]
    _att_id_to_name = {a.get("id", ""): a for a in capa.get("attack", [])}
    _att_sorted = sorted(_attack_rule_counts.items(), key=lambda kv: -kv[1])
    _attack_rows = "".join(
        f'<tr>'
        f'<td><code>{esc(_aid)}</code></td>'
        f'<td>{esc(_att_id_to_name.get(_aid, {}).get("technique", ""))}</td>'
        f'<td>{esc(_att_id_to_name.get(_aid, {}).get("tactic", ""))}</td>'
        f'<td style="text-align:right">{_count}</td>'
        f'</tr>'
        for _aid, _count in _att_sorted
    )
attack_aggregation_html = ""
if _attack_rows:
    attack_aggregation_html = f"""
<div class="c">
  <h2>ATT&amp;CK Technique Aggregation ({len(_attack_rule_counts)} unique techniques)</h2>
  <p style="color: var(--text-secondary); font-size: 13px;">
    Per-technique rule_count: how many capa rules cited this MITRE ATT&amp;CK technique.
    Higher counts indicate strong technique signal. Useful for prioritizing analysis
    of which techniques the binary most strongly exhibits.
  </p>
  <table>
    <thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Rule Count</th></tr></thead>
    <tbody>{_attack_rows}</tbody>
  </table>
</div>
"""

# C11: MBC behavior aggregation table
_mbc_rule_counts = capa.get("mbc_rule_counts", {}) or {}
_mbc_rows = ""
if _mbc_rule_counts:
    _mbc_id_to_entry = {b.get("id", ""): b for b in capa.get("mbc", [])}
    _mbc_sorted = sorted(_mbc_rule_counts.items(), key=lambda kv: -kv[1])
    _mbc_rows = "".join(
        f'<tr>'
        f'<td><code>{esc(_bid)}</code></td>'
        f'<td>{esc(_mbc_id_to_entry.get(_bid, {}).get("behavior", ""))}</td>'
        f'<td>{esc(_mbc_id_to_entry.get(_bid, {}).get("objective", ""))}</td>'
        f'<td style="text-align:right">{_count}</td>'
        f'</tr>'
        for _bid, _count in _mbc_sorted
    )
mbc_aggregation_html = ""
if _mbc_rows:
    mbc_aggregation_html = f"""
<div class="c">
  <h2>MBC Behavior Aggregation ({len(_mbc_rule_counts)} unique behaviors)</h2>
  <p style="color: var(--text-secondary); font-size: 13px;">
    Per-behavior rule_count: how many capa rules cited this MAEC/MBC malware
    behavior. MBC categorizes malware functionality at a behavior level,
    complementing ATT&amp;CK (techniques) and CAPEC (attack patterns).
  </p>
  <table>
    <thead><tr><th>ID</th><th>Behavior</th><th>Objective</th><th>Rule Count</th></tr></thead>
    <tbody>{_mbc_rows}</tbody>
  </table>
</div>
"""

capa_tab = f"""
<div class="c">
  <h2>MITRE ATT&amp;CK Techniques</h2>
  <div>{att_pills or '<em>None matched.</em>'}</div>
</div>
<div class="c">
  <h2>Malware Behavior Catalog (MBC)</h2>
  <div>{mbc_pills or '<em>None matched.</em>'}</div>
</div>
{attack_aggregation_html}
{mbc_aggregation_html}
<div class="c">
  <h2>Capability Namespaces ({len(capa['namespaces'])})</h2>
  <table>
    <thead><tr><th>Namespace</th><th>Rule count</th></tr></thead>
    <tbody>{ns_rows or '<tr><td colspan=2><em>No capa results.</em></td></tr>'}</tbody>
  </table>
</div>
<div class="c">
  <h2>All Matched Rules ({capa['rule_count']})</h2>
  <table>
    {_rule_table_header}
    <tbody>{rule_rows or f'<tr><td colspan={_rule_table_colspan}><em>No rules matched.</em></td></tr>'}</tbody>
  </table>
</div>
"""

# ---------------- v2.5.0: Manalyze + peframe + signsrch sections --------------
# Built as standalone HTML chunks then appended to capa_tab below.
_mz = S.get("manalyze", {}) or {}
manalyze_section = ""
if _mz.get("ran"):
    _mz_findings = "".join(
        f"<li>{esc(f)}</li>" for f in _mz.get("plugin_findings", [])
    ) or "<li><em>No flagged plugins.</em></li>"
    _mz_imports = "".join(
        f"<li><code>{esc(i)}</code></li>"
        for i in _mz.get("suspicious_imports", [])[:50]
    ) or "<li><em>None.</em></li>"
    _mz_packers = "".join(
        f"<li>{esc(p)}</li>" for p in _mz.get("packer_hits", [])
    ) or "<li><em>None.</em></li>"
    manalyze_section = f"""
<div class="c">
  <h2>Manalyze (PE heuristic analyzer)</h2>
  <h3>Plugin findings ({len(_mz.get('plugin_findings', []))})</h3>
  <ul>{_mz_findings}</ul>
  <h3>Suspicious imports ({len(_mz.get('suspicious_imports', []))})</h3>
  <ul>{_mz_imports}</ul>
  <h3>Packer hits ({len(_mz.get('packer_hits', []))})</h3>
  <ul>{_mz_packers}</ul>
</div>
"""

_pf = S.get("peframe", {}) or {}
peframe_section = ""
if _pf.get("ran"):
    _pf_packers = ", ".join(esc(p) for p in _pf.get("packers", [])) or "<em>None.</em>"
    _pf_antidbg = ", ".join(esc(p) for p in _pf.get("antidbg", [])) or "<em>None.</em>"
    _pf_antivm  = ", ".join(esc(p) for p in _pf.get("antivm", []))  or "<em>None.</em>"
    _pf_apis = "".join(
        f"<li><code>{esc(a)}</code></li>"
        for a in _pf.get("suspicious_apis", [])[:50]
    ) or "<li><em>None.</em></li>"
    peframe_section = f"""
<div class="c">
  <h2>peframe (PE behavioral analyzer)</h2>
  <table class="kv"><tbody>
    <tr><td>Packers</td><td>{_pf_packers}</td></tr>
    <tr><td>Anti-debug</td><td>{_pf_antidbg}</td></tr>
    <tr><td>Anti-VM</td><td>{_pf_antivm}</td></tr>
    <tr><td>URLs in strings</td><td>{_pf.get('url_count', 0)}</td></tr>
    <tr><td>Office macros</td><td>{"yes" if _pf.get("macros") else "no"}</td></tr>
  </tbody></table>
  <h3>Suspicious APIs ({len(_pf.get('suspicious_apis', []))})</h3>
  <ul>{_pf_apis}</ul>
</div>
"""

_ss = S.get("signsrch", {}) or {}
signsrch_section = ""
if _ss.get("ran"):
    _ss_titles = "".join(
        f"<li>{esc(t)}</li>" for t in _ss.get("top_titles", [])
    ) or "<li><em>No signature hits.</em></li>"
    signsrch_section = f"""
<div class="c">
  <h2>signsrch (binary signature scanner)</h2>
  <p>Total hits: <strong>{_ss.get('hits', 0)}</strong></p>
  <h3>Top unique algorithms / signatures</h3>
  <ul>{_ss_titles}</ul>
</div>
"""

# Append v2.5.0 sections to the Capabilities tab content
capa_tab = capa_tab + manalyze_section + peframe_section + signsrch_section

# ---------------- v2.5.0: Vulnerabilities (CWE) tab ---------------------------
_cwe = S.get("cwe_checker", {}) or {}
cwe_tab = ""
if _cwe.get("ran"):
    _by_cwe_rows = "".join(
        f"<tr><td><code>{esc(k)}</code></td><td>{v}</td></tr>"
        for k, v in sorted(_cwe.get("by_cwe", {}).items(), key=lambda kv: -kv[1])
    ) or "<tr><td colspan=2><em>No CWE hits.</em></td></tr>"
    _warn_rows = ""
    for w in _cwe.get("warnings", [])[:200]:
        _addrs = ", ".join(esc(str(a)) for a in (w.get("addresses") or []))
        _warn_rows += (
            f"<tr><td><code>{esc(w.get('name',''))}</code></td>"
            f"<td>{esc(w.get('description',''))}</td>"
            f"<td><code>{_addrs}</code></td></tr>"
        )
    if not _warn_rows:
        _warn_rows = "<tr><td colspan=3><em>No warnings.</em></td></tr>"
    cwe_tab = f"""
<div class="c">
  <h2>cwe_checker findings</h2>
  <p>Total hits: <strong>{_cwe.get('total_hits', 0)}</strong></p>
  <h3>By CWE class</h3>
  <table>
    <thead><tr><th>CWE</th><th>Hit count</th></tr></thead>
    <tbody>{_by_cwe_rows}</tbody>
  </table>
</div>
<div class="c">
  <h2>Warnings (first 200)</h2>
  <table>
    <thead><tr><th>CWE</th><th>Description</th><th>Addresses</th></tr></thead>
    <tbody>{_warn_rows}</tbody>
  </table>
</div>
"""

# ---------------- Signatures tab ----------------------------------------------
yara_pills = "".join(pill(y, "crit") for y in S["yara_hits"])
clamav_pills = "".join(pill(y, "crit") for y in S["clamav_hits"])

auth_table = build_kv_rows([
    ("Signature present", "YES" if auth.get("present") else "NO"),
    ("Signature valid", "YES" if auth.get("valid") else ("NO" if auth.get("valid") is False else "N/A")),
    ("Signer CN", esc(auth.get("signer") or "")),
])
auth_raw = esc(auth.get("raw", "")) or "<em>No output.</em>"

sig_tab = f"""
<div class="c">
  <h2>YARA Matches ({len(S['yara_hits'])})</h2>
  <div>{yara_pills or '<em>No YARA rules matched.</em>'}</div>
</div>
<div class="c">
  <h2>ClamAV Hits ({len(S['clamav_hits'])})</h2>
  <div>{clamav_pills or '<em>No ClamAV detections.</em>'}</div>
</div>
<div class="c">
  <h2>Authenticode Verification</h2>
  <table class="kv"><tbody>{auth_table}</tbody></table>
  <details><summary>Raw osslsigncode output</summary><pre>{auth_raw}</pre></details>
</div>
<div class="c">
  <h2>Detect It Easy (DIE)</h2>
  <pre>{esc(chr(10).join(die.get('findings', [])) or '--')}</pre>
</div>
"""

# ---------------- IOCs tab ----------------------------------------------------
ioc_json = None
iocpath = os.path.join(OUTDIR, "80-iocs", "_iocs.json")
if os.path.isfile(iocpath):
    try:
        with open(iocpath, encoding="utf-8") as f:
            ioc_json = json.load(f)
    except Exception:
        ioc_json = None

ioc_blocks = []
if ioc_json:
    for cat in sorted(k for k in ioc_json.keys() if k != "_meta"):
        entries = ioc_json[cat]
        if not entries:
            continue
        # v3.7.3 (audit-31 C2): each entry carries ioc_class of "behavioral" or
        # "infrastructure" (cert / schema / platform hosts). Show behavioral
        # indicators first and tag infrastructure rows so the analyst reads the
        # behavioral set without the cert/schema clutter mixed in.
        def _cls(e):
            return e.get("ioc_class", "behavioral")
        ordered = sorted(entries, key=lambda e: (0 if _cls(e) == "behavioral" else 1, e["value"]))
        n_infra = sum(1 for e in entries if _cls(e) == "infrastructure")
        def _row(e):
            infra = _cls(e) == "infrastructure"
            tag = ('<span style="color:var(--text-muted);font-size:11px;border:1px solid var(--border);'
                   'border-radius:3px;padding:0 4px;margin-left:6px;">infra</span>') if infra else ''
            style = ' style="opacity:0.7"' if infra else ''
            return (f"<tr{style}><td><code>{esc(e['value'])}</code>{tag}</td>"
                    f"<td style='color:var(--text-muted);font-size:12px'>{esc(', '.join(e['sources']))}</td></tr>")
        rows = "".join(_row(e) for e in ordered[:500])
        _infra_note = (f" &middot; <span style='color:var(--text-secondary);font-size:12px'>"
                       f"{n_infra} infrastructure (cert / schema / platform)</span>") if n_infra else ""
        ioc_blocks.append(f"""
        <div class="c">
          <h2>{esc(cat.replace('_', ' ').title())} ({len(entries)}){_infra_note}</h2>
          <table>
            <thead><tr><th>Value</th><th>Source(s)</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
        """)
ioc_tab = "\n".join(ioc_blocks) or "<div class='c'><p><em>No IOCs extracted.</em></p></div>"

# v3.3.0 (audit-24 A4.1): finding-driven deepening panel.
# If the .NET deobfuscation deepening pass ran (_deepened/), surface the IOCs
# found in the CLEANED assembly and highlight any that did NOT appear in the
# primary run -- these are indicators that obfuscation had hidden from the
# first pass. This is the payoff of adaptive re-analysis: it makes the
# "what did deobfuscation reveal?" question a visible answer rather than
# something the analyst has to diff by hand.
deepened_dir = os.path.join(OUTDIR, "_deepened")
deepened_ioc_path = os.path.join(deepened_dir, "80-iocs", "_iocs.json")
if os.path.isfile(deepened_ioc_path):
    try:
        with open(deepened_ioc_path, encoding="utf-8") as f:
            deep_json = json.load(f)
    except Exception:
        deep_json = None
    if deep_json:
        # Build the set of primary-run IOC values for delta comparison.
        primary_values = set()
        if ioc_json:
            for cat in ioc_json:
                if cat == "_meta":
                    continue
                for e in ioc_json[cat]:
                    primary_values.add(e.get("value", ""))
        deep_blocks = []
        new_count = 0
        for cat in sorted(k for k in deep_json.keys() if k != "_meta"):
            entries = deep_json[cat]
            if not entries:
                continue
            rows = []
            for e in entries[:500]:
                val = e.get("value", "")
                is_new = val not in primary_values
                if is_new:
                    new_count += 1
                badge = (' <span class="pill high" style="font-size:10px">NEW after deobf</span>'
                         if is_new else "")
                rows.append(
                    f"<tr><td><code>{esc(val)}</code>{badge}</td>"
                    f"<td style='color:var(--text-muted);font-size:12px'>"
                    f"{esc(', '.join(e.get('sources', [])))}</td></tr>"
                )
            deep_blocks.append(
                f'<div class="c"><h3>{esc(cat.replace("_", " ").title())} '
                f'({len(entries)})</h3><table><thead><tr><th>Value</th>'
                f'<th>Source(s)</th></tr></thead><tbody>{"".join(rows)}</tbody>'
                f'</table></div>'
            )
        if deep_blocks:
            ioc_tab = (
                '<div class="note" style="border-left-color: var(--accent);">'
                '<strong>Finding-driven deepening (A4.1):</strong> the .NET assembly '
                'was deobfuscated (de4dot), and IOC extraction was re-run on the '
                f'cleaned assembly. It surfaced <strong>{new_count}</strong> indicator(s) '
                'not present in the primary pass (badged <span class="pill high" '
                'style="font-size:10px">NEW after deobf</span> below). These were '
                'likely hidden by string obfuscation in the original.'
                '</div>'
                + ioc_tab
                + '<div class="c"><h2>Deepened IOCs (from deobfuscated assembly)</h2>'
                '<p style="color:var(--text-secondary);font-size:13px">Extracted from '
                '<code>_deepened/80-iocs/</code> after de4dot deobfuscation.</p></div>'
                + "".join(deep_blocks)
            )

# ---------------- Decompilation tab -------------------------------------------
ghidra_size = S["ghidra"]["dump_size_bytes"]
dotnet_count = S["dotnet"]["cs_file_count"]

# v3.0.7 (audit-11 C1) - enrich .NET decompilation section.
# Pre-v3.0.7 the section emitted just "X .cs files in path". Operators
# couldn't see WHICH files, what classes / namespaces, or whether dnSpyEx
# (a second decompiler perspective) ran successfully. The enriched section
# now shows: a manifest of top .cs files by size with hyperlinks; a
# namespace-tree summary; the dnSpyEx pass status; the de4dot detection
# preview; the monodis IL header status.

# --- Build .cs manifest from the ilspy output dir ---
import os as _os_dn
dotnet_section_extra = ""
ilspy_dir = _os_dn.path.join(OUTDIR, "20-dotnet", "ilspy")
if _os_dn.path.isdir(ilspy_dir):
    cs_files = []
    for root, dirs, files in _os_dn.walk(ilspy_dir):
        for f in files:
            if f.endswith(".cs"):
                full = _os_dn.path.join(root, f)
                rel = _os_dn.path.relpath(full, ilspy_dir)
                try:
                    sz = _os_dn.path.getsize(full)
                except OSError:
                    sz = 0
                cs_files.append((rel, sz))
    if cs_files:
        cs_files.sort(key=lambda x: -x[1])  # largest first

        # Namespace summary: derive from path structure (ilspycmd organizes
        # output into subdirectories matching namespace components).
        namespaces = {}
        for rel, _sz in cs_files:
            ns_parts = _os_dn.path.dirname(rel).split(_os_dn.sep)
            ns = ".".join(p for p in ns_parts if p) or "(global)"
            namespaces[ns] = namespaces.get(ns, 0) + 1
        ns_rows = "".join(
            f"<tr><td><code>{esc(ns)}</code></td><td>{count}</td></tr>"
            for ns, count in sorted(namespaces.items(), key=lambda x: (-x[1], x[0]))[:30]
        )

        # Top-30 manifest by size with hyperlinks
        manifest_rows = "".join(
            f'<tr><td><a href="20-dotnet/ilspy/{esc(rel)}">'
            f'<code>{esc(rel)}</code></a></td><td>{fmt_bytes(sz)}</td></tr>'
            for rel, sz in cs_files[:30]
        )
        more_note = (
            f"<p><em>{len(cs_files) - 30} additional file(s) not shown; "
            f"see <code>20-dotnet/ilspy/</code>.</em></p>"
            if len(cs_files) > 30 else ""
        )
        dotnet_section_extra = f"""
        <h3 style="color:var(--accent);margin-top:18px">Namespace summary
        ({len(namespaces)} namespace(s))</h3>
        <table>
          <thead><tr><th>Namespace</th><th>Files</th></tr></thead>
          <tbody>{ns_rows}</tbody>
        </table>
        <h3 style="color:var(--accent);margin-top:18px">Largest .cs files
        (top 30 of {len(cs_files)})</h3>
        <table>
          <thead><tr><th>Path</th><th>Size</th></tr></thead>
          <tbody>{manifest_rows}</tbody>
        </table>
        {more_note}
        """

# --- dnSpyEx pass status ---
dnspyex_status = ""
dnspy_orig = _os_dn.path.join(OUTDIR, "26-dnspyex", "original")
if _os_dn.path.isdir(dnspy_orig):
    dnspy_cs_count = 0
    for root, _dirs, files in _os_dn.walk(dnspy_orig):
        dnspy_cs_count += sum(1 for f in files if f.endswith(".cs"))
    dnspy_status_color = "var(--accent)" if dnspy_cs_count > 0 else "#f87171"
    dnspy_status_text = (
        f"{dnspy_cs_count} .cs files produced"
        if dnspy_cs_count > 0
        else "0 .cs produced (see diagnostic below)"
    )
    # v3.0.8 (audit-12 B2) - when 0 .cs produced, surface the dnspyex.log
    # content into the report. dnSpy.Console emits decompiled C# to stdout
    # (which run_tool captures to .log) when it can't write project files.
    # If the log contains substantial text and the output dir is empty,
    # the operator needs to see WHY - both the log content (likely C# text)
    # and a clear explanation that --sln-name + --project-guid combination
    # is what triggers project-file output.
    dnspy_diagnostic = ""
    if dnspy_cs_count == 0:
        dnspy_log_path = _os_dn.path.join(OUTDIR, "26-dnspyex", "dnspyex.log")
        if _os_dn.path.isfile(dnspy_log_path):
            try:
                log_size = _os_dn.path.getsize(dnspy_log_path)
                with open(dnspy_log_path, encoding="utf-8", errors="replace") as f:
                    log_head = f.read(8000)
                # Heuristic: if log contains C# tokens, dnSpy emitted to stdout
                cs_signal = sum(log_head.count(token) for token in
                                ("namespace ", "class ", "public ", "private ",
                                 "void ", "using "))
                diag_msg = (
                    "<p style='color:#f87171'><b>Diagnostic:</b> dnSpyEx "
                    "produced 0 .cs files. dnSpy.Console emits decompiled "
                    "output to stdout (captured to dnspyex.log) instead of "
                    "files when the project-layout flags are not both set. "
                    "Both <code>--project-guid</code> AND <code>--sln-name</code> "
                    "are required (per dnSpy.Console/Program.cs source). "
                    "If the log content below contains C# code, dnSpy ran "
                    "successfully but wrote to stdout instead of files.</p>"
                ) if cs_signal > 5 else (
                    "<p style='color:#f87171'><b>Diagnostic:</b> dnSpyEx "
                    "produced 0 .cs files. Log preview below shows the "
                    "actual error or output.</p>"
                )
                dnspy_diagnostic = (
                    f"{diag_msg}"
                    f"<details><summary>"
                    f"<code>26-dnspyex/dnspyex.log</code> preview "
                    f"({fmt_bytes(log_size)} total, first 8000 chars shown)"
                    f"</summary><pre>{esc(log_head)}</pre></details>"
                )
            except Exception as _e:
                dnspy_diagnostic = (
                    f"<p style='color:#f87171'>Diagnostic unavailable: "
                    f"could not read dnspyex.log ({_e}).</p>"
                )

    dnspyex_status = (
        f'<div class="c">'
        f'<h2>dnSpyEx (Second Decompiler Perspective)</h2>'
        f'<p>dnSpyEx is a parallel decompiler perspective on the same assembly. '
        f'Disagreements between ilspycmd and dnSpyEx output can flag obfuscation '
        f'that fooled one but not the other.</p>'
        f'<p>Status: <span style="color:{dnspy_status_color}"><b>'
        f'{dnspy_status_text}</b></span></p>'
        f'<p>Location: <code>26-dnspyex/original/</code></p>'
        f'{dnspy_diagnostic}'
        f'</div>'
    )

# --- de4dot detection preview ---
de4dot_section = ""
de4dot_detect_path = _os_dn.path.join(OUTDIR, "22-de4dot", "detection.txt")
if _os_dn.path.isfile(de4dot_detect_path):
    try:
        with open(de4dot_detect_path, encoding="utf-8", errors="replace") as f:
            d4_content = f.read(5000)
        de4dot_section = (
            f'<div class="c">'
            f'<h2>de4dot Obfuscator Detection</h2>'
            f'<p>de4dot scans for known .NET obfuscators (ConfuserEx, '
            f'Eazfuscator, KoiVM/VMProtect, etc.). Detection output:</p>'
            f'<pre>{esc(d4_content)}</pre>'
            f'</div>'
        )
    except Exception:
        pass

# --- monodis IL header preview ---
monodis_section = ""
monodis_path = _os_dn.path.join(OUTDIR, "20-dotnet", "monodis.il")
if _os_dn.path.isfile(monodis_path):
    try:
        with open(monodis_path, encoding="utf-8", errors="replace") as f:
            mono_content = f.read(3000)
        monodis_section = (
            f'<div class="c">'
            f'<h2>monodis IL Header (preview)</h2>'
            f'<p>monodis emits IL bytecode + metadata. First 3000 chars of '
            f'<code>20-dotnet/monodis.il</code>:</p>'
            f'<pre>{esc(mono_content)}</pre>'
            f'</div>'
        )
    except Exception:
        pass

# ============================================================================
# v3.5.0 (audit-26 A5.3): inline decompiled-pseudocode panel + .NET decompiler
# comparison. The Decompilation tab previously showed only file pointers; this
# renders the actual Ghidra pseudocode inline (top functions by size) and a
# side-by-side view of the .NET decompiler perspectives (ilspycmd vs dnSpyEx).
# ============================================================================
import glob as _glob_dc

def _report_parse_decomp():
    """Return the list of decompiled functions for this binary.

    Prefers 30-ghidra/dump-parsed.json (written by 89-viz's parser, A4.4).
    Falls back to parsing the *.ghidra-dump.txt directly when viz was skipped
    (SKIP_VIZ=1), so the Decompilation tab does not depend on the viz stage.
    """
    gd = os.path.join(OUTDIR, "30-ghidra")
    # 1. Prefer the parsed JSON.
    pj = os.path.join(gd, "dump-parsed.json")
    if os.path.isfile(pj):
        try:
            with open(pj, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data.get("decompilation"), list):
                return data["decompilation"]
        except Exception:
            pass
    # 2. Fallback: parse the raw dump directly (same Section-13 logic).
    hits = sorted(_glob_dc.glob(os.path.join(gd, "*.ghidra-dump.txt")))
    if not hits:
        return []
    try:
        with open(hits[0], encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except Exception:
        return []
    out = []
    import re as _re_dc
    sec_re = _re_dc.compile(r'^\s*SECTION\s+(\d+)\s+-\s+(.*)$')
    # v3.7.2 (audit-30 A1): accept BARE hex ("00402051") as well as "0x"-prefixed.
    # GhidraDump.py's fmt_addr() emits bare hex; the pre-v3.7.2 regex required
    # "0x" and matched nothing on real dumps, so the inline decompilation panel
    # fell back to the "no data" placeholder.
    hdr_re = _re_dc.compile(r'^###\s+(\S.*?)\s+@\s+((?:0x)?[0-9a-fA-F]+)\s+\((\d+)\s+bytes\)\s*$')
    current = None
    cur = None
    def flush():
        if cur is not None:
            code = "\n".join(cur["code_lines"]).rstrip()
            st = cur["status"]
            if st == "ok" and not code.strip():
                st = "empty"
            out.append({"name": cur["name"], "addr": cur["addr"],
                        "bytes": cur["bytes"], "code": code, "status": st})
    for ln in lines:
        m = sec_re.match(ln)
        if m:
            if current == 13:
                flush(); cur = None
            current = int(m.group(1)); continue
        if current != 13:
            continue
        hm = hdr_re.match(ln)
        if hm:
            flush()
            cur = {"name": hm.group(1), "addr": hm.group(2),
                   "bytes": int(hm.group(3)), "code_lines": [], "status": "ok"}
            continue
        if cur is None:
            continue
        body = ln[4:] if ln.startswith("    ") else ln
        st = body.strip()
        if st.startswith("// decompile failed") or st.startswith("// decompile exception"):
            cur["status"] = "failed"; continue
        if st.startswith("// skipped:"):
            cur["status"] = "skipped"; continue
        if st.startswith("--- Decompilation complete"):
            continue
        cur["code_lines"].append(body)
    if current == 13:
        flush()
    return out

ghidra_pseudocode_panel = ""
try:
    _decomp_funcs = _report_parse_decomp()
    # Keep only functions that actually decompiled to code.
    _ok_funcs = [d for d in _decomp_funcs if d.get("status") == "ok" and d.get("code", "").strip()]
    if _ok_funcs:
        TOP_DECOMP = 15
        _ok_sorted = sorted(_ok_funcs, key=lambda d: d.get("bytes", 0), reverse=True)
        _shown = _ok_sorted[:TOP_DECOMP]
        _blocks = []
        for d in _shown:
            _blocks.append(
                f'<details style="margin:8px 0"><summary style="cursor:pointer;'
                f'font-family:Consolas,monospace;color:var(--accent)">'
                f'{esc(d["name"])} <span style="color:var(--text-muted)">@ '
                f'{esc(d["addr"])} ({d["bytes"]} bytes)</span></summary>'
                f'<pre style="max-height:480px;overflow:auto"><code>{esc(d["code"])}'
                f'</code></pre></details>'
            )
        _trunc = (f' (showing top {TOP_DECOMP} of {len(_ok_funcs)} by size)'
                  if len(_ok_funcs) > TOP_DECOMP else "")
        _skipped_n = sum(1 for d in _decomp_funcs if d.get("status") == "skipped")
        _failed_n = sum(1 for d in _decomp_funcs if d.get("status") == "failed")
        _stat_note = ""
        if _skipped_n or _failed_n:
            _stat_note = (f'<p style="color:var(--text-secondary);font-size:13px">'
                          f'{_skipped_n} function(s) skipped (exceeded size cap), '
                          f'{_failed_n} failed to decompile.</p>')
        ghidra_pseudocode_panel = (
            f'<div class="c"><h2>Decompiled Pseudocode (Ghidra)</h2>'
            f'<p>C-like pseudocode from Ghidra\'s DecompInterface{_trunc}. '
            f'Click a function to expand.</p>{_stat_note}'
            f'{"".join(_blocks)}</div>'
        )
    else:
        ghidra_pseudocode_panel = (
            '<div class="c"><h2>Decompiled Pseudocode (Ghidra)</h2>'
            '<p><em>No decompiled functions available. Ghidra Section 13 was '
            'empty, skipped (ghidra.dump.skip_decomp=1), or the binary has no '
            'decompilable functions.</em></p></div>'
        )
except Exception:
    ghidra_pseudocode_panel = ""

# .NET decompiler comparison: ilspycmd vs dnSpyEx coverage side by side.
dotnet_decompiler_comparison = ""
try:
    if S.get("dotnet", {}).get("cs_file_count") or S.get("de4dot", {}).get("deobfuscated"):
        _ilspy_dir = os.path.join(OUTDIR, "20-dotnet", "ilspy")
        _dnspy_dir = os.path.join(OUTDIR, "20-dotnet", "dnspy")
        def _count_cs(d):
            if not os.path.isdir(d):
                return None
            try:
                return sum(1 for _r, _ds, _fs in os.walk(d) for _f in _fs if _f.endswith(".cs"))
            except Exception:
                return None
        _ilspy_n = _count_cs(_ilspy_dir)
        _dnspy_n = _count_cs(_dnspy_dir)
        def _cell(n):
            if n is None:
                return '<span style="color:var(--text-muted)">not run</span>'
            return f'<b>{n}</b> .cs file(s)'
        dotnet_decompiler_comparison = (
            '<div class="c"><h2>.NET Decompiler Comparison</h2>'
            '<p>Two independent decompiler perspectives on the same assembly. '
            'When they disagree, cross-reading both catches decompiler-specific '
            'artifacts and obfuscation-induced errors.</p>'
            '<table><thead><tr><th>Decompiler</th><th>Output</th>'
            '<th>Location</th></tr></thead><tbody>'
            f'<tr><td>ilspycmd</td><td>{_cell(_ilspy_n)}</td>'
            f'<td><code>20-dotnet/ilspy/</code></td></tr>'
            f'<tr><td>dnSpyEx</td><td>{_cell(_dnspy_n)}</td>'
            f'<td><code>20-dotnet/dnspy/</code></td></tr>'
            '</tbody></table></div>'
        )
except Exception:
    dotnet_decompiler_comparison = ""

# =============================================================================
# v3.7.0 (audit-28): three global-RE panels derived from the summary keys
# code_structure (Feature 3), function_purpose (Feature 2), data_flow (F1).
# All are rendered in the Decompilation tab, below the pseudocode.
# =============================================================================

# Feature 3 -- structural characterization panel.
code_structure_panel = ""
try:
    _cs = S.get("code_structure", {}) or {}
    _cs_funcs = _cs.get("functions", [])
    if _cs_funcs:
        _cs_tot = _cs.get("totals", {})
        TOP_CS = 25
        _cs_rows = []
        for _f in _cs_funcs[:TOP_CS]:
            _m = _f.get("metrics", {})
            _sigs = _f.get("signatures", [])
            _sig_html = ""
            if _sigs:
                _badge = {
                    "xor_in_loop": ('#e74c3c', 'XOR-in-loop'),
                    "stack_string": ('#e67e22', 'stack-string'),
                    "high_complexity": ('#9b59b6', 'high-complexity'),
                }
                _sig_html = " ".join(
                    f'<span style="color:{_badge.get(s,("#888",s))[0]};font-weight:bold;font-size:11px">'
                    f'{esc(_badge.get(s,("#888",s))[1])}</span>'
                    for s in _sigs
                )
            _cs_rows.append(
                f'<tr><td><code>{esc(_f.get("name",""))}</code></td>'
                f'<td>{_m.get("cyclomatic_proxy",0)}</td>'
                f'<td>{_m.get("loop_count",0)}</td>'
                f'<td>{_m.get("branch_count",0)}</td>'
                f'<td>{_m.get("call_count",0)}</td>'
                f'<td>{_m.get("max_nesting",0)}</td>'
                f'<td>{_sig_html}</td></tr>'
            )
        _cs_trunc = (f' (showing top {TOP_CS} of {len(_cs_funcs)} by complexity)'
                     if len(_cs_funcs) > TOP_CS else "")
        _cs_flags = []
        if _cs_tot.get("with_xor_in_loop"):
            _cs_flags.append(f'{_cs_tot["with_xor_in_loop"]} with XOR-in-loop (possible crypto/encoding)')
        if _cs_tot.get("with_stack_strings"):
            _cs_flags.append(f'{_cs_tot["with_stack_strings"]} with stack-string construction (possible obfuscation)')
        if _cs_tot.get("high_complexity"):
            _cs_flags.append(f'{_cs_tot["high_complexity"]} high-complexity (cyclomatic proxy >= 10)')
        _cs_flag_html = (f'<p style="font-size:13px">{"; ".join(_cs_flags)}.</p>'
                         if _cs_flags else "")
        code_structure_panel = (
            f'<div class="c"><h2>Structural Characterization ({_cs_tot.get("functions_characterized",0)})</h2>'
            f'<p style="color:var(--text-secondary);font-size:13px">Control-structure '
            f'metrics and recognized code-pattern signatures from a lightweight '
            f'textual analysis of the decompiled pseudocode{_cs_trunc}. Cyclomatic '
            f'proxy = branches + loops + 1 (a complexity indicator, not the formal '
            f'metric). Signature patterns are heuristic starting points, not '
            f'proof.</p>{_cs_flag_html}'
            f'<table><thead><tr><th>Function</th><th>Cyclo</th><th>Loops</th>'
            f'<th>Branches</th><th>Calls</th><th>Nesting</th><th>Signatures</th>'
            f'</tr></thead><tbody>{"".join(_cs_rows)}</tbody></table></div>'
        )
except Exception:
    code_structure_panel = ""

# Feature 2 -- function-purpose hypotheses panel.
function_purpose_panel = ""
try:
    _fp = S.get("function_purpose", []) or []
    if _fp:
        TOP_FP = 30
        _CONF_COLOR = {"High": "#27ae60", "Medium": "#e67e22",
                       "Low": "#e6b800", "Speculative": "#888"}
        _fp_rows = []
        for _p in _fp[:TOP_FP]:
            _conf = _p.get("confidence", "Speculative")
            _color = _CONF_COLOR.get(_conf, "#888")
            _ev = "; ".join(_p.get("evidence", []))
            _fp_rows.append(
                f'<tr><td><code>{esc(_p.get("name",""))}</code></td>'
                f'<td>{esc(_p.get("purpose",""))}</td>'
                f'<td><span style="color:{_color};font-weight:bold">{esc(_conf)}</span></td>'
                f'<td style="font-size:12px">{esc(_ev)}</td></tr>'
            )
        _fp_trunc = (f' (showing top {TOP_FP} of {len(_fp)} by confidence)'
                     if len(_fp) > TOP_FP else "")
        function_purpose_panel = (
            f'<div class="c"><h2>Function-Purpose Hypotheses ({len(_fp)})</h2>'
            f'<p style="color:var(--text-secondary);font-size:13px">Inferred purpose '
            f'per function, synthesized from the APIs it calls, the strings it '
            f'references, and its structural signatures, graded on a calibrated '
            f'confidence scale{_fp_trunc}. <span style="color:#27ae60;font-weight:bold">'
            f'High</span> = direct API evidence; '
            f'<span style="color:#e67e22;font-weight:bold">Medium</span> = one strong '
            f'structural signal; <span style="color:#e6b800;font-weight:bold">Low</span> '
            f'= indirect (string) signal; <span style="color:#888;font-weight:bold">'
            f'Speculative</span> = name or shape only. Hypotheses, not conclusions.</p>'
            f'<table><thead><tr><th>Function</th><th>Purpose</th><th>Confidence</th>'
            f'<th>Evidence</th></tr></thead><tbody>{"".join(_fp_rows)}</tbody></table></div>'
        )
except Exception:
    function_purpose_panel = ""

# Feature 1 -- data-flow (call-graph reachability) panel.
data_flow_panel = ""
try:
    _df = S.get("data_flow", []) or []
    if _df:
        TOP_DF = 40
        _SINK_COLOR = {"network-send": "#e74c3c", "file-write": "#e67e22",
                       "process-exec": "#c0392b"}
        _df_rows = []
        for _fl in _df[:TOP_DF]:
            _stype = _fl.get("sink_type", "")
            _color = _SINK_COLOR.get(_stype, "#888")
            _path = " &rarr; ".join(esc(p) for p in _fl.get("path", []))
            _df_rows.append(
                f'<tr><td><code>{esc(_fl.get("string","")[:50])}</code></td>'
                f'<td><code>{esc(_fl.get("source",""))}</code></td>'
                f'<td style="font-size:12px">{_path}</td>'
                f'<td><span style="color:{_color};font-weight:bold">{esc(_stype)}</span> '
                f'(<code>{esc(_fl.get("sink",""))}</code>)</td></tr>'
            )
        _df_trunc = (f' (showing top {TOP_DF} of {len(_df)})'
                     if len(_df) > TOP_DF else "")
        data_flow_panel = (
            f'<div class="c"><h2>Data-Flow Indicators ({len(_df)})</h2>'
            f'<p style="color:var(--text-secondary);font-size:13px">Call-graph '
            f'reachability from a string-referencing function (source) to a sink '
            f'that sends data out, writes a file, or executes a process{_df_trunc}. '
            f'<strong>This is static reachability, not taint-tracked data flow</strong>: '
            f'it shows a call path exists from the string\'s function to a sink, not '
            f'that the string\'s value provably reaches it. A lead to verify, not a '
            f'conclusion.</p>'
            f'<table><thead><tr><th>String</th><th>Source function</th>'
            f'<th>Call path</th><th>Sink</th></tr></thead>'
            f'<tbody>{"".join(_df_rows)}</tbody></table></div>'
        )
except Exception:
    data_flow_panel = ""

decomp_tab = f"""
<div class="c">
  <h2>Ghidra Comprehensive Dump</h2>
  <p>Dump size: {fmt_bytes(ghidra_size)}</p>
  <p>Location: <code>30-ghidra/{esc(fname)}.ghidra-dump.txt</code></p>
</div>
{ghidra_pseudocode_panel}
{code_structure_panel}
{function_purpose_panel}
{data_flow_panel}
<div class="c">
  <h2>.NET Decompilation (ilspycmd)</h2>
  <p>C# files produced: <b>{dotnet_count}</b></p>
  <p>Location: <code>20-dotnet/ilspy/</code></p>
  {
      f'<p><b>Deobfuscated pass:</b> {S["de4dot"]["deobfuscated_cs_count"]} .cs files'
      f' at <code>22-de4dot/deobfuscated-ilspy/</code></p>'
      if S.get("de4dot", {}).get("deobfuscated") else ""
  }
  {dotnet_section_extra}
</div>
{dotnet_decompiler_comparison}
{dnspyex_status}
{de4dot_section}
{monodis_section}
<div class="c">
  <h2>Alternative Disassembly (radare2, rizin, objdump, llvm-objdump)</h2>
  <p>Each disassembler writes its complete output under a dedicated directory for
     cross-verification:</p>
  <ul>
    <li><code>40-r2/</code> -- radare2 exhaustive command suite (aaa/aaaa)</li>
    <li><code>42-rizin/</code> -- rizin rz-bin metadata + disasm</li>
    <li><code>44-llvm/</code> -- llvm-objdump with all-headers + dwarf</li>
  </ul>
  <p style="color:var(--text-secondary);font-size:13px">
  <b>Note for .NET assemblies:</b> Native disassemblers analyze the PE shell
  + native CLR loader stub (<code>_CorExeMain</code> / <code>_CorDllMain</code>
  bootstrap). The managed CIL bytecode appears as raw data to native tools;
  CIL decompilation is performed by ilspycmd / dnSpyEx (see .NET Decompilation
  sections above). Empty/minimal native disasm output on a .NET assembly is
  expected and not an error.</p>
</div>
"""

# ---------------- Logs tab ----------------------------------------------------
# v3.0.7 (audit-11 C3) - Walk ALL stage directories, not just 90-logs.
# Pre-v3.0.7 the Logs tab scanned ONLY ${OUTDIR}/90-logs/ which contained
# only exiftool.log. Per-tool logs (ilspycmd.log, de4dot.log, dnspyex.log,
# r2-driver.log, ghidra logs, etc.) live under their own stage directories
# and were never picked up. The Logs tab effectively stopped after exiftool.
#
# Fix: walk the entire OUTDIR; collect every *.log file; group by stage
# prefix (00-, 10-, 12-, 14-, 16-, 17-, 18-, 20-, 22-, 24-, 26-, 30-, etc.);
# render as collapsible per-stage groups with per-log <details> entries.
import re as _re_logs
log_blocks_by_stage = {}
log_block_count = 0

if os.path.isdir(OUTDIR):
    for root, dirs, files in os.walk(OUTDIR):
        # Skip the 89-viz directory (not log content; visualizations are their own tab)
        if "89-viz" in dirs:
            dirs.remove("89-viz")
        for fn in files:
            # Only .log files are aggregated here. .txt outputs have their
            # own tabs (Decompilation, IOCs, etc.) and aren't logs.
            if not fn.endswith(".log"):
                continue
            fpath = os.path.join(root, fn)
            rel_path = os.path.relpath(fpath, OUTDIR)
            # Group key: top-level directory under OUTDIR (e.g., "20-dotnet",
            # "40-r2"). The 90-logs dir gets its own group.
            top_dir = rel_path.split(os.sep)[0] if os.sep in rel_path else "(root)"
            try:
                sz = os.path.getsize(fpath)
                with open(fpath, encoding="utf-8", errors="replace") as f:
                    content = f.read(50000)  # first 50KB
                if sz > 50000:
                    content += f"\n\n[... {sz - 50000} more bytes - see file on disk ...]"
                block = f"""
                <details>
                  <summary>{esc(rel_path)} -- {fmt_bytes(sz)}</summary>
                  <pre>{esc(content)}</pre>
                </details>
                """
                log_blocks_by_stage.setdefault(top_dir, []).append(block)
                log_block_count += 1
            except Exception:
                continue

if log_blocks_by_stage:
    # Render as collapsible per-stage <details> wrappers, sorted by stage prefix.
    # Stage dirs sort naturally because they're prefixed with two-digit numbers.
    grouped_logs = []
    for stage_dir in sorted(log_blocks_by_stage.keys()):
        blocks = log_blocks_by_stage[stage_dir]
        grouped_logs.append(
            f'<details open><summary><b>{esc(stage_dir)}</b> ({len(blocks)} log file(s))</summary>'
            f'<div style="margin-left:20px">{"".join(blocks)}</div>'
            f'</details>'
        )
    logs_tab = (
        "<div class='c'>"
        f"<h2>Per-tool Logs ({log_block_count})</h2>"
        "<p>Logs collected from all stage directories under this binary's output. "
        "Each stage's logs are grouped under a collapsible header. Logs over 50KB "
        "are truncated; full content available on disk.</p>"
        + "".join(grouped_logs)
        + "</div>"
    )
else:
    logs_tab = "<div class='c'><h2>Per-tool Logs</h2><em>No log files produced.</em></div>"

# ---------------- Obfuscation tab (v2.3.0, always visible) --------------------
# v3.0.10 (audit-14 E2) - lead with Unified Verdict from cross-tool
# obfuscator_unified aggregator (built in 85-summary.sh). Pre-v3.0.10
# the tab showed only de4dot + DIE rows; manalyze peid signatures and
# peframe packer detections were silently dropped at the report layer
# even when they had positive matches. The unified panel synthesizes
# all four sources into a single answer; the per-tool table below
# remains for audit-trail visibility.
d4 = S.get("de4dot", {}) or {}
_pk = S["die"].get("packer") or ""
_pr = S["die"].get("protector") or ""
_obf_uni = S.get("obfuscator_unified", {}) or {}
_obf_uni_sources = _obf_uni.get("sources", {}) or {}
_obf_mz = _obf_uni_sources.get("manalyze", {}) or {}
_obf_pf = _obf_uni_sources.get("peframe", {}) or {}

# Build the Unified Verdict header. When ANY source detected something,
# show a high-severity pill with the unified text. When all sources say
# "no detection", show a low-severity pill confirming the binary is not
# obfuscated. The "Unknown to de4dot but other sources also clean"
# case gets its own neutral pill so operators don't misread it as
# definitively "not obfuscated".
_uni_verdict_text = _obf_uni.get("unified_verdict", "")
_uni_any_detected = _obf_uni.get("any_detected", False)
if _uni_any_detected:
    _uni_pill = pill("OBFUSCATED / PACKED", "high")
    _uni_intro = (
        '<p>The cross-tool aggregator detected obfuscation, packing, or '
        'protection from at least one source. See the per-tool breakdown '
        'below for which tool flagged what; the deobfuscation artifacts '
        'panel further down shows what de4dot extracted.</p>'
    )
elif "Unknown Obfuscator" in _uni_verdict_text or "may use a custom" in _uni_verdict_text:
    _uni_pill = pill("inconclusive", "info")
    _uni_intro = (
        '<p>de4dot reports Unknown Obfuscator but no other source corroborated. '
        'The binary may use a custom or unrecognized obfuscation scheme, OR may '
        'simply not be obfuscated. Inspect the per-tool breakdown and the '
        'deobfuscation artifacts panel for context.</p>'
    )
else:
    _uni_pill = pill("not obfuscated", "low")
    _uni_intro = (
        '<p>None of the four signal sources (de4dot, DIE, manalyze peid, '
        'peframe) detected obfuscation, packing, or protection. The binary '
        'appears to be unmodified.</p>'
    )

unified_verdict_block = (
    '<div class="c">'
    '<h2>Unified Verdict</h2>'
    f'<p><strong>Status:</strong> {_uni_pill}</p>'
    f'<p><strong>Detail:</strong> {esc(_uni_verdict_text) if _uni_verdict_text else "(no signal)"}</p>'
    f'{_uni_intro}'
    '</div>'
)

obf_rows = []
# Row 1: de4dot detection
if d4.get("ran"):
    if d4.get("obfuscator"):
        obf_rows.append(("de4dot-cex", pill(d4["obfuscator"], "high"),
                         f"{d4.get('deobfuscated_cs_count', 0)} .cs files from deobfuscated assembly"))
    else:
        obf_rows.append(("de4dot-cex", pill("clean / unknown obfuscator", "info"),
                         "Ran but did not identify a supported obfuscator. This is"
                         " the expected result for non-obfuscated or custom-obfuscated assemblies."))
else:
    obf_rows.append(("de4dot-cex", pill("did not run", "low"),
                     "Non-.NET binary, or de4dot-cex not available at install time."))
# Row 2: DIE packer
if _pk:
    obf_rows.append(("DIE packer", pill(_pk, "high"),
                     "Detect It Easy identified a packer signature on this binary."))
else:
    obf_rows.append(("DIE packer", pill("none", "info"),
                     "No packer signature matched."))
# Row 3: DIE protector
if _pr:
    obf_rows.append(("DIE protector", pill(_pr, "high"),
                     "Detect It Easy identified a protector signature."))
else:
    obf_rows.append(("DIE protector", pill("none", "info"),
                     "No protector signature matched."))
# v3.0.10 (audit-14 E2) - Row 4+5: manalyze peid + manalyze packer.
# Pre-v3.0.10 manalyze's peid plugin output was discarded at the
# parser layer; even when it had a positive match the report didn't
# show it.
_mz_peid = _obf_mz.get("peid_signatures", []) or []
if _mz_peid:
    obf_rows.append(("manalyze peid", pill(", ".join(_mz_peid[:2]), "high"),
                     "PEiD signature(s) matched (manalyze peid plugin). PEiD is "
                     "the industry-standard signature DB; matches here often catch "
                     "packers/protectors that de4dot misses."))
else:
    obf_rows.append(("manalyze peid", pill("no signature match", "info"),
                     "PEiD signatures did not match. Either binary is not packed/"
                     "protected, or it uses a custom scheme not in the PEiD DB."))
_mz_packer = _obf_mz.get("packer_hits", []) or []
if _mz_packer:
    obf_rows.append(("manalyze packer", pill(", ".join(_mz_packer[:2]), "high"),
                     "manalyze packer plugin found suspicious section names/sizes "
                     "consistent with packed content."))
else:
    obf_rows.append(("manalyze packer", pill("clean", "info"),
                     "No packer-typical PE structural anomalies found."))
# v3.0.10 (audit-14 E2) - Row 6: peframe packer detections.
_pf_packers = _obf_pf.get("packers", []) or []
if _pf_packers:
    obf_rows.append(("peframe packer", pill(", ".join(_pf_packers[:2]), "high"),
                     "peframe identified one or more packer signatures."))
else:
    obf_rows.append(("peframe packer", pill("no detection", "info"),
                     "peframe did not identify a known packer."))
# Row 7: entropy
if ent["high_count"] > 0:
    obf_rows.append(("Section entropy", pill(f"{ent['high_count']} high-entropy", "high"),
                     "Sections with entropy above 7.0 often indicate packed or encrypted content."))
else:
    obf_rows.append(("Section entropy", pill("normal", "info"),
                     "No sections flagged as high-entropy."))

obf_rows_html = "".join(
    f"<tr><td><b>{esc(tool)}</b></td><td>{verdict}</td><td>{esc(note)}</td></tr>"
    for tool, verdict, note in obf_rows
)

# v3.0.8 (audit-12 D2) - Build de4dot artifacts block separately so we can
# render full detail. Pre-v3.0.8 only showed deobfuscated_cs_count and a
# pointer to the directory; the actual deobfuscation output (assembly size
# delta, embedded resource extraction, presence of cleaner method bodies)
# was never surfaced. When de4dot detects "Unknown Obfuscator" but the
# deobfuscation pass still produces a usable output assembly (audit-12 D1),
# THIS block surfaces those artifacts so operators can see what de4dot
# extracted even on unrecognized protectors.
de4dot_artifacts_block = '<div class="c"><h2>Deobfuscation Artifacts</h2>'
import os as _os_d4
d4_deobf_dir = _os_d4.path.join(OUTDIR, "22-de4dot", "deobfuscated")
deobf_files_present = []
if _os_d4.path.isdir(d4_deobf_dir):
    for fn in _os_d4.listdir(d4_deobf_dir):
        fp = _os_d4.path.join(d4_deobf_dir, fn)
        if _os_d4.path.isfile(fp):
            deobf_files_present.append((fn, _os_d4.path.getsize(fp)))

if deobf_files_present:
    rows = "".join(
        f'<tr><td><code>22-de4dot/deobfuscated/{esc(fn)}</code></td>'
        f'<td>{fmt_bytes(sz)}</td></tr>'
        for fn, sz in sorted(deobf_files_present)
    )
    # Compute size delta vs original
    orig_sz = S["file"]["size"]
    deobf_total = sum(s for _, s in deobf_files_present)
    delta_pct = ((deobf_total - orig_sz) / orig_sz * 100) if orig_sz else 0
    delta_label = (
        f"+{delta_pct:.1f}%" if delta_pct >= 0 else f"{delta_pct:.1f}%"
    )
    delta_color = (
        "var(--accent)" if abs(delta_pct) > 5 else "var(--text-secondary)"
    )

    obf_detected = (S.get("de4dot") or {}).get("obfuscator")
    if obf_detected:
        intro = (
            f'<p>de4dot-cex identified <code>{esc(obf_detected)}</code> and ran'
            f' a targeted deobfuscation pass.</p>'
        )
    else:
        # "Unknown Obfuscator" pass that still produced output (audit-12 D1)
        intro = (
            f'<p>de4dot-cex did not identify a supported obfuscator, but the'
            f' generic deobfuscation pass produced an output assembly. Even'
            f' without obfuscator-specific logic, de4dot extracts embedded'
            f' resources, attempts string-decryption, and rewrites lightly-'
            f'obfuscated method bodies. The output below may still be more'
            f' analyzable than the original.</p>'
        )

    de4dot_artifacts_block += (
        f"{intro}"
        f'<p><b>Output assembly size:</b> {fmt_bytes(deobf_total)} '
        f'<span style="color:{delta_color}">({delta_label} vs original'
        f' {fmt_bytes(orig_sz)})</span></p>'
        f'<table>'
        f'<thead><tr><th>Deobfuscated File</th><th>Size</th></tr></thead>'
        f'<tbody>{rows}</tbody>'
        f'</table>'
    )
    if (S.get("de4dot") or {}).get("deobfuscated_cs_count", 0) > 0:
        de4dot_artifacts_block += (
            f'<p>A second ilspycmd pass on the deobfuscated assembly produced'
            f' <b>{S["de4dot"]["deobfuscated_cs_count"]}</b> .cs files at'
            f' <code>22-de4dot/deobfuscated-ilspy/</code>.</p>'
            f'<p>To compare pre/post, diff the two ilspy trees: original at'
            f' <code>20-dotnet/ilspy/</code> vs. deobfuscated at'
            f' <code>22-de4dot/deobfuscated-ilspy/</code>.</p>'
        )
else:
    de4dot_artifacts_block += (
        '<p><em>No deobfuscated artifacts produced.</em> '
        'de4dot-cex either did not identify a supported obfuscator and '
        'the generic pass produced no usable output, or the binary was '
        'not a .NET assembly.</p>'
    )
de4dot_artifacts_block += '</div>'

obfuscation_tab = f"""
{unified_verdict_block}
<div class="c">
  <h2>Per-Tool Detection Breakdown</h2>
  <p>This tab combines signals from six sources: de4dot-cex (.NET obfuscator
     detection), Detect It Easy packer + protector, manalyze peid plugin
     (PEiD signatures), manalyze packer plugin (PE structural anomalies),
     peframe packer detection, and per-section entropy analysis. Any row
     showing a non-info pill is a candidate for manual follow-up.
     The Unified Verdict above synthesizes these into one answer.</p>
  <table>
    <thead><tr><th>Tool / Signal</th><th>Result</th><th>Interpretation</th></tr></thead>
    <tbody>{obf_rows_html}</tbody>
  </table>
</div>
{de4dot_artifacts_block}
"""

# ---------------- Summary banner cells ----------------------------------------
banner_cells = [
    ("total", fmt_bytes(S["file"]["size"]), "File Size"),
    ("", f"{ss['ascii']:,}", "ASCII Strings"),
    ("", f"{capa['rule_count']}", "capa Rules"),
    ("high", f"{len(capa['attack'])}", "ATT&CK Techniques"),
    ("med", f"{len(capa['mbc'])}", "MBC Behaviors"),
    ("crit", f"{len(S['yara_hits'])}", "YARA Hits"),
    ("", f"{len(S['pe']['imports'])}", "Imported Libs"),
    ("", f"{len(S['pe']['exports'])}", "Exports"),
    ("high", f"{ent['high_count']}", "High-Entropy Secs"),
    ("", f"{S['iocs']['total']}", "IOCs Extracted"),
]
if S["dotnet"]["cs_file_count"]:
    banner_cells.append(("", f"{S['dotnet']['cs_file_count']}", "C# Files"))
banner_html = "".join(
    f'<div class="summary-cell {cls}"><span class="num">{esc(n)}</span><span class="lbl">{esc(l)}</span></div>'
    for cls, n, l in banner_cells
)

# ---------------- Assemble ----------------------------------------------------
subtitle_parts = [f"Severity: {sev.upper()}"]
if verdict.get("is_signed"): subtitle_parts.append("signed")
else: subtitle_parts.append("unsigned")
if verdict.get("is_packed"): subtitle_parts.append("packed")
if verdict.get("has_suspicious_imports"): subtitle_parts.append("suspicious imports")
subtitle = " &middot; ".join(subtitle_parts)

now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

# ---------------- v2.6.0: type-specific tab content ---------------------------
# Each block is built only when the corresponding stage produced output.

# Mach-O tab
_mh = S.get("macho", {}) or {}
macho_tab = ""
if _mh.get("ran"):
    libs_html = "".join(f"<li><code>{esc(l)}</code></li>" for l in _mh.get("libraries", [])[:50]) or "<li><em>None.</em></li>"
    macho_tab = f"""
<div class="c">
  <h2>Mach-O Structure</h2>
  <table class="kv"><tbody>
    <tr><td>Load commands</td><td>{_mh.get('load_commands', 0)}</td></tr>
    <tr><td>Sections</td><td>{_mh.get('sections', 0)}</td></tr>
    <tr><td>Code signed</td><td>{"yes" if _mh.get("code_signed") else "no"}</td></tr>
    <tr><td>Imported libraries</td><td>{len(_mh.get('libraries', []))}</td></tr>
  </tbody></table>
  <h3>Imported libraries</h3>
  <ul>{libs_html}</ul>
</div>
"""

# WASM tab
_ws = S.get("wasm", {}) or {}
wasm_tab = ""
if _ws.get("ran"):
    wasm_tab = f"""
<div class="c">
  <h2>WebAssembly Module</h2>
  <table class="kv"><tbody>
    <tr><td>Validates</td><td>{pill('PASS', 'low') if _ws.get('validates') else (pill('FAIL', 'high') if _ws.get('validates') is False else 'unknown')}</td></tr>
    <tr><td>Imports</td><td>{_ws.get('imports', 0)}</td></tr>
    <tr><td>Exports</td><td>{_ws.get('exports', 0)}</td></tr>
    <tr><td>Function types</td><td>{_ws.get('functions', 0)}</td></tr>
  </tbody></table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Full text format (.wat), structural objdump, and C-like decompile output are in the
    <code>54-wasm/</code> directory.
  </p>
</div>
"""

# PYC tab
_pc = S.get("pyc", {}) or {}
pyc_tab = ""
if _pc.get("ran"):
    succ = _pc.get("decompilers_succeeded", [])
    succ_html = " ".join(pill(s, "low") for s in succ) or "<em>None succeeded.</em>"
    pyc_tab = f"""
<div class="c">
  <h2>Python Bytecode</h2>
  <table class="kv"><tbody>
    <tr><td>Magic identification</td><td>{esc(_pc.get('header_magic', ''))}</td></tr>
    <tr><td>Decompilers that produced output</td><td>{succ_html}</td></tr>
  </tbody></table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Decompiled source files (pycdc, uncompyle6, decompyle3) and disassembly (pycdas, python -m dis) are in the <code>56-pyc/</code> directory.
  </p>
</div>
"""

# JAR tab
_jr = S.get("jar", {}) or {}
jar_tab = ""
if _jr.get("ran"):
    jar_tab = f"""
<div class="c">
  <h2>Java Archive (JAR/WAR/EAR)</h2>
  <table class="kv"><tbody>
    <tr><td>.class file count</td><td>{_jr.get('class_count', 0)}</td></tr>
    <tr><td>MANIFEST.MF present</td><td>{"yes" if _jr.get("manifest_present") else "no"}</td></tr>
    <tr><td>CFR decompiled .java files</td><td>{_jr.get('cfr_files', 0)}</td></tr>
    <tr><td>procyon decompiled .java files</td><td>{_jr.get('procyon_files', 0)}</td></tr>
  </tbody></table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Per-tool output: <code>58-jar/cfr/</code>, <code>58-jar/procyon/</code>, <code>58-jar/javap-sample.txt</code>.
  </p>
</div>
"""

# PDF tab
_pd = S.get("pdf", {}) or {}
pdf_tab = ""
if _pd.get("ran"):
    risk_pills = " ".join(pill(esc(k), "high") for k in _pd.get("high_risk_keywords", [])) or "<em>None detected.</em>"
    pdf_tab = f"""
<div class="c">
  <h2>PDF Risk Indicators</h2>
  <table class="kv"><tbody>
    <tr><td>High-risk keywords</td><td>{risk_pills}</td></tr>
    <tr><td>qpdf warnings</td><td>{_pd.get('qpdf_warnings', 0)}</td></tr>
  </tbody></table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Full pdfid keyword scan, pdf-parser object dumps, peepdf JS analysis, mutool info, and qpdf check output are in the <code>62-pdf/</code> directory.
  </p>
</div>
"""

# OLE tab
_ol = S.get("ole", {}) or {}
ole_tab = ""
if _ol.get("ran"):
    mr_v = _ol.get("mraptor_verdict")
    mr_html = pill(esc(mr_v or "unknown"), "high" if mr_v == "SUSPICIOUS" else ("med" if mr_v == "Macro" else "low"))
    ole_tab = f"""
<div class="c">
  <h2>OLE / OOXML Office Document</h2>
  <table class="kv"><tbody>
    <tr><td>Macros present (olevba)</td><td>{"yes" if _ol.get("macros_present") else "no"}</td></tr>
    <tr><td>mraptor verdict</td><td>{mr_html}</td></tr>
    <tr><td>DDE links present (msodde)</td><td>{"yes" if _ol.get("dde_present") else "no"}</td></tr>
    <tr><td>Embedded objects (oleobj)</td><td>{_ol.get('embedded_objects', 0)}</td></tr>
  </tbody></table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Per-tool output: olevba.txt, oleid.txt, mraptor.txt, msodde.txt, oledump.txt in <code>64-ole/</code>.
  </p>
</div>
"""

# Go runtime tab
_go = S.get("go_info", {}) or {}
go_tab = ""
if _go.get("detected"):
    go_tab = f"""
<div class="c">
  <h2>Go Binary Analysis (redress)</h2>
  <table class="kv"><tbody>
    <tr><td>Compiler version</td><td><code>{esc(_go.get('compiler_version', '') or 'unknown')}</code></td></tr>
    <tr><td>Package count</td><td>{_go.get('package_count', 0)}</td></tr>
  </tbody></table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Full redress output: info.txt, packages.txt, types.txt, source.txt, moduledata.txt, gomod.txt in <code>55-go/</code>.
  </p>
</div>
"""

# Rust runtime tab
_ru = S.get("rust_info", {}) or {}
rust_tab = ""
if _ru.get("detected"):
    paths_html = "".join(f"<li><code>{esc(p)}</code></li>" for p in _ru.get("rustc_paths", [])[:10]) or "<li><em>None captured.</em></li>"
    rust_tab = f"""
<div class="c">
  <h2>Rust Binary Analysis</h2>
  <p>Distinctive rustc paths (typically reveal the rust version used to compile):</p>
  <ul>{paths_html}</ul>
  <p style="color:var(--text-secondary);margin-top:8px">
    Demangled symbol table (if rustfilt is installed) is at <code>57-rust/nm-rust-demangled.txt</code>.
  </p>
</div>
"""

# ---------------- v2.7.0: cross-cutting capability tabs ----------------------

# Fuzzy hashes tab - small inline content, but always-on so add to overview-adjacent
# v3.0.10 (audit-14 F1) - extended to surface pehash data (imphash,
# per-header hashes, per-section hashes) in addition to ssdeep + tlsh.
# Pre-v3.0.10 the pehash output was generated by 14-pev.sh but never
# read by 85-summary.sh nor surfaced here. The tab is now richer and
# renders as soon as either ssdeep/tlsh OR pehash data is available.
_fh = S.get("fuzzy_hashes", {}) or {}
_pehash = _fh.get("pehash", {}) or {}
_pehash_file = _pehash.get("file", {}) or {}
_pehash_headers = _pehash.get("headers", []) or []
_pehash_sections = _pehash.get("sections", []) or []
fuzzy_tab = ""
_have_fuzzy = bool(_fh.get("ssdeep") or _fh.get("tlsh"))
_have_pehash = bool(_pehash_file or _pehash_headers or _pehash_sections)
if _have_fuzzy or _have_pehash:
    # File-level fuzzy block: ssdeep + tlsh + pehash file-level hashes
    _file_rows = ""
    if _fh.get("ssdeep"):
        _file_rows += f'<tr><td>ssdeep (whole-file)</td><td><code>{esc(_fh.get("ssdeep"))}</code></td></tr>'
    if _fh.get("tlsh"):
        _file_rows += f'<tr><td>TLSH (whole-file)</td><td><code>{esc(_fh.get("tlsh"))}</code></td></tr>'
    # pehash file-level
    for k, label in [("md5", "MD5 (pehash, file)"),
                     ("sha1", "SHA-1 (pehash, file)"),
                     ("sha256", "SHA-256 (pehash, file)"),
                     ("ssdeep", "ssdeep (pehash, file)"),
                     ("imphash", "imphash (Mandiant import hash)")]:
        v = _pehash_file.get(k)
        if v:
            _file_rows += f'<tr><td>{esc(label)}</td><td><code>{esc(v)}</code></td></tr>'
    if not _file_rows:
        _file_rows = '<tr><td colspan="2"><em>No file-level fuzzy hashes computed.</em></td></tr>'

    # Per-header table (PE only)
    _header_block = ""
    if _pehash_headers:
        _header_rows = ""
        for hdr in _pehash_headers:
            name = hdr.get("header_name", "(unknown)")
            md5 = hdr.get("md5", "")
            ssdeep = hdr.get("ssdeep", "")
            _header_rows += (
                f'<tr><td>{esc(name)}</td>'
                f'<td><code>{esc(md5)}</code></td>'
                f'<td><code style="font-size:11px">{esc(ssdeep)}</code></td></tr>'
            )
        _header_block = (
            '<h3 style="margin-top:18px">PE Header Hashes</h3>'
            '<table><thead><tr><th>Header</th><th>MD5</th><th>ssdeep</th></tr></thead>'
            f'<tbody>{_header_rows}</tbody></table>'
        )

    # Per-section table (PE only)
    _section_block = ""
    if _pehash_sections:
        _section_rows = ""
        for sec in _pehash_sections:
            name = sec.get("section_name", "(unknown)")
            md5 = sec.get("md5", "")
            ssdeep = sec.get("ssdeep", "")
            _section_rows += (
                f'<tr><td><code>{esc(name)}</code></td>'
                f'<td><code>{esc(md5)}</code></td>'
                f'<td><code style="font-size:11px">{esc(ssdeep)}</code></td></tr>'
            )
        _section_block = (
            '<h3 style="margin-top:18px">PE Section Hashes</h3>'
            '<table><thead><tr><th>Section</th><th>MD5</th><th>ssdeep</th></tr></thead>'
            f'<tbody>{_section_rows}</tbody></table>'
        )

    fuzzy_tab = f"""
<div class="c">
  <h2>Fuzzy &amp; PE Hashes</h2>
  <h3>File-Level</h3>
  <table class="kv"><tbody>
    {_file_rows}
  </tbody></table>
  {_header_block}
  {_section_block}
  <p style="color:var(--text-secondary);margin-top:12px">
    These hashes enable similarity comparison with other binaries.
    <strong>imphash</strong> (Mandiant Import Hash) clusters samples by
    identical import tables - same imphash often means same malware
    family or build pipeline. <strong>ssdeep</strong> and <strong>TLSH</strong>
    are fuzzy / context-triggered piecewise hashes that match similar
    files even with small modifications. The codebase-level similarity
    matrix is at <code>../_similarity-matrix.html</code> when multiple
    binaries are analyzed in the same run.
  </p>
</div>
"""

# Crypto keys tab
_ck = S.get("crypto_keys", {}) or {}
crypto_tab = ""
if _ck.get("ran") and _ck.get("total", 0) > 0:
    by_conf = _ck.get("by_confidence", {}) or {}
    by_type = _ck.get("by_type", {}) or {}
    type_rows = "".join(
        f"<tr><td><code>{esc(k)}</code></td><td>{v}</td></tr>"
        for k, v in sorted(by_type.items(), key=lambda kv: -kv[1])
    ) or "<tr><td colspan=2><em>None.</em></td></tr>"
    crypto_tab = f"""
<div class="c">
  <h2>Crypto Key &amp; Secret Candidates</h2>
  <table class="kv"><tbody>
    <tr><td>Total candidates</td><td>{_ck.get('total', 0)}</td></tr>
    <tr><td>High confidence</td><td>{pill(str(by_conf.get('high', 0)), 'high' if by_conf.get('high', 0) > 0 else 'low')}</td></tr>
    <tr><td>Medium confidence</td><td>{by_conf.get('medium', 0)}</td></tr>
    <tr><td>Low confidence</td><td>{by_conf.get('low', 0)}</td></tr>
    <tr><td>signsrch crypto-class hits</td><td>{_ck.get('signsrch_crypto_hits', 0)}</td></tr>
  </tbody></table>
  <h3>By candidate type</h3>
  <table>
    <thead><tr><th>Type</th><th>Count</th></tr></thead>
    <tbody>{type_rows}</tbody>
  </table>
  <p style="color:var(--text-secondary);margin-top:8px">
    High-confidence matches are PEM block markers and AES S-box patterns. Medium
    are DER ASN.1 sequences and high-entropy regions matching key-bit boundaries.
    Low-confidence matches are generic high-entropy regions; many false positives
    are expected at low confidence.
  </p>
</div>
"""

# Authenticode chain tab
_ach = S.get("authenticode_chain", {}) or {}
authchain_tab = ""
if _ach.get("ran"):
    validates = _ach.get("validates")
    val_pill = pill(esc(validates or "unknown"),
                    "low" if validates == "yes" else
                    ("high" if validates == "no" else "med"))
    authchain_tab = f"""
<div class="c">
  <h2>Authenticode Certificate Chain</h2>
  <table class="kv"><tbody>
    <tr><td>Chain validates</td><td>{val_pill}</td></tr>
    <tr><td>Self-signed leaf</td><td>{"yes" if _ach.get("self_signed") else "no"}</td></tr>
    <tr><td>Cert expired</td><td>{"yes" if _ach.get("expired") else "no"}</td></tr>
    <tr><td>Known signer org</td><td>{esc(_ach.get('known_org') or 'no match against bundled list')}</td></tr>
  </tbody></table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Validation uses <code>osslsigncode verify -CAfile</code> against the system CA
    store (<code>/etc/ssl/certs/ca-certificates.crt</code>). The known-org list is a
    bundled subset of common code-signing CAs (Microsoft, Adobe, Google, Apple,
    Mozilla, ...); absence of a match does NOT indicate malicious intent.
  </p>
</div>
"""

# angr CFG tab
_ag = S.get("angr_cfg", {}) or {}
angr_tab = ""
if _ag.get("ran") and _ag.get("loaded"):
    angr_tab = f"""
<div class="c">
  <h2>angr CFGFast Recovery</h2>
  <table class="kv"><tbody>
    <tr><td>Architecture</td><td><code>{esc(_ag.get('arch') or 'unknown')}</code></td></tr>
    <tr><td>Functions recovered</td><td>{_ag.get('function_count', 0)}</td></tr>
    <tr><td>CFG nodes</td><td>{_ag.get('node_count', 0)}</td></tr>
    <tr><td>CFG edges</td><td>{_ag.get('edge_count', 0)}</td></tr>
    <tr><td>Indirect jumps resolved</td><td>{_ag.get('indirect_resolved', 0)}</td></tr>
    <tr><td>Indirect jumps UNresolved</td><td>{_ag.get('indirect_unresolved', 0)}</td></tr>
  </tbody></table>
  <p style="color:var(--text-secondary);margin-top:8px">
    angr CFGFast performs static control-flow recovery using VEX IR plus heuristic
    indirect-jump resolution. Unresolved indirect jumps mark places where dynamic
    analysis would add information; for deeper symbolic exploration, invoke angr
    interactively from the venv.
  </p>
</div>
"""

# radiff2 tab (only when --diff-against was used)
_rdiff = S.get("radiff2", {}) or {}
radiff_tab = ""
if _rdiff.get("ran") and _rdiff.get("similarity") is not None:
    sim = _rdiff.get("similarity")
    sim_pct = int(sim * 100) if sim is not None else 0
    sim_pill = pill(f"{sim_pct}%", "low" if sim_pct >= 80 else ("med" if sim_pct >= 30 else "high"))
    radiff_tab = f"""
<div class="c">
  <h2>radiff2 Binary Diff</h2>
  <table class="kv"><tbody>
    <tr><td>Reference</td><td><code>{esc(_rdiff.get('reference') or '?')}</code></td></tr>
    <tr><td>Similarity score</td><td>{sim_pill} ({sim:.4f})</td></tr>
    <tr><td>Function-level matches</td><td>{_rdiff.get('function_matches', 0)}</td></tr>
  </tbody></table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Per-tool output: <code>87-radiff2/similarity.txt</code>, <code>functions.txt</code>,
    <code>imports.txt</code>, <code>strings.txt</code>, <code>count.txt</code>.
  </p>
</div>
"""

# yarGen tab (only when --enable-yargen was used)
_yg = S.get("yargen", {}) or {}
yargen_tab = ""
if _yg.get("ran") and _yg.get("rule_count", 0) > 0:
    yargen_tab = f"""
<div class="c">
  <h2>yarGen YARA Rules (auto-generated)</h2>
  <table class="kv"><tbody>
    <tr><td>Rules generated</td><td>{_yg.get('rule_count', 0)}</td></tr>
    <tr><td>Rule file</td><td><code>{esc(_yg.get('rule_file') or '')}</code></td></tr>
  </tbody></table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Auto-generated rules need post-processing before deployment (review for
    overly-specific or random-looking strings; cross-check against a clean reference set).
    The full rule file is at <code>88-yargen/yargen_rules.yar</code>.
  </p>
</div>
"""

# ---------------- v2.8.0: Mobile (DEX/APK) tabs ------------------------------

# APK container tab
_apk = S.get("apk", {}) or {}
apk_tab = ""
if _apk.get("ran"):
    abi_rows = ""
    if _apk.get("native_libs_per_abi"):
        for abi, libs in sorted(_apk["native_libs_per_abi"].items()):
            abi_rows += f"<tr><td><code>{esc(abi)}</code></td><td>{len(libs)} libs</td><td>{esc(', '.join(libs[:5]))}{('...' if len(libs) > 5 else '')}</td></tr>"
    apk_tab = f"""
<div class="c">
  <h2>APK Container</h2>
  <table class="kv"><tbody>
    <tr><td>Extraction directory</td><td><code>{esc(_apk.get('extraction_dir') or '(none)')}</code></td></tr>
    <tr><td>apktool extraction success</td><td>{pill('yes' if _apk.get('apktool_success') else 'no', 'low' if _apk.get('apktool_success') else 'high')}</td></tr>
    <tr><td>DEX files</td><td>{_apk.get('dex_count', 0)}</td></tr>
    <tr><td>smali class count</td><td>{_apk.get('smali_class_count', 0)}</td></tr>
    <tr><td>Native ABIs</td><td>{len(_apk.get('native_libs_per_abi', {}))}</td></tr>
  </tbody></table>
  <h3>Native libraries per ABI</h3>
  <table>
    <thead><tr><th>ABI</th><th>Count</th><th>Libraries (first 5)</th></tr></thead>
    <tbody>{abi_rows or '<tr><td colspan=3><em>None.</em></td></tr>'}</tbody>
  </table>
  <p style="color:var(--text-secondary);margin-top:8px">
    APK contents are dispatched to type-specific stages: AndroidManifest.xml -&gt;
    stage_axml, classes*.dex -&gt; stage_dex, lib/&lt;abi&gt;/*.so -&gt; stage_elf
    (largest .so per ABI to avoid redundant analysis).
  </p>
</div>
"""

# AndroidManifest tab
_mf = S.get("manifest", {}) or {}
manifest_tab = ""
if _mf.get("ran"):
    perm_rows = ""
    for perm in _mf.get("dangerous_permissions", [])[:50]:
        perm_rows += f"<tr><td><code>{esc(perm.get('permission', ''))}</code></td><td>{esc(perm.get('category', ''))}</td></tr>"
    if not perm_rows:
        perm_rows = "<tr><td colspan=2><em>No dangerous permissions detected.</em></td></tr>"
    deep_links_html = ""
    if _mf.get("deep_link_schemes"):
        deep_links_html = ", ".join(f"<code>{esc(s)}</code>" for s in _mf['deep_link_schemes'][:20])
    else:
        deep_links_html = "<em>none</em>"
    dangerous_count = _mf.get('dangerous_permission_count', 0)
    dangerous_pill = pill(str(dangerous_count), 'high' if dangerous_count >= 5 else ('med' if dangerous_count > 0 else 'low'))
    manifest_tab = f"""
<div class="c">
  <h2>AndroidManifest.xml</h2>
  <table class="kv"><tbody>
    <tr><td>Package name</td><td><code>{esc(_mf.get('package_name') or '(unknown)')}</code></td></tr>
    <tr><td>Version</td><td>{esc(_mf.get('version_name') or '?')} (code {esc(_mf.get('version_code') or '?')})</td></tr>
    <tr><td>SDK levels</td><td>min={esc(_mf.get('min_sdk') or '?')} target={esc(_mf.get('target_sdk') or '?')} compile={esc(_mf.get('compile_sdk') or '?')}</td></tr>
    <tr><td>Total permissions</td><td>{_mf.get('permission_count', 0)}</td></tr>
    <tr><td>Dangerous permissions</td><td>{dangerous_pill}</td></tr>
    <tr><td>Exported activities</td><td>{_mf.get('exported_activities_count', 0)}</td></tr>
    <tr><td>Exported services</td><td>{_mf.get('exported_services_count', 0)}</td></tr>
    <tr><td>Exported receivers</td><td>{_mf.get('exported_receivers_count', 0)}</td></tr>
    <tr><td>Exported providers</td><td>{_mf.get('exported_providers_count', 0)}</td></tr>
    <tr><td>Intent filters</td><td>{_mf.get('intent_filter_count', 0)}</td></tr>
    <tr><td>Deep link schemes</td><td>{deep_links_html}</td></tr>
  </tbody></table>
  <h3>Dangerous permissions (categorized)</h3>
  <table>
    <thead><tr><th>Permission</th><th>Category</th></tr></thead>
    <tbody>{perm_rows}</tbody>
  </table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Dangerous permissions categorized by Android runtime permission groups
    plus malware-hunting heuristics (BIND_ACCESSIBILITY_SERVICE for banking
    trojans, SYSTEM_ALERT_WINDOW for tapjacking, REQUEST_INSTALL_PACKAGES for
    droppers).
  </p>
</div>
"""

# DEX decompilation tab
_dex = S.get("dex", {}) or {}
dex_tab = ""
if _dex.get("ran") and _dex.get("dex_files"):
    rows = ""
    for d in _dex.get("dex_files", []):
        rows += (
            f"<tr><td><code>{esc(d.get('dir', ''))}</code></td>"
            f"<td>{d.get('jadx_java_count', 0)}</td>"
            f"<td>{d.get('baksmali_smali_count', 0)}</td>"
            f"<td>{'yes' if d.get('dex2jar_jar') else 'no'}</td></tr>"
        )
    dex_tab = f"""
<div class="c">
  <h2>DEX Decompilation</h2>
  <table>
    <thead><tr><th>DEX dir</th><th>jadx Java files</th><th>baksmali smali files</th><th>dex2jar .jar</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Three-tier decompilation: jadx (primary, best-quality Java),
    baksmali (always-works smali fallback), dex2jar+CFR (different
    decompilation path; sometimes recovers what jadx misses).
  </p>
</div>
"""

# APK signature tab
_sig = S.get("apksig", {}) or {}
apksig_tab = ""
if _sig.get("ran"):
    sch = _sig.get("schemes", {}) or {}
    scheme_pills = " ".join([
        pill("v1", "low" if sch.get('v1_jar') else "dim"),
        pill("v2", "low" if sch.get('v2_apk_sig') else "dim"),
        pill("v3", "low" if sch.get('v3_apk_sig') else "dim"),
        pill("v4", "low" if sch.get('v4_apk_sig') else "dim"),
    ])
    verifies = _sig.get("verifies")
    verifies_pill = pill(
        "verifies" if verifies is True else ("DOES NOT VERIFY" if verifies is False else "unknown"),
        "low" if verifies is True else ("high" if verifies is False else "med")
    )
    janus_pill = pill(
        "vulnerable" if _sig.get('janus_vulnerable') else "ok",
        "high" if _sig.get('janus_vulnerable') else "low"
    )
    signer_rows = ""
    for i, signer in enumerate(_sig.get("signers", []), start=1):
        signer_rows += (
            f"<tr><td>#{i}</td>"
            f"<td><code>{esc(signer.get('dn', '?'))}</code></td>"
            f"<td>{esc(signer.get('key_algorithm', '?'))} "
            f"{signer.get('key_size_bits', '?')}-bit</td>"
            f"<td><code style='font-size:11px'>{esc((signer.get('sha256') or '')[:48])}{'...' if signer.get('sha256') and len(signer.get('sha256', '')) > 48 else ''}</code></td>"
            f"</tr>"
        )
    if not signer_rows:
        signer_rows = "<tr><td colspan=4><em>No signer info recovered.</em></td></tr>"
    apksig_tab = f"""
<div class="c">
  <h2>APK Signature</h2>
  <table class="kv"><tbody>
    <tr><td>Verification tool</td><td><code>{esc(_sig.get('tool') or '(none)')}</code></td></tr>
    <tr><td>Verifies</td><td>{verifies_pill}</td></tr>
    <tr><td>Signing schemes active</td><td>{scheme_pills}</td></tr>
    <tr><td>Signer count</td><td>{_sig.get('signer_count', 0)}</td></tr>
    <tr><td>Janus vulnerability (CVE-2017-13156)</td><td>{janus_pill}</td></tr>
    <tr><td>Known org match</td><td>{esc(_sig.get('known_org') or 'no match against bundled list')}</td></tr>
  </tbody></table>
  <h3>Signer certificates</h3>
  <table>
    <thead><tr><th>#</th><th>Distinguished Name</th><th>Key</th><th>SHA-256</th></tr></thead>
    <tbody>{signer_rows}</tbody>
  </table>
  <p style="color:var(--text-secondary);margin-top:8px">
    Janus vulnerability triggers when an APK is v1-only signed and runs on
    Android &le; 6.0; attackers can prepend malicious DEX bytecode without
    invalidating the v1 signature. v2/v3/v4 schemes fix this by signing
    the entire APK byte-stream.
  </p>
</div>
"""

# ---------------- v2.9.0: Visualizations tab --------------------------------

_viz = S.get("viz", {}) or {}
viz_tab = ""
if _viz.get("ran") and _viz.get("count", 0) > 0:
    import os as _os, re as _re
    viz_dir = _os.path.join(OUTDIR, "89-viz")
    embedded_svgs = []
    viz_files = [
        ("01-sections.html",   "Section / Segment Treemap",
         "Area = size; color = Shannon entropy; red border = executable."),
        ("02-imports.html",    "Imports / Dependencies",
         "API count per imported library; red bars highlight network/registry libraries."),
        ("03-capa-mitre.html", "capa-MITRE ATT&amp;CK Heatmap",
         "Tactics ordered along the kill-chain; cell intensity = capa rule match count."),
        ("04-iocs.html",       "IOC Distribution",
         "Indicators by category; red bars highlight network-pivotable IOCs."),
        ("05-severity.html",   "Severity Contribution",
         "Stacked decomposition of severity reasons by signal source."),
        ("06-dynamic.html",    "Dynamic Analysis Behavior",
         "Behavioral counts across dynamic tier(s); badges flag cross-tier indicators."),
        # v3.0.6 (audit-10 E1+E2): graphs tab. Embeds pre-rendered call graph
        # + CFG. The 07-graphs.html may contain MULTIPLE SVGs (one per source
        # backend - r2 and angr) wrapped in <div> sections. The extraction
        # logic below detects this filename specifically and extracts the
        # full <body> content rather than just the first <svg>.
        ("07-graphs.html",     "Call Graph + CFG",
         "Pre-rendered graphs from radare2 (agC global call graph) and "
         "angr (CFGFast control-flow graph)."),
        # v3.3.0 (audit-24 A5.4): GhidraDump-driven panels.
        ("08-call-graph.html", "Call Graph (Ghidra)",
         "Directed function call graph from Ghidra Section 14. Orange = hub "
         "(&gt;5 callees), blue = caller, gray = leaf. Top-50 by out-degree."),
        ("09-xrefs.html",      "Cross-References (Ghidra)",
         "Top-30 most-referenced targets from Ghidra Section 15. Bar length "
         "= inbound reference count."),
        ("10-function-complexity.html", "Function Complexity (Ghidra)",
         "Top-40 functions by size from Ghidra Section 11. Orange = largest "
         "quartile (candidate analysis targets)."),
    ]
    for fname, title, subtitle in viz_files:
        fpath = _os.path.join(viz_dir, fname)
        if not _os.path.exists(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8") as f:
                viz_html = f.read()

            # v3.0.6 (audit-10): 07-graphs.html may contain MULTIPLE <svg>
            # blocks (one per backend, each in its own <div> with header).
            # For that file specifically, extract the full body content.
            # For all other viz files, the legacy first-svg extraction
            # still applies.
            if fname == "07-graphs.html":
                # Extract whatever sits between </header> and <footer> (or
                # </body>); this gives us the multi-section body.
                body_match = _re.search(
                    r'</header>(.*?)(?:<footer|</body>|</html>)',
                    viz_html, _re.DOTALL
                )
                if body_match:
                    content = body_match.group(1).strip()
                else:
                    # Fallback: find all SVG blocks and concatenate.
                    svgs = _re.findall(r'<svg[^>]*>.*?</svg>', viz_html, _re.DOTALL)
                    if svgs:
                        content = "".join(svgs)
                    else:
                        m2 = _re.search(r'<p[^>]*>.*?</p>', viz_html, _re.DOTALL)
                        content = m2.group(0) if m2 else "<p><em>(no graphs)</em></p>"
            else:
                # Extract just the <svg>...</svg> block (or paragraph-only when no
                # data was available)
                m = _re.search(r'<svg[^>]*>.*?</svg>', viz_html, _re.DOTALL)
                if m:
                    content = m.group(0)
                else:
                    # Try to extract the <p>...</p> placeholder text
                    m2 = _re.search(r'<p[^>]*>.*?</p>', viz_html, _re.DOTALL)
                    content = m2.group(0) if m2 else "<p><em>(viz not generated)</em></p>"
            embedded_svgs.append(
                f'<div class="c">'
                f'<h3>{title}</h3>'
                f'<p style="color:var(--text-secondary);font-size:13px;margin:4px 0 12px">{subtitle}</p>'
                f'{content}'
                f'<p style="margin-top:8px"><a href="89-viz/{fname}" target="_blank" '
                f'style="font-size:12px">Open standalone</a></p>'
                f'</div>'
            )
        except Exception:
            continue
    if embedded_svgs:
        viz_tab = (
            '<div class="c">'
            f'<h2>Visualizations ({len(embedded_svgs)})</h2>'
            '<p>Inline SVG visualizations of section layout, imports, '
            'capa-MITRE ATT&amp;CK coverage, IOC distribution, severity '
            'contribution, and (v3.0.6) call graph + CFG. Each is a '
            'self-contained scalable graphic; the "Open standalone" link '
            'below each chart opens the dedicated page in 89-viz/.</p>'
            '</div>'
            + "".join(embedded_svgs)
        )

# ---------------- v3.0.0: Dynamic Analysis tab ------------------------------
# v3.0.9 (audit-13 C2) - when DYNAMIC was enabled but no tier produced output,
# read 98-dynamic-trace/aggregated.json directly to surface per-tier skip
# reasons so operators can immediately see what's missing (--allow-real-
# execution, container image, ELF target, etc).

_dyn = S.get("dynamic", {}) or {}
dynamic_tab = ""

# v3.0.9 (audit-13 C2) - Build a "no tiers ran" panel when dynamic was
# enabled but every tier was a no-op. Read aggregator output directly for
# skip_reasons.
import os as _os_dyn
import json as _json_dyn
_dyn_agg_path = _os_dyn.path.join(OUTDIR, "98-dynamic-trace", "aggregated.json")
_dyn_agg = {}
if _os_dyn.path.isfile(_dyn_agg_path):
    try:
        with open(_dyn_agg_path, encoding="utf-8") as _fdyn:
            _dyn_agg = _json_dyn.load(_fdyn)
    except Exception:
        _dyn_agg = {}

if _dyn.get("ran"):
    tools_used = _dyn.get("tools_used", []) or []
    real_exec = _dyn.get("real_execution", False)
    cross_tier = _dyn.get("cross_tier", {}) or {}

    # Header summary
    dyn_header = (
        '<div class="c">'
        f'<h2>Dynamic Analysis ({", ".join(tools_used)})</h2>'
        f'<p><strong>Real execution:</strong> {"yes" if real_exec else "no (qiling emulation only)"}.'
        f' <strong>Total duration:</strong> {_dyn.get("duration_total_sec", 0):.1f}s.'
        f' <strong>Exit status:</strong> {_dyn.get("exit_status", "n/a")}.</p>'
        '</div>'
    )

    # Counts table
    counts_rows = ""
    for label, key in [
        ("Syscalls captured",       "syscall_count_total"),
        ("API calls captured",      "api_call_count_total"),
        ("File writes",             "file_write_count_total"),
        ("Registry writes",         "registry_write_count_total"),
        ("Network attempts",        "network_attempt_count_total"),
        ("Spawned processes",       "spawned_process_count_total"),
    ]:
        v = _dyn.get(key, 0)
        # Highlight non-zero counts in suspicious categories
        bold = "font-weight:bold;color:var(--severity-medium)" if v > 0 and key in (
            "network_attempt_count_total", "registry_write_count_total",
            "spawned_process_count_total"
        ) else ""
        counts_rows += f'<tr><th>{esc(label)}</th><td style="{bold}">{v}</td></tr>'

    counts_block = (
        '<div class="c"><h3>Behavioral Counts</h3>'
        f'<table class="kv"><tbody>{counts_rows}</tbody></table>'
        '</div>'
    )

    # Cross-tier indicators
    indicators_html = ""
    if cross_tier.get("any_persistence"):
        indicators_html += (
            '<li style="color:var(--severity-high)">'
            '<strong>Persistence detected:</strong> writes to system paths or registry'
            ' Run keys observed at runtime.</li>'
        )
    if cross_tier.get("any_network"):
        indicators_html += (
            '<li style="color:var(--severity-medium)">'
            '<strong>Network activity:</strong> outbound connection attempts at runtime.</li>'
        )
    common_hosts = cross_tier.get("common_network_hosts") or []
    if common_hosts:
        host_items = "".join(
            f'<li><code>{esc(h.get("host", ""))}</code> seen by tiers: '
            f'{esc(", ".join(h.get("tiers", [])))}</li>'
            for h in common_hosts[:10]
        )
        indicators_html += (
            '<li style="color:var(--severity-high)">'
            f'<strong>Cross-tier-confirmed network hosts ({len(common_hosts)}):</strong>'
            f'<ul>{host_items}</ul></li>'
        )

    indicators_block = ""
    if indicators_html:
        indicators_block = (
            '<div class="c"><h3>Behavioral Indicators</h3>'
            f'<ul>{indicators_html}</ul>'
            '</div>'
        )
    elif _dyn.get("syscall_count_total", 0) == 0 and _dyn.get("api_call_count_total", 0) == 0:
        indicators_block = (
            '<div class="c"><h3>Behavioral Indicators</h3>'
            '<p><em>No syscalls or API calls captured. The binary may have terminated'
            ' immediately, hit anti-emulation defenses, or been incompatible with the'
            ' selected tier (e.g., wrong rootfs architecture for qiling).</em></p>'
            '</div>'
        )
    else:
        indicators_block = (
            '<div class="c"><h3>Behavioral Indicators</h3>'
            '<p>No high-confidence behavioral indicators detected.'
            ' The binary executed without persistence writes or'
            ' cross-tier-confirmed network activity. See the per-tier raw'
            ' logs in <code>92-dynamic-qiling/</code>, <code>94-dynamic-firejail/</code>,'
            ' and <code>96-dynamic-docker/</code> for full traces.</p>'
            '</div>'
        )

    # Per-tier links
    tier_links_html = '<ul>'
    for tier_name, dirname in [
        ("qiling",   "92-dynamic-qiling"),
        ("firejail", "94-dynamic-firejail"),
        ("docker",   "96-dynamic-docker"),
        ("cuckoo",   "97-dynamic-cuckoo"),
    ]:
        if tier_name in tools_used:
            tier_links_html += (
                f'<li><strong>{esc(tier_name)}:</strong> '
                f'<a href="{dirname}/_dynamic.json">_dynamic.json</a> &middot; '
                f'<a href="{dirname}/">raw logs</a></li>'
            )
    tier_links_html += (
        '<li><strong>Aggregator:</strong> '
        '<a href="98-dynamic-trace/aggregated.json">aggregated.json</a> '
        '(cross-tier merged, uniform schema)</li>'
        '</ul>'
    )
    links_block = (
        '<div class="c"><h3>Per-Tier Outputs</h3>'
        f'{tier_links_html}'
        '</div>'
    )

    dynamic_tab = dyn_header + counts_block + indicators_block + links_block

# v3.0.9 (audit-13 C2) - Fallback panel when dynamic was attempted but no
# tier produced output. Pre-v3.0.9 this case produced no Dynamic Analysis
# tab at all, leaving the operator wondering whether dynamic was even run.
# Now: surface the per-tier skip reasons in a clear actionable panel.
elif _dyn_agg.get("modes_attempted"):
    attempted = _dyn_agg.get("modes_attempted", []) or []
    skip_reasons_map = _dyn_agg.get("skip_reasons", {}) or {}
    noop_tiers = [t.replace(" (no-op)", "") for t in attempted if "(no-op)" in t]

    skip_rows = ""
    for tier in ("qiling", "firejail", "docker", "cuckoo"):
        if tier in noop_tiers:
            reason = skip_reasons_map.get(tier, "no reason captured")
            skip_rows += (
                f"<tr><td><b>{esc(tier)}</b></td>"
                f"<td><span class='pill low'>skipped</span></td>"
                f"<td>{esc(reason)}</td></tr>"
            )

    # Build the action-oriented guidance text
    has_pe = "pe" in (S.get("file", {}).get("file_type", "")).lower() or S.get("pe", {}).get("is_pe")
    guidance_lines = []
    if "qiling" in noop_tiers:
        qreason = skip_reasons_map.get("qiling", "")
        if "Windows rootfs empty" in qreason or "rootfs" in qreason.lower():
            guidance_lines.append(
                "qiling could not run because its Windows rootfs is empty (Microsoft "
                "DLLs not bundled per EULA). For PE binaries, use the docker tier "
                "instead: re-run installer with <code>--with-docker</code> and pass "
                "<code>--dynamic-mode=docker --allow-real-execution</code> at run time."
            )
    if "firejail" in noop_tiers:
        freason = skip_reasons_map.get("firejail", "")
        if "non-ELF" in freason or "ELF-only" in freason:
            guidance_lines.append(
                "firejail is ELF-only and cannot run on this binary type. Use the "
                "docker tier (with Wine for PE) instead."
            )
        elif "real-execution" in freason or "ALLOW_REAL" in freason:
            guidance_lines.append(
                "firejail requires <code>--allow-real-execution</code> at run time "
                "to actually execute the binary. Add that flag to enable firejail."
            )
    if "docker" in noop_tiers:
        dreason = skip_reasons_map.get("docker", "")
        if "image not built" in dreason or "not installed" in dreason:
            guidance_lines.append(
                "docker tier requires the <code>retoolkit-dynamic:latest</code> "
                "container image. Re-run installer with <code>--with-docker</code> "
                "to build it. Then add <code>--allow-real-execution</code> at run time."
            )
        elif "real-execution" in dreason or "ALLOW_REAL" in dreason:
            guidance_lines.append(
                "docker tier requires <code>--allow-real-execution</code> at run time. "
                "Add that flag to enable docker."
            )
    if "cuckoo" in noop_tiers:
        creason = skip_reasons_map.get("cuckoo", "")
        if "binary not found" in creason or "not configured" in creason:
            guidance_lines.append(
                "cuckoo tier requires a configured cuckoo VM-sandbox installation. "
                "This is environment-specific and not auto-installed; see cuckoo "
                "documentation for setup instructions."
            )

    if not guidance_lines:
        guidance_lines.append(
            "All dynamic tiers reported skip; check the Reason column above for "
            "specifics. Add <code>--allow-real-execution</code> at run time to "
            "enable real-execution tiers if their other prereqs are met."
        )

    guidance_html = "<ul>" + "".join(f"<li>{g}</li>" for g in guidance_lines) + "</ul>"

    dynamic_tab = (
        '<div class="c">'
        '<h2>Dynamic Analysis: 0 tiers produced output</h2>'
        '<p>Dynamic analysis was enabled with <code>--dynamic</code> but no '
        'tier was able to run on this binary. Each tier reported a skip '
        'reason; see the table below for specifics and the guidance for '
        'how to enable a working tier.</p>'
        f'<table><thead><tr><th>Tier</th><th>Status</th><th>Reason</th></tr></thead>'
        f'<tbody>{skip_rows}</tbody></table>'
        '</div>'
        '<div class="c">'
        '<h3>How to get dynamic output for this binary</h3>'
        f'{guidance_html}'
        '<p style="color:var(--text-secondary);font-size:13px">'
        'See <code>98-dynamic-trace/aggregated.json</code> for the full '
        'aggregator output (including per-tier skip reasons in machine-readable '
        'form).</p>'
        '</div>'
    )

# v3.6.0 (audit-27 F2): capability characterization matrix panel. A high-level
# "what CAN this binary do" grid derived from imports + capa + IOCs. Placed in
# the Overview tab as an at-a-glance characterization. Renders only when the
# matrix has at least one non-none domain.
capability_matrix_panel = ""
try:
    _cm = S.get("capability_matrix", {}) or {}
    if _cm and any(d.get("status", "none") != "none" for d in _cm.values()):
        _CM_LABELS = {
            "network": "Network", "filesystem": "Filesystem", "crypto": "Cryptography",
            "process_execution": "Process / Execution", "persistence": "Persistence",
            "anti_analysis": "Anti-Analysis",
        }
        _CM_COLORS = {"confirmed": "#e74c3c", "potential": "#e67e22", "none": "#718096"}
        _cm_rows = []
        for _dom, _label in _CM_LABELS.items():
            _d = _cm.get(_dom, {"status": "none", "evidence": []})
            _st = _d.get("status", "none")
            _color = _CM_COLORS.get(_st, "#718096")
            _ev = "; ".join(_d.get("evidence", [])) or "<span style='color:var(--text-muted)'>no signal</span>"
            _cm_rows.append(
                f'<tr><td>{esc(_label)}</td>'
                f'<td><span style="color:{_color};font-weight:bold">{esc(_st.upper())}</span></td>'
                f'<td style="font-size:12px">{_ev}</td></tr>'
            )
        capability_matrix_panel = (
            '<div class="c"><h2>Capability Matrix</h2>'
            '<p style="color:var(--text-secondary);font-size:13px">A characterization '
            'of what this binary <em>can</em> do, synthesized from imports, capa '
            'capabilities, and IOCs. <span style="color:#e74c3c;font-weight:bold">'
            'CONFIRMED</span> = direct import or capa hit; '
            '<span style="color:#e67e22;font-weight:bold">POTENTIAL</span> = indirect '
            'signal (capa keyword or IOC). This is evidence reorganized for '
            'characterization, not new detection.</p>'
            '<table><thead><tr><th>Domain</th><th>Status</th><th>Evidence</th></tr>'
            '</thead><tbody>' + "".join(_cm_rows) + '</tbody></table></div>'
        )
except Exception:
    capability_matrix_panel = ""

tabs = [
    ("overview", "Overview", verdict_html + explainable_html + capability_matrix_panel + f'<div class="c"><h2>File Properties</h2><table class="kv"><tbody>{overview_rows}</tbody></table></div>' + overview_audit18_panels),
    ("structure", "PE / Structure", pe_tab),
    ("impexp", "Imports / Exports", impexp_tab),
    ("strings", "Strings", strings_tab),
    ("capa", "Capabilities", capa_tab),
    ("sigs", "Signatures", sig_tab),
    ("obfus", "Obfuscation", obfuscation_tab),
    ("iocs", "IOCs", ioc_tab),
    ("decomp", "Decompilation", decomp_tab),
    ("logs", "Logs", logs_tab),
]
# v2.5.0: insert Vulnerabilities tab after Capabilities only when cwe_checker ran
if cwe_tab:
    tabs.insert(5, ("vulns", "Vulnerabilities (CWE)", cwe_tab))

# v2.6.0: prepend type-specific tabs at position 1 (right after Overview)
# so they're the first thing the analyst sees for these binary types
v26_type_tabs = []
if macho_tab: v26_type_tabs.append(("macho", "Mach-O", macho_tab))
if wasm_tab:  v26_type_tabs.append(("wasm",  "WASM",   wasm_tab))
if pyc_tab:   v26_type_tabs.append(("pyc",   "PYC",    pyc_tab))
if jar_tab:   v26_type_tabs.append(("jar",   "JAR",    jar_tab))
if pdf_tab:   v26_type_tabs.append(("pdf",   "PDF",    pdf_tab))
if ole_tab:   v26_type_tabs.append(("ole",   "OLE",    ole_tab))
if go_tab:    v26_type_tabs.append(("go",    "Go",     go_tab))
if rust_tab:  v26_type_tabs.append(("rust",  "Rust",   rust_tab))
# v2.8.0: mobile tabs are type-specific (only present for APK/DEX inputs);
# they sit alongside the v2.6.0 type tabs rather than the v2.7.0 capability
# tabs because they describe properties of the input rather than analyses
# applied to all inputs.
if apk_tab:      v26_type_tabs.append(("apk",      "APK",       apk_tab))
if manifest_tab: v26_type_tabs.append(("manifest", "Manifest",  manifest_tab))
if dex_tab:      v26_type_tabs.append(("dex",      "DEX",       dex_tab))
if apksig_tab:   v26_type_tabs.append(("apksig",   "APK Sig",   apksig_tab))
for offset, t in enumerate(v26_type_tabs):
    tabs.insert(1 + offset, t)

# v2.7.0: append cross-cutting capability tabs to the END of tabs list (just
# before Logs). These are global so they sit alongside Capabilities/Signatures
# rather than the type-specific tabs.
v27_capability_tabs = []
if fuzzy_tab:     v27_capability_tabs.append(("fuzzy",     "Fuzzy Hashes", fuzzy_tab))
if crypto_tab:    v27_capability_tabs.append(("crypto",    "Crypto Keys",  crypto_tab))
if authchain_tab: v27_capability_tabs.append(("authchain", "Auth Chain",   authchain_tab))
if angr_tab:      v27_capability_tabs.append(("angr",      "angr CFG",     angr_tab))
if radiff_tab:    v27_capability_tabs.append(("radiff",    "radiff2",      radiff_tab))
if yargen_tab:    v27_capability_tabs.append(("yargen",    "YARA Rules",   yargen_tab))
# Insert at position before "logs" tab
if v27_capability_tabs:
    logs_idx = next((i for i, t in enumerate(tabs) if t[0] == "logs"), len(tabs))
    for offset, t in enumerate(v27_capability_tabs):
        tabs.insert(logs_idx + offset, t)

# v2.9.0: Visualizations tab inserted right before Logs tab (after v2.7.0
# capability tabs if present). Single global tab embedding all 5 SVGs.
if viz_tab:
    logs_idx = next((i for i, t in enumerate(tabs) if t[0] == "logs"), len(tabs))
    tabs.insert(logs_idx, ("viz", "Visualizations", viz_tab))

# v3.0.0: Dynamic Analysis tab inserted right before Visualizations (or
# Logs when viz_tab is empty). Order: capability tabs -> Dynamic Analysis
# -> Visualizations -> Logs. This puts behavioral data in front of
# rendered charts since "what did it do" is a more pressing question
# than "show me a treemap" when dynamic data is available.
if dynamic_tab:
    insert_anchor = "viz" if viz_tab else "logs"
    anchor_idx = next((i for i, t in enumerate(tabs) if t[0] == insert_anchor), len(tabs))
    tabs.insert(anchor_idx, ("dynamic", "Dynamic Analysis", dynamic_tab))

# v3.0.2 (audit-6): three new tabs for rop-gadgets, binary-diff, and retdec.
# Each is inserted only when the corresponding stage actually ran (data
# present in summary). Tabs are inserted just before Dynamic Analysis (so
# they group with capability stages rather than behavioral ones).
_rop = S.get("rop_gadgets", {}) or {}
_bdiff = S.get("binary_diff", {}) or {}
_retdec = S.get("retdec", {}) or {}

def _rop_tab_html(rop):
    rows = "".join(
        f'<tr><td><code>{esc(item.get("insn",""))}</code></td>'
        f'<td>{int(item.get("count",0))}</td></tr>'
        for item in (rop.get("first_insn_top") or [])
    )
    if not rows:
        rows = '<tr><td colspan="2"><em>(no gadgets enumerated)</em></td></tr>'
    return (
        f'<h2>ROP Gadgets <span class="muted">(pwntools)</span></h2>'
        f'<p><strong>Total gadgets enumerated:</strong> {int(rop.get("total_gadgets",0))}</p>'
        f'<p>Gadget enumeration uses pwntools&apos; <code>ROP</code> class. '
        f'See <code>46-rop-gadgets/gadgets.txt</code> for the full listing '
        f'and <code>gadgets.json</code> for machine-readable output.</p>'
        f'<h3>Top-5 first-instruction histogram</h3>'
        f'<table><thead><tr><th>First instruction</th><th>Gadget count</th></tr></thead>'
        f'<tbody>{rows}</tbody></table>'
    )

def _bdiff_tab_html(bdiff):
    pct = bdiff.get("divergence_pct", 0.0)
    return (
        f'<h2>Binary Diff <span class="muted">(bsdiff + byte-offset snapshot)</span></h2>'
        f'<p>Reference and target byte-level comparison. The bsdiff patch '
        f'is at <code>91-binary-diff/bsdiff-patch.bin</code>; full byte-offset '
        f'differences in <code>vbindiff-snapshot.txt</code>.</p>'
        f'<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>'
        f'<tr><td>Reference size (bytes)</td><td>{int(bdiff.get("reference_size",0)):,}</td></tr>'
        f'<tr><td>Target size (bytes)</td><td>{int(bdiff.get("target_size",0)):,}</td></tr>'
        f'<tr><td>Differing byte count</td><td>{int(bdiff.get("differing_byte_count",0)):,}</td></tr>'
        f'<tr><td>Divergence (%)</td><td>{pct}%</td></tr>'
        f'<tr><td>bsdiff patch size (bytes)</td><td>{int(bdiff.get("patch_size",0)):,}</td></tr>'
        f'</tbody></table>'
        f'<p class="muted">For interactive byte-level review run: '
        f'<code>vbindiff &lt;reference&gt; &lt;target&gt;</code></p>'
    )

def _retdec_tab_html(retdec):
    return (
        f'<h2>RetDec Decompilation <span class="muted">(opt-in via --with-retdec)</span></h2>'
        f'<p>RetDec is Avast&apos;s open-source machine-code decompiler. Output '
        f'lives at <code>26-retdec/decompiled.c</code> (decompiled pseudo-C), '
        f'<code>decompiled.ll</code> (LLVM IR), and <code>config.json</code> '
        f'(decompilation metadata). RetDec runs in a Docker container; the '
        f'first invocation pulls the image (~2 GB).</p>'
        f'<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>'
        f'<tr><td>Decompiled .c size (bytes)</td><td>{int(retdec.get("size_bytes",0)):,}</td></tr>'
        f'<tr><td>Decompiled .c lines</td><td>{int(retdec.get("decompiled_lines",0)):,}</td></tr>'
        f'</tbody></table>'
    )

# Insert audit-6 tabs in this order: ROP Gadgets, Binary Diff, RetDec.
# Anchor is the dynamic tab (or viz, or logs in cascade).
audit6_anchor = next(
    (a for a in ("dynamic", "viz", "logs") if any(t[0] == a for t in tabs)),
    None,
)
audit6_anchor_idx = (
    next((i for i, t in enumerate(tabs) if t[0] == audit6_anchor), len(tabs))
    if audit6_anchor else len(tabs)
)

# Build in order then splice in reverse so the final order in tabs[] is
# (capability tabs) ROP -> BinaryDiff -> RetDec -> Dynamic -> Viz -> Logs
audit6_inserts = []
if _retdec.get("ran"):
    audit6_inserts.append(("retdec", "RetDec", _retdec_tab_html(_retdec)))
if _bdiff.get("ran"):
    audit6_inserts.append(("bindiff", "Binary Diff", _bdiff_tab_html(_bdiff)))
if _rop.get("ran"):
    audit6_inserts.append(("rop", "ROP Gadgets", _rop_tab_html(_rop)))

for entry in audit6_inserts:
    tabs.insert(audit6_anchor_idx, entry)

tab_buttons = "".join(
    f'<button class="tab{" active" if i == 0 else ""}" id="tab-{tid}" onclick="st(\'{tid}\')">{esc(label)}</button>'
    for i, (tid, label, _) in enumerate(tabs)
)
tab_pages = "".join(
    f'<div class="tp{" active" if i == 0 else ""}" id="pg-{tid}">{body}</div>'
    for i, (tid, _, body) in enumerate(tabs)
)

out_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(fname)} -- RE Report</title>
<style>{CSS}</style>
</head>
<body>
<a id="top"></a>
<div class="w">
  <div class="doc-header">
    <div class="doc-title">{esc(fname)} -- Reverse Engineering Report</div>
    <div class="doc-subtitle">{subtitle} &middot; {esc(S['file']['file_type'])} &middot; {now}</div>
  </div>

  <div class="summary-banner">
    <h3>At A Glance</h3>
    <div class="summary-grid">{banner_html}</div>
  </div>

  <div class="tn">{tab_buttons}</div>
  {tab_pages}

  <div class="footer">
    Generated by RE-Toolkit v3.0.0 &middot; {now}
    &middot; <a href="../index.html">&larr; Codebase Index</a>
  </div>
</div>
<script>{JS}</script>
</body>
</html>
"""

# v3.7.2 (audit-30 A4): redact operator-identifying absolute paths from the
# finished report before writing it. This is a defense-in-depth final pass: the
# per-tool "Command:" headers and the ledger are already sanitized at their
# source (sanitize_path_str in lib/tool-runner.sh), but the report also embeds
# paths that arrive by other routes (the summary's file field, quoted tool
# output, etc.), so a single sweep over the assembled HTML guarantees nothing
# leaks regardless of source. The report uses only RELATIVE hrefs (verified
# audit-30), so rewriting absolute paths cannot break any link.
#   - the analysis output root (parent of OUTDIR) -> <output>
#   - any residual home directory (/home/<user>, /Users/<user>, /root) -> redacted
# so a path like /home/alice/Desktop/retoolkit/out/bin.exe/_input/bin.exe
# becomes <output>/bin.exe/_input/bin.exe with no username.
def _redact_operator_paths(html):
    import re as _re_rd
    try:
        _output_root = os.path.dirname(os.path.abspath(OUTDIR.rstrip("/")))
        if _output_root and _output_root not in ("", "/"):
            html = html.replace(_output_root, "<output>")
    except Exception:
        pass
    # Generic home-directory redaction for anything outside the output root
    # (e.g. the RE-Toolkit install dir under the operator's home). Keeps the
    # trailing path structure, drops only the "/home/<user>" identity segment.
    html = _re_rd.sub(r'/home/[^/\s"\'<>]+', '/home/<user>', html)
    html = _re_rd.sub(r'/Users/[^/\s"\'<>]+', '/Users/<user>', html)
    html = _re_rd.sub(r'/root/[^/\s"\'<>]+', '/root/<redacted>', html)
    return html

out_html = _redact_operator_paths(out_html)

with open(os.path.join(OUTDIR, "_report.html"), "w", encoding="utf-8") as f:
    f.write(out_html)
print(f"Report: {os.path.join(OUTDIR, '_report.html')} ({len(out_html):,} bytes)")
PYEOF

    if [[ -f "${outdir}/_report.html" ]]; then
        log_step "report: $(du -h "${outdir}/_report.html" | cut -f1) → ${outdir}/_report.html"
    fi
}

# =============================================================================
