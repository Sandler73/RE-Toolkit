#!/usr/bin/env bash
# =============================================================================
# stages/static/85-summary.sh
# =============================================================================
#
# Synopsis:
#     Per-binary summary synthesis producing the authoritative _summary.json.
#
# Description:
#     Reads every stage output and writes: _summary.json -- structured findings
#     (fed to report stage) _verdict.txt -- one-line human verdict The JSON is
#     the single source of truth for the HTML report generator.
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
#     stage_summary()
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_summary() {
    local target="$1" outdir="$2"
    [[ -z "$VENV_PY" ]] && { log_step "summary: skipped (no venv)"; return 0; }

    "$VENV_PY" - "$target" "$outdir" <<'PYEOF' || true
"""Per-binary summary synthesizer for RE-Toolkit.

Reads every stage's output and produces _summary.json + _verdict.txt at the
root of the binary's output dir. The JSON is the single source of truth
consumed by stage_report to build the HTML.

Dependency-free (stdlib only).
"""
import os, sys, json, re, hashlib
from datetime import datetime, timezone

TARGET, OUTDIR = sys.argv[1], sys.argv[2]

def read_text(path, limit=None):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            d = f.read()
        return d if limit is None else d[:limit]
    except Exception:
        return ""

def read_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None

def file_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

def file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0

# ---- Extract hashes ----------------------------------------------------------
hashes = {}
hashes_txt = read_text(os.path.join(OUTDIR, "00-triage", "hashes.txt"))
for line in hashes_txt.splitlines():
    m = re.match(r'(sha256|sha1|md5)\s+([0-9a-fA-F]+)', line.strip())
    if m:
        hashes[m.group(1)] = m.group(2)

# ---- File type ---------------------------------------------------------------
file_txt = read_text(os.path.join(OUTDIR, "00-triage", "file.txt")).strip()
size = file_size(TARGET)

# ---- DIE ---------------------------------------------------------------------
die_txt = read_text(os.path.join(OUTDIR, "00-triage", "die.txt"))
die_findings = []
die_packer = None
die_compiler = None
die_protector = None
for line in die_txt.splitlines():
    s = line.strip()
    if not s or s.startswith('===') or s.startswith('---'):
        continue
    die_findings.append(s)
    low = s.lower()
    if 'packer:' in low and die_packer is None:
        die_packer = s.split(':', 1)[1].strip()
    if 'compiler:' in low and die_compiler is None:
        die_compiler = s.split(':', 1)[1].strip()
    if 'protector:' in low and die_protector is None:
        die_protector = s.split(':', 1)[1].strip()

# ---- Authenticode -----------------------------------------------------------
auth_txt = read_text(os.path.join(OUTDIR, "00-triage", "authenticode.txt"))
auth = {"present": False, "valid": None, "signer": None, "raw": auth_txt.strip()}
if auth_txt:
    low = auth_txt.lower()
    if "signature verification ok" in low or "successfully verified" in low:
        auth["present"] = True
        auth["valid"] = True
    elif "no signature found" in low or "not signed" in low:
        auth["present"] = False
    elif "signature verification" in low and ("fail" in low or "error" in low):
        auth["present"] = True
        auth["valid"] = False
    # Signer DN: look for a line starting with "Subject:" or containing CN=
    for line in auth_txt.splitlines():
        m = re.search(r'CN\s*=\s*([^,\n]+)', line)
        if m and auth["signer"] is None:
            auth["signer"] = m.group(1).strip()

# ---- Entropy ----------------------------------------------------------------
ent_txt = read_text(os.path.join(OUTDIR, "00-triage", "entropy.txt"))
entropy_overall = None
entropy_sections = []
entropy_high_count = 0
m = re.search(r'Overall entropy:\s*([0-9.]+)', ent_txt)
if m:
    try:
        entropy_overall = float(m.group(1))
    except ValueError:
        pass
for line in ent_txt.splitlines():
    m = re.match(r'\s*(\S+)\s+(\d+)\s+(\d+)\s+([0-9.]+)\s*(HIGH|LOW)?', line)
    if m and m.group(1) not in ('Section', 'Offset', 'File:', 'Size:'):
        try:
            ent_val = float(m.group(4))
            entry = {
                "name": m.group(1),
                "vsize": int(m.group(2)),
                "rsize": int(m.group(3)),
                "entropy": ent_val,
                "flag": m.group(5) or "",
            }
            entropy_sections.append(entry)
            if ent_val > 7.0:
                entropy_high_count += 1
        except ValueError:
            pass

# ---- TrID (v2.3.0) ----------------------------------------------------------
# Format: "  NN.N% (.ext) Description (prevalence)"
# We capture the top 3 matches for the _summary.json.
trid_txt = read_text(os.path.join(OUTDIR, "00-triage", "trid.txt"))
trid_matches = []
for line in trid_txt.splitlines():
    m = re.match(r'\s*([0-9]+\.[0-9]+)%\s*\(\.([^)]*)\)\s*(.*)', line)
    if m:
        try:
            trid_matches.append({
                "confidence": float(m.group(1)),
                "extension":  m.group(2),
                "description": m.group(3).strip(),
            })
            # v3.0.14 (audit-18 B1) - bump cap from 3 to 10. The
            # Overview tab now surfaces the full top-10 match list
            # with confidence percentages; pre-v3.0.14 only the top
            # 3 reached the report. Audit-17 F1 made TrID actually
            # find its definitions, so we now have meaningful data
            # to surface; raising the cap turns that into analyst
            # value rather than buried-in-trid.txt detail.
            if len(trid_matches) >= 10:
                break
        except ValueError:
            pass

# ---- pescan anomaly flags (v2.3.0) ------------------------------------------
# pescan prints lines like "suspicious: <reason>" when it finds anomalies.
# We capture these verbatim; stage_report surfaces them in the PE tab.
pescan_txt = read_text(os.path.join(OUTDIR, "14-pev", "pescan.txt"))
pescan_anomalies = []
for line in pescan_txt.splitlines():
    s = line.strip()
    if not s:
        continue
    low = s.lower()
    if ('suspicious' in low or 'anomal' in low or 'possibly packed' in low
            or 'tls callback' in low or 'no signature' in low):
        pescan_anomalies.append(s)

# ---- de4dot detection (v2.3.0) ----------------------------------------------
# Parse 22-de4dot/detection.txt. "Detected <obfuscator>" line signals a hit.
# Absence = either cleanly non-obfuscated or unrecognized obfuscator.
de4dot_txt = read_text(os.path.join(OUTDIR, "22-de4dot", "detection.txt"))
de4dot = {
    "ran":            bool(de4dot_txt),
    "obfuscator":     None,
    "deobfuscated":   False,
    "deobfuscated_cs_count": 0,
}
for line in de4dot_txt.splitlines():
    m = re.match(r'^Detected\s+(.*?)(?:\s*\(|\s*$)', line)
    if m:
        de4dot["obfuscator"] = m.group(1).strip()
        break
# Check if deobfuscated output exists
d4_deobf_dir = os.path.join(OUTDIR, "22-de4dot", "deobfuscated")
if os.path.isdir(d4_deobf_dir):
    deobf_files = [f for f in os.listdir(d4_deobf_dir)
                   if not f.endswith('.log') and os.path.isfile(os.path.join(d4_deobf_dir, f))]
    de4dot["deobfuscated"] = len(deobf_files) > 0
d4_ilspy_dir = os.path.join(OUTDIR, "22-de4dot", "deobfuscated-ilspy")
if os.path.isdir(d4_ilspy_dir):
    de4dot["deobfuscated_cs_count"] = sum(
        1 for root, _, files in os.walk(d4_ilspy_dir)
        for f in files if f.endswith('.cs')
    )

# v3.0.10 (audit-14 E1) - unified obfuscator/packer detection aggregator.
# v3.0.11 (audit-15 A1) - FORWARD DECLARATION ONLY. The fully populated
# version is built in the "obfuscator_unified finalization" block at the
# end of summary construction (after manalyze_data, die_packer/protector,
# and peframe_data are all defined). Pre-v3.0.11 this block referenced
# manalyze_data here, which does not exist yet (it's defined ~300 lines
# later in the heredoc). The forward reference passed bash -n
# (Python is parsed by the interpreter, not by bash) but produced
# NameError at runtime, crashing Stage 85 and cascading to no
# _summary.json / no _verdict.txt / no _report.html.
#
# Fix: forward-declare obfuscator_unified as an empty placeholder with
# only de4dot data (which IS already defined above). All other source
# data is populated at finalization time.
#
# Operator finding F6 (audit-14): de4dot frequently reports "Unknown
# Obfuscator" but other tools (DIE, manalyze peid plugin, peframe
# packers) often have positive detections that audit-12 D1 only
# partially surfaced. This dict aggregates ALL signal sources into a
# single per-source breakdown, then computes a unified verdict so the
# Obfuscation tab in the report can show "de4dot says Unknown but
# DIE detected ConfuserEx 1.0.0" as one coherent answer.
obfuscator_unified = {
    "any_detected": False,
    "sources": {
        "de4dot": {
            "obfuscator": de4dot.get("obfuscator"),
            "deobfuscated": de4dot.get("deobfuscated", False),
        },
        # The following sources are forward-declared empty; populated at
        # finalization (see "obfuscator_unified finalization" block).
        "die": {"packer": "", "protector": ""},
        "manalyze": {"packer_hits": [], "peid_signatures": []},
        "peframe": {"packers": []},
    },
    "unified_verdict": "",
}
# any_detected from de4dot only at this point. The full check (which
# considers ALL sources) runs at finalization.
if de4dot.get("obfuscator") and de4dot["obfuscator"].lower() not in ("unknown", "unknown obfuscator"):
    obfuscator_unified["any_detected"] = True

# ---- LIEF supplementary (v2.3.0) --------------------------------------------
# The lief-full.json has structural data we already collect from other tools,
# but two things stage_summary wants: signature count (Authenticode crosscheck)
# and TLS callback count (suspicious-execution indicator).
lief_summary = {"parsed": False, "signature_count": 0, "tls_callbacks": 0}
lief_json_path = os.path.join(OUTDIR, "12-lief", "lief-full.json")
if os.path.isfile(lief_json_path):
    try:
        with open(lief_json_path, encoding="utf-8") as f:
            _lief = json.load(f)
        lief_summary["parsed"] = True
        lief_summary["format"] = _lief.get("format", "")
        sigs = _lief.get("signatures", []) or []
        lief_summary["signature_count"] = len(sigs)
        tls = _lief.get("tls", {}) or {}
        cbs = tls.get("callbacks", []) or []
        lief_summary["tls_callbacks"] = len(cbs)
    except Exception:
        pass

# ---- YARA -------------------------------------------------------------------
yara_txt = read_text(os.path.join(OUTDIR, "00-triage", "yara-matches.txt"))
yara_hits = []
for line in yara_txt.splitlines():
    s = line.strip()
    if not s or s.startswith('===') or 'yara' not in s.lower() and '/' not in s and s[0].islower() == False:
        # YARA output looks like "RuleName /path/to/binary"
        parts = s.split(None, 1)
        if len(parts) == 2 and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', parts[0]):
            yara_hits.append(parts[0])
            continue
    # Matches like "rulename [meta] /path/to/target"
    m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s', s)
    if m:
        if m.group(1) not in yara_hits:
            yara_hits.append(m.group(1))

# ---- ClamAV -----------------------------------------------------------------
clamav_txt = read_text(os.path.join(OUTDIR, "00-triage", "clamav.txt"))
clamav_hits = []
for line in clamav_txt.splitlines():
    if ' FOUND' in line:
        parts = line.split(':', 1)
        if len(parts) == 2:
            clamav_hits.append(parts[1].replace(' FOUND', '').strip())

# ---- capa -------------------------------------------------------------------
capa_data = read_json(os.path.join(OUTDIR, "00-triage", "capa.json"))
capa = {
    "rule_count": 0,
    "rules": [],
    "attack": [],       # [{id: Txxx, technique: "..."}]
    "mbc": [],          # [{id: Bxxx, behavior: "..."}]
    "namespaces": {},   # namespace -> count
    # v3.0.14 (audit-18 B6) - rule_count per technique/behavior
    # for the new aggregation tables in Capabilities tab.
    "attack_rule_counts": {},  # "T1059" -> count of rules that hit
    "mbc_rule_counts": {},     # "B0023" -> count of rules that hit
}
if capa_data:
    rules_node = capa_data.get("rules", {})
    if isinstance(rules_node, dict):
        capa["rule_count"] = len(rules_node)
        for rname, rbody in rules_node.items():
            meta = (rbody or {}).get("meta", {}) if isinstance(rbody, dict) else {}
            # v3.0.14 (audit-18 B6) - extract per-rule evidence from
            # capa.json. The "matches" field on each rule body is a
            # list of [Address, Result] pairs where Address has type
            # ("absolute"|"file"|"dn token") and value (int VA or
            # token), and Result has node, children, and success.
            # We capture just the addresses + a count of children
            # (basic-block / instruction-level matches per address)
            # to keep _summary.json size manageable. The full
            # evidence trace lives in capa-rendered.txt.
            rule_evidence = []
            rule_match_count = 0
            try:
                _matches = (rbody or {}).get("matches", []) if isinstance(rbody, dict) else []
                if isinstance(_matches, list):
                    rule_match_count = len(_matches)
                    for _m in _matches[:20]:  # cap at 20 to bound JSON size
                        if isinstance(_m, list) and len(_m) >= 2:
                            _addr, _result = _m[0], _m[1]
                            _va = ""
                            if isinstance(_addr, dict):
                                _av = _addr.get("value", "")
                                _at = _addr.get("type", "")
                                if isinstance(_av, int):
                                    _va = f"0x{_av:x}"
                                else:
                                    _va = str(_av)
                                if _at and _at != "absolute":
                                    _va = f"{_at}:{_va}"
                            _children = 0
                            if isinstance(_result, dict):
                                _children = len(_result.get("children", []) or [])
                            rule_evidence.append({
                                "va": _va,
                                "feature_count": _children,
                            })
            except Exception:
                pass
            rule_entry = {
                "name": rname,
                "namespace": meta.get("namespace", ""),
                "scope": meta.get("scope", ""),
                "match_count": rule_match_count,
                "evidence": rule_evidence,
            }
            capa["rules"].append(rule_entry)
            ns = meta.get("namespace", "")
            if ns:
                capa["namespaces"][ns] = capa["namespaces"].get(ns, 0) + 1
            # ATT&CK -- capa schema: meta.attack = [{id: "T1059", ...}, ...]
            # v3.0.14 (audit-18 B6) - also tally rule_count per technique
            # so the Capabilities tab can show "T1059: 4 rules" etc.
            _seen_attack_in_rule = set()
            for att in meta.get("attack", []) or []:
                if isinstance(att, dict):
                    entry = {
                        "id": att.get("id", ""),
                        "technique": att.get("technique", ""),
                        "tactic": att.get("tactic", ""),
                        "subtechnique": att.get("subtechnique", ""),
                    }
                    if entry not in capa["attack"]:
                        capa["attack"].append(entry)
                    _aid = att.get("id", "")
                    if _aid and _aid not in _seen_attack_in_rule:
                        _seen_attack_in_rule.add(_aid)
                        capa["attack_rule_counts"][_aid] = (
                            capa["attack_rule_counts"].get(_aid, 0) + 1
                        )
            # MBC
            _seen_mbc_in_rule = set()
            for mb in meta.get("mbc", []) or []:
                if isinstance(mb, dict):
                    entry = {
                        "id": mb.get("id", ""),
                        "behavior": mb.get("behavior", ""),
                        "objective": mb.get("objective", ""),
                        "method": mb.get("method", ""),
                    }
                    if entry not in capa["mbc"]:
                        capa["mbc"].append(entry)
                    _bid = mb.get("id", "")
                    if _bid and _bid not in _seen_mbc_in_rule:
                        _seen_mbc_in_rule.add(_bid)
                        capa["mbc_rule_counts"][_bid] = (
                            capa["mbc_rule_counts"].get(_bid, 0) + 1
                        )

# ---- String counts ---------------------------------------------------------
strings_stats = {
    "ascii": file_lines(os.path.join(OUTDIR, "00-triage", "strings-ascii.txt")),
    "utf16le": file_lines(os.path.join(OUTDIR, "00-triage", "strings-utf16le.txt")),
    "utf16be": file_lines(os.path.join(OUTDIR, "00-triage", "strings-utf16be.txt")),
}

# ---- PE / imports / exports -------------------------------------------------
pe_txt = read_text(os.path.join(OUTDIR, "10-pe", "pefile.txt"))
is_pe = bool(pe_txt and "DOS_HEADER" in pe_txt)
imports = []   # {"lib": "kernel32.dll", "funcs": [...], "kind": "import"|"delay"|"bound"}
exports = []   # {"name": ..., "ord": ..., "rva": ...}
sections_pe = []
assembly_refs = []  # v3.0.10 (audit-14 D3) - .NET AssemblyRef table
current_lib = None
in_imports = False
in_exports = False
in_sections = False
in_assemblyref = False  # v3.0.10
for line in pe_txt.splitlines():
    s = line.strip()
    if s == "=== IMPORTS ===":
        in_imports, in_exports, in_sections, in_assemblyref = True, False, False, False; continue
    if s == "=== EXPORTS ===":
        in_imports, in_exports, in_sections, in_assemblyref = False, True, False, False; continue
    if s == "=== SECTIONS ===":
        in_imports, in_exports, in_sections, in_assemblyref = False, False, True, False; continue
    if s == "=== ASSEMBLYREF ===":
        # v3.0.10 (audit-14 D3) - .NET assembly references section
        in_imports, in_exports, in_sections, in_assemblyref = False, False, False, True; continue
    if s.startswith("==="):
        in_imports = in_exports = in_sections = in_assemblyref = False; continue
    if in_imports:
        # v3.0.10 (audit-14 D3) - recognize three import-line prefixes:
        #   "Lib: foo.dll"          -> kind=import   (standard imports)
        #   "Lib (delay): foo.dll"  -> kind=delay    (delay-loaded)
        #   "Lib (bound): foo.dll"  -> kind=bound    (bound at link time)
        # Pre-v3.0.10 only the first form was emitted by 10-pe.sh and
        # parsed here; delay/bound were silently dropped, contributing
        # to the operator's "1 import" undercount on real Windows EXEs.
        m = re.match(r'Lib\s*\(delay\):\s*(\S+)', s)
        if m:
            current_lib = {"lib": m.group(1), "funcs": [], "kind": "delay"}
            imports.append(current_lib); continue
        m = re.match(r'Lib\s*\(bound\):\s*(\S+)', s)
        if m:
            current_lib = {"lib": m.group(1), "funcs": [], "kind": "bound"}
            imports.append(current_lib); continue
        m = re.match(r'Lib:\s*(\S+)', s)
        if m:
            current_lib = {"lib": m.group(1), "funcs": [], "kind": "import"}
            imports.append(current_lib)
        elif current_lib is not None and s:
            current_lib["funcs"].append(s)
    elif in_exports:
        m = re.match(r'ord=(\d+)\s+rva=(\S+)\s+(.+)', s)
        if m:
            exports.append({"ord": int(m.group(1)), "rva": m.group(2), "name": m.group(3)})
    elif in_sections:
        m = re.match(r'(\S+)\s+vaddr=(\S+)\s+vsize=(\S+)\s+rsize=(\S+)\s+flags=(\S+)', s)
        if m:
            sections_pe.append({
                "name": m.group(1),
                "vaddr": m.group(2), "vsize": m.group(3),
                "rsize": m.group(4), "flags": m.group(5),
            })
    elif in_assemblyref:
        # v3.0.10 (audit-14 D3) - parse "Ref: <name> v<version>" lines
        # emitted by 10-pe.sh's dnfile-based AssemblyRef enumeration.
        m = re.match(r'Ref:\s*(\S+)\s+v(\S+)', s)
        if m:
            assembly_refs.append({"name": m.group(1), "version": m.group(2)})

# Suspicious import categories (same conventions as PEStudio-style triage)
SUSPICIOUS_IMPORTS = {
    "injection": {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "SetWindowsHookExA", "SetWindowsHookExW",
        "QueueUserAPC", "NtMapViewOfSection", "ZwMapViewOfSection",
    },
    "evasion": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA",
        "GetTickCount", "QueryPerformanceCounter",
    },
    "network": {
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA",
        "HttpSendRequestA", "HttpSendRequestW", "WinHttpOpen",
        "WinHttpConnect", "socket", "connect", "send", "recv",
        "URLDownloadToFileA", "URLDownloadToFileW",
    },
    "persistence": {
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "RegCreateKeyExW", "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW",
    },
    "crypto": {
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
        "CryptAcquireContextW", "BCryptEncrypt", "BCryptDecrypt",
    },
    "process_manipulation": {
        "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
        "OpenProcess", "TerminateProcess", "NtSuspendProcess",
    },
}

suspicious = {}  # category -> [funcname,...]
for entry in imports:
    for fn in entry["funcs"]:
        for cat, names in SUSPICIOUS_IMPORTS.items():
            if fn in names:
                suspicious.setdefault(cat, []).append(fn)

# ---- .NET ilspy -------------------------------------------------------------
dotnet_cs_count = 0
ilspy_dir = os.path.join(OUTDIR, "20-dotnet", "ilspy")
if os.path.isdir(ilspy_dir):
    for root, _, files in os.walk(ilspy_dir):
        for fn in files:
            if fn.endswith(".cs"):
                dotnet_cs_count += 1

# ---- Ghidra dump ------------------------------------------------------------
ghidra_dump_size = 0
_ghidra_dump_path = None
for fn in os.listdir(os.path.join(OUTDIR, "30-ghidra")) if os.path.isdir(os.path.join(OUTDIR, "30-ghidra")) else []:
    if fn.endswith(".ghidra-dump.txt"):
        _ghidra_dump_path = os.path.join(OUTDIR, "30-ghidra", fn)
        ghidra_dump_size = file_size(_ghidra_dump_path)
        break

# v3.7.0 (audit-28): parse the Ghidra dump's decompilation (Section 13) and
# call graph (Section 14) here in the summary stage. stage_summary (85) runs
# BEFORE stage_viz (89), which is what writes 30-ghidra/dump-parsed.json -- so
# the summary cannot rely on that file existing yet and parses the raw dump
# directly. This is a third, self-contained copy of the Section-13/14 parse
# (89-viz and 90-report have the others); kept local to isolate the v3.7.0
# feature work from those working parsers. FUTURE: factor into a shared
# lib/ghidra-parse.sh emitter (viz-helper pattern) to retire the duplication.
def _summary_parse_ghidra(dump_path):
    """Return {"decompilation": [...], "call_graph": [...]} from a raw dump."""
    out = {"decompilation": [], "call_graph": []}
    if not dump_path or not os.path.isfile(dump_path):
        return out
    try:
        with open(dump_path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except Exception:
        return out
    sec_re = re.compile(r'^\s*SECTION\s+(\d+)\s+-\s+(.*)$')
    # v3.7.2 (audit-30 A1): accept BARE hex addresses ("00402051") as well as
    # "0x"-prefixed. GhidraDump.py's fmt_addr() emits bare hex; the pre-v3.7.2
    # regex required "0x" and so matched nothing on real dumps, leaving the
    # v3.7.0 features (structural / function-purpose / data-flow) empty.
    _ADDR = r'(?:0x)?[0-9a-fA-F]+'
    hdr_re = re.compile(r'^###\s+(\S.*?)\s+@\s+(' + _ADDR + r')\s+\((\d+)\s+bytes\)\s*$')
    current = None
    cur = None

    def flush():
        if cur is not None:
            code = "\n".join(cur["code_lines"]).rstrip()
            st = cur["status"]
            if st == "ok" and not code.strip():
                st = "empty"
            out["decompilation"].append({
                "name": cur["name"], "addr": cur["addr"],
                "bytes": cur["bytes"], "code": code, "status": st,
            })

    for ln in lines:
        m = sec_re.match(ln)
        if m:
            if current == 13:
                flush(); cur = None
            current = int(m.group(1))
            continue
        if current == 13:
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
        elif current == 14:
            s = ln.rstrip()
            if not s:
                continue
            mcaller = re.match(r'^(\S.*?)\s+\((' + _ADDR + r')\)\s+calls:\s*$', s)
            if mcaller:
                out["call_graph"].append({"caller": mcaller.group(1), "callees": []})
                continue
            mcallee = re.match(r'^\s+->\s+(\S.*?)\s+\((' + _ADDR + r')\)\s*$', s)
            if mcallee and out["call_graph"]:
                out["call_graph"][-1]["callees"].append(mcallee.group(1))
    if current == 13:
        flush()
    return out

_ghidra_parsed = _summary_parse_ghidra(_ghidra_dump_path)
decompilation = _ghidra_parsed["decompilation"]
call_graph = _ghidra_parsed["call_graph"]

# ---- IOCs -------------------------------------------------------------------
ioc_data = read_json(os.path.join(OUTDIR, "80-iocs", "_iocs.json"))
ioc_totals = {}
if ioc_data:
    for k, v in ioc_data.items():
        if k == "_meta": continue
        if isinstance(v, list):
            ioc_totals[k] = len(v)
ioc_total = sum(ioc_totals.values())

# ---- Severity calculation (v3.2.0 audit-23 A2.1: weighted model) -------------
# Replaces the pre-v3.2.0 linear if/elif ladder (first-match-wins, no
# accumulation, no explainability) with a weighted-signal model. Each signal
# contributes a documented (name, weight, evidence) tuple to score_signals[].
# After ALL signals are collected -- including the type-specific ones appended
# later in this script (PDF/OLE/authchain/CWE) -- compute_score_band() derives
# the final severity from the total. This eliminates the pre-v3.2.0
# incoherence where type-specific blocks did ad-hoc `if severity == "low":
# severity = "medium"` string bumps (which also used the wrong value "medium"
# vs the ladder's "med", and only ever bumped from "low").
#
# Score bands (documented, tunable):
#     >= 100 : crit    60-99 : high    30-59 : med    10-29 : low    0-9 : info
#
# The weighted model preserves the backward-compatible `severity` (same 5
# values crit/high/med/low/info) and `severity_reasons` keys, and ADDS
# score, score_band, and score_breakdown[] for the A5.1 explainable panel.
is_packed = bool(die_packer or entropy_high_count > 0)
is_signed = bool(auth.get("present") and auth.get("valid"))
has_suspicious = bool(suspicious)

# score_signals: list of dicts {name, weight, evidence}. Populated here for
# the universal signals and appended-to later by type-specific blocks. The
# final band is computed at end-of-script via compute_score_band().
score_signals = []

# v3.2.0 (A2.1): advisory_notes carries diagnostic / operator-guidance
# messages that are NOT risk signals (e.g. "dynamic analysis could not run,
# check skip reasons", SIGILL/SIGSEGV emulation explanations). These must not
# inflate the risk score, but they are still surfaced in the verdict so the
# operator sees them. Kept separate from score_signals for exactly this
# reason: mixing diagnostics into the score was part of the pre-v3.2.0
# incoherence.
advisory_notes = []

def add_signal(name, weight, evidence):
    """Append a scored signal. weight may be capped by the caller.

    name     : short signal identifier (shown in the explainable panel)
    weight   : integer points contributed to the risk score
    evidence : human-readable evidence string (what triggered this signal)
    """
    if weight <= 0:
        return
    score_signals.append({"name": name, "weight": int(weight), "evidence": str(evidence)})

# --- Universal signals (all binary types) ---
# Definitive AV detection: ClamAV is a signature-based scanner; a hit is the
# single strongest signal we have.
if clamav_hits:
    add_signal("clamav_detection", 100,
               f"ClamAV hits: {', '.join(clamav_hits)}")

# YARA rule matches. 3+ distinct rules is a strong corroborated signal;
# 1-2 is meaningful but weaker (could be a broad/generic rule).
if yara_hits and len(yara_hits) >= 3:
    add_signal("yara_multi", 70,
               f"{len(yara_hits)} YARA rule matches")
elif yara_hits:
    add_signal("yara_few", 40,
               f"YARA matches: {', '.join(yara_hits[:3])}")

# Packer + suspicious imports composite. Packing alone is common (legit
# software packs too); packing WITH suspicious imports AND unsigned is the
# classic packed-dropper profile. The composite captures the INTERACTION
# (the combination is more suspicious than its parts summed). To avoid
# over-weighting the "packed" concept, when a composite fires we suppress the
# standalone packer_detected signal below (composite_fired flag), since the
# composite already accounts for packing. The per-category suspicious_imports
# and high_entropy signals still fire independently -- they measure different
# facets (which categories, how much entropy) and legitimately corroborate.
composite_fired = False
if not is_signed and is_packed and has_suspicious:
    add_signal("unsigned_packed_suspicious", 40,
               "unsigned + packed + suspicious-import combination")
    composite_fired = True
elif is_packed and has_suspicious:
    add_signal("packed_suspicious", 25,
               "packed with suspicious imports")
    composite_fired = True

# Suspicious imports by category (process injection, persistence, etc).
# 15 points per category, capped at 45 so a single binary with every
# category doesn't dominate the score on imports alone.
if has_suspicious:
    cats = sorted(suspicious.keys())
    add_signal("suspicious_imports", min(15 * len(cats), 45),
               f"suspicious import categories: {', '.join(cats)}")

# Packer detection (DIE-identified). Distinct from the composite above so a
# packed-but-signed binary still registers some weight. Suppressed when a
# composite already fired (the composite accounts for packing), so we don't
# double-count the packing concept.
if die_packer and not composite_fired:
    add_signal("packer_detected", 20, f"packer: {die_packer}")

# High-entropy sections. 8 points each, capped at 24. Weak-ish alone (some
# legit resources are high-entropy) but corroborates packing.
if entropy_high_count > 0:
    add_signal("high_entropy", min(8 * entropy_high_count, 24),
               f"{entropy_high_count} high-entropy section(s)")

# Unsigned PE (weak signal alone; most malware is unsigned but so is a lot
# of legit internal tooling). Low weight so it nudges rather than decides.
if is_pe and not auth.get("present"):
    add_signal("unsigned_pe", 5, "PE is unsigned")

# IOC density (weak). A high count of extracted IOCs (URLs, IPs, etc) is
# mildly suspicious in aggregate.
if ioc_total > 20:
    add_signal("ioc_density", 5, f"{ioc_total} IOCs extracted")

# severity + severity_reasons are computed at end-of-script (after
# type-specific signals). Initialize here so any code between here and there
# that references them (defensive) sees valid values. Recomputed by
# compute_score_band() below.
severity = "info"
severity_reasons = []

# ---- Verdict line -----------------------------------------------------------
verdict_parts = []
fname = os.path.basename(TARGET)

# Type + architecture
ft_short = file_txt.split(',')[0].strip() if file_txt else "unknown"
verdict_parts.append(ft_short)

# Signed?
if auth.get("present"):
    if auth.get("valid"):
        signer = auth.get("signer") or "unknown signer"
        verdict_parts.append(f"signed ({signer})")
    else:
        verdict_parts.append("signature INVALID")
elif is_pe:
    verdict_parts.append("unsigned")

# Packed?
if die_packer:
    verdict_parts.append(f"packed with {die_packer}")
elif entropy_high_count > 0:
    verdict_parts.append(f"{entropy_high_count} high-entropy sections")

# v2.3.0: obfuscation (from de4dot detection, not packer)
if de4dot.get("obfuscator"):
    verdict_parts.append(f"obfuscated with {de4dot['obfuscator']}")

# v2.3.0: pescan anomalies summary
if pescan_anomalies:
    verdict_parts.append(f"{len(pescan_anomalies)} pescan anomalies")

# capa summary
if capa["rule_count"] > 0:
    att_count = len(capa["attack"])
    mbc_count = len(capa["mbc"])
    bits = [f"{capa['rule_count']} capa rules"]
    if att_count: bits.append(f"{att_count} ATT&CK techniques")
    if mbc_count: bits.append(f"{mbc_count} MBC behaviors")
    verdict_parts.append(", ".join(bits))

# Suspicious imports
if suspicious:
    cat_summary = ", ".join(f"{k}({len(v)})" for k, v in sorted(suspicious.items()))
    verdict_parts.append(f"suspicious imports: {cat_summary}")

# ---- v2.5.0: Manalyze JSON parser ------------------------------------------
manalyze_data = {
    "ran": False,
    "suspicious_imports": [],
    "plugin_findings": [],
    "packer_hits": [],
    "score": None,
}
mz_path = os.path.join(OUTDIR, "16-manalyze", "manalyze.json")
if os.path.exists(mz_path):
    manalyze_data["ran"] = True
    mz_json = read_json(mz_path) or {}
    # Manalyze JSON top level keys are file hashes; descend one level
    for _file_key, _file_block in mz_json.items():
        if not isinstance(_file_block, dict):
            continue
        plugins = _file_block.get("Plugins", {}) or {}
        # Imports plugin: list of suspicious API combinations
        imp_plug = plugins.get("imports", {}) or plugins.get("Imports", {})
        if isinstance(imp_plug, dict):
            level = imp_plug.get("level", "")
            for finding in (imp_plug.get("plugin_output", {}) or {}).values():
                if isinstance(finding, list):
                    for item in finding:
                        if isinstance(item, str):
                            manalyze_data["suspicious_imports"].append(item)
            if level and level not in ("safe", "info"):
                manalyze_data["plugin_findings"].append(f"imports:{level}")
        # Packer detection plugin
        pkr_plug = plugins.get("packer", {}) or plugins.get("Packer", {})
        if isinstance(pkr_plug, dict):
            for finding in (pkr_plug.get("plugin_output", {}) or {}).values():
                if isinstance(finding, list):
                    for item in finding:
                        if isinstance(item, str):
                            manalyze_data["packer_hits"].append(item)
        # v3.0.10 (audit-14 E1) - peid plugin parsing. The peid plugin
        # returns PEiD signature matches that often identify packers/
        # protectors that de4dot misses (e.g., native UPX, MPRESS, NSIS,
        # Themida, Confuser variants). Pre-v3.0.10 the peid plugin output
        # was discarded; only the imports + packer plugins were parsed.
        # Including peid signals here drives the unified obfuscator
        # detection in the next block.
        peid_plug = plugins.get("peid", {}) or plugins.get("PeID", {}) or plugins.get("PEID", {})
        if isinstance(peid_plug, dict):
            for finding in (peid_plug.get("plugin_output", {}) or {}).values():
                if isinstance(finding, list):
                    for item in finding:
                        if isinstance(item, str):
                            # peid signatures look like "Microsoft Visual C++ 8" or "UPX 3.96 -> Markus Oberhumer..."
                            manalyze_data.setdefault("peid_signatures", []).append(item)
                elif isinstance(finding, str):
                    manalyze_data.setdefault("peid_signatures", []).append(finding)
        # All other plugins: collect their level if it's malicious/suspicious
        for plug_name, plug_data in plugins.items():
            if isinstance(plug_data, dict):
                level = plug_data.get("level", "")
                if level in ("malicious", "suspicious"):
                    manalyze_data["plugin_findings"].append(f"{plug_name}:{level}")
    if manalyze_data["plugin_findings"]:
        verdict_parts.append(
            f"manalyze: {len(manalyze_data['plugin_findings'])} flagged plugin(s)"
        )
# Ensure peid_signatures key exists even when manalyze didn't run
manalyze_data.setdefault("peid_signatures", [])

# ---- v2.5.0: peframe JSON parser -------------------------------------------
peframe_data = {
    "ran": False,
    "packers": [],
    "antidbg": [],
    "antivm": [],
    "suspicious_apis": [],
    "macros": False,
    "url_count": 0,
}
pf_path = os.path.join(OUTDIR, "17-peframe", "peframe.json")
if os.path.exists(pf_path):
    peframe_data["ran"] = True
    pf_json = read_json(pf_path) or {}
    # peframe JSON has top-level keys like 'peinfo', 'features', 'strings', ...
    features = pf_json.get("peinfo", {}).get("features", {}) or pf_json.get("features", {})
    if isinstance(features, dict):
        peframe_data["packers"] = list(features.get("packer", []) or [])
        peframe_data["antidbg"] = list(features.get("antidbg", []) or [])
        peframe_data["antivm"] = list(features.get("antivm", []) or [])
    # Suspicious APIs nested under behavior block (varies by peframe version)
    behavior = pf_json.get("peinfo", {}).get("behavior", {}) or pf_json.get("behavior", {})
    if isinstance(behavior, dict):
        for cat, items in behavior.items():
            if isinstance(items, list):
                peframe_data["suspicious_apis"].extend(items)
    # Macro detection (Office docs - usually empty for PE files, but parse anyway)
    docinfo = pf_json.get("docinfo") or {}
    if isinstance(docinfo, dict) and docinfo.get("macro"):
        peframe_data["macros"] = True
    # URL count (peframe extracts URLs from strings)
    strings_block = pf_json.get("strings", {}) or {}
    urls = strings_block.get("url", []) or []
    peframe_data["url_count"] = len(urls) if isinstance(urls, list) else 0
    if peframe_data["packers"] or peframe_data["antidbg"] or peframe_data["antivm"]:
        flags = []
        if peframe_data["packers"]:  flags.append(f"{len(peframe_data['packers'])} packer")
        if peframe_data["antidbg"]:  flags.append(f"{len(peframe_data['antidbg'])} antidbg")
        if peframe_data["antivm"]:   flags.append(f"{len(peframe_data['antivm'])} antivm")
        verdict_parts.append("peframe: " + ", ".join(flags))

# ---- v2.5.0: cwe_checker JSON parser ---------------------------------------
cwe_data = {
    "ran": False,
    "total_hits": 0,
    "by_cwe": {},
    "warnings": [],
}
cwe_path = os.path.join(OUTDIR, "34-cwe", "cwe_checker.json")
if os.path.exists(cwe_path):
    cwe_data["ran"] = True
    cwe_json = read_json(cwe_path)
    # cwe_checker JSON is a list of warning objects, each with name/description
    if isinstance(cwe_json, list):
        cwe_data["total_hits"] = len(cwe_json)
        for warn in cwe_json:
            if isinstance(warn, dict):
                name = warn.get("name", "?")
                cwe_data["by_cwe"][name] = cwe_data["by_cwe"].get(name, 0) + 1
                # Keep first 50 warnings inline; the rest live in the JSON file
                if len(cwe_data["warnings"]) < 50:
                    cwe_data["warnings"].append({
                        "name": name,
                        "description": (warn.get("description") or "")[:200],
                        "addresses": warn.get("addresses", [])[:5],
                    })
    if cwe_data["total_hits"] > 0:
        top_cwes = ", ".join(
            f"{k}({v})" for k, v in sorted(
                cwe_data["by_cwe"].items(), key=lambda kv: -kv[1]
            )[:5]
        )
        verdict_parts.append(
            f"cwe_checker: {cwe_data['total_hits']} hit(s) [{top_cwes}]"
        )
        # Bump severity for high-impact CWE classes
        critical_cwes = {"CWE119", "CWE415", "CWE416", "CWE787"}
        critical_hits = sum(v for k, v in cwe_data["by_cwe"].items() if k in critical_cwes)
        if critical_hits > 0:
            # v3.2.0 (A2.1): weighted signal, 20 per critical hit capped at 40.
            add_signal("cwe_critical", min(20 * critical_hits, 40),
                       f"{critical_hits} critical CWE hit(s) (memory-safety class)")

# ---- v2.5.0: signsrch hit count --------------------------------------------
signsrch_data = {"ran": False, "hits": 0, "top_titles": [], "hit_details": []}
ss_path = os.path.join(OUTDIR, "00-triage", "signsrch.txt")
if os.path.exists(ss_path):
    signsrch_data["ran"] = True
    ss_text = read_text(ss_path) or ""
    # Match lines like "  1234abcd  42  Title goes here"
    # Group 1=offset (8 hex), Group 2=count, Group 3=title
    import re as _re
    hit_lines_full = _re.findall(
        r'^\s*([0-9a-fA-F]{8})\s+(\d+)\s+(.+)$', ss_text, _re.MULTILINE
    )
    signsrch_data["hits"] = len(hit_lines_full)
    # v3.0.14 (audit-18 B7) - capture per-hit detail for the
    # Strings tab signsrch panel: offset (file offset where the
    # signature matched), bytes_count (signature width), and title
    # (algorithm/constant name). Pre-v3.0.14 only the unique-title
    # list reached _summary.json; the offsets which are essential
    # for analyst pivot to disasm/hexdump were dropped on the floor.
    for off_hex, count_str, title in hit_lines_full[:50]:
        try:
            signsrch_data["hit_details"].append({
                "offset": "0x" + off_hex.lower(),
                "bytes": int(count_str),
                "title": title.strip(),
            })
        except (ValueError, TypeError):
            pass
    # Top 10 unique titles (pre-v3.0.14 behavior preserved)
    seen = set()
    for _o, _c, title in hit_lines_full:
        title = title.strip()
        if title and title not in seen:
            seen.add(title)
            signsrch_data["top_titles"].append(title)
            if len(signsrch_data["top_titles"]) >= 10:
                break

# ---- v2.5.0: checksec mitigations (ELF) ------------------------------------
mitigations = {
    "ran": False,
    "nx": None, "pie": None, "relro": None,
    "canary": None, "fortify": None, "rpath": None,
}
cs_path = os.path.join(OUTDIR, "50-elf", "checksec.txt")
if os.path.exists(cs_path):
    mitigations["ran"] = True
    cs_text = read_text(cs_path) or ""
    cs_lower = cs_text.lower()
    # Pattern matching against checksec's tabular output. checksec.sh,
    # checksec(apt), and pwn checksec all use slightly different labels;
    # try multiple formats. None means we couldn't determine.
    if "no canary found" in cs_lower or "canary    no" in cs_lower:
        mitigations["canary"] = "absent"
    elif "canary found" in cs_lower or "canary   yes" in cs_lower:
        mitigations["canary"] = "present"
    if "nx disabled" in cs_lower or "nx    no" in cs_lower:
        mitigations["nx"] = "disabled"
    elif "nx enabled" in cs_lower or "nx    yes" in cs_lower:
        mitigations["nx"] = "enabled"
    if "no pie" in cs_lower or "pie    no" in cs_lower:
        mitigations["pie"] = "no-pie"
    elif "pie enabled" in cs_lower or "pie    yes" in cs_lower:
        mitigations["pie"] = "pie"
    if "no relro" in cs_lower or "relro     no" in cs_lower:
        mitigations["relro"] = "none"
    elif "partial relro" in cs_lower:
        mitigations["relro"] = "partial"
    elif "full relro" in cs_lower:
        mitigations["relro"] = "full"
    if "fortify_source" in cs_lower or "fortify    yes" in cs_lower:
        mitigations["fortify"] = "enabled"
    # Verdict contribution: if we have a clear missing mitigation, flag it
    missing = []
    if mitigations["nx"] == "disabled":     missing.append("NX")
    if mitigations["pie"] == "no-pie":      missing.append("PIE")
    if mitigations["relro"] == "none":      missing.append("RELRO")
    if mitigations["canary"] == "absent":   missing.append("Canary")
    if missing:
        verdict_parts.append("missing ELF mitigations: " + ",".join(missing))

verdict_line = f"{fname}: " + "; ".join(verdict_parts) + "."
if severity_reasons:
    verdict_line += f" [severity={severity}: {'; '.join(severity_reasons)}]"

# ---- v2.6.0: New binary type bucket parsers ---------------------------------
import os as _os

# macho block (52-macho/)
macho_data = {"ran": False, "load_commands": 0, "sections": 0, "libraries": [], "code_signed": False}
mh_lief = _os.path.join(OUTDIR, "52-macho", "lief-macho.txt")
if _os.path.exists(mh_lief):
    macho_data["ran"] = True
    txt = read_text(mh_lief) or ""
    # Count load commands and sections
    macho_data["load_commands"] = len([l for l in txt.splitlines() if l.strip().startswith("[") and " - size " in l])
    macho_data["sections"] = sum(1 for l in txt.splitlines() if " entropy=" in l)
    # Collect library names
    in_libs = False
    for line in txt.splitlines():
        if line.startswith("=== Imported libraries"):
            in_libs = True; continue
        if in_libs:
            if line.startswith("==="): break
            line = line.strip()
            if line and not line.startswith("==="):
                # Format: "  /path/to/lib  (compat=..., current=...)"
                lib = line.split("  ")[0].strip()
                if lib:
                    macho_data["libraries"].append(lib)
    macho_data["code_signed"] = "Present: yes" in txt
    if macho_data["sections"]:
        verdict_parts.append(f"macho: {macho_data['sections']} sections, {len(macho_data['libraries'])} libs")

# wasm block (54-wasm/)
wasm_data = {"ran": False, "validates": None, "imports": 0, "exports": 0, "functions": 0}
ws_objdump = _os.path.join(OUTDIR, "54-wasm", "objdump.txt")
if _os.path.exists(ws_objdump):
    wasm_data["ran"] = True
    txt = read_text(ws_objdump) or ""
    # Parse section counts from wasm-objdump -x
    for line in txt.splitlines():
        line_s = line.strip()
        if line_s.startswith("Type[") and "]:" in line_s:
            try: wasm_data["functions"] = int(line_s.split("[")[1].split("]")[0])
            except (ValueError, IndexError): pass
        elif line_s.startswith("Import[") and "]:" in line_s:
            try: wasm_data["imports"] = int(line_s.split("[")[1].split("]")[0])
            except (ValueError, IndexError): pass
        elif line_s.startswith("Export[") and "]:" in line_s:
            try: wasm_data["exports"] = int(line_s.split("[")[1].split("]")[0])
            except (ValueError, IndexError): pass
ws_validate = _os.path.join(OUTDIR, "54-wasm", "validate.txt")
if _os.path.exists(ws_validate):
    val_text = read_text(ws_validate) or ""
    wasm_data["validates"] = "error" not in val_text.lower()

# pyc block (56-pyc/)
pyc_data = {"ran": False, "decompilers_succeeded": [], "header_magic": ""}
pc_root = _os.path.join(OUTDIR, "56-pyc")
if _os.path.isdir(pc_root):
    pyc_data["ran"] = True
    for tool, fname_check in [
        ("pycdc", "pycdc.py"),
        ("pycdas", "pycdas.txt"),
        ("python-dis", "dis.txt"),
        ("uncompyle6", "uncompyle6.py"),
        ("decompyle3", "decompyle3.py"),
    ]:
        p = _os.path.join(pc_root, fname_check)
        if _os.path.exists(p) and _os.path.getsize(p) > 50:
            pyc_data["decompilers_succeeded"].append(tool)
    h = _os.path.join(pc_root, "header.txt")
    if _os.path.exists(h):
        for line in (read_text(h) or "").splitlines():
            if "magic family" in line:
                pyc_data["header_magic"] = line.strip()
                break

# jar block (58-jar/)
jar_data = {"ran": False, "class_count": 0, "cfr_files": 0, "procyon_files": 0, "manifest_present": False}
jr_root = _os.path.join(OUTDIR, "58-jar")
if _os.path.isdir(jr_root):
    jar_data["ran"] = True
    listing = _os.path.join(jr_root, "listing.txt")
    if _os.path.exists(listing):
        jar_data["class_count"] = sum(1 for l in (read_text(listing) or "").splitlines() if l.endswith(".class"))
    cfr_dir = _os.path.join(jr_root, "cfr")
    if _os.path.isdir(cfr_dir):
        for root, _, files in _os.walk(cfr_dir):
            for fn in files:
                if fn.endswith(".java"): jar_data["cfr_files"] += 1
    proc_dir = _os.path.join(jr_root, "procyon")
    if _os.path.isdir(proc_dir):
        for root, _, files in _os.walk(proc_dir):
            for fn in files:
                if fn.endswith(".java"): jar_data["procyon_files"] += 1
    jar_data["manifest_present"] = _os.path.exists(_os.path.join(jr_root, "MANIFEST.MF")) and \
        _os.path.getsize(_os.path.join(jr_root, "MANIFEST.MF")) > 0
    if jar_data["class_count"]:
        verdict_parts.append(f"jar: {jar_data['class_count']} classes, CFR={jar_data['cfr_files']}, procyon={jar_data['procyon_files']}")

# pdf block (62-pdf/)
pdf_data = {"ran": False, "high_risk_keywords": [], "objects": 0, "qpdf_warnings": 0}
pd_root = _os.path.join(OUTDIR, "62-pdf")
if _os.path.isdir(pd_root):
    pdf_data["ran"] = True
    pdfid_file = _os.path.join(pd_root, "pdfid.txt")
    if _os.path.exists(pdfid_file):
        txt = read_text(pdfid_file) or ""
        for kw in ["/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/AcroForm", "/XFA"]:
            for line in txt.splitlines():
                if kw in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[-1].isdigit() and int(parts[-1]) > 0:
                        pdf_data["high_risk_keywords"].append(f"{kw}({parts[-1]})")
                        break
    qpdf_file = _os.path.join(pd_root, "qpdf-check.txt")
    if _os.path.exists(qpdf_file):
        txt = read_text(qpdf_file) or ""
        pdf_data["qpdf_warnings"] = sum(1 for l in txt.splitlines() if "WARNING" in l or "warning:" in l)
    if pdf_data["high_risk_keywords"]:
        verdict_parts.append(f"pdf risk indicators: {', '.join(pdf_data['high_risk_keywords'][:5])}")
        if any("JavaScript" in k or "OpenAction" in k or "Launch" in k for k in pdf_data["high_risk_keywords"]):
            # v3.2.0 (A2.1): weighted signal. PDF with active-content
            # indicators (JS / auto-run OpenAction / Launch action) is a
            # classic malicious-PDF profile.
            add_signal("pdf_active_content", 30,
                       "PDF with JavaScript / OpenAction / Launch")

# ole block (64-ole/)
ole_data = {"ran": False, "macros_present": False, "mraptor_verdict": None, "dde_present": False, "embedded_objects": 0}
ol_root = _os.path.join(OUTDIR, "64-ole")
if _os.path.isdir(ol_root):
    ole_data["ran"] = True
    # olevba: macros present?
    olevba_file = _os.path.join(ol_root, "olevba.txt")
    if _os.path.exists(olevba_file):
        txt = read_text(olevba_file) or ""
        ole_data["macros_present"] = ("VBA MACRO" in txt) or ("Suspicious" in txt)
    # mraptor
    mr_file = _os.path.join(ol_root, "mraptor.txt")
    if _os.path.exists(mr_file):
        txt = read_text(mr_file) or ""
        if "SUSPICIOUS" in txt: ole_data["mraptor_verdict"] = "SUSPICIOUS"
        elif "Macro" in txt:    ole_data["mraptor_verdict"] = "Macro"
        else:                   ole_data["mraptor_verdict"] = "clean"
    # msodde
    dde_file = _os.path.join(ol_root, "msodde.txt")
    if _os.path.exists(dde_file):
        txt = read_text(dde_file) or ""
        ole_data["dde_present"] = "DDE" in txt and ("function" in txt.lower() or "links" in txt.lower())
    if ole_data["mraptor_verdict"] == "SUSPICIOUS":
        verdict_parts.append("ole: SUSPICIOUS macros (mraptor)")
        # v3.2.0 (A2.1): weighted signal. mraptor flags auto-exec + suspicious
        # macro API combinations characteristic of malicious Office documents.
        add_signal("ole_suspicious_macros", 30,
                   "OLE document with suspicious macros (mraptor)")

# Go runtime sub-detection (55-go/)
go_data = {"detected": False, "compiler_version": "", "package_count": 0}
go_root = _os.path.join(OUTDIR, "55-go")
if _os.path.isdir(go_root):
    go_data["detected"] = True
    info_file = _os.path.join(go_root, "info.txt")
    if _os.path.exists(info_file):
        for line in (read_text(info_file) or "").splitlines():
            if "version" in line.lower() or line.startswith("go1."):
                go_data["compiler_version"] = line.strip()[:120]
                break
    pkg_file = _os.path.join(go_root, "packages.txt")
    if _os.path.exists(pkg_file):
        go_data["package_count"] = sum(1 for l in (read_text(pkg_file) or "").splitlines() if l.strip())
    if go_data["detected"]:
        verdict_parts.append(f"Go binary: {go_data['package_count']} packages")

# Rust runtime sub-detection (57-rust/)
rust_data = {"detected": False, "rustc_paths": []}
rust_root = _os.path.join(OUTDIR, "57-rust")
if _os.path.isdir(rust_root):
    rust_data["detected"] = True
    rp_file = _os.path.join(rust_root, "rustc-paths.txt")
    if _os.path.exists(rp_file):
        rust_data["rustc_paths"] = [l.strip() for l in (read_text(rp_file) or "").splitlines() if l.strip()][:10]
    if rust_data["detected"]:
        verdict_parts.append(f"Rust binary: {len(rust_data['rustc_paths'])} rustc paths")

# ---- v2.7.0: cross-cutting capability stage parsers -------------------------

# Fuzzy hashes (81-fuzzyhash/hashes.json)
fuzzy_data = {"ssdeep": None, "tlsh": None, "ssdeep_error": None, "tlsh_error": None}
fh_path = _os.path.join(OUTDIR, "81-fuzzyhash", "hashes.json")
if _os.path.exists(fh_path):
    try:
        fh_json = read_json(fh_path) or {}
        fuzzy_data["ssdeep"] = fh_json.get("ssdeep")
        fuzzy_data["tlsh"] = fh_json.get("tlsh")
        fuzzy_data["ssdeep_error"] = fh_json.get("ssdeep_error")
        fuzzy_data["tlsh_error"] = fh_json.get("tlsh_error")
    except Exception:
        pass

# v3.0.10 (audit-14 F1) - parse 14-pev/pehash.txt to surface PE-specific
# hashes (imphash, per-header hashes, per-section hashes) in the Fuzzy
# Hashes tab. Pre-v3.0.10 pehash.txt was generated but never read; the
# tab only showed ssdeep + tlsh from 81-fuzzyhash. Extends fuzzy_data
# with a "pehash" sub-dict containing:
#   file: {md5, sha1, sha256, ssdeep, imphash}
#   headers: [{name, md5, sha1, sha256, ssdeep}, ...]
#   sections: [{name, md5, sha1, sha256, ssdeep}, ...]
# Format produced by `pehash -a` is indented YAML-like text:
#   file
#       filepath: ...
#       md5: ...
#       imphash: ...
#   headers
#       header
#           header_name: IMAGE_DOS_HEADER
#           md5: ...
#   sections
#       section
#           section_name: .text
#           md5: ...
fuzzy_data["pehash"] = {"file": {}, "headers": [], "sections": []}
ph_path = _os.path.join(OUTDIR, "14-pev", "pehash.txt")
if _os.path.exists(ph_path):
    try:
        ph_text = read_text(ph_path) or ""
        # State machine: track which section ("file"/"headers"/"sections")
        # we're in, and which sub-record (header or section) is current.
        ph_state = None    # "file" | "headers" | "sections" | None
        ph_current = None  # current sub-record dict (for headers/sections)
        for raw in ph_text.splitlines():
            stripped = raw.strip()
            if not stripped:
                continue
            # Top-level section markers (no leading indent)
            indent = len(raw) - len(raw.lstrip())
            if indent == 0:
                if stripped == "file":
                    ph_state = "file"
                    ph_current = fuzzy_data["pehash"]["file"]
                elif stripped == "headers":
                    ph_state = "headers"
                    ph_current = None
                elif stripped == "sections":
                    ph_state = "sections"
                    ph_current = None
                else:
                    # something we don't recognize; reset
                    ph_state = None
                    ph_current = None
                continue
            # Sub-record markers ("header" / "section" - start new record)
            if stripped == "header" and ph_state == "headers":
                ph_current = {}
                fuzzy_data["pehash"]["headers"].append(ph_current)
                continue
            if stripped == "section" and ph_state == "sections":
                ph_current = {}
                fuzzy_data["pehash"]["sections"].append(ph_current)
                continue
            # Key: value pairs at any indent
            if ":" in stripped and ph_current is not None:
                k, _, v = stripped.partition(":")
                k = k.strip()
                v = v.strip()
                # Filter out empty values and keep only the hash-relevant
                # fields plus name fields. Skip filepath (operational
                # noise that varies per run).
                if k in ("md5", "sha1", "sha256", "ssdeep", "imphash",
                         "header_name", "section_name") and v:
                    ph_current[k] = v
    except Exception as e:
        fuzzy_data["pehash"]["error"] = str(e)

# Crypto keys (82-cryptokeys/key-candidates.json)
crypto_data = {"ran": False, "total": 0, "by_confidence": {}, "by_type": {}}
ck_path = _os.path.join(OUTDIR, "82-cryptokeys", "key-candidates.json")
if _os.path.exists(ck_path):
    crypto_data["ran"] = True
    try:
        ck_json = read_json(ck_path) or {}
        crypto_data["total"] = ck_json.get("total_candidates", 0)
        crypto_data["by_confidence"] = ck_json.get("by_confidence", {})
        crypto_data["by_type"] = ck_json.get("by_type", {})
    except Exception:
        pass
    # signsrch crypto-class re-pass count
    ss_crypto = _os.path.join(OUTDIR, "82-cryptokeys", "signsrch-crypto.txt")
    if _os.path.exists(ss_crypto):
        crypto_data["signsrch_crypto_hits"] = sum(
            1 for l in (read_text(ss_crypto) or "").splitlines() if l.strip()
        )
    # Severity bump if HIGH confidence keys found (PEM blocks, AES S-box)
    if crypto_data.get("by_confidence", {}).get("high", 0) > 0:
        verdict_parts.append(f"crypto: {crypto_data['by_confidence']['high']} high-confidence key candidate(s)")

# Authenticode chain validation (83-authenticode/verdict.txt)
authchain_data = {"ran": False, "validates": None, "self_signed": False, "expired": False, "known_org": None}
ac_path = _os.path.join(OUTDIR, "83-authenticode")
if _os.path.isdir(ac_path):
    authchain_data["ran"] = True
    verdict_file = _os.path.join(ac_path, "verdict.txt")
    if _os.path.exists(verdict_file):
        for line in (read_text(verdict_file) or "").splitlines():
            if "Chain validates:" in line:
                authchain_data["validates"] = line.split(":", 1)[-1].strip()
            elif "Self-signed leaf:" in line and "yes" in line:
                authchain_data["self_signed"] = True
            elif "Cert expired:" in line and "yes" in line:
                authchain_data["expired"] = True
    org_file = _os.path.join(ac_path, "known-org-check.txt")
    if _os.path.exists(org_file):
        for line in (read_text(org_file) or "").splitlines():
            if "MATCH:" in line:
                authchain_data["known_org"] = line.split("MATCH:", 1)[-1].strip()
                break
    if authchain_data.get("validates") == "no":
        verdict_parts.append("authenticode chain INVALID")
        # v3.2.0 (A2.1): weighted signal. A signature that is PRESENT but
        # fails validation is worse than no signature -- it suggests tampering
        # or a forged/broken cert chain.
        add_signal("authenticode_invalid", 45,
                   "authenticode chain failed validation")
    elif authchain_data.get("known_org"):
        verdict_parts.append(f"signed by known org: {authchain_data['known_org']}")

# angr CFG (86-angr/cfg-summary.json)
angr_data = {"ran": False, "loaded": False, "function_count": 0, "node_count": 0,
             "edge_count": 0, "indirect_resolved": 0, "indirect_unresolved": 0}
an_path = _os.path.join(OUTDIR, "86-angr", "cfg-summary.json")
if _os.path.exists(an_path):
    angr_data["ran"] = True
    try:
        an_json = read_json(an_path) or {}
        angr_data["loaded"] = an_json.get("loaded", False)
        angr_data["arch"] = an_json.get("arch")
        angr_data["function_count"] = an_json.get("function_count", 0)
        angr_data["node_count"] = an_json.get("node_count", 0)
        angr_data["edge_count"] = an_json.get("edge_count", 0)
        angr_data["indirect_resolved"] = an_json.get("indirect_jumps_resolved", 0)
        angr_data["indirect_unresolved"] = an_json.get("indirect_jumps_unresolved", 0)
    except Exception:
        pass
    if angr_data["loaded"]:
        verdict_parts.append(f"angr CFG: {angr_data['function_count']} fns, "
                             f"{angr_data['indirect_resolved']}/{angr_data['indirect_resolved']+angr_data['indirect_unresolved']} indirect jumps resolved")

# radiff2 binary diff (87-radiff2/similarity.txt)
radiff_data = {"ran": False, "reference": None, "similarity": None, "function_matches": 0}
rd_path = _os.path.join(OUTDIR, "87-radiff2")
if _os.path.isdir(rd_path):
    radiff_data["ran"] = True
    ref_file = _os.path.join(rd_path, "_reference.txt")
    if _os.path.exists(ref_file):
        for line in (read_text(ref_file) or "").splitlines():
            if line.startswith("Reference:"):
                radiff_data["reference"] = line.split(":", 1)[-1].strip()
                break
    sim_file = _os.path.join(rd_path, "similarity.txt")
    if _os.path.exists(sim_file):
        # Output format: "similarity: 0.97\ndistance: 743"
        for line in (read_text(sim_file) or "").splitlines():
            if line.startswith("similarity:"):
                try:
                    radiff_data["similarity"] = float(line.split(":", 1)[-1].strip())
                except (ValueError, IndexError):
                    pass
                break
    fn_file = _os.path.join(rd_path, "functions.txt")
    if _os.path.exists(fn_file):
        # Each line with " | MATCH " or " => " counts as a function pair
        radiff_data["function_matches"] = sum(
            1 for l in (read_text(fn_file) or "").splitlines() if " MATCH " in l or " => " in l
        )
    if radiff_data.get("similarity") is not None:
        verdict_parts.append(f"radiff2 vs ref: similarity={radiff_data['similarity']:.2f}")

# yarGen rules (88-yargen/yargen_rules.yar)
yargen_data = {"ran": False, "rule_count": 0, "rule_file": None}
yg_path = _os.path.join(OUTDIR, "88-yargen", "yargen_rules.yar")
if _os.path.exists(yg_path):
    yargen_data["ran"] = True
    yargen_data["rule_file"] = yg_path
    yargen_data["rule_count"] = sum(
        1 for l in (read_text(yg_path) or "").splitlines() if l.startswith("rule ")
    )
    if yargen_data["rule_count"] > 0:
        verdict_parts.append(f"yarGen: {yargen_data['rule_count']} rule(s) generated")

# ---- v2.8.0: Mobile (DEX/APK) parsers ---------------------------------------

# APK container metadata (72-apk/inventory.txt + extraction-summary.txt)
apk_data = {
    "ran": False,
    "dex_count": 0,
    "native_libs_per_abi": {},
    "extraction_dir": None,
    "apktool_success": False,
    "smali_class_count": 0,
}
apk_path = _os.path.join(OUTDIR, "72-apk")
if _os.path.isdir(apk_path):
    apk_data["ran"] = True
    inv_file = _os.path.join(apk_path, "inventory.txt")
    if _os.path.exists(inv_file):
        inv_text = read_text(inv_file) or ""
        apk_data["dex_count"] = sum(
            1 for l in inv_text.splitlines() if "classes" in l and l.strip().endswith(".dex")
        )
        # Native libs per ABI: lib/<abi>/<name>.so
        import re as _re
        for line in inv_text.splitlines():
            m = _re.search(r'lib/([^/]+)/([^/]+)\.so$', line)
            if m:
                abi = m.group(1)
                apk_data["native_libs_per_abi"].setdefault(abi, []).append(m.group(2))
    extracted_dir = _os.path.join(OUTDIR, "72-apk-extracted")
    if _os.path.isdir(extracted_dir):
        apk_data["extraction_dir"] = extracted_dir
        smali_dir = _os.path.join(extracted_dir, "smali")
        if _os.path.isdir(smali_dir):
            apk_data["apktool_success"] = True
            # Count smali files (cheap proxy for class count)
            try:
                count = 0
                for root, _, files in _os.walk(smali_dir):
                    count += sum(1 for f in files if f.endswith(".smali"))
                apk_data["smali_class_count"] = count
            except Exception:
                pass
    if apk_data["dex_count"] > 0:
        verdict_parts.append(f"APK: {apk_data['dex_count']} DEX, "
                             f"{len(apk_data['native_libs_per_abi'])} native ABI(s)")

# Manifest (76-axml/manifest-summary.json)
manifest_data = {"ran": False}
mf_json = _os.path.join(OUTDIR, "76-axml", "manifest-summary.json")
if _os.path.exists(mf_json):
    manifest_data["ran"] = True
    try:
        mfj = read_json(mf_json) or {}
        manifest_data["package_name"] = mfj.get("package_name")
        manifest_data["min_sdk"] = mfj.get("min_sdk")
        manifest_data["target_sdk"] = mfj.get("target_sdk")
        manifest_data["compile_sdk"] = mfj.get("compile_sdk")
        manifest_data["version_name"] = mfj.get("version_name")
        manifest_data["version_code"] = mfj.get("version_code")
        manifest_data["permission_count"] = len(mfj.get("permissions", []))
        manifest_data["dangerous_permissions"] = mfj.get("dangerous_permissions", [])
        manifest_data["dangerous_permission_count"] = len(mfj.get("dangerous_permissions", []))
        manifest_data["exported_activities_count"] = len(mfj.get("exported_activities", []))
        manifest_data["exported_services_count"] = len(mfj.get("exported_services", []))
        manifest_data["exported_receivers_count"] = len(mfj.get("exported_receivers", []))
        manifest_data["exported_providers_count"] = len(mfj.get("exported_providers", []))
        manifest_data["intent_filter_count"] = mfj.get("intent_filter_count", 0)
        manifest_data["deep_link_schemes"] = mfj.get("deep_link_schemes", [])
    except Exception:
        pass
    # Severity bumps
    if manifest_data.get("dangerous_permission_count", 0) >= 5:
        verdict_parts.append(f"manifest: {manifest_data['dangerous_permission_count']} "
                             f"dangerous permissions")
        # v3.2.0 (A2.1): weighted signal. 5+ dangerous permissions is a
        # meaningful over-privileging signal for Android packages.
        add_signal("apk_dangerous_perms", 20,
                   f"{manifest_data['dangerous_permission_count']} dangerous Android permissions")
    # Exported components without permission guard - elevation risk
    exported_unguarded = sum([
        manifest_data.get("exported_activities_count", 0),
        manifest_data.get("exported_services_count", 0),
        manifest_data.get("exported_receivers_count", 0),
        manifest_data.get("exported_providers_count", 0),
    ])
    if exported_unguarded > 0:
        manifest_data["exported_components_total"] = exported_unguarded
        verdict_parts.append(f"manifest: {exported_unguarded} exported components")

# DEX decompilation tier results (74-dex/_summary.txt OR 74-dex-N/_summary.txt)
dex_data = {"ran": False, "dex_files": []}
# Iterate possible DEX subdirs (74-dex, 74-dex-1, 74-dex-2, ...)
for entry in sorted(_os.listdir(OUTDIR)) if _os.path.isdir(OUTDIR) else []:
    if not entry.startswith("74-dex"):
        continue
    dex_dir = _os.path.join(OUTDIR, entry)
    if not _os.path.isdir(dex_dir):
        continue
    dex_data["ran"] = True
    dex_entry = {"dir": entry}
    # jadx
    jx_summary = _os.path.join(dex_dir, "jadx-summary.txt")
    if _os.path.exists(jx_summary):
        for ln in (read_text(jx_summary) or "").splitlines():
            if "Java file count:" in ln:
                try: dex_entry["jadx_java_count"] = int(ln.split(":")[-1].strip())
                except (ValueError, IndexError): pass
    # baksmali
    bk_summary = _os.path.join(dex_dir, "baksmali-summary.txt")
    if _os.path.exists(bk_summary):
        for ln in (read_text(bk_summary) or "").splitlines():
            if "smali file count:" in ln:
                try: dex_entry["baksmali_smali_count"] = int(ln.split(":")[-1].strip())
                except (ValueError, IndexError): pass
    # dex2jar
    dex_entry["dex2jar_jar"] = _os.path.exists(_os.path.join(dex_dir, "classes.jar"))
    dex_data["dex_files"].append(dex_entry)
if dex_data["dex_files"]:
    total_jadx = sum(d.get("jadx_java_count", 0) for d in dex_data["dex_files"])
    if total_jadx > 0:
        verdict_parts.append(f"DEX: jadx recovered {total_jadx} Java files "
                             f"across {len(dex_data['dex_files'])} DEX")

# APK signature (78-apksig/signature-summary.json)
apksig_data = {"ran": False}
ap_json = _os.path.join(OUTDIR, "78-apksig", "signature-summary.json")
if _os.path.exists(ap_json):
    apksig_data["ran"] = True
    try:
        apj = read_json(ap_json) or {}
        apksig_data["tool"] = apj.get("tool")
        apksig_data["verifies"] = apj.get("verifies")
        apksig_data["schemes"] = apj.get("schemes", {})
        apksig_data["signer_count"] = apj.get("signer_count", 0)
        apksig_data["signers"] = apj.get("signers", [])
        apksig_data["janus_vulnerable"] = apj.get("janus_vulnerable", False)
        # Cross-reference v2.7.0 known-orgs list against Android signer DN
        # The known-orgs list is duplicated here for in-stage matching;
        # canonical list lives in 83-authenticode.sh.
        known_orgs_android = [
            "Google LLC", "Google Inc", "Microsoft Corporation",
            "Amazon", "Apple Inc", "Meta Platforms",
            "Samsung", "Huawei", "Xiaomi", "OnePlus",
            "Spotify AB", "Twitter, Inc", "Meta Platforms, Inc",
        ]
        for signer in apksig_data["signers"]:
            dn = signer.get("dn", "") or ""
            for org in known_orgs_android:
                if org in dn:
                    apksig_data["known_org"] = org
                    break
            if apksig_data.get("known_org"):
                break
    except Exception:
        pass
    # Severity bumps
    if apksig_data.get("verifies") is False:
        verdict_parts.append("APK signature INVALID")
        # v3.2.0 (A2.1): weighted signal. An APK whose signature fails
        # verification is high-risk (tampered or improperly re-signed).
        add_signal("apk_signature_invalid", 45,
                   "APK signature failed verification")
    if apksig_data.get("janus_vulnerable"):
        verdict_parts.append("APK Janus-vulnerable (v1-only signing)")
        # v3.2.0 (A2.1): weighted signal. Janus (CVE-2017-13156) allows DEX
        # injection on legacy Android when only v1 signing is present.
        add_signal("apk_janus", 20,
                   "Janus CVE-2017-13156 (v1-only signing on legacy Android)")
    if apksig_data.get("known_org"):
        verdict_parts.append(f"APK signed by known org: {apksig_data['known_org']}")

# ---- v2.9.0: Visualization metadata ----------------------------------------
# stage_viz writes _viz-summary.json listing which visualizations rendered.
# We surface the metadata here so 90-report.sh can decide whether to render
# the Visualizations tab.
viz_data = {"ran": False, "generated": [], "skipped": [], "errors": []}
viz_meta_path = _os.path.join(OUTDIR, "89-viz", "_viz-summary.json")
if _os.path.exists(viz_meta_path):
    viz_data["ran"] = True
    try:
        vmj = read_json(viz_meta_path) or {}
        viz_data["generated"] = vmj.get("generated", [])
        viz_data["skipped"] = vmj.get("skipped", [])
        viz_data["errors"] = vmj.get("errors", [])
        viz_data["count"] = len(viz_data["generated"])
    except Exception:
        pass
    if viz_data.get("count", 0) > 0:
        verdict_parts.append(f"viz: {viz_data['count']} visualization(s) rendered")

# ---- v3.0.0: Dynamic analysis aggregated data ------------------------------
# stage_dynamic_trace (98) writes aggregated.json fusing per-tier
# _dynamic.json files into a single uniform schema. We surface counts
# here for the report's Dynamic Analysis tab and for severity input.
dynamic_data = {
    "ran": False,
    "tools_used": [],
    "modes_attempted": [],
    "real_execution": False,
    "exit_status": None,
    "duration_total_sec": 0.0,
    "syscall_count_total": 0,
    "api_call_count_total": 0,
    "file_write_count_total": 0,
    "registry_write_count_total": 0,
    "network_attempt_count_total": 0,
    "spawned_process_count_total": 0,
    "cross_tier": {},
}
dyn_path = _os.path.join(OUTDIR, "98-dynamic-trace", "aggregated.json")
if _os.path.exists(dyn_path):
    try:
        dj = read_json(dyn_path) or {}
        dynamic_data["ran"] = bool(dj.get("any_ran"))
        dynamic_data["tools_used"] = dj.get("tools_used", []) or []
        dynamic_data["modes_attempted"] = dj.get("modes_attempted", []) or []
        dynamic_data["real_execution"] = bool(dj.get("real_execution"))
        # Pick the most-real tier's exit status as primary (cuckoo > docker
        # > firejail > qiling; cuckoo has the strongest isolation barrier)
        statuses = dj.get("exit_statuses", {}) or {}
        for prefer in ("cuckoo", "docker", "firejail", "qiling"):
            if prefer in statuses:
                dynamic_data["exit_status"] = statuses[prefer]
                break
        dynamic_data["duration_total_sec"]      = float(dj.get("duration_total_sec") or 0)
        dynamic_data["syscall_count_total"]     = int(dj.get("syscall_count_total") or 0)
        dynamic_data["api_call_count_total"]    = int(dj.get("api_call_count_total") or 0)
        dynamic_data["file_write_count_total"]  = int(dj.get("file_write_count_total") or 0)
        dynamic_data["registry_write_count_total"]  = int(dj.get("registry_write_count_total") or 0)
        dynamic_data["network_attempt_count_total"] = int(dj.get("network_attempt_count_total") or 0)
        dynamic_data["spawned_process_count_total"] = int(dj.get("spawned_process_count_total") or 0)
        dynamic_data["cross_tier"] = dj.get("cross_tier", {}) or {}
    except Exception as e:
        dynamic_data["errors"] = [str(e)]

if dynamic_data["ran"]:
    tier_str = ",".join(dynamic_data["tools_used"])
    verdict_parts.append(
        f"dynamic ({tier_str}): {dynamic_data['syscall_count_total']} syscalls, "
        f"{dynamic_data['api_call_count_total']} API calls, "
        f"{dynamic_data['network_attempt_count_total']} network attempts"
    )
    # Severity bumps from dynamic findings (per spec D52)
    # v3.2.0 (A2.1): these are real runtime behavioral risk signals -> weighted.
    if dynamic_data["network_attempt_count_total"] > 0:
        add_signal("dynamic_network", 20,
                   f"dynamic: {dynamic_data['network_attempt_count_total']} network attempt(s) at runtime")
    if dynamic_data["registry_write_count_total"] > 5:
        add_signal("dynamic_registry_persistence", 25,
                   f"dynamic: {dynamic_data['registry_write_count_total']} registry writes (persistence pattern)")
    if dynamic_data["spawned_process_count_total"] > 2:
        add_signal("dynamic_process_spawns", 25,
                   f"dynamic: {dynamic_data['spawned_process_count_total']} child process spawns (dropper pattern)")
    if dynamic_data["cross_tier"].get("any_persistence"):
        add_signal("dynamic_persistence_confirmed", 45,
                   "dynamic: writes to persistence locations detected")
    if dynamic_data["cross_tier"].get("common_network_hosts"):
        n_common = len(dynamic_data["cross_tier"]["common_network_hosts"])
        add_signal("dynamic_c2_confirmed", 45,
                   f"dynamic: {n_common} network host(s) confirmed by 2+ tiers (high-confidence C2 indicator)")
else:
    # v3.0.9 (audit-13 C1+C2) - distinguish "no tiers ran" from "tiers ran but
    # found nothing". Pre-v3.0.9 the absence of dynamic_data["ran"] just
    # produced no verdict line; the operator had no signal that dynamic
    # analysis was attempted but blocked by missing prereqs. Now: if
    # aggregated.json's modes_attempted shows tiers were attempted but all
    # were no-ops, emit a clear actionable summary line listing each tier
    # and why it skipped.
    try:
        if dyn_path and _os.path.exists(dyn_path):
            dj_full = read_json(dyn_path) or {}
            attempted = dj_full.get("modes_attempted", []) or []
            skip_reasons = dj_full.get("skip_reasons", {}) or {}
            if attempted:
                noop_tiers = [t.replace(" (no-op)", "") for t in attempted if "(no-op)" in t]
                if noop_tiers and not dj_full.get("any_ran"):
                    # All tiers were attempted but all skipped
                    reason_strs = []
                    for tier in noop_tiers:
                        r = skip_reasons.get(tier, "no reason captured")
                        reason_strs.append(f"{tier}={r}")
                    verdict_parts.append(
                        f"dynamic: 0 tiers produced output ({'; '.join(reason_strs)})"
                    )
                    advisory_notes.append(
                        "dynamic: no tiers were able to run - check skip reasons"
                        " and consider --allow-real-execution for firejail/docker"
                    )
    except Exception:
        pass
    # Anti-emulation / qiling-unsupported-instruction signal.
    #
    # v3.0.8 (audit-12 C1) - distinguish two failure modes that map to the
    # same exit signal but require very different operator action:
    #
    # SIGILL (signal 4) on qiling tier: most commonly means qiling/Unicorn
    # hit an instruction the engine doesn't implement (newer SIMD: AVX,
    # AVX2, AVX-512; some anti-debug primitives; TLS / SEH unwind sequences;
    # certain Win32 fast-path syscall stubs). qiling's instruction coverage
    # is incomplete; ~50-80% of real-world Windows PE binaries hit this on
    # first ql.run(). The fix for the operator is to retry on a real-execution
    # tier (firejail for Linux ELF, docker+wine for PE) where actual CPU
    # decodes the instruction.
    #
    # SIGILL on a non-qiling tier (firejail / docker / cuckoo): more likely
    # genuine anti-emulation (the binary detected a sandbox indicator and
    # deliberately executed an illegal instruction to crash analyzers).
    #
    # SIGSEGV (signal 11) on any tier: usually corrupt loader, missing
    # imports, or genuine anti-debug check that crashed the process.
    es = dynamic_data["exit_status"]
    tiers_used = dynamic_data.get("tools_used") or []
    qiling_only = (tiers_used == ["qiling"]) or (len(tiers_used) == 1 and tiers_used[0] == "qiling")
    if es is not None and es < 0 and abs(es) == 4:  # SIGILL
        if qiling_only:
            advisory_notes.append(
                "dynamic (qiling): SIGILL / unsupported instruction. qiling's "
                "Unicorn engine does not implement every x86/x86_64 instruction "
                "(AVX/AVX2/AVX-512, some SEH/TLS sequences, certain fast-path "
                "syscall stubs). Retry on a real-execution tier "
                "(--dynamic-mode=firejail for ELF, --dynamic-mode=docker for "
                "PE under Wine, requires --allow-real-execution) for actual "
                "CPU decode."
            )
        else:
            advisory_notes.append(
                "dynamic: SIGILL on real-execution tier suggests genuine "
                "anti-emulation defense (binary detected sandbox and executed "
                "illegal instruction to crash analyzers)"
            )
    elif es is not None and es < 0 and abs(es) == 11:  # SIGSEGV
        advisory_notes.append(
            f"dynamic: exit signal {abs(es)} (SIGSEGV) suggests corrupt "
            f"loader, missing imports, or anti-debug check that crashed "
            f"the process"
        )

# ---- v3.0.2 (audit-6) parsers: rop-gadgets, binary-diff, retdec ------------

# stage_rop_gadgets output (46-rop-gadgets/gadgets.json)
rop_data = {"ran": False, "total_gadgets": 0, "first_insn_top": []}
rop_path = _os.path.join(OUTDIR, "46-rop-gadgets", "gadgets.json")
if _os.path.exists(rop_path):
    try:
        rj = read_json(rop_path) or {}
        rop_data["ran"] = True
        rop_data["total_gadgets"] = int(rj.get("total_gadgets") or 0)
        # Build first-instruction histogram for the top-5 most common
        from collections import Counter as _Counter
        first_counts = _Counter()
        for g in (rj.get("gadgets") or [])[:50000]:  # cap iteration for safety
            insns = g.get("insns") or []
            if insns:
                first = (insns[0].split()[0] if insns[0].split() else "?")
                first_counts[first] += 1
        rop_data["first_insn_top"] = [
            {"insn": k, "count": v} for k, v in first_counts.most_common(5)
        ]
    except Exception as e:
        rop_data["error"] = str(e)
if rop_data["ran"]:
    verdict_parts.append(f"rop_gadgets={rop_data['total_gadgets']}")

# stage_binary_diff output (91-binary-diff/_diff.json)
bdiff_data = {"ran": False, "differing_byte_count": 0, "patch_size": 0,
              "reference_size": 0, "target_size": 0, "divergence_pct": 0.0}
bdiff_path = _os.path.join(OUTDIR, "91-binary-diff", "_diff.json")
if _os.path.exists(bdiff_path):
    try:
        bj = read_json(bdiff_path) or {}
        bdiff_data["ran"] = True
        bdiff_data["differing_byte_count"] = int(bj.get("differing_byte_count") or 0)
        bdiff_data["patch_size"] = int(bj.get("bsdiff_patch_size") or 0)
        bdiff_data["reference_size"] = int(bj.get("reference_size") or 0)
        bdiff_data["target_size"] = int(bj.get("target_size") or 0)
        if bdiff_data["target_size"] > 0:
            bdiff_data["divergence_pct"] = round(
                100.0 * bdiff_data["differing_byte_count"] / bdiff_data["target_size"], 2
            )
    except Exception as e:
        bdiff_data["error"] = str(e)
if bdiff_data["ran"]:
    verdict_parts.append(
        f"binary_diff={bdiff_data['differing_byte_count']}B "
        f"({bdiff_data['divergence_pct']}%)"
    )

# stage_retdec output (26-retdec/decompiled.c)
retdec_data = {"ran": False, "decompiled_lines": 0, "size_bytes": 0}
retdec_c = _os.path.join(OUTDIR, "26-retdec", "decompiled.c")
if _os.path.exists(retdec_c):
    try:
        retdec_data["ran"] = True
        retdec_data["size_bytes"] = _os.path.getsize(retdec_c)
        with open(retdec_c, "r", encoding="utf-8", errors="replace") as fh:
            retdec_data["decompiled_lines"] = sum(1 for _ in fh)
    except Exception as e:
        retdec_data["error"] = str(e)
if retdec_data["ran"]:
    verdict_parts.append(f"retdec={retdec_data['decompiled_lines']}LoC")

# ---- v3.2.0 (audit-23 A2.1): compute weighted score + band ------------------
# All universal signals (added ~line 588) and type-specific signals
# (CWE/PDF/OLE/authchain, added inline above) are now collected in
# score_signals[]. Derive the final score, band, and the backward-compatible
# severity + severity_reasons from them.
#
# This runs BEFORE the final verdict_line rebuilds below so they show the
# correct severity. It replaces the pre-v3.2.0 linear ladder + the scattered
# `if severity == "low": severity = "medium"` type-specific bumps with one
# coherent computation.
def compute_score_band(signals):
    """Sum signal weights and map the total to a severity band.

    Returns (total_score, band, ordered_reasons). Bands:
        >= 100 crit | 60-99 high | 30-59 med | 10-29 low | 0-9 info
    ordered_reasons is the evidence strings sorted by descending weight so
    the most significant contributors lead.
    """
    total = sum(s["weight"] for s in signals)
    if total >= 100:
        band = "crit"
    elif total >= 60:
        band = "high"
    elif total >= 30:
        band = "med"
    elif total >= 10:
        band = "low"
    else:
        band = "info"
    ordered = sorted(signals, key=lambda s: s["weight"], reverse=True)
    reasons = [s["evidence"] for s in ordered]
    return total, band, reasons

risk_score, severity, severity_reasons = compute_score_band(score_signals)
# Append advisory notes (diagnostics / operator guidance) AFTER the scored
# reasons. They appear in the verdict but did not contribute to the score.
if advisory_notes:
    severity_reasons = severity_reasons + advisory_notes
# score_breakdown: the per-signal detail for the A5.1 explainable verdict
# panel, sorted by descending weight (most significant first).
score_breakdown = sorted(score_signals, key=lambda s: s["weight"], reverse=True)

# Re-render verdict_line with v2.6.0 + v2.7.0 + v2.8.0 + v2.9.0 + v3.0.0 + v3.0.2 contributions
verdict_line = f"{fname}: " + "; ".join(verdict_parts) + "."
if severity_reasons:
    verdict_line += f" [severity={severity}: {'; '.join(severity_reasons)}]"

# v3.0.10 (audit-14 E1) - finalize obfuscator_unified now that ALL
# upstream parsers have populated their data (de4dot, die_packer/
# die_protector, manalyze_data, peframe_data). At this point we can
# compute the cross-tool unified verdict text that 90-report.sh will
# render in the Obfuscation tab.
# v3.0.11 (audit-15 A1) - manalyze data also populated here at
# finalization. Pre-v3.0.11 the manalyze sub-dict was populated at the
# forward declaration ~1300 lines earlier, before manalyze_data was
# defined - causing NameError. Now ALL non-de4dot sources are filled
# in at finalization time when their parsers have completed.
obfuscator_unified["sources"]["die"]["packer"] = die_packer or ""
obfuscator_unified["sources"]["die"]["protector"] = die_protector or ""
obfuscator_unified["sources"]["manalyze"]["packer_hits"] = (
    list(manalyze_data.get("packer_hits", []) or [])
)
obfuscator_unified["sources"]["manalyze"]["peid_signatures"] = (
    list(manalyze_data.get("peid_signatures", []) or [])
)
obfuscator_unified["sources"]["peframe"]["packers"] = list(peframe_data.get("packers", []) or [])

# Re-evaluate any_detected with all sources now populated
_obf_de4dot = de4dot.get("obfuscator") or ""
_obf_de4dot_real = _obf_de4dot and _obf_de4dot.lower() not in ("unknown", "unknown obfuscator")
_obf_die_real = bool(die_packer or die_protector)
_obf_manalyze_real = bool(
    obfuscator_unified["sources"]["manalyze"]["packer_hits"]
    or obfuscator_unified["sources"]["manalyze"]["peid_signatures"]
)
_obf_peframe_real = bool(obfuscator_unified["sources"]["peframe"]["packers"])
obfuscator_unified["any_detected"] = (
    _obf_de4dot_real or _obf_die_real or _obf_manalyze_real or _obf_peframe_real
)

# Build the unified verdict string. Priority: most specific first.
# 1. de4dot real detection wins (it's a .NET-specific signature DB)
# 2. DIE protector > DIE packer (protector is more specific)
# 3. manalyze peid signatures (PEiD is industry-standard)
# 4. peframe packer detections
# 5. de4dot "Unknown" + any other source = "Unknown to de4dot, but X says Y"
_verdict_parts = []
if _obf_de4dot_real:
    _verdict_parts.append(f"de4dot detected: {_obf_de4dot}")
if die_protector:
    _verdict_parts.append(f"DIE protector: {die_protector}")
if die_packer and die_packer != die_protector:
    _verdict_parts.append(f"DIE packer: {die_packer}")
if obfuscator_unified["sources"]["manalyze"]["peid_signatures"]:
    _peid_sigs = obfuscator_unified["sources"]["manalyze"]["peid_signatures"][:3]
    _verdict_parts.append(f"manalyze peid: {'; '.join(_peid_sigs)}")
if obfuscator_unified["sources"]["manalyze"]["packer_hits"]:
    _pkr_hits = obfuscator_unified["sources"]["manalyze"]["packer_hits"][:3]
    _verdict_parts.append(f"manalyze packer: {'; '.join(_pkr_hits)}")
if obfuscator_unified["sources"]["peframe"]["packers"]:
    _pf_pkr = obfuscator_unified["sources"]["peframe"]["packers"][:3]
    _verdict_parts.append(f"peframe packer: {'; '.join(_pf_pkr)}")

if _verdict_parts:
    obfuscator_unified["unified_verdict"] = " / ".join(_verdict_parts)
elif _obf_de4dot and not _obf_de4dot_real:
    # de4dot ran but said Unknown, AND no other source detected anything
    obfuscator_unified["unified_verdict"] = (
        "de4dot reports Unknown Obfuscator; no corroborating signal from "
        "DIE, manalyze, or peframe. Binary may use a custom or unrecognized "
        "obfuscation scheme, or may not be obfuscated."
    )
else:
    obfuscator_unified["unified_verdict"] = (
        "No obfuscator/packer detected by any of de4dot, DIE, manalyze, peframe."
    )

# Add to verdict_parts so the verdict_line shows the unified result
if obfuscator_unified["any_detected"]:
    verdict_parts.append(f"obfuscation: {obfuscator_unified['unified_verdict']}")
    # Re-render verdict_line one more time
    verdict_line = f"{fname}: " + "; ".join(verdict_parts) + "."
    if severity_reasons:
        verdict_line += f" [severity={severity}: {'; '.join(severity_reasons)}]"

# =============================================================================
# v3.0.14 (audit-18) -- Report-expansion schema additions block
# =============================================================================
# This block aggregates new schema fields surfacing audit-15/16/17
# newly-captured signal in the Overview/Strings/Structure/Capabilities
# tabs. All fields are ADDITIVE; missing data is rendered as empty
# panel with "no data" microcopy in 90-report.sh (defensive .get()).
#
# Fields populated:
#   die["timing"]         -- per-signature timing breakdown from
#                            audit-16 F7 -l (--profiling) flag
#   findaes_data          -- findaes -v context bytes (audit-16 F13)
#   binwalk_extract_data  -- partial-success status + file count
#                            (audit-17 F2 surfacing extends to report)
#   bloaty_data           -- parsed sections/symbols/compileunits
#                            tables (audit-15 + audit-17 F5 PE-aware)
#
# All parsers are defensive: catch all exceptions, return defaults
# on any read failure, never block summary construction.
# =============================================================================

# ---- die timing breakdown (audit-16 F7 -l --profiling) ----------------------
# diec -l emits per-signature-type timing lines like:
#   "Signature 'PE' = X ms"
#   "Total time: Y ms"
# When timing data isn't present (older diec, or -l flag not supported)
# this dict stays empty. Surfaced in Overview tab.
die_timing = {"ran": False, "signatures": [], "total_ms": None}
_die_path = os.path.join(OUTDIR, "00-triage", "die.txt")
if os.path.exists(_die_path):
    _die_text = read_text(_die_path) or ""
    # Match "  X.XXX ms  signature_name" or "Total time: X ms"
    # Different diec builds emit different formats; capture both.
    import re as _re_die
    # Pattern 1: "Signature: NAME (X ms)"
    for _line in _die_text.splitlines():
        _ms_match = _re_die.search(r'(\d+(?:\.\d+)?)\s*ms', _line)
        if not _ms_match:
            continue
        _ms_val = float(_ms_match.group(1))
        _line_low = _line.lower().strip()
        if "total" in _line_low:
            die_timing["total_ms"] = _ms_val
            die_timing["ran"] = True
        else:
            # Try to extract signature name
            _sig_name = _line.strip()
            # Strip the timing portion
            _sig_name = _re_die.sub(r'\s*[\(\[]?\s*\d+(?:\.\d+)?\s*ms\s*[\)\]]?\s*', '', _sig_name)
            _sig_name = _sig_name.strip(' :;,-=')
            if _sig_name and len(_sig_name) < 200:
                die_timing["signatures"].append({
                    "name": _sig_name,
                    "ms": _ms_val,
                })
                die_timing["ran"] = True
    # Cap to top 20 by time
    if die_timing["signatures"]:
        die_timing["signatures"].sort(key=lambda x: -x["ms"])
        die_timing["signatures"] = die_timing["signatures"][:20]

# ---- findaes -v context bytes (audit-16 F13) -------------------------------
# findaes -v output format (per source):
#   "Found AES-128 key at offset N: HH HH HH HH ..."
# We capture offset + 16 bytes of context per match.
findaes_data = {"ran": False, "matches": []}
_fa_path = os.path.join(OUTDIR, "82-cryptokeys", "findaes.txt")
if os.path.exists(_fa_path):
    findaes_data["ran"] = True
    _fa_text = read_text(_fa_path) or ""
    import re as _re_fa
    # Match common findaes output forms:
    #   "AES-128 key found at offset 0xNNNN" -- with or without context bytes
    #   "AES-256 key found at offset NNNN: XX YY ZZ ..."
    #   "Found AES key at: 0xN..."
    for _line in _fa_text.splitlines():
        _m = _re_fa.search(r'AES[- ]?(\d+)?\s*key.*?(?:offset|at)\s*[:=]?\s*(0x[0-9a-fA-F]+|\d+)', _line, _re_fa.IGNORECASE)
        if _m:
            _bits = _m.group(1) or "?"
            _offset = _m.group(2)
            # Try to extract context bytes from same or adjacent line
            _ctx_match = _re_fa.search(r'((?:[0-9a-fA-F]{2}\s+){4,16})', _line)
            _ctx = _ctx_match.group(1).strip() if _ctx_match else ""
            findaes_data["matches"].append({
                "key_bits": _bits,
                "offset": _offset,
                "context": _ctx,
            })
            if len(findaes_data["matches"]) >= 50:
                break

# ---- binwalk-extract status (audit-17 F2 surfacing extension) --------------
# 00-triage/binwalk-extract.txt + extracted dir file count.
binwalk_extract_data = {
    "ran": False,
    "file_count": 0,
    "partial_success": False,
    "extracted_types": [],
}
_be_path = os.path.join(OUTDIR, "00-triage", "binwalk-extract.txt")
_be_dir = os.path.join(OUTDIR, "00-triage", "binwalk-extracted")
if os.path.exists(_be_path):
    binwalk_extract_data["ran"] = True
    _be_text = read_text(_be_path) or ""
    if "WARNING: One or more files failed to extract" in _be_text:
        binwalk_extract_data["partial_success"] = True
    if os.path.isdir(_be_dir):
        _ext_files = []
        for _root, _dirs, _files in os.walk(_be_dir):
            for _f in _files:
                _ext_files.append(os.path.join(_root, _f))
                if len(_ext_files) >= 1000:
                    break
            if len(_ext_files) >= 1000:
                break
        binwalk_extract_data["file_count"] = len(_ext_files)
        # First 10 extracted file names (just basename) for analyst preview
        for _ef in _ext_files[:10]:
            _name = os.path.basename(_ef)
            if _name and _name not in binwalk_extract_data["extracted_types"]:
                binwalk_extract_data["extracted_types"].append(_name)

# ---- bloaty 3-mode parsers (audit-15 + audit-17 F5 PE-aware) ----------------
# Parses bloaty's human-readable text output. Format is:
#   <FILE_PCT>%  <FILE_SIZE>  <VM_PCT>%  <VM_SIZE>  <NAME>
# (column order may swap; we detect via header line).
# For PE binaries only sections+segments runs (audit-17 F5); for ELF
# and Mach-O all 3 invocations run.
bloaty_data = {
    "ran": False,
    "format_supported": "",  # "full" | "pe-limited" | ""
    "sections": [],
    "symbols": [],
    "compileunits": [],
}

def _parse_bloaty_text(path, max_rows=20):
    """Parse bloaty's human-readable text output into list of
    {name, vm_pct, vm_size, file_pct, file_size} dicts.

    Returns empty list on any read or parse error. Caps at max_rows
    to keep _summary.json size manageable.
    """
    import re as _re_b
    if not os.path.exists(path):
        return []
    try:
        text = read_text(path) or ""
    except Exception:
        return []
    rows = []
    # Detect column order via header line. bloaty emits either:
    #   "    FILE SIZE        VM SIZE"
    #   "    VM SIZE        FILE SIZE"
    file_first = True  # Default ordering observed on most bloaty builds
    for _hl in text.splitlines()[:5]:
        _hl_up = _hl.upper().strip()
        if _hl_up.startswith("FILE SIZE") or _hl_up.startswith("FILE  SIZE"):
            file_first = True
            break
        if _hl_up.startswith("VM SIZE") or _hl_up.startswith("VM  SIZE"):
            file_first = False
            break
    # Match data lines: 4 columns (pct, size, pct, size) + name
    # Size token examples: "8.85Mi", "300Ki", "42", "0", "1.07Mi"
    _row_re = _re_b.compile(
        r'^\s*([\d.]+)%\s+(\S+)\s+([\d.]+)%\s+(\S+)\s+(.+?)\s*$'
    )
    for _line in text.splitlines():
        _m = _row_re.match(_line)
        if not _m:
            continue
        _p1, _s1, _p2, _s2, _name = _m.groups()
        _name = _name.strip()
        # Filter out separator/decoration lines that happen to match
        if _name.startswith("---"):
            continue
        try:
            _p1f, _p2f = float(_p1), float(_p2)
        except ValueError:
            continue
        if file_first:
            row = {
                "name": _name,
                "file_pct": _p1f,
                "file_size": _s1,
                "vm_pct": _p2f,
                "vm_size": _s2,
            }
        else:
            row = {
                "name": _name,
                "vm_pct": _p1f,
                "vm_size": _s1,
                "file_pct": _p2f,
                "file_size": _s2,
            }
        # Skip the TOTAL row -- it's always 100% and not informative
        if _name.upper() == "TOTAL":
            continue
        rows.append(row)
        if len(rows) >= max_rows:
            break
    return rows

# Sections: PE OR ELF/Mach-O (always present if bloaty ran)
for _bdir in ("10-pe", "50-elf"):
    _bs_path = os.path.join(OUTDIR, _bdir, "bloaty-sections.txt")
    if os.path.exists(_bs_path):
        bloaty_data["ran"] = True
        bloaty_data["sections"] = _parse_bloaty_text(_bs_path, max_rows=30)
        break

# Symbols: ELF/Mach-O only per audit-17 F5
_bsym_path = os.path.join(OUTDIR, "50-elf", "bloaty-symbols.txt")
if os.path.exists(_bsym_path):
    bloaty_data["ran"] = True
    bloaty_data["symbols"] = _parse_bloaty_text(_bsym_path, max_rows=30)

# Compileunits: ELF/Mach-O only per audit-17 F5
_bcu_path = os.path.join(OUTDIR, "50-elf", "bloaty-debug.txt")
if os.path.exists(_bcu_path):
    bloaty_data["ran"] = True
    bloaty_data["compileunits"] = _parse_bloaty_text(_bcu_path, max_rows=30)

# Format-supported flag: PE if only sections/segments produced (no
# symbols.txt or debug.txt files); full otherwise. Used by report
# tab to decide whether to show PE-limitation note or full tables.
_pe_limit_doc = os.path.join(OUTDIR, "10-pe", "bloaty-PE-LIMITATION.txt")
if os.path.exists(_pe_limit_doc):
    bloaty_data["format_supported"] = "pe-limited"
elif bloaty_data["symbols"] or bloaty_data["compileunits"]:
    bloaty_data["format_supported"] = "full"
elif bloaty_data["sections"]:
    bloaty_data["format_supported"] = "sections-only"

# =============================================================================
# end v3.0.14 (audit-18) schema additions block
# =============================================================================

# =============================================================================
# v3.6.0 (audit-27 F2) -- Capability characterization matrix
# =============================================================================
# A synthesized "what CAN this binary do" view across the core global-RE
# capability domains, derived ENTIRELY from already-collected signals (imports,
# capa namespaces/ATT&CK, IOCs). Each domain gets a status:
#   confirmed  -- a direct, strong signal (matching import or capa hit)
#   potential  -- a weaker/indirect signal (IOC presence, related namespace)
#   none       -- no signal found
# with the evidence that produced it. Framing adapted from the binary-re
# synthesis skill's capability-mapping matrix
# (github.com/2389-research/binary-re). This does NOT invent capabilities: it
# reorganizes existing evidence into an analyst-facing characterization grid.
def _build_capability_matrix():
    # Flatten all imported function names (native PE imports).
    imported = set()
    for entry in imports:
        for fn in entry.get("funcs", []):
            imported.add(fn)

    # capa namespaces (lowercased for matching) + ATT&CK technique names.
    capa_ns = " ".join(capa.get("namespaces", {}).keys()).lower()
    capa_attack = " ".join(
        (a.get("technique", "") or "") for a in capa.get("attack", [])
    ).lower()
    capa_blob = capa_ns + " " + capa_attack

    # Cross-platform import name hints per domain (native PE + POSIX).
    DOMAIN_IMPORTS = {
        "network": {
            "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "HttpSendRequestA",
            "HttpSendRequestW", "WinHttpOpen", "WinHttpConnect", "socket", "connect",
            "send", "recv", "URLDownloadToFileA", "URLDownloadToFileW", "WSAStartup",
            "gethostbyname", "getaddrinfo", "bind", "listen", "accept",
        },
        "filesystem": {
            "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "DeleteFileA",
            "DeleteFileW", "CopyFileA", "MoveFileA", "fopen", "open", "read",
            "write", "unlink", "rename", "FindFirstFileA", "FindNextFileA",
        },
        "crypto": {
            "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
            "CryptAcquireContextW", "BCryptEncrypt", "BCryptDecrypt",
            "EVP_EncryptInit", "EVP_DecryptInit", "AES_encrypt", "AES_decrypt",
            "SHA256_Init", "SHA1_Init", "MD5_Init",
        },
        "process_execution": {
            "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA",
            "ShellExecuteW", "system", "execve", "execl", "execlp", "fork",
            "posix_spawn", "CreateRemoteThread", "OpenProcess", "TerminateProcess",
        },
        "persistence": {
            "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
            "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
        },
        "anti_analysis": {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugStringA", "GetTickCount",
            "QueryPerformanceCounter",
        },
    }
    # capa-namespace keyword hints per domain (weaker corroboration).
    DOMAIN_CAPA_KW = {
        "network": ["communicat", "network", "http", "socket", "c2"],
        "filesystem": ["file", "filesystem", "directory"],
        "crypto": ["crypto", "encrypt", "hash", "cipher"],
        "process_execution": ["execut", "process", "command", "shell", "inject"],
        "persistence": ["persist", "registry", "service", "autorun", "startup"],
        "anti_analysis": ["anti", "debugg", "evasion", "obfuscat", "vm"],
    }
    # IOC-based potential signals per domain.
    ioc_network = (ioc_totals.get("urls", 0) + ioc_totals.get("domains", 0)
                   + ioc_totals.get("ipv4", 0) + ioc_totals.get("ipv6", 0))
    ioc_fs = ioc_totals.get("windows_paths", 0)

    matrix = {}
    for domain, names in DOMAIN_IMPORTS.items():
        evidence = []
        status = "none"
        hit_imports = sorted(imported & names)
        if hit_imports:
            status = "confirmed"
            evidence.append("imports: " + ", ".join(hit_imports[:6])
                            + (" ..." if len(hit_imports) > 6 else ""))
        # capa keyword corroboration.
        kw_hit = [kw for kw in DOMAIN_CAPA_KW.get(domain, []) if kw in capa_blob]
        if kw_hit:
            if status == "none":
                status = "potential"
            evidence.append("capa: " + ", ".join(kw_hit))
        # IOC-based potential (network + filesystem only).
        if domain == "network" and ioc_network > 0 and status == "none":
            status = "potential"
            evidence.append(f"IOCs: {ioc_network} network indicator(s)")
        if domain == "filesystem" and ioc_fs > 0 and status == "none":
            status = "potential"
            evidence.append(f"IOCs: {ioc_fs} path indicator(s)")
        matrix[domain] = {"status": status, "evidence": evidence}
    return matrix

capability_matrix = _build_capability_matrix()

# v3.6.0 (audit-27 F1): string-to-function mapping counts (from the r2 stage's
# correlator at 40-r2/_strfunc-summary.json). Counts only; the full mapping
# lives in 40-r2/string-to-function.json and is surfaced in the report.
strfunc_summary = read_json(os.path.join(OUTDIR, "40-r2", "_strfunc-summary.json")) or {
    "strings_scanned": 0, "functions_known": 0, "strings_mapped_to_functions": 0
}

# =============================================================================
# v3.7.0 (audit-28 Feature 3) -- AST / structural characterization
# =============================================================================
# Parse each decompiled function's C pseudocode into structural metrics and
# flag recognizable code-pattern signatures. The signature catalog is grounded
# in standard RE pattern-recognition tradecraft (adapted from the SBC "Art of
# Reverse Engineering" guide by Oussama Afnakkar): encryption/XOR loops, stack-
# string construction (anti-static-analysis obfuscation), and control-structure
# density. This is a lightweight textual analysis of decompiler output, NOT a
# true compiler AST -- it is a heuristic characterization, labeled as such.
def _characterize_code_structure(decomp_funcs):
    # C keywords that look like calls but are not, so call_count does not
    # count them.
    NON_CALL_KW = {
        "if", "for", "while", "switch", "return", "sizeof", "do", "else",
        "case", "default", "goto", "break", "continue",
    }
    ident_call_re = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    # A "stack string" heuristic: repeated single-character assignments of the
    # form `xxx[<n>] = 'c';` or `*(char*)(... ) = 0x??;` to sequential slots.
    char_assign_re = re.compile(r"""\[\s*\d+\s*\]\s*=\s*('.'|0x[0-9a-fA-F]{2}|\d{1,3})\s*;""")

    funcs = []
    totals = {
        "functions_characterized": 0,
        "with_loops": 0,
        "with_xor_in_loop": 0,
        "with_stack_strings": 0,
        "high_complexity": 0,  # cyclomatic_proxy >= 10
    }
    for d in decomp_funcs:
        if d.get("status") != "ok":
            continue
        code = d.get("code", "") or ""
        if not code.strip():
            continue

        # Control-structure counts (word-boundary matches on the pseudocode).
        loop_count = len(re.findall(r'\b(for|while)\b', code)) + len(re.findall(r'\bdo\b', code))
        branch_count = (len(re.findall(r'\bif\b', code))
                        + len(re.findall(r'\bcase\b', code))
                        + len(re.findall(r'\bswitch\b', code)))
        cyclomatic_proxy = branch_count + loop_count + 1
        comparison_count = len(re.findall(r'(==|!=|<=|>=|<|>)', code))

        # Call count: identifiers immediately followed by '(' minus C keywords.
        call_count = 0
        for m in ident_call_re.finditer(code):
            if m.group(1) not in NON_CALL_KW:
                call_count += 1

        # Max brace nesting depth.
        depth = 0
        max_nesting = 0
        for ch in code:
            if ch == "{":
                depth += 1
                max_nesting = max(max_nesting, depth)
            elif ch == "}":
                depth = max(0, depth - 1)

        # Signature: XOR inside a loop body. Heuristic -- an XOR operator ('^'
        # not part of '^=' comparison noise is fine to include) appearing in a
        # function that also has a loop. Tighten by requiring the '^' to occur
        # after the first loop keyword position.
        xor_in_loop = False
        if loop_count > 0 and ("^" in code):
            first_loop = re.search(r'\b(for|while|do)\b', code)
            if first_loop and "^" in code[first_loop.start():]:
                xor_in_loop = True

        # Signature: stack-string construction (>=4 sequential char/byte slot
        # assignments).
        stack_string = len(char_assign_re.findall(code)) >= 4

        signatures = []
        if xor_in_loop:
            signatures.append("xor_in_loop")        # possible crypto/encoding
        if stack_string:
            signatures.append("stack_string")       # anti-static obfuscation
        if cyclomatic_proxy >= 10:
            signatures.append("high_complexity")

        metrics = {
            "loop_count": loop_count,
            "branch_count": branch_count,
            "cyclomatic_proxy": cyclomatic_proxy,
            "comparison_count": comparison_count,
            "call_count": call_count,
            "max_nesting": max_nesting,
            "size_bytes": d.get("bytes", 0),
        }
        funcs.append({
            "name": d.get("name", ""),
            "addr": d.get("addr", ""),
            "metrics": metrics,
            "signatures": signatures,
        })
        totals["functions_characterized"] += 1
        if loop_count > 0:
            totals["with_loops"] += 1
        if xor_in_loop:
            totals["with_xor_in_loop"] += 1
        if stack_string:
            totals["with_stack_strings"] += 1
        if cyclomatic_proxy >= 10:
            totals["high_complexity"] += 1

    # Sort by cyclomatic_proxy descending (most complex first).
    funcs.sort(key=lambda f: f["metrics"]["cyclomatic_proxy"], reverse=True)
    return {"functions": funcs, "totals": totals}

code_structure = _characterize_code_structure(decompilation)

# =============================================================================
# v3.7.0 (audit-28 Feature 2) -- Function-purpose hypotheses + confidence
# =============================================================================
# For each decompiled function, synthesize a purpose hypothesis from multiple
# evidence sources and grade it on a calibrated confidence scale. The scale
# (High / Medium / Low / Speculative, with explicit evidence requirements) is
# adapted from the binary-re synthesis skill (github.com/2389-research/binary-re).
# Evidence sources:
#   - imports the function calls (call-graph callees matching known API names)
#   - strings the function references (inverted F1 string-to-function map)
#   - structural signatures from Feature 3 (xor_in_loop, stack_string)
#   - the function name itself (only a Speculative signal when stripped names
#     are absent)
def _build_function_purpose(decomp_funcs, cg, struct, domain_imports):
    # Invert F1 string-to-function: function name -> [strings it references].
    fn_to_strings = {}
    sf = read_json(os.path.join(OUTDIR, "40-r2", "string-to-function.json"))
    if isinstance(sf, dict):
        for rec in sf.get("strings", []):
            sval = rec.get("string", "")
            for finfo in rec.get("functions", []):
                fn_to_strings.setdefault(finfo.get("name", ""), []).append(sval)

    # caller -> set(callees) from the call graph.
    callees_of = {}
    for entry in cg:
        callees_of.setdefault(entry.get("caller", ""), set()).update(
            entry.get("callees", [])
        )

    # structural signatures by function name.
    sig_of = {f["name"]: set(f.get("signatures", [])) for f in struct.get("functions", [])}
    metrics_of = {f["name"]: f.get("metrics", {}) for f in struct.get("functions", [])}

    # Domain -> which callee/import names imply that purpose. Reuse the F2
    # DOMAIN_IMPORTS sets (passed in) for consistency with the capability matrix.
    def domain_hits(callees, domain):
        names = domain_imports.get(domain, set())
        return sorted(n for n in callees if n in names)

    purposes = []
    for d in decomp_funcs:
        if d.get("status") != "ok":
            continue
        name = d.get("name", "")
        callees = callees_of.get(name, set())
        strings_ref = fn_to_strings.get(name, [])
        sigs = sig_of.get(name, set())

        evidence = []
        purpose = None
        # Confidence tiers accumulate; we take the strongest matched purpose.
        # Each candidate purpose records (purpose, confidence, evidence-add).
        candidates = []

        net = domain_hits(callees, "network")
        if net:
            candidates.append(("network I/O", "High", f"calls network APIs: {', '.join(net[:4])}"))
        fs = domain_hits(callees, "filesystem")
        if fs:
            candidates.append(("file I/O", "High", f"calls file APIs: {', '.join(fs[:4])}"))
        cr = domain_hits(callees, "crypto")
        if cr:
            candidates.append(("cryptography", "High", f"calls crypto APIs: {', '.join(cr[:4])}"))
        px = domain_hits(callees, "process_execution")
        if px:
            candidates.append(("process/execution", "High", f"calls exec APIs: {', '.join(px[:4])}"))

        # Structural-signature-based purposes (Medium: one strong structural
        # signal without a corroborating import).
        if "xor_in_loop" in sigs and not cr:
            candidates.append(("crypto/encoding (structural)", "Medium",
                               "XOR-in-loop pattern (no crypto import)"))
        if "stack_string" in sigs:
            candidates.append(("string obfuscation", "Medium",
                               "stack-string construction pattern"))

        # String-reference-based hints (Low: indirect).
        if strings_ref:
            url_like = [s for s in strings_ref if ("://" in s or "http" in s.lower())]
            path_like = [s for s in strings_ref if ("/" in s or "\\" in s) and "://" not in s]
            if url_like:
                candidates.append(("network endpoint handling", "Low",
                                   f"references URL string(s): {url_like[0][:40]}"))
            elif path_like:
                candidates.append(("filesystem path handling", "Low",
                                   f"references path string(s): {path_like[0][:40]}"))

        # Orchestration hint from name + fan-out (Speculative unless corroborated).
        if name in ("main", "entry", "_start", "WinMain", "wmain"):
            m = metrics_of.get(name, {})
            if m.get("call_count", 0) >= 3:
                candidates.append(("entry / orchestration", "Medium",
                                   f"entry-point name with high fan-out ({m.get('call_count',0)} calls)"))
            else:
                candidates.append(("entry / orchestration", "Speculative",
                                   "entry-point name"))

        if not candidates:
            # Nothing but the raw structure -- Speculative "general logic".
            m = metrics_of.get(name, {})
            if m:
                candidates.append(("general logic", "Speculative",
                                   f"no distinctive API/string/pattern; "
                                   f"cyclomatic proxy {m.get('cyclomatic_proxy', 1)}"))

        if not candidates:
            continue

        # Pick the highest-confidence candidate as the primary purpose;
        # collect the rest as supporting evidence.
        conf_rank = {"High": 3, "Medium": 2, "Low": 1, "Speculative": 0}
        candidates.sort(key=lambda c: conf_rank.get(c[1], 0), reverse=True)
        purpose, confidence, _ = candidates[0]
        # If two independent High signals, note corroboration (still High).
        high_hits = [c for c in candidates if c[1] == "High"]
        for _, _, ev in candidates:
            evidence.append(ev)

        purposes.append({
            "name": name,
            "addr": d.get("addr", ""),
            "purpose": purpose,
            "confidence": confidence,
            "evidence": evidence,
        })

    # Sort by confidence (High first), then by evidence count.
    conf_rank = {"High": 3, "Medium": 2, "Low": 1, "Speculative": 0}
    purposes.sort(key=lambda p: (conf_rank.get(p["confidence"], 0), len(p["evidence"])),
                  reverse=True)
    return purposes

# DOMAIN_IMPORTS lives inside _build_capability_matrix; expose a shared copy so
# the function-purpose synthesis uses the SAME API name sets as the capability
# matrix (single source of truth for "which API implies which domain").
_SHARED_DOMAIN_IMPORTS = {
    "network": {
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "HttpSendRequestA",
        "HttpSendRequestW", "WinHttpOpen", "WinHttpConnect", "socket", "connect",
        "send", "recv", "sendto", "WSASend", "URLDownloadToFileA",
        "URLDownloadToFileW", "WSAStartup", "gethostbyname", "getaddrinfo",
        "bind", "listen", "accept",
    },
    "filesystem": {
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "DeleteFileA",
        "DeleteFileW", "CopyFileA", "MoveFileA", "fopen", "open", "read",
        "write", "fwrite", "fread", "unlink", "rename", "FindFirstFileA",
        "FindNextFileA",
    },
    "crypto": {
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
        "CryptAcquireContextW", "BCryptEncrypt", "BCryptDecrypt",
        "EVP_EncryptInit", "EVP_DecryptInit", "AES_encrypt", "AES_decrypt",
        "SHA256_Init", "SHA1_Init", "MD5_Init",
    },
    "process_execution": {
        "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA",
        "ShellExecuteW", "system", "execve", "execl", "execlp", "fork",
        "posix_spawn", "CreateRemoteThread", "OpenProcess", "TerminateProcess",
    },
}

function_purpose = _build_function_purpose(
    decompilation, call_graph, code_structure, _SHARED_DOMAIN_IMPORTS
)

# =============================================================================
# v3.7.0 (audit-28 Feature 1) -- Data-flow tracing (call-graph reachability)
# =============================================================================
# Trace each interesting string from the function that references it (its
# SOURCE, per F1 string-to-function) forward through the call graph to a SINK:
# a function that calls a network-send / file-write / process-exec API. This
# builds directly on the F1 string-to-function base.
#
# HONEST SCOPE (L28): this is STATIC REACHABILITY over the call graph, not true
# taint-tracked data flow. It does not follow the string's actual value through
# registers/variables; it answers "is there a call path from a function that
# references this string to a function that reaches a sink?" -- a data-flow
# INDICATOR, not proof that the string reaches the sink. Labeled as such in the
# output and the report.
def _trace_data_flow(cg, domain_imports, max_depth=4, max_flows=200):
    # SINK APIs: where data leaves the program (network out, file write, exec).
    SINK_IMPORTS = {
        "send": "network-send", "sendto": "network-send", "WSASend": "network-send",
        "HttpSendRequestA": "network-send", "HttpSendRequestW": "network-send",
        "InternetWriteFile": "network-send",
        "WriteFile": "file-write", "fwrite": "file-write", "write": "file-write",
        "CreateProcessA": "process-exec", "CreateProcessW": "process-exec",
        "WinExec": "process-exec", "ShellExecuteA": "process-exec",
        "ShellExecuteW": "process-exec", "system": "process-exec",
        "execve": "process-exec", "execl": "process-exec",
    }
    # caller -> list(callees)
    callees_of = {}
    for entry in cg:
        callees_of.setdefault(entry.get("caller", ""), []).extend(
            entry.get("callees", [])
        )

    def find_sink_path(start, seen, depth):
        """BFS/DFS forward from start; return (path, sink_fn, sink_api) or None."""
        if depth > max_depth:
            return None
        for callee in callees_of.get(start, []):
            if callee in SINK_IMPORTS:
                return ([start, callee], callee, SINK_IMPORTS[callee])
            if callee in seen:
                continue
            seen.add(callee)
            sub = find_sink_path(callee, seen, depth + 1)
            if sub:
                path, sink_fn, sink_api = sub
                return ([start] + path, sink_fn, sink_api)
        return None

    # SOURCES: functions that reference a string (from F1).
    sf = read_json(os.path.join(OUTDIR, "40-r2", "string-to-function.json"))
    flows = []
    if isinstance(sf, dict):
        for rec in sf.get("strings", []):
            if len(flows) >= max_flows:
                break
            sval = rec.get("string", "")
            for finfo in rec.get("functions", []):
                src = finfo.get("name", "")
                if not src:
                    continue
                res = find_sink_path(src, {src}, 0)
                if res:
                    path, sink_fn, sink_api = res
                    flows.append({
                        "string": sval,
                        "source": src,
                        "path": path,
                        "sink": sink_fn,
                        "sink_type": sink_api,
                    })
                    if len(flows) >= max_flows:
                        break
    return flows

data_flow = _trace_data_flow(call_graph, _SHARED_DOMAIN_IMPORTS)

# =============================================================================

# ---- Write outputs ----------------------------------------------------------
summary = {
    "_meta": {
        "version": "3.0.2",
        "generated": datetime.now(timezone.utc).isoformat(),
        "target": TARGET,
        "outdir": OUTDIR,
    },
    "file": {
        "name": fname,
        "path": TARGET,
        "size": size,
        "file_type": file_txt,
        "hashes": hashes,
    },
    "die": {
        "packer": die_packer,
        "compiler": die_compiler,
        "protector": die_protector,
        "findings": die_findings,
    },
    "trid": trid_matches,
    "pescan_anomalies": pescan_anomalies,
    "de4dot": de4dot,
    # v3.0.10 (audit-14 E1) - cross-tool obfuscator/packer detection
    # aggregator. Synthesizes signals from de4dot, DIE, manalyze peid
    # plugin, and peframe into a single unified verdict. The Obfuscation
    # tab in 90-report.sh consumes this directly.
    "obfuscator_unified": obfuscator_unified,
    "lief": lief_summary,
    "authenticode": auth,
    "entropy": {
        "overall": entropy_overall,
        "sections": entropy_sections,
        "high_count": entropy_high_count,
    },
    "yara_hits": yara_hits,
    "clamav_hits": clamav_hits,
    "capa": capa,
    "capability_matrix": capability_matrix,
    "strfunc": strfunc_summary,
    "code_structure": code_structure,
    "function_purpose": function_purpose,
    "data_flow": data_flow,
    "strings_stats": strings_stats,
    "pe": {
        "is_pe": is_pe,
        "imports": imports,
        "exports": exports,
        "sections": sections_pe,
        "suspicious_imports": suspicious,
        # v3.0.10 (audit-14 D3) - .NET AssemblyRef table; empty for native PE
        "assembly_refs": assembly_refs,
    },
    "dotnet": {
        "cs_file_count": dotnet_cs_count,
    },
    "ghidra": {
        "dump_size_bytes": ghidra_dump_size,
    },
    "iocs": {
        "totals": ioc_totals,
        "total": ioc_total,
    },
    # v2.5.0 additions
    "manalyze": manalyze_data,
    "peframe": peframe_data,
    "cwe_checker": cwe_data,
    "signsrch": signsrch_data,
    "mitigations": mitigations,
    # v2.6.0 additions
    "macho": macho_data,
    "wasm": wasm_data,
    "pyc": pyc_data,
    "jar": jar_data,
    "pdf": pdf_data,
    "ole": ole_data,
    "go_info": go_data,
    "rust_info": rust_data,
    # v2.7.0 additions
    "fuzzy_hashes": fuzzy_data,
    "crypto_keys": crypto_data,
    "authenticode_chain": authchain_data,
    "angr_cfg": angr_data,
    "radiff2": radiff_data,
    "yargen": yargen_data,
    # v2.8.0 additions (mobile DEX/APK)
    "apk": apk_data,
    "manifest": manifest_data,
    "dex": dex_data,
    "apksig": apksig_data,
    # v2.9.0 additions (visualization)
    "viz": viz_data,
    # v3.0.0 additions (dynamic analysis)
    "dynamic": dynamic_data,
    # v3.0.2 additions (audit-6: rop-gadgets, binary-diff, retdec)
    "rop_gadgets": rop_data,
    "binary_diff": bdiff_data,
    "retdec": retdec_data,
    # v3.0.14 (audit-18) additions for report-expansion phase 1
    "die_timing": die_timing,
    "findaes": findaes_data,
    "binwalk_extract": binwalk_extract_data,
    "bloaty": bloaty_data,
    "verdict": {
        "line": verdict_line,
        "severity": severity,
        "reasons": severity_reasons,
        "is_packed": is_packed,
        "is_signed": is_signed,
        "has_suspicious_imports": has_suspicious,
        # v3.2.0 (audit-23 A2.1): weighted-model additions. severity + reasons
        # above remain for backward compat (report + downstream read them);
        # these add the numeric score and the per-signal breakdown that the
        # A5.1 explainable verdict panel renders.
        "risk_score": risk_score,
        "score_band": severity,
        "score_breakdown": score_breakdown,
    },
}

with open(os.path.join(OUTDIR, "_summary.json"), "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=False)

with open(os.path.join(OUTDIR, "_verdict.txt"), "w", encoding="utf-8") as f:
    f.write(verdict_line + "\n")

# v3.0.10 (audit-14 D3) - extended summary line shows kind breakdown
# of imports (static/delay/bound) plus AssemblyRef count for .NET.
# Pre-v3.0.10 the line just showed "imports=N" where N was the total
# number of DLLs in the standard import table; for .NET this was
# usually 1 (mscoree.dll) and for native PE it under-counted because
# delay-imports were silently dropped. The expanded form lets
# operators see at a glance whether the parser found delay/bound
# imports too, and how many .NET assembly references exist.
_imp_static = sum(1 for x in imports if x.get("kind") == "import")
_imp_delay = sum(1 for x in imports if x.get("kind") == "delay")
_imp_bound = sum(1 for x in imports if x.get("kind") == "bound")
_arefs = len(assembly_refs)
if _imp_delay or _imp_bound or _arefs:
    _imports_summary = f"imports={_imp_static}+{_imp_delay}d+{_imp_bound}b/{_arefs}aref"
else:
    _imports_summary = f"imports={len(imports)}"

print(f"Summary: severity={severity}, capa_rules={capa['rule_count']}, "
      f"iocs={ioc_total}, {_imports_summary}, "
      f"cwe_hits={cwe_data['total_hits']}, signsrch_hits={signsrch_data['hits']}, "
      f"go_detected={go_data['detected']}, rust_detected={rust_data['detected']}, "
      f"crypto_keys={crypto_data['total']}, angr_fns={angr_data['function_count']}, "
      f"apk_perms={manifest_data.get('permission_count', 0) if manifest_data.get('ran') else '-'}, "
      f"dex_jadx_files={sum(d.get('jadx_java_count', 0) for d in dex_data['dex_files'])}")
PYEOF

    if [[ -f "${outdir}/_verdict.txt" ]]; then
        log_step "summary: $(cat "${outdir}/_verdict.txt")"
    fi
}
