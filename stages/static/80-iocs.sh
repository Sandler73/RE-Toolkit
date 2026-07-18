#!/usr/bin/env bash
# =============================================================================
# stages/static/80-iocs.sh
# =============================================================================
#
# Synopsis:
#     IOC extraction and three-way classification over prior stage output.
#
# Description:
#     Post-processor: reads files the pipeline already produces (strings, capa,
#     FLOSS, ilspy .cs, Ghidra dump) and extracts indicators: URLs, IPs,
#     domains, email addresses, Windows registry keys, Windows/Unix file paths,
#     Bitcoin addresses, GUID-shaped identifiers (possible mutex names), named
#     pipe patterns. Results are deduplicated and attributed to source file.
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
#     stage_iocs()
#     main()
#
# Output subtrees:
#     ${outdir}/80-iocs/
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_iocs() {
    local target="$1" outdir="$2"
    local ioc="${outdir}/80-iocs"
    mkdir -p "$ioc"

    [[ -z "$VENV_PY" ]] && { log_step "iocs: skipped (no venv)"; return 0; }

    "$VENV_PY" - "$outdir" "${ioc}/_iocs.json" "${ioc}/_iocs.txt" <<'PYEOF' || true
"""IOC extractor for RE-Toolkit.

Reads text artifacts from a binary's analysis output directory and extracts
indicators of compromise. Deduplicates per-category and records the source
file for each IOC so analysts can trace back.

Dependency-free (stdlib only). Best-effort: unreadable files are skipped.
"""
import os, sys, re, json
from collections import defaultdict

OUTDIR, JSON_OUT, TXT_OUT = sys.argv[1], sys.argv[2], sys.argv[3]

# Which files to scan. Tune these if the pipeline layout changes.
# v3.7.3 (audit-31 C2): tool-SELF-REPORT files are intentionally NOT scanned.
# capa-rendered.txt carries capa rule-author emails (Mandiant/FLARE) and rule
# reference URLs (stackoverflow, mandiant), trid.txt carries TrID's own author
# address (mark0.net) and help URLs (wikipedia, archiveteam), and die.txt is
# DIE's own banner -- none are target-derived, so scanning them polluted the
# IOC set with tool-analysis noise. Only TARGET-derived string sources are
# scanned below (raw strings, floss, pestr, monodis, decompiled code, the
# Ghidra dump, r2/rizin strings).
SCAN_GLOBS = [
    "00-triage/strings-ascii.txt",
    "00-triage/strings-utf16le.txt",
    "00-triage/strings-utf16be.txt",
    "10-pe/floss.txt",
    "10-pe/pefile.txt",
    "14-pev/pestr.txt",
    "20-dotnet/monodis.txt",
    "20-dotnet/ilspy/**/*.cs",
    "22-de4dot/deobfuscated-ilspy/**/*.cs",
    "30-ghidra/*.ghidra-dump.txt",
    "40-r2/strings-deep.txt",
    "40-r2/all-functions-disasm.txt",
    "42-rizin/strings-deep.txt",
    "50-elf/readelf.txt",
]

# v2.3.0: bulk_extractor output files are already structured IOC lists
# (one per line). Merge them into the output with high-confidence tag.
# Key = our category; value = bulk_extractor filename.
BULK_MERGE_MAP = {
    "urls":     "18-bulk/url.txt",
    "emails":   "18-bulk/email.txt",
    "domains":  "18-bulk/domain.txt",
    "ipv4":     "18-bulk/ip.txt",
}

# Regex patterns. These are intentionally slightly loose -- precision is
# low on purpose because analysts want to see "is there anything URL-shaped
# in this binary" not "prove it's an exact valid URL". A false-positive
# noise filter at the end trims common legitimate strings.
PATTERNS = {
    "urls": re.compile(
        rb'\b(?:https?|ftp|ftps|file)://[-A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%]{4,200}',
        re.IGNORECASE),
    "ipv4": re.compile(
        rb'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b'),
    "ipv6": re.compile(
        rb'\b(?:[0-9a-fA-F]{1,4}:){5,7}[0-9a-fA-F]{1,4}\b'),
    "domains": re.compile(
        rb'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}(?:com|net|org|io|co|ru|cn|info|biz|gov|mil|edu|us|uk|de|fr|jp|br|au|ca|in|pw|xyz|top|online|site|club|app|dev|ai|tech|cloud|live|world|store|pro|ltd)\b',
        re.IGNORECASE),
    "emails": re.compile(
        rb'\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Z|a-z]{2,10}\b'),
    "registry_keys": re.compile(
        rb'\b(?:HKEY_[A-Z_]+|HKCU|HKLM|HKCR|HKU)[\\\/][^\x00-\x1f\"<>|?*]{3,250}',
        re.IGNORECASE),
    "windows_paths": re.compile(
        rb'\b[A-Za-z]:\\(?:[^\x00-\x1f"<>|?*\\/:]{1,80}\\){0,10}[^\x00-\x1f"<>|?*\\/:]{1,200}'),
    "unix_paths": re.compile(
        rb'(?:^|[\s"\'])/(?:usr|etc|var|opt|tmp|home|root|bin|sbin|lib|proc|dev)/[^\s"\'<>|?*\x00-\x1f]{2,200}'),
    "bitcoin_addr": re.compile(
        rb'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b'),
    "guids": re.compile(
        rb'\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?'),
    "named_pipes": re.compile(
        rb'\\\\\.\\pipe\\[A-Za-z0-9_\-]{2,100}',
        re.IGNORECASE),
    "mutex_candidates": re.compile(
        rb'\b(?:Global|Local)\\[A-Za-z0-9_\-.{}]{3,100}'),
}

# Noise filter -- domains / URLs / paths that are overwhelmingly legitimate
# and don't represent malicious indicators. Conservative; we'd rather
# include something benign than filter something important.
#
# v3.7.3 (audit-31 C2): three-way classification. Values are DROPPED (pure
# tool-analysis garbage the analyst never wants), TAGGED "infrastructure"
# (real strings in the target, but schema / certificate / platform
# infrastructure rather than behavioral indicators -- kept but separated), or
# KEPT "behavioral" (the default). Operator decision audit-31 #2: tag schema /
# infrastructure rather than drop it.

# INFRASTRUCTURE / SCHEMA -- kept but tagged ioc_class="infrastructure".
INFRA_DOMAINS = {
    # Certificate-authority chain infrastructure (code-signing / TLS). These
    # appear as CRL / OCSP / cert-download hosts embedded by the signer.
    "globalsign.com", "usertrust.com", "sectigo.com", "comodoca.com",
    "digicert.com", "verisign.com", "entrust.net", "letsencrypt.org",
    "godaddy.com", "amazontrust.com", "quovadisglobal.com",
    # OVAL / XCCDF / SCAP + related schema authorities (very common in
    # SCAP and vulnerability-scanner binaries).
    "oval.mitre.org", "cpe.mitre.org", "cve.mitre.org", "mitre.org",
    "nvd.nist.gov", "scap.nist.gov", "nist.gov",
    # XML / document schema authorities.
    "w3.org", "xmlsoap.org", "schemas.xmlsoap.org",
    "openxmlformats.org", "schemas.openxmlformats.org",
    "oasis-open.org", "purl.org",
    # Platform / runtime infrastructure.
    "microsoft.com", "windows.com", "msdn.microsoft.com",
    "schemas.microsoft.com", "go.microsoft.com", "windowsupdate.com",
    "apple.com", "mozilla.org", "ieee.org", "ietf.org",
}
# PURE NOISE -- dropped outright. Tool-author / tool-reference domains that
# only ever enter via analysis metadata (belt-and-suspenders now that the
# tool-self-report files are no longer scanned), and generic placeholders.
DROP_DOMAINS = {
    "mandiant.com", "intezer.com", "fireeye.com", "google.com",
    "mark0.net", "ghidra.app", "en.wikipedia.org", "wikipedia.org",
    "stackoverflow.com", "fileformats.archiveteam.org", "archiveteam.org",
    "gmail.com", "example.com", "example.org", "localhost",
}
DROP_EMAIL_DOMAINS = {
    "mandiant.com", "intezer.com", "fireeye.com", "google.com", "gmail.com",
}
NOISE_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "::1", "::"}
# .NET / version-number strings that the IPv4 regex captures as "IPs".
_VERSION_IP_RE = re.compile(rb'^\d{1,3}\.0\.0\.0$')
# PascalCase.PascalCase code identifiers the domain regex captures as "domains"
# (e.g. System.IO, Logger.Info, MyApplication.app). Real domains are lower-case.
_CODE_IDENT_DOMAIN_RE = re.compile(rb'^[A-Z][A-Za-z0-9]*\.[A-Z][A-Za-z0-9]*$')
NOISE_PATHS_PREFIXES = (
    b"C:\\Windows\\System32\\", b"C:\\Windows\\SysWOW64\\",
    b"C:\\Windows\\Microsoft.NET\\", b"C:\\Program Files\\",
    b"C:\\Program Files (x86)\\",
)

def _host_matches(host, domain_set):
    """True if host is (a subdomain of) any domain in domain_set.

    v3.7.3 (audit-31 C2): boundary-aware so cert-string artifacts don't defeat
    it. URL hosts extracted from binary strings often carry trailing bytes
    (e.g. "ocsp.sectigo.com0", "crl.usertrust.com0v"); a plain endswith would
    miss them. We match the domain as a suffix that begins at start-or-dot and
    is followed by end-or-non-letter, so "sectigo.com" matches
    "ocsp.sectigo.com0" but NOT "notsectigo.com" or "evil-sectigo.com".
    """
    if not host:
        return False
    for d in domain_set:
        if re.search(r'(^|\.)' + re.escape(d) + r'([^a-z]|$)', host):
            return True
    return False

def _is_infra_host(host):
    """host is a lower-case str. True if it is (a subdomain of) infra/schema."""
    return _host_matches(host, INFRA_DOMAINS)

def _is_drop_host(host):
    return _host_matches(host, DROP_DOMAINS)

def domain_from_url(u):
    """Very rough: pull the host out of a URL for noise filtering."""
    try:
        rest = u.split(b"://", 1)[1]
        host = rest.split(b"/", 1)[0].split(b":", 1)[0]
        return host.decode("ascii", errors="replace").lower()
    except Exception:
        return ""

def collect_files():
    """Expand SCAN_GLOBS against OUTDIR. Each result: (path, relative_tag)."""
    import glob
    seen = set()
    out = []
    for g in SCAN_GLOBS:
        for p in glob.glob(os.path.join(OUTDIR, g)):
            if p in seen or not os.path.isfile(p):
                continue
            seen.add(p)
            try:
                if os.path.getsize(p) > 200 * 1024 * 1024:
                    continue  # 200MB cap -- avoid reading a giant dump into RAM
            except OSError:
                continue
            tag = os.path.relpath(p, OUTDIR)
            out.append((p, tag))
    # Also scan ilspy .cs files if present (small files, many of them)
    ilspy_dir = os.path.join(OUTDIR, "20-dotnet", "ilspy")
    if os.path.isdir(ilspy_dir):
        for root, _, files in os.walk(ilspy_dir):
            for fn in files:
                if fn.endswith(".cs"):
                    p = os.path.join(root, fn)
                    tag = os.path.relpath(p, OUTDIR)
                    out.append((p, tag))
    return out

def classify_value(category, value_bytes):
    """Classify an extracted value. Returns (action, cleaned_bytes, ioc_class).

    v3.7.3 (audit-31 C2). action is one of:
      "drop"  -- pure tool-analysis garbage / false positives; discard.
      "keep"  -- retain; ioc_class is "behavioral" (default) or
                 "infrastructure" (certificate / schema / platform hosts,
                 kept but separated from behavioral indicators).
    """
    v = value_bytes.strip(b'"\'<>(){}[] \t\r\n.,;:')
    if not v:
        return "drop", v, "behavioral"

    if category == "urls":
        host = domain_from_url(v)
        # Operator-path / self-reference file:// URLs (e.g. Ghidra's
        # "file:///home/<user>/.../sample.exe?MD5=..." watermark) are never
        # target IOCs -- drop them (also avoids leaking the operator path).
        low = v.lower()
        if low.startswith(b"file://"):
            if (b"/home/" in low or b"/users/" in low or b"/root/" in low
                    or b"?md5=" in low or b"<output>" in low):
                return "drop", v, "behavioral"
        if host and _is_drop_host(host):
            return "drop", v, "behavioral"
        if host and _is_infra_host(host):
            return "keep", v, "infrastructure"
        return "keep", v, "behavioral"

    if category == "domains":
        # Reject code identifiers the regex mis-captures as domains
        # (System.IO, Logger.Info, MyApplication.app).
        if _CODE_IDENT_DOMAIN_RE.match(v):
            return "drop", v, "behavioral"
        try:
            host = v.decode("ascii", errors="replace").lower()
        except Exception:
            return "keep", v, "behavioral"
        if _is_drop_host(host):
            return "drop", v, "behavioral"
        if _is_infra_host(host):
            return "keep", v, "infrastructure"
        return "keep", v, "behavioral"

    if category == "emails":
        try:
            dom = v.decode("ascii", errors="replace").lower().rsplit("@", 1)[-1]
        except Exception:
            dom = ""
        # Tool-author addresses (Mandiant/FLARE/Intezer/etc.) are analysis
        # noise, not target indicators.
        if any(dom == d or dom.endswith("." + d) for d in DROP_EMAIL_DOMAINS):
            return "drop", v, "behavioral"
        return "keep", v, "behavioral"

    if category in ("ipv4", "ipv6"):
        try:
            sv = v.decode("ascii")
        except Exception:
            return "keep", v, "behavioral"
        if sv in NOISE_IPS:
            return "drop", v, "behavioral"
        # .NET assembly version numbers (1.0.0.0, 4.0.0.0, 6.0.0.0) captured
        # as IPv4 -- drop the "N.0.0.0" shape.
        if category == "ipv4" and _VERSION_IP_RE.match(v):
            return "drop", v, "behavioral"
        return "keep", v, "behavioral"

    if category == "windows_paths":
        # Kick out plain system paths -- keep only paths NOT under standard
        # system dirs (those are legitimate dependencies, not indicators).
        if any(v.startswith(pfx) for pfx in NOISE_PATHS_PREFIXES):
            return "drop", v, "behavioral"
        return "keep", v, "behavioral"

    return "keep", v, "behavioral"

def main():
    files = collect_files()

    # category -> { value -> set(source_tags) }
    collected = defaultdict(lambda: defaultdict(set))
    # v3.7.3 (audit-31 C2): category -> { value -> ioc_class }
    value_class = defaultdict(dict)
    files_scanned = 0
    files_skipped = 0

    for path, tag in files:
        try:
            with open(path, "rb") as f:
                data = f.read()
            files_scanned += 1
        except Exception:
            files_skipped += 1
            continue

        for category, rx in PATTERNS.items():
            for m in rx.finditer(data):
                raw = m.group(0)
                action, v, klass = classify_value(category, raw)
                if action == "drop":
                    continue
                try:
                    s = v.decode("utf-8", errors="replace")
                except Exception:
                    continue
                # Reasonable length cap per value
                if len(s) > 250:
                    continue
                collected[category][s].add(tag)
                # Infrastructure classification is sticky: if any source marks
                # a value infrastructure it stays infrastructure.
                if value_class[category].get(s) != "infrastructure":
                    value_class[category][s] = klass

    # v2.3.0: merge bulk_extractor's structured output files. bulk_extractor
    # scans raw bytes byte-by-byte with scanners specific to each IOC class,
    # producing one-per-line output files. They catch things the regex pass
    # misses (base64-encoded URLs, gzipped content, PDF-embedded strings).
    # We apply the same noise filter to be consistent.
    bulk_merge_count = 0
    for category, rel_path in BULK_MERGE_MAP.items():
        bp = os.path.join(OUTDIR, rel_path)
        if not os.path.isfile(bp):
            continue
        try:
            with open(bp, "rb") as bf:
                for raw_line in bf:
                    raw_line = raw_line.strip()
                    if not raw_line or raw_line.startswith(b'#'):
                        continue
                    # bulk_extractor format: "<offset>\t<value>\t<context>"
                    # We just want the value field.
                    parts = raw_line.split(b'\t')
                    if len(parts) < 2:
                        continue
                    value = parts[1]
                    action, v, klass = classify_value(category, value)
                    if action == "drop":
                        continue
                    try:
                        s = v.decode("utf-8", errors="replace")
                    except Exception:
                        continue
                    if len(s) > 250:
                        continue
                    collected[category][s].add(rel_path)
                    if value_class[category].get(s) != "infrastructure":
                        value_class[category][s] = klass
                    bulk_merge_count += 1
        except Exception:
            pass

    # Build output structures
    out_json = {
        "_meta": {
            "outdir": OUTDIR,
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "categories": sorted(collected.keys()),
            # v3.7.3 (audit-31 C2): each IOC record carries an ioc_class of
            # "behavioral" or "infrastructure" (certificate / schema / platform
            # hosts, kept but separated). Counts for quick reference.
            "class_counts": {
                "behavioral": sum(
                    1 for c in collected for s in collected[c]
                    if value_class[c].get(s, "behavioral") == "behavioral"),
                "infrastructure": sum(
                    1 for c in collected for s in collected[c]
                    if value_class[c].get(s) == "infrastructure"),
            },
        }
    }
    flat_lines = []
    flat_lines.append(f"# IOC extraction summary")
    flat_lines.append(f"# files_scanned={files_scanned}  files_skipped={files_skipped}")
    flat_lines.append(f"# ioc_class: behavioral={out_json['_meta']['class_counts']['behavioral']}  "
                      f"infrastructure={out_json['_meta']['class_counts']['infrastructure']} "
                      f"(infrastructure = cert/schema/platform hosts, separated from behavioral)")
    flat_lines.append("")

    for cat in sorted(PATTERNS.keys()):
        vals = collected.get(cat, {})
        out_json[cat] = []
        for v, sources in sorted(vals.items()):
            out_json[cat].append({
                "value": v,
                "ioc_class": value_class[cat].get(v, "behavioral"),
                "sources": sorted(sources),
            })
        # Text summary: behavioral first, then a clearly separated
        # infrastructure block, so the analyst reads indicators without the
        # cert/schema clutter mixed in.
        behavioral = sorted(v for v in vals if value_class[cat].get(v, "behavioral") == "behavioral")
        infra = sorted(v for v in vals if value_class[cat].get(v) == "infrastructure")
        flat_lines.append(f"=== {cat} ({len(vals)}: {len(behavioral)} behavioral, {len(infra)} infrastructure) ===")
        for v in behavioral:
            srcs = ",".join(sorted(vals[v]))
            flat_lines.append(f"  {v}    [from: {srcs}]")
        if infra:
            flat_lines.append(f"  -- infrastructure (cert / schema / platform) --")
            for v in infra:
                srcs = ",".join(sorted(vals[v]))
                flat_lines.append(f"  [infra] {v}    [from: {srcs}]")
        flat_lines.append("")

    with open(JSON_OUT, "w", encoding="utf-8") as f:
        json.dump(out_json, f, indent=2, sort_keys=False)
    with open(TXT_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(flat_lines))

    total = sum(len(collected[c]) for c in collected)
    print(f"IOCs: {total} across {len(collected)} categories "
          f"(scanned {files_scanned} files; +{bulk_merge_count} bulk_extractor entries)")

main()
PYEOF

    if [[ -f "${ioc}/_iocs.json" ]]; then
        local count
        count=$(safe_grep_count '"value":' "${ioc}/_iocs.json")
        log_step "iocs: ${count} total indicators  →  ${ioc}/_iocs.txt"
    fi
}
