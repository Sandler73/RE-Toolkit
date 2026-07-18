#!/usr/bin/env bash
# =============================================================================
# stages/static/82-cryptokeys.sh
# =============================================================================
#
# Synopsis:
#     Cryptographic key and embedded secret extraction.
#
# Description:
#     Heuristic crypto key / secret extraction. False positives are inevitable
#     (random bytes can look like keys); the JSON output marks confidence
#     levels:
#     - High: matches against known crypto magic (PEM headers, DER OIDs)
#     - Medium: high entropy + size matches common key bit-lengths
#       (1024/2048/3072/4096 RSA, 256/384/521 ECDSA, 256 Ed25519)
#     - Low: generic high-entropy regions (informational only)
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
#     stage_cryptokeys()
#
# Output subtrees:
#     ${outdir}/00-triage/
#     ${outdir}/82-cryptokeys/
#
# Skip controls:
#     SKIP_CRYPTOKEYS
#
# Tools invoked (run_tool labels):
#     findaes
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_cryptokeys() {
    local target="$1" outdir="$2"
    local ck="${outdir}/82-cryptokeys"

    if [[ ${SKIP_CRYPTOKEYS:-0} -eq 1 ]]; then
        log_step "cryptokeys: skipped (SKIP_CRYPTOKEYS=1)"
        return 0
    fi

    mkdir -p "$ck"

    # signsrch crypto-class re-pass (already runs in stage_triage at lower
    # priority; here we filter for crypto algorithm matches specifically)
    if [[ -f "${outdir}/00-triage/signsrch.txt" ]]; then
        grep -aiE "AES|DES|RC[0-9]|RSA|SHA|MD5|TEA|Blowfish|Twofish|Salsa|ChaCha|elliptic|curve|secp|prime|mersenne" \
            "${outdir}/00-triage/signsrch.txt" > "${ck}/signsrch-crypto.txt" 2>/dev/null || true
    fi

    # findaes (if installed) - scans for AES key schedule patterns
    # v3.0.12 (audit-16 A4) - operator F13: add -v for extended output.
    # findaes -v adds context bytes around each candidate key schedule
    # match, useful for analyst verification of false-positive vs real key.
    if command -v findaes >/dev/null 2>&1; then
        run_tool "findaes" "${ck}/findaes.txt" 60 \
            findaes -v "$target"
    fi

    # PEM block extraction with grep (covers RSA, EC, X509, generic PEM)
    {
        echo "=== PEM-encoded blocks (BEGIN/END pairs) ==="
        # Use strings(1) so we don't choke on binary noise around the PEM
        strings -n 16 "$target" 2>/dev/null | \
            grep -E "^-----(BEGIN|END) " | head -100 || \
            echo "  (no PEM markers)"
    } > "${ck}/pem-markers.txt"

    # Custom entropy walker + key-magic detector (Python heredoc)
    if [[ -n "$VENV_PY" ]]; then
        "$VENV_PY" - "$target" "$ck" > "${ck}/_walker.log" 2>&1 <<'PYEOF' || true
"""Custom crypto key heuristic detector.

Scans the target for:
  - PEM block markers (high confidence)
  - DER ASN.1 SEQUENCE openings (medium confidence)
  - Common AES S-box patterns (high confidence)
  - High-entropy regions matching common key sizes (low/medium confidence)

Outputs key-candidates.json.
"""
import sys
import os
import json
import math
import re

target_path = sys.argv[1]
outdir = sys.argv[2]

candidates = []

with open(target_path, "rb") as f:
    data = f.read()

# 1. PEM markers (high confidence) - already in pem-markers.txt but
#    re-detect here for the JSON
pem_pat = re.compile(rb"-----BEGIN [A-Z ]+-----")
for m in pem_pat.finditer(data):
    end = data.find(b"-----END", m.end(), m.end() + 8192)
    candidates.append({
        "type": "pem",
        "confidence": "high",
        "offset": m.start(),
        "header": data[m.start():m.end()].decode("ascii", errors="replace"),
        "blob_size": (end - m.start()) if end > 0 else 0,
    })

# 2. AES S-box detection (high confidence). The forward S-box always
#    starts with 63 7c 77 7b f2 6b 6f c5; the inverse S-box starts with
#    52 09 6a d5 30 36 a5 38.
aes_sbox_fwd = bytes.fromhex("637c777bf26b6fc5")
aes_sbox_inv = bytes.fromhex("52096ad5303605a5")  # close approx; some impls differ slightly
for needle, label in [(aes_sbox_fwd, "AES forward S-box"),
                       (bytes.fromhex("52096ad53036a538"), "AES inverse S-box")]:
    idx = 0
    while True:
        pos = data.find(needle, idx)
        if pos < 0: break
        candidates.append({
            "type": "aes_sbox",
            "label": label,
            "confidence": "high",
            "offset": pos,
        })
        idx = pos + 1
        if len(candidates) > 500: break

# 3. DER SEQUENCE for RSA private/public keys.
#    RSA key BLOBs typically start with 30 82 (long-form length) followed
#    by length bytes putting total in 1024-4096 byte range.
for m in re.finditer(rb"\x30\x82..\x02\x01", data):  # SEQ + INTEGER 1
    blob_len = (data[m.start()+2] << 8) | data[m.start()+3]
    if 200 <= blob_len <= 8000:  # reasonable RSA blob size
        candidates.append({
            "type": "der_sequence",
            "confidence": "medium",
            "offset": m.start(),
            "declared_length": blob_len,
            "note": "DER SEQUENCE matching ASN.1 RSA-key shape",
        })

# 4. High-entropy region walker (low/medium confidence)
def shannon_entropy(buf):
    if not buf: return 0.0
    counts = [0]*256
    for b in buf: counts[b] += 1
    total = float(len(buf))
    entropy = 0.0
    for c in counts:
        if c == 0: continue
        p = c/total
        entropy -= p * math.log2(p)
    return entropy

WINDOW = 256  # bytes per window
STEP = 128
for offset in range(0, max(0, len(data) - WINDOW), STEP):
    chunk = data[offset:offset+WINDOW]
    e = shannon_entropy(chunk)
    if e >= 7.5:  # very high entropy - candidate for raw key material
        # Check if window size matches a common key bit-length boundary
        size_class = None
        for bits, label in [(128, "128-bit"), (256, "256-bit (AES-256/Ed25519)"),
                             (1024, "1024-bit RSA"), (2048, "2048-bit RSA"),
                             (3072, "3072-bit RSA"), (4096, "4096-bit RSA")]:
            byte_size = bits // 8
            if WINDOW == byte_size or (offset + byte_size <= len(data) and
                                       shannon_entropy(data[offset:offset+byte_size]) >= 7.5):
                size_class = label
                break
        candidates.append({
            "type": "high_entropy",
            "confidence": "medium" if size_class else "low",
            "offset": offset,
            "window": WINDOW,
            "entropy": round(e, 3),
            "size_class": size_class,
        })
        if len([c for c in candidates if c["type"] == "high_entropy"]) > 50:
            break  # cap to avoid excessive output

# Summary
summary = {
    "target": target_path,
    "total_candidates": len(candidates),
    "by_confidence": {
        "high":   len([c for c in candidates if c["confidence"] == "high"]),
        "medium": len([c for c in candidates if c["confidence"] == "medium"]),
        "low":    len([c for c in candidates if c["confidence"] == "low"]),
    },
    "by_type": {},
    "candidates": candidates[:200],  # cap inline list
}
for c in candidates:
    t = c["type"]
    summary["by_type"][t] = summary["by_type"].get(t, 0) + 1

with open(os.path.join(outdir, "key-candidates.json"), "w") as f:
    json.dump(summary, f, indent=2)
print(f"key-candidates: {len(candidates)} total "
      f"(high={summary['by_confidence']['high']}, "
      f"med={summary['by_confidence']['medium']}, "
      f"low={summary['by_confidence']['low']})")
PYEOF
        log_step "cryptokeys walker: $(safe_grep_count offset "${ck}/key-candidates.json") JSON entries"
    fi
}
