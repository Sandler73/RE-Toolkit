#!/usr/bin/env bash
# =============================================================================
# stages/static/12-lief.sh
# =============================================================================
#
# Synopsis:
#     LIEF exhaustive format-agnostic binary parsing.
#
# Description:
#     LIEF parses PE, ELF, and Mach-O with a single unified API. The goal here
#     is a maximum-depth dump of every structural element LIEF exposes. Output
#     goes to a single `lief-full.txt` file (optionally a JSON sibling).
#
#     Pattern: pure-Python heredoc via $VENV_PY. The script skips silently if
#     the module isn't installed. No timeouts needed in practice (LIEF is
#     fast).
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
#     stage_lief()
#
# Output subtrees:
#     ${outdir}/12-lief/
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_lief() {
    local target="$1" outdir="$2"
    [[ -z "$VENV_PY" ]] && { log_info "Stage 12 -- LIEF skipped (no python venv)"; return 0; }

    local lf="${outdir}/12-lief"
    mkdir -p "$lf"

    # LIEF import is opportunistic -- if it's not installed, emit a notice.
    if ! "$VENV_PY" -c 'import lief' >/dev/null 2>&1; then
        echo "lief not installed in $VENV_PY; skipping LIEF stage" > "${lf}/lief-skipped.txt"
        log_warn "LIEF module not available in venv; skipping Stage 12"
        return 0
    fi

    "$VENV_PY" - "$target" "${lf}/lief-full.txt" "${lf}/lief-full.json" <<'PYEOF'
"""
LIEF exhaustive binary dump.
Dumps every structural element LIEF exposes for PE / ELF / Mach-O binaries.
Writes a human-readable report (lief-full.txt) and a structured JSON
companion (lief-full.json) that stage_summary can consume.
"""
import sys, json, os, hashlib, traceback

TARGET   = sys.argv[1]
TXT_OUT  = sys.argv[2]
JSON_OUT = sys.argv[3]

def _sha256(data):
    try:   return hashlib.sha256(bytes(data)).hexdigest()
    except Exception: return ""

def _entropy(data):
    try:
        import math
        if not data: return 0.0
        b = bytes(data)
        counts = [0] * 256
        for c in b: counts[c] += 1
        n = len(b)
        ent = 0.0
        for c in counts:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return round(ent, 4)
    except Exception:
        return 0.0

def safe(fn, default=None):
    try: return fn()
    except Exception: return default

def section_common(sec):
    return {
        "name":          safe(lambda: sec.name, ""),
        "offset":        safe(lambda: int(sec.offset), 0),
        "size":          safe(lambda: int(sec.size), 0),
        "virtual_size":  safe(lambda: int(getattr(sec, 'virtual_size', 0)), 0),
        "virtual_addr":  safe(lambda: int(getattr(sec, 'virtual_address', 0)), 0),
        "entropy":       safe(lambda: round(float(sec.entropy), 4), 0.0),
        "content_sha256":safe(lambda: _sha256(sec.content), ""),
        "characteristics_str": safe(lambda: str(getattr(sec, 'characteristics_lists', ''))),
    }

def parse_pe(binary):
    out = {"format": "PE"}
    # DOS header
    d = binary.dos_header
    out["dos_header"] = {
        "magic":            hex(safe(lambda: d.magic, 0)),
        "addressof_new_exeheader": hex(safe(lambda: d.addressof_new_exeheader, 0)),
    }
    # COFF + Optional
    h = binary.header
    out["coff_header"] = {
        "machine":           str(safe(lambda: h.machine, "")),
        "numberof_sections": int(safe(lambda: h.numberof_sections, 0)),
        "time_date_stamps":  int(safe(lambda: h.time_date_stamps, 0)),
        "characteristics":   str(safe(lambda: h.characteristics_list, "")),
    }
    oh = binary.optional_header
    out["optional_header"] = {
        "magic":            str(safe(lambda: oh.magic, "")),
        "subsystem":        str(safe(lambda: oh.subsystem, "")),
        "image_base":       hex(safe(lambda: oh.imagebase, 0)),
        "section_alignment":hex(safe(lambda: oh.section_alignment, 0)),
        "file_alignment":   hex(safe(lambda: oh.file_alignment, 0)),
        "size_image":       int(safe(lambda: oh.sizeof_image, 0)),
        "addressof_entrypoint": hex(safe(lambda: oh.addressof_entrypoint, 0)),
        "dll_characteristics":  str(safe(lambda: oh.dll_characteristics_lists, "")),
        "checksum":         hex(safe(lambda: oh.checksum, 0)),
    }
    # Sections
    out["sections"] = []
    for s in binary.sections:
        sd = section_common(s)
        sd["characteristics"] = str(safe(lambda: s.characteristics_lists, ""))
        out["sections"].append(sd)
    # Imports
    out["imports"] = []
    for lib in safe(lambda: binary.imports, []) or []:
        entries = []
        for entry in lib.entries:
            entries.append({
                "name":    safe(lambda: entry.name, ""),
                "ordinal": safe(lambda: int(entry.ordinal) if entry.is_ordinal else None),
                "iat_rva": safe(lambda: hex(int(entry.iat_address)), ""),
                "is_ordinal": safe(lambda: bool(entry.is_ordinal), False),
            })
        out["imports"].append({"name": lib.name, "entries": entries})
    # Exports
    out["exports"] = []
    if binary.has_exports:
        exp = binary.get_export()
        for e in exp.entries:
            out["exports"].append({
                "name":     safe(lambda: e.name, ""),
                "ordinal":  safe(lambda: int(e.ordinal), 0),
                "rva":      safe(lambda: hex(int(e.address)), ""),
                "forwarder":safe(lambda: e.forward_information.library + "." + e.forward_information.function if e.is_forwarded else None),
            })
    # Delayed imports
    out["delay_imports"] = []
    for lib in safe(lambda: binary.delay_imports, []) or []:
        out["delay_imports"].append({
            "name": lib.name,
            "entries": [safe(lambda: e.name, "") for e in lib.entries],
        })
    # Resources
    try:
        if binary.has_resources:
            def walk(node, depth=0):
                nd = {
                    "depth": depth,
                    "id": safe(lambda: int(node.id), 0),
                    "name": safe(lambda: node.name, ""),
                    "is_directory": safe(lambda: node.is_directory, False),
                    "is_data":      safe(lambda: node.is_data, False),
                }
                if nd["is_data"]:
                    nd["code_page"] = safe(lambda: int(node.code_page), 0)
                    nd["size"]      = safe(lambda: len(bytes(node.content)), 0)
                    nd["entropy"]   = _entropy(node.content)
                nd["children"] = [walk(c, depth + 1) for c in node.childs]
                return nd
            out["resources"] = walk(binary.resources)
    except Exception as e:
        out["resources_error"] = str(e)
    # Signatures (Authenticode)
    out["signatures"] = []
    for sig in safe(lambda: binary.signatures, []) or []:
        sigd = {
            "version":          safe(lambda: int(sig.version), 0),
            "digest_algorithm": str(safe(lambda: sig.digest_algorithm, "")),
            "signers": [],
        }
        for signer in safe(lambda: sig.signers, []) or []:
            sigd["signers"].append({
                "version":          safe(lambda: int(signer.version), 0),
                "serial_number":    safe(lambda: bytes(signer.serial_number).hex(), ""),
                "issuer":           safe(lambda: signer.issuer, ""),
                "digest_algorithm": str(safe(lambda: signer.digest_algorithm, "")),
                "encryption_algorithm": str(safe(lambda: signer.encryption_algorithm, "")),
            })
        out["signatures"].append(sigd)
    # Load Config
    try:
        if binary.has_configuration:
            lc = binary.load_configuration
            out["load_config"] = {
                "security_cookie":   safe(lambda: hex(int(lc.security_cookie)), ""),
                "se_handler_table":  safe(lambda: hex(int(lc.se_handler_table)), ""),
                "se_handler_count":  safe(lambda: int(lc.se_handler_count), 0),
                "guard_cf_flags":    safe(lambda: str(lc.guard_cf_flags_list), ""),
            }
    except Exception as e:
        out["load_config_error"] = str(e)
    # Rich Header
    try:
        if binary.has_rich_header:
            rh = binary.rich_header
            out["rich_header"] = {
                "key": hex(safe(lambda: rh.key, 0)),
                "entries": [
                    {
                        "id":    hex(safe(lambda: e.id, 0)),
                        "build_id": safe(lambda: int(e.build_id), 0),
                        "count": safe(lambda: int(e.count), 0),
                    } for e in rh.entries
                ],
            }
    except Exception as e:
        out["rich_header_error"] = str(e)
    # TLS
    try:
        if binary.has_tls:
            t = binary.tls
            out["tls"] = {
                "addressof_callbacks": safe(lambda: hex(int(t.addressof_callbacks)), ""),
                "callbacks": [hex(c) for c in safe(lambda: list(t.callbacks), []) or []],
                "size_of_zero_fill":    safe(lambda: int(t.sizeof_zero_fill), 0),
                "characteristics":      safe(lambda: int(t.characteristics), 0),
            }
    except Exception as e:
        out["tls_error"] = str(e)
    # Debug
    out["debug"] = []
    for d_entry in safe(lambda: binary.debug, []) or []:
        out["debug"].append({
            "type":       str(safe(lambda: d_entry.type, "")),
            "timestamp":  safe(lambda: int(d_entry.timestamp), 0),
            "sizeof_data":safe(lambda: int(d_entry.sizeof_data), 0),
            "addressof_rawdata": safe(lambda: hex(int(d_entry.addressof_rawdata)), ""),
        })
    return out

def parse_elf(binary):
    out = {"format": "ELF"}
    h = binary.header
    out["elf_header"] = {
        "file_type":      str(safe(lambda: h.file_type, "")),
        "machine_type":   str(safe(lambda: h.machine_type, "")),
        "entrypoint":     hex(safe(lambda: h.entrypoint, 0)),
        "object_file_version": str(safe(lambda: h.object_file_version, "")),
        "identity_class": str(safe(lambda: h.identity_class, "")),
        "identity_data":  str(safe(lambda: h.identity_data, "")),
        "identity_os_abi":str(safe(lambda: h.identity_os_abi, "")),
    }
    out["sections"] = [section_common(s) for s in binary.sections]
    out["segments"] = []
    for seg in binary.segments:
        out["segments"].append({
            "type":       str(safe(lambda: seg.type, "")),
            "flags":      str(safe(lambda: seg.flags, "")),
            "virtual_address": hex(safe(lambda: seg.virtual_address, 0)),
            "physical_address": hex(safe(lambda: seg.physical_address, 0)),
            "virtual_size": int(safe(lambda: seg.virtual_size, 0)),
            "physical_size": int(safe(lambda: seg.physical_size, 0)),
        })
    out["dynamic_entries"] = []
    for e in safe(lambda: binary.dynamic_entries, []) or []:
        out["dynamic_entries"].append({
            "tag":    str(safe(lambda: e.tag, "")),
            "value":  safe(lambda: int(e.value), 0),
        })
    out["libraries"] = list(safe(lambda: binary.libraries, []) or [])
    out["imported_functions"] = [str(f) for f in safe(lambda: binary.imported_functions, []) or []][:2000]
    out["exported_functions"] = [str(f) for f in safe(lambda: binary.exported_functions, []) or []][:2000]
    # Notes
    out["notes"] = []
    for n in safe(lambda: binary.notes, []) or []:
        out["notes"].append({
            "name":   safe(lambda: n.name, ""),
            "type":   str(safe(lambda: n.type, "")),
            "description_size": safe(lambda: len(bytes(n.description)), 0),
        })
    return out

def parse_macho(binary):
    out = {"format": "Mach-O"}
    h = binary.header
    out["macho_header"] = {
        "cpu_type":    str(safe(lambda: h.cpu_type, "")),
        "file_type":   str(safe(lambda: h.file_type, "")),
        "flags":       str(safe(lambda: h.flags_list, "")),
        "magic":       hex(safe(lambda: h.magic, 0)),
    }
    out["sections"] = [section_common(s) for s in binary.sections]
    out["load_commands"] = []
    for lc in binary.commands:
        out["load_commands"].append({
            "command":   str(safe(lambda: lc.command, "")),
            "size":      safe(lambda: int(lc.size), 0),
        })
    out["imported_functions"] = [str(f) for f in safe(lambda: binary.imported_functions, []) or []][:2000]
    out["exported_functions"] = [str(f) for f in safe(lambda: binary.exported_functions, []) or []][:2000]
    return out

# ---- main ----
try:
    import lief
    # Silence LIEF's own banner noise to stderr
    try: lief.logging.disable()
    except Exception: pass
    binary = lief.parse(TARGET)
    if binary is None:
        result = {"error": "lief.parse returned None", "target": TARGET}
    elif isinstance(binary, lief.PE.Binary):
        result = parse_pe(binary)
    elif isinstance(binary, lief.ELF.Binary):
        result = parse_elf(binary)
    elif isinstance(binary, lief.MachO.Binary):
        result = parse_macho(binary)
    elif isinstance(binary, lief.MachO.FatBinary):
        # Iterate all slices
        result = {"format": "Mach-O Fat", "slices": [parse_macho(b) for b in binary]}
    else:
        result = {"format": "unknown", "type_name": type(binary).__name__}
    result["_meta"] = {"target": TARGET, "size": os.path.getsize(TARGET)}
except Exception as e:
    result = {"error": str(e), "traceback": traceback.format_exc(), "target": TARGET}

with open(JSON_OUT, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, default=str)

def emit_txt(r, fh, indent=0):
    pad = "  " * indent
    if isinstance(r, dict):
        for k, v in r.items():
            if isinstance(v, (dict, list)) and v:
                fh.write(f"{pad}{k}:\n")
                emit_txt(v, fh, indent + 1)
            else:
                fh.write(f"{pad}{k}: {v}\n")
    elif isinstance(r, list):
        for i, item in enumerate(r):
            fh.write(f"{pad}[{i}]\n")
            emit_txt(item, fh, indent + 1)
    else:
        fh.write(f"{pad}{r}\n")

with open(TXT_OUT, "w", encoding="utf-8") as fh:
    fh.write("=" * 72 + "\n")
    fh.write("LIEF exhaustive dump\n")
    fh.write("=" * 72 + "\n\n")
    emit_txt(result, fh)

print(f"LIEF dump: {result.get('format', 'ERR')} "
      f"({os.path.getsize(TXT_OUT) // 1024} KB text, "
      f"{os.path.getsize(JSON_OUT) // 1024} KB json)")
PYEOF

    if [[ -f "${lf}/lief-full.json" ]]; then
        log_step "lief: dump written → ${lf}/lief-full.txt"
    else
        log_warn "lief: no output produced"
    fi
}
