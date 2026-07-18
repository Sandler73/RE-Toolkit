#!/usr/bin/env bash
# =============================================================================
# stages/static/76-axml.sh
# =============================================================================
#
# Synopsis:
#     AndroidManifest.xml binary-XML decode and permission analysis.
#
# Description:
#     AndroidManifest.xml is the security-relevant heart of an APK:
#     - <uses-permission> declares what the app can do
#     - <activity android:exported="true"> opens entry points to other apps
#     - <intent-filter> declares URL handlers, deep links, broadcast receivers
#     - <provider android:exported="true"> exposes content URIs
#     - <meta-data> sometimes contains config-as-data (API keys, flags)
#
#     Two input modes: 1. Already-decoded plain-text XML (from apktool d). Read
#     directly. 2. Binary AXML (raw from APK or standalone). Decode via aapt2
#     dump xmltree as fallback.
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
#     stage_axml()
#
# Output subtrees:
#     ${outdir}/76-axml/
#
# Skip controls:
#     SKIP_AXML
#
# Tools invoked (run_tool labels):
#     aapt-xmltree, aapt2-xmltree
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_axml() {
    local target="$1" outdir="$2"
    local ax="${outdir}/76-axml"

    if [[ ${SKIP_AXML:-0} -eq 1 ]]; then
        log_step "axml: skipped (SKIP_AXML=1)"
        return 0
    fi

    mkdir -p "$ax"

    # ---- Decode (or copy) AndroidManifest.xml ------------------------------
    local decoded="${ax}/AndroidManifest-decoded.xml"

    # Detect format: plain-text XML (apktool output) starts with "<?xml"
    # or "<manifest"; binary AXML starts with magic bytes 03 00 08 00.
    local first_bytes
    first_bytes=$(head -c 16 "$target" 2>/dev/null)
    if [[ "$first_bytes" =~ ^\<\?xml || "$first_bytes" =~ ^\<manifest ]]; then
        # Already plain-text (apktool already decoded it during stage_apk)
        cp "$target" "$decoded"
        log_step "axml: input is already plain-text; copied to $decoded"
    else
        # Binary AXML; needs decoding
        if command -v aapt2 >/dev/null 2>&1; then
            run_tool "aapt2-xmltree" "${ax}/aapt2.log" 60 \
                aapt2 dump xmltree --file AndroidManifest.xml "$target"
            # Best-effort: copy aapt2 output as a "decoded" representation
            # (it's not strict XML but it's human-readable)
            if [[ -s "${ax}/aapt2.log" ]]; then
                cp "${ax}/aapt2.log" "$decoded"
            fi
        elif command -v aapt >/dev/null 2>&1; then
            run_tool "aapt-xmltree" "${ax}/aapt.log" 60 \
                aapt dump xmltree "$target" AndroidManifest.xml
            if [[ -s "${ax}/aapt.log" ]]; then
                cp "${ax}/aapt.log" "$decoded"
            fi
        else
            log_warn "axml: neither aapt2 nor aapt installed; cannot decode binary AXML"
            cp "$target" "$decoded"  # raw copy; better than nothing for grep
        fi
    fi

    # ---- Permission extraction ----------------------------------------------
    {
        echo "=== Declared permissions (uses-permission) ==="
        if [[ -f "$decoded" ]]; then
            # Two patterns: plain XML (`<uses-permission android:name="...">`)
            # and aapt2 xmltree (`E: uses-permission ... A: android:name="..."`)
            grep -aE 'uses-permission' "$decoded" \
                | grep -aoE 'android\.permission\.[A-Z_]+' \
                | sort -u || echo "  (none found)"
        fi
    } > "${ax}/permissions.txt"

    # ---- Exported components ------------------------------------------------
    {
        echo "=== Exported components (android:exported=\"true\") ==="
        echo ""
        if [[ -f "$decoded" ]]; then
            for comp_type in activity service receiver provider; do
                echo "--- ${comp_type^} ---"
                # Match in plain XML form: <activity ... android:exported="true">
                # and in aapt2 xmltree form
                local matches
                matches=$(grep -aiE "<${comp_type}[[:space:]>]" "$decoded" 2>/dev/null \
                    | grep -aiE 'android:exported[[:space:]]*=[[:space:]]*"?true"?' \
                    | head -50)
                if [[ -n "$matches" ]]; then
                    echo "$matches"
                else
                    echo "  (none exported)"
                fi
                echo ""
            done
        fi
    } > "${ax}/exported-components.txt"

    # ---- Build manifest-summary.json via Python heredoc --------------------
    if [[ -n "$VENV_PY" && -f "$decoded" ]]; then
        "$VENV_PY" - "$decoded" "$ax" > "${ax}/_summary.log" 2>&1 <<'PYEOF' || true
"""Parse AndroidManifest.xml (decoded form) and emit manifest-summary.json.

Handles two input formats:
  1. Plain XML (apktool output). Use ElementTree.
  2. aapt2 xmltree text format. Parse line-based with regex.

The dangerous-permission list is from Android's runtime permission group
guidance plus malware-hunting heuristics (READ_SMS + RECEIVE_BOOT_COMPLETED
combined = SMS-stealer pattern; BIND_ACCESSIBILITY_SERVICE = banking trojan
overlay pattern).
"""
import sys
import os
import json
import re

decoded_path = sys.argv[1]
outdir = sys.argv[2]

# Dangerous permission list. Categories:
#  - PII: contacts, calendar, call log
#  - Comms: SMS, MMS, phone state, voicemail
#  - Sensors: camera, microphone, location
#  - Storage: external storage
#  - Privileged: install packages, accessibility, device admin, system overlay
DANGEROUS_PERMS = {
    # PII
    "READ_CONTACTS": "PII (contacts)",
    "WRITE_CONTACTS": "PII (contacts)",
    "READ_CALENDAR": "PII (calendar)",
    "WRITE_CALENDAR": "PII (calendar)",
    "READ_CALL_LOG": "PII (call log)",
    "WRITE_CALL_LOG": "PII (call log)",
    # Comms
    "READ_SMS": "Comms (SMS reading)",
    "SEND_SMS": "Comms (SMS sending)",
    "RECEIVE_SMS": "Comms (SMS receiving)",
    "READ_PHONE_STATE": "Comms (phone state)",
    "READ_PHONE_NUMBERS": "Comms (phone numbers)",
    "CALL_PHONE": "Comms (place calls)",
    "PROCESS_OUTGOING_CALLS": "Comms (outgoing calls)",
    # Sensors / hardware
    "CAMERA": "Sensors (camera)",
    "RECORD_AUDIO": "Sensors (microphone)",
    "ACCESS_FINE_LOCATION": "Sensors (precise location)",
    "ACCESS_COARSE_LOCATION": "Sensors (coarse location)",
    "ACCESS_BACKGROUND_LOCATION": "Sensors (background location)",
    "BODY_SENSORS": "Sensors (body sensors)",
    # Storage
    "READ_EXTERNAL_STORAGE": "Storage (read)",
    "WRITE_EXTERNAL_STORAGE": "Storage (write)",
    "MANAGE_EXTERNAL_STORAGE": "Storage (full management)",
    # Privileged / dangerous
    "REQUEST_INSTALL_PACKAGES": "PRIVILEGED (install other apps)",
    "BIND_ACCESSIBILITY_SERVICE": "PRIVILEGED (accessibility - banking trojan vector)",
    "BIND_DEVICE_ADMIN": "PRIVILEGED (device admin)",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "PRIVILEGED (read all notifications)",
    "SYSTEM_ALERT_WINDOW": "PRIVILEGED (overlay - tapjacking vector)",
    "WRITE_SETTINGS": "PRIVILEGED (modify system settings)",
}

result = {
    "package_name": None,
    "version_code": None,
    "version_name": None,
    "min_sdk": None,
    "target_sdk": None,
    "compile_sdk": None,
    "permissions": [],
    "dangerous_permissions": [],
    "exported_activities": [],
    "exported_services": [],
    "exported_receivers": [],
    "exported_providers": [],
    "intent_filter_count": 0,
    "deep_link_schemes": [],
    "uses_native_libs": False,
    "format": "unknown",
    "parse_errors": [],
}

with open(decoded_path, "r", encoding="utf-8", errors="replace") as f:
    content = f.read()

# Detect format
if content.lstrip().startswith("<?xml") or content.lstrip().startswith("<manifest"):
    result["format"] = "xml"
elif "E: manifest" in content or "N: android=" in content:
    result["format"] = "aapt-xmltree"
else:
    result["format"] = "unknown"

# Parse XML format
if result["format"] == "xml":
    try:
        import xml.etree.ElementTree as ET
        # Strip namespaces for simpler XPath-like access
        ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
        tree = ET.parse(decoded_path)
        root = tree.getroot()
        result["package_name"] = root.get("package")
        result["version_code"] = root.get(ANDROID_NS + "versionCode")
        result["version_name"] = root.get(ANDROID_NS + "versionName")
        # SDK levels in <uses-sdk>
        sdk = root.find("uses-sdk")
        if sdk is not None:
            result["min_sdk"] = sdk.get(ANDROID_NS + "minSdkVersion")
            result["target_sdk"] = sdk.get(ANDROID_NS + "targetSdkVersion")
            result["compile_sdk"] = sdk.get(ANDROID_NS + "compileSdkVersion")
        # Permissions
        for perm in root.iter("uses-permission"):
            pname = perm.get(ANDROID_NS + "name", "")
            short = pname.rsplit(".", 1)[-1]
            result["permissions"].append(pname)
            if short in DANGEROUS_PERMS:
                result["dangerous_permissions"].append({
                    "permission": pname, "category": DANGEROUS_PERMS[short]
                })
        # Exported components
        app = root.find("application")
        if app is not None:
            for tag in ("activity", "service", "receiver", "provider"):
                for comp in app.iter(tag):
                    exported = comp.get(ANDROID_NS + "exported", "")
                    name = comp.get(ANDROID_NS + "name", "")
                    perm_guard = comp.get(ANDROID_NS + "permission", "")
                    has_intent_filter = bool(list(comp.iter("intent-filter")))
                    # Component is "effectively exported" if:
                    #  - android:exported="true" explicit, OR
                    #  - has intent-filter (legacy implicit export rule pre-12)
                    is_exported = (exported == "true") or (
                        not exported and has_intent_filter
                    )
                    if is_exported:
                        target_list = result[f"exported_{tag}s" if tag != "activity" else "exported_activities"]
                        target_list.append({
                            "name": name,
                            "exported_attr": exported or "(implicit)",
                            "permission_guard": perm_guard or None,
                            "has_intent_filter": has_intent_filter,
                        })
                    # Count intent filters & deep link schemes
                    for ifilter in comp.iter("intent-filter"):
                        result["intent_filter_count"] += 1
                        for data in ifilter.iter("data"):
                            scheme = data.get(ANDROID_NS + "scheme")
                            if scheme and scheme not in result["deep_link_schemes"]:
                                result["deep_link_schemes"].append(scheme)
        # Native libs hint
        if app is not None and app.get(ANDROID_NS + "extractNativeLibs") is not None:
            result["uses_native_libs"] = True
    except Exception as e:
        result["parse_errors"].append(f"XML parse: {type(e).__name__}: {e}")

# Parse aapt2 xmltree format (regex-based)
elif result["format"] == "aapt-xmltree":
    # Format: lines like
    #   E: manifest (line=N)
    #     A: package="com.example" ...
    #     A: android:versionCode=(type 0x10)0x1 ...
    #   E: uses-permission (line=N)
    #     A: android:name="android.permission.INTERNET"
    pkg_match = re.search(r'A:\s+package="([^"]+)"', content)
    if pkg_match:
        result["package_name"] = pkg_match.group(1)
    vc_match = re.search(r'A:\s+android:versionCode\([^)]+\)=[^"]*"?(\d+)', content) or \
               re.search(r'A:\s+android:versionCode\([^)]+\)=\(type [^)]+\)0x([0-9a-fA-F]+)', content)
    if vc_match:
        try:
            result["version_code"] = str(int(vc_match.group(1), 16) if 'x' in vc_match.group(0) else vc_match.group(1))
        except Exception:
            pass
    vn_match = re.search(r'A:\s+android:versionName.*?="([^"]+)"', content)
    if vn_match:
        result["version_name"] = vn_match.group(1)
    # Permissions
    for m in re.finditer(r'E:\s+uses-permission.*?\n\s+A:\s+android:name.*?="([^"]+)"', content, re.DOTALL):
        pname = m.group(1)
        short = pname.rsplit(".", 1)[-1]
        result["permissions"].append(pname)
        if short in DANGEROUS_PERMS:
            result["dangerous_permissions"].append({
                "permission": pname, "category": DANGEROUS_PERMS[short]
            })

with open(os.path.join(outdir, "manifest-summary.json"), "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print(f"axml: package={result['package_name']}, "
      f"perms={len(result['permissions'])}, "
      f"dangerous={len(result['dangerous_permissions'])}, "
      f"exported_activities={len(result['exported_activities'])}, "
      f"format={result['format']}")
PYEOF
        log_step "axml: $(grep -m1 'package=' "${ax}/_summary.log" 2>/dev/null || echo 'parsed')"
    fi
}
