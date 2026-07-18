#!/usr/bin/env bash
# =============================================================================
# stages/static/00-triage.sh
# =============================================================================
#
# Synopsis:
#     Universal triage: identity, hashes, entropy, signatures, and carving.
#
# Description:
#     Universal triage: identity, hashes, entropy, signatures, and carving.
#     - Signsrch (Luigi Auriemma's binary crypto/algorithm signature scanner)
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
#     stage_triage()
#
# Output subtrees:
#     ${outdir}/00-triage/
#     ${outdir}/90-logs/
#
# Skip controls:
#     SKIP_CLAMAV
#     SKIP_SIGNSRCH
#     SKIP_YARA
#
# Tools invoked (run_tool labels):
#     binwalk-arch, binwalk-entropy, binwalk-extract, binwalk-opcodes,
#     binwalk-signature, clamscan, clamscan-verbose, diec-detect, diec-json,
#     diec-text, exiftool, signsrch, yara
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_triage() {
    local target="$1" outdir="$2"
    local tri="${outdir}/00-triage"
    local logs="${outdir}/90-logs"
    mkdir -p "$tri" "$logs"

    # file, stat, hashes, exiftool
    file -b "$target" > "${tri}/file.txt"
    stat "$target"   > "${tri}/stat.txt"
    {
        echo "sha256 $(sha256sum "$target" | cut -d' ' -f1)"
        echo "sha1   $(sha1sum "$target" | cut -d' ' -f1)"
        echo "md5    $(md5sum "$target" | cut -d' ' -f1)"
    } > "${tri}/hashes.txt"

    if command -v exiftool >/dev/null 2>&1; then
        run_tool "exiftool" "${logs}/exiftool.log" 60 \
            exiftool -a "$target"
        cp "${logs}/exiftool.log" "${tri}/exiftool.txt" 2>/dev/null || true
    fi

    # strings (ASCII + Unicode)
    strings -a "$target" > "${tri}/strings-ascii.txt" 2>/dev/null || true
    strings -a -el "$target" > "${tri}/strings-utf16le.txt" 2>/dev/null || true
    strings -a -eb "$target" > "${tri}/strings-utf16be.txt" 2>/dev/null || true
    log_step "strings: ASCII=$(wc -l < "${tri}/strings-ascii.txt" 2>/dev/null || echo 0)  UTF16LE=$(wc -l < "${tri}/strings-utf16le.txt" 2>/dev/null || echo 0)"

    # xxd head
    xxd -l 512 "$target" > "${tri}/xxd-head.txt" 2>/dev/null || true

    # YARA
    if [[ $SKIP_YARA -eq 0 ]] && command -v yara >/dev/null 2>&1 && [[ -n "$YARA_RULES" ]]; then
        # If $YARA_RULES is a directory, use -r; if a file (master.yar), don't.
        # yara: drop `--threads N` (v2.1.3). Some yara builds require
        # `--threads=N` (with equals) rather than `--threads N`; default
        # threading is single-threaded for single-file scans anyway, so
        # just don't specify it.
        if [[ -f "$YARA_RULES" ]]; then
            run_tool "yara" "${tri}/yara-matches.txt" "$TOOL_TIMEOUT" \
                yara "$YARA_RULES" "$target"
        elif [[ -d "$YARA_RULES" ]]; then
            run_tool "yara" "${tri}/yara-matches.txt" "$TOOL_TIMEOUT" \
                yara -s -r "$YARA_RULES" "$target"
            # v3.0.11 (audit-15 B3) - `-s` flag added: prints the actual
            # matched strings (offset + value) for every hit. Pre-v3.0.11
            # output was just "rule_name target" lines with no insight
            # into WHAT triggered the match. With -s, operators see the
            # exact byte sequence that fired each rule, enabling false-
            # positive triage and IOC extraction.
        fi
    fi

    # ClamAV
    # v3.0.11 (audit-15 B3) - dual invocation. The first
    # (--infected --no-summary) is the actionable triage view that
    # shows ONLY infections; this is what severity logic reads. The
    # second (--verbose) writes a full scan report with per-engine
    # progress, archive entry traversal, and "OK" verdicts for
    # contextual visibility into what ClamAV actually examined. The
    # verbose output is kept separate so scoring code in 85-summary.sh
    # remains tied to the clean infected-only file.
    if [[ $SKIP_CLAMAV -eq 0 ]] && command -v clamscan >/dev/null 2>&1; then
        run_tool "clamscan" "${tri}/clamav.txt" "$TOOL_TIMEOUT" \
            clamscan --no-summary --infected "$target"
        run_tool "clamscan-verbose" "${tri}/clamav-verbose.txt" "$TOOL_TIMEOUT" \
            clamscan --verbose --stdout "$target"
    fi

    # binwalk
    # v3.0.11 (audit-15 B1) - expanded from -B-only to multi-mode coverage.
    # Pre-v3.0.11 only signature scan ran; entropy / opcodes / architecture
    # / extraction were unused. Operator finding F4 (audit-15): "binwalk
    # severely underutilized." Per the binwalk(1) manpage:
    #   -B, --signature   common file signatures (have)
    #   -E, --entropy     entropy analysis (NEW; flags packed/encrypted)
    #   -A, --opcodes     common executable opcode signatures (NEW;
    #                     surfaces architectures binwalk recognizes
    #                     beyond what TrID/file see)
    #   -Y, --disasm      capstone-based CPU architecture detection (NEW)
    #   -e, --extract     extract embedded files (NEW; key for firmware
    #                     and dropper analysis)
    #   -v, --verbose     verbose output (added on signature scan)
    #
    # Notes on flags considered but NOT added:
    #   -W, --hexdump     COMPARES two files; single-file mode is
    #                     redundant with xxd; skip
    #   -I, --invalid     shows invalid signature matches (false-positive
    #                     noise); skip unless operator opts in
    #   -M, --matryoshka  recursive extraction; can produce huge trees;
    #                     skip per default to avoid disk-explosion
    #   --plot            uses pyqtgraph + os._exit; not headless-safe
    #                     per the manpage's own warning; skip
    #   -R, --raw         requires a target byte sequence; skip
    #
    # v3.0.12 (audit-16 B1, B2, B3) - operator findings F1-F3 fixes:
    #   F1: binwalk -E without -N pops up a matplotlib X11 graph
    #       window blocking the automation pipeline. Add -N
    #       (--nplot) to disable graphical plot generation entirely.
    #       The text-mode entropy data still writes to stdout/file.
    #       -J (--save) is NOT added: -J saves the plot as PNG (which
    #       implies generating it), which still requires X11 in some
    #       binwalk builds. -N alone is the headless-safe path.
    #   F2: binwalk -e refuses to run extraction utilities (third-
    #       party, security concern) unless --run-as=$USER is passed
    #       AND binwalk itself is running as that user. Use $(whoami)
    #       so the flag matches whoever is invoking the driver - if
    #       running as root, "--run-as=root"; if as user, "--run-as=$user".
    #   F3: binwalk -A produces just column headers when no opcode
    #       signatures match. This is correct behavior for managed-
    #       runtime binaries (.NET PE, Java JAR/CLASS) where binwalk's
    #       opcode signature DB has no patterns to match. Empty output
    #       is a valid no-data result, not a failure. NO CODE CHANGE.
    #
    # All extraction goes to a sub-dir of the binwalk output to keep
    # the outdir hierarchy clean.
    if command -v binwalk >/dev/null 2>&1; then
        run_tool "binwalk-signature" "${tri}/binwalk-signature.txt" "$TOOL_TIMEOUT" \
            binwalk -B -v "$target"
        run_tool "binwalk-entropy" "${tri}/binwalk-entropy.txt" "$TOOL_TIMEOUT" \
            binwalk -E -N "$target"
        run_tool "binwalk-opcodes" "${tri}/binwalk-opcodes.txt" "$TOOL_TIMEOUT" \
            binwalk -A "$target"
        run_tool "binwalk-arch" "${tri}/binwalk-arch.txt" "$TOOL_TIMEOUT" \
            binwalk -Y "$target"
        # Extraction goes to a subdirectory to keep outdir tidy. -e flag
        # writes to current working directory by default; -C overrides.
        # --run-as=$(whoami) per binwalk extractor.py line 153 requirement.
        local bw_extract_dir="${tri}/binwalk-extracted"
        local _bw_user; _bw_user=$(whoami 2>/dev/null || echo root)
        mkdir -p "$bw_extract_dir"
        run_tool "binwalk-extract" "${tri}/binwalk-extract.txt" "$TOOL_TIMEOUT" \
            binwalk -e --run-as="$_bw_user" -C "$bw_extract_dir" "$target"
        # v3.0.13 (audit-17 B2) - operator F2: binwalk-extract often
        # emits "WARNING: One or more files failed to extract: either
        # no utility was found or it's unimplemented" when binwalk
        # recognizes embedded items (CAB, NSIS, MSI, custom firmware
        # formats, niche compression types) but the corresponding
        # extractor utility isn't installed or doesn't exist. This is
        # PARTIAL SUCCESS: items with known extractors DO get extracted;
        # items with missing extractors are skipped with the warning.
        # Surface this clearly for operators so they don't read the
        # WARNING as a complete failure.
        if [[ -f "${tri}/binwalk-extract.txt" ]]; then
            local _ext_count=0
            if [[ -d "$bw_extract_dir" ]]; then
                _ext_count=$(find "$bw_extract_dir" -type f 2>/dev/null | wc -l)
            fi
            if grep -qE 'WARNING: One or more files failed to extract' "${tri}/binwalk-extract.txt" 2>/dev/null; then
                if [[ $_ext_count -gt 0 ]]; then
                    log_step "binwalk-extract: partial success ($_ext_count files extracted; some carve targets had missing extractor utilities - WARNING is expected)"
                else
                    log_step "binwalk-extract: 0 files extracted (target may not contain embedded files, or extractor utilities not installed)"
                fi
            elif [[ $_ext_count -gt 0 ]]; then
                log_step "binwalk-extract: $_ext_count files extracted"
            fi
        fi
    fi

    # capa - capability analysis with debug + very-verbose output.
    # v3.0.12 (audit-16 A1) - flag corrections per operator F4-F6:
    #   -v -> -vv  (very verbose: rule trace, evidence locations).
    #              Per capa source main.py: -v/--verbose and
    #              -vv/--vverbose are distinct; -vv is the analyst-
    #              useful trace. -v alone shows only top-level matches.
    #   ADD -d/--debug  (debug output to STDERR; captured separately
    #              to capa-debug.log so JSON/text outputs stay clean).
    #   ADD -f auto  (explicit format auto-detect; per capa source
    #              this is already the default but explicit is more
    #              robust against future default changes).
    #   NOT ADDED: -b auto (operator F6 asked for "-b auto" but capa
    #              source main.py shows -b accepts only
    #              {vivisect,viv,binja,binaryninja,pyghidra} - no
    #              "auto" value exists. Defaults to vivisect which
    #              is fine for static PE/ELF/.NET analysis.)
    #
    # STDERR capture: Each capa invocation writes its STDOUT to the
    # named output file; the corresponding capa-debug-*.log file
    # captures STDERR. With -d, STDERR contains the debug trace
    # showing rule matching, feature extraction, and any errors.
    if [[ -n "$CAPA_CMD" ]]; then
        if [[ -n "$CAPA_RULES" && -d "$CAPA_RULES" ]]; then
            "$CAPA_CMD" -r "$CAPA_RULES" -j -f auto -d "$target" \
                >"${tri}/capa.json" \
                2>"${tri}/capa-debug-json.log" || true
            "$CAPA_CMD" -r "$CAPA_RULES" -vv -f auto -d "$target" \
                >"${tri}/capa-rendered.txt" \
                2>"${tri}/capa-debug-text.log" || true
            log_step "capa-json: OK (debug to capa-debug-json.log)"
            log_step "capa-text: OK (-vv debug to capa-debug-text.log)"
        else
            # Last-resort attempt without explicit rules -- capa may still
            # have its own embedded discovery. Likely produces nothing useful.
            "$CAPA_CMD" -j -f auto -d "$target" \
                >"${tri}/capa.json" \
                2>"${tri}/capa-debug-json.log" || true
            "$CAPA_CMD" -vv -f auto -d "$target" \
                >"${tri}/capa-rendered.txt" \
                2>"${tri}/capa-debug-text.log" || true
            log_step "capa-json (no rules): OK"
            log_step "capa-text (no rules): OK"
        fi
    fi

    # ---- v2.2.0 additions -------------------------------------------------
    # Detect It Easy -- packer/compiler/protector fingerprint. Always on when
    # installed. Output both text (human-readable) and JSON (machine-readable
    # for the summary + report stages).
    # v3.0.10 (audit-14 A3) - per DIE manpage, the scan modes are:
    #   -d, --deepscan        Deep scan (signature mode)
    #   -u, --heuristicscan   Heuristic scan (fuzzy signatures)
    #   -a, --alltypes        Scan all types (handles edge-case formats)
    #   -e, --entropy         Show entropy
    # Pre-v3.0.10 invocation was just `-d`, which left heuristic scan
    # OFF. Operator's v3.0.9 install reported the warning "Heuristic
    # scan is disabled. Use '--heuristicscan' to enable" as the full
    # output. Adding -u + -a + -e enables a richer scan profile.
    #
    # v3.0.12 (audit-16 A2) - operator F7 added flags:
    #   -b, --verbose         verbose output
    #   -p, --plaintext       result as plain text (clean for parsing
    #                          / record output without Qt status text)
    #   -l, --profiling       profiling signatures (timing breakdown
    #                          of which signatures matched, useful for
    #                          slow-scan diagnosis)
    #   -i, --info            show file info (architecture, mime,
    #                          hashes, basic metadata)
    # Database flags considered + rejected: -D/--database,
    # -E/--extradatabase, -C/--customdatabase. On Kali, diec's apt
    # package places signatures at /usr/share/detect-it-easy/db/
    # which the binary auto-discovers via Qt resource loading. No
    # need to specify -D in scripted invocation - the default
    # database is used. -E and -C are for analyst-supplied custom
    # signature sets which we don't ship with RE-Toolkit.
    #
    # Defensively probe --help for flag presence to handle older DIE
    # builds that don't support all flags.
    if command -v diec >/dev/null 2>&1; then
        local _diec_help diec_flags=("-d")
        _diec_help=$(diec --help 2>&1 || true)
        echo "$_diec_help" | grep -q -- '--heuristicscan'  && diec_flags+=("-u")
        echo "$_diec_help" | grep -q -- '--alltypes'       && diec_flags+=("-a")
        echo "$_diec_help" | grep -q -- '--entropy'        && diec_flags+=("-e")
        echo "$_diec_help" | grep -q -- '--verbose'        && diec_flags+=("-b")
        echo "$_diec_help" | grep -q -- '--plaintext'      && diec_flags+=("-p")
        echo "$_diec_help" | grep -q -- '--profiling'      && diec_flags+=("-l")
        echo "$_diec_help" | grep -q -- '--info'           && diec_flags+=("-i")
        run_tool "diec-text" "${tri}/die.txt" 60 \
            diec "${diec_flags[@]}" "$target"
        # v3.7.2 (audit-30 B2): the flag set above includes -e (entropy). On
        # some diec builds the entropy view dominates the output and the primary
        # file-type / compiler / linker / library detection (DIE's main value)
        # is not shown -- so a .NET assembly reports only "not packed" + section
        # entropy. Add a dedicated DETECTION-ONLY pass (no -e, no -d deep scan)
        # whose output is DIE's standard identification, captured regardless of
        # how the entropy pass renders. Additive and non-blocking: it cannot
        # affect the existing die.txt / die.json consumers.
        run_tool "diec-detect" "${tri}/die-detect.txt" 60 \
            diec -a "$target"
        # diec's JSON mode: -j (some builds need --json). Use fallback.
        # Note: -j and -p are mutually exclusive output modes; build a
        # JSON-flavored flag set without -p.
        if echo "$_diec_help" | grep -q -- '-j'; then
            local diec_json_flags=()
            for f in "${diec_flags[@]}"; do
                [[ "$f" == "-p" ]] && continue  # JSON mode supersedes plaintext
                diec_json_flags+=("$f")
            done
            run_tool "diec-json" "${tri}/die.json" 60 \
                diec "${diec_json_flags[@]}" -j "$target"
        fi
        log_step "DIE: $(head -c 100 "${tri}/die.txt" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
    fi

    # v2.3.0: TrID -- complementary file-signature identifier. TrID uses a
    # different (hand-curated) signature DB from DIE, so the two tools
    # disagree usefully and often catch things the other misses.
    #   -n:20   : return top 20 matches
    #   -v      : verbose (includes file size, TrID version, DB info)
    # Exits non-zero when no sig matches (common for novel binaries), so we
    # capture output either way; do not use run_tool.
    if command -v trid >/dev/null 2>&1; then
        # v3.0.16 (audit-20 CRITICAL) - DO NOT add -ae to this invocation.
        # Per TrID official docs:
        #   -ae   Add guessed extension to filename
        #   -ce   Change filename extension
        # `-ae` RENAMES THE INPUT FILE ON DISK by appending the guessed
        # extension. If TrID guesses ".exe" for "sample.exe", the
        # file becomes "sample.exe.exe". This is catastrophic in
        # an analysis pipeline -- every subsequent stage looks for the
        # original path and finds nothing. Stage 30 Ghidra's
        # "IOException: File not found" is the loudest symptom but every
        # post-stage-0 tool is affected.
        #
        # Pre-v3.0.13: -ae was present but TrID silently failed on defs
        # lookup (no -d:, no symlink), so the rename action never fired.
        # The bug was masked.
        # v3.0.13 (audit-17 F1): added explicit -d: path probing so TrID
        # always finds its defs and always succeeds. The -ae flag was
        # left in by inertia -- nobody verified what -ae actually does
        # to the file on disk. Result: every v3.0.13/v3.0.14/v3.0.15 run
        # against a PE file destroyed the operator's input.
        # v3.0.16: drop -ae. We never wanted file rename; we want file
        # identification. The only reason -ae was here historically is
        # nobody read the flag's semantics carefully.
        # Lesson L63: tools that mutate input must be audited per-flag
        # against official docs before pipeline invocation.
        # v3.0.13 (audit-17 A1) - operator F1: TrID still failed in
        # v3.0.12 with "File /usr/local/bin/triddefs.trd not found!"
        # because the audit-16 D1 install-time symlink only gets
        # created when the operator re-runs the installer. If they
        # extracted v3.0.12 over v3.0.11 without re-installing, the
        # symlink isn't there. Robust fix: pass -d: flag explicitly
        # so we don't depend on TrID's PATH-relative search at all.
        # Per official trid help syntax: -d:file (colon, no space).
        # Probe canonical paths in order; first hit wins.
        local _trid_defs=""
        for _p in /usr/share/trid/triddefs.trd \
                  /usr/local/bin/triddefs.trd \
                  /etc/trid/triddefs.trd \
                  /opt/trid/triddefs.trd; do
            if [[ -f "$_p" ]]; then _trid_defs="$_p"; break; fi
        done
        {
            if [[ -n "$_trid_defs" ]]; then
                echo "=== trid -n:20 -v -d:${_trid_defs} ==="
                trid -n:20 -v "-d:${_trid_defs}" "$target" 2>&1 || true
            else
                echo "=== trid -n:20 -v (defs auto-search) ==="
                trid -n:20 -v "$target" 2>&1 || true
            fi
            echo ""
            echo "=== exit code: $? ==="
        } > "${tri}/trid.txt"
        local trid_top
        trid_top=$(grep -E '^\s*[0-9]+\.[0-9]+% \(\.' "${tri}/trid.txt" 2>/dev/null | head -1 | sed 's/^ *//')
        [[ -n "$trid_top" ]] && log_step "TrID: $trid_top"
    fi

    # Authenticode -- signature verification for PE files only.
    # osslsigncode exits:
    #   0 = signature present + verified
    #   1 = signature present but verification failed
    #   >1 = no signature / not a PE / read error
    # We capture the output either way; the shell capture of exit codes
    # lives in the log file. _summary.json parses the text.
    if command -v osslsigncode >/dev/null 2>&1; then
        local ft
        ft=$(file -b "$target" 2>/dev/null)
        if [[ "$ft" == *"PE32"* || "$ft" == *"MS-DOS"* || "$ft" == *"Mono/.Net"* ]]; then
            # Don't use run_tool -- it treats non-zero exit as warn, but
            # osslsigncode exit>0 is common and informative (= not signed).
            {
                echo "=== osslsigncode verify ==="
                osslsigncode verify -in "$target" 2>&1
                echo ""
                echo "=== exit code: $? ==="
            } > "${tri}/authenticode.txt"
            local auth_head
            auth_head=$(grep -iE 'signature (verification|ok|missing)|no signature|not signed' \
                        "${tri}/authenticode.txt" 2>/dev/null | head -1)
            [[ -n "$auth_head" ]] && log_step "Authenticode: $auth_head"
        fi
    fi

    # Per-section entropy. This uses pefile for PE binaries (native + .NET),
    # raw-block Shannon entropy for ELF and unknowns. Output is plain text,
    # one section per line, with a "HIGH ENTROPY" flag on anything > 7.0
    # (strongly suggests packing/encryption/compression).
    if [[ -n "$VENV_PY" ]]; then
        "$VENV_PY" - "$target" > "${tri}/entropy.txt" 2>&1 <<'PYEOF' || true
import sys, math, os

def shannon(data):
    if not data: return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent

path = sys.argv[1]
size = os.path.getsize(path)

print(f"File: {path}")
print(f"Size: {size} bytes")

try:
    import pefile
    pe = pefile.PE(path, fast_load=True)
    with open(path, 'rb') as f:
        overall = shannon(f.read())
    print(f"Overall entropy: {overall:.3f}")
    print()
    print(f"{'Section':<12} {'VSize':>10} {'RSize':>10} {'Entropy':>10}  Flag")
    print("-" * 64)
    for s in pe.sections:
        name = s.Name.decode(errors='replace').rstrip('\x00')
        ent = s.get_entropy()
        flag = "HIGH" if ent > 7.0 else ("LOW" if ent < 1.0 else "")
        print(f"{name:<12} {s.Misc_VirtualSize:>10} {s.SizeOfRawData:>10} {ent:>10.3f}  {flag}")
    pe.close()
except Exception:
    # Fall back to raw-block entropy (1MB blocks)
    with open(path, 'rb') as f:
        data = f.read()
    overall = shannon(data)
    print(f"Overall entropy: {overall:.3f}  (raw scan -- not a PE, or pefile unavailable)")
    print()
    block = 65536
    print(f"{'Offset':>10} {'Entropy':>10}  Flag")
    print("-" * 40)
    for i in range(0, min(len(data), 16 * 1024 * 1024), block):
        chunk = data[i:i+block]
        if not chunk: break
        ent = shannon(chunk)
        flag = "HIGH" if ent > 7.0 else ("LOW" if ent < 1.0 else "")
        print(f"{i:>10} {ent:>10.3f}  {flag}")
PYEOF
        local max_ent
        max_ent=$(awk '/^[._][A-Za-z0-9]+ +[0-9]+ +[0-9]+ +[0-9.]+/ {
                         if($4+0 > max) max=$4+0
                       } END { printf "%.2f", max }' "${tri}/entropy.txt" 2>/dev/null)
        [[ -n "$max_ent" && "$max_ent" != "0.00" ]] && log_step "Max section entropy: $max_ent"
    fi

    # v2.5.0: signsrch - Luigi Auriemma's binary signature scanner.
    # Detects crypto algorithms, compression algorithms, anti-debug patterns,
    # and known constants by scanning for byte patterns from a curated DB
    # (~2300 signatures as of signsrch 0.2.4). The `-e` flag tells signsrch
    # to interpret the file as PE/ELF and report RVAs instead of raw offsets,
    # which is more useful when correlating with disassembly output.
    if [[ ${SKIP_SIGNSRCH:-0} -eq 0 ]]; then
        if command -v signsrch >/dev/null 2>&1; then
            # v3.0.12 (audit-16 C1) - operator F8: signsrch fails with
            # "No such file or directory" on deeply nested paths with
            # special characters (version dots, dashes, nested extraction-directory patterns). signsrch is from 2016 and has known bugs with
            # long/complex paths in its argv handling. Workaround: copy
            # the target to a short /tmp path, run signsrch on that
            # path, clean up. The signature output is identical; only
            # the path-handling shim differs.
            local _ss_target="/tmp/signsrch-$$-$(basename "$target")"
            if cp "$target" "$_ss_target" 2>/dev/null; then
                run_tool "signsrch" "${tri}/signsrch.txt" 120 \
                    signsrch -e "$_ss_target"
                rm -f "$_ss_target"
            else
                # Fallback to original path if temp copy fails (full /tmp,
                # permission issue, etc). Most binaries are small (<100MB)
                # so the copy almost always succeeds.
                run_tool "signsrch" "${tri}/signsrch.txt" 120 \
                    signsrch -e "$target"
            fi
            local hit_count=0
            # v3.0.5 (audit-9 A1): the previous capture was:
            #   hit_count=$(grep -cE PATTERN FILE 2>/dev/null || echo 0)
            # which had a subtle bug: grep -c writes "0" to stdout when
            # there are no matches AND returns exit code 1 (some greps);
            # the `|| echo 0` then ALSO writes "0", so hit_count became
            # the two-line string "0\n0". Line 233's
            #   [[ ${hit_count:-0} -gt 0 ]]
            # then ran [[ "0 0" -gt 0 ]] which threw:
            #   00-triage.sh: line 233: [[: 0 0: arithmetic syntax error
            #   in expression (error token is "0")
            # Fix: guard the file existence first, force a single-value
            # capture, and use head -1 + tr -d to defensively reject any
            # multi-line stdout. The result is always exactly one integer.
            if [[ -s "${tri}/signsrch.txt" ]]; then
                hit_count=$(grep -cE '^\s*[0-9a-f]{8}\s+[0-9]+\s+' \
                    "${tri}/signsrch.txt" 2>/dev/null | head -1 | tr -dc '0-9')
                hit_count="${hit_count:-0}"
            fi
            [[ "$hit_count" -gt 0 ]] && \
                log_step "signsrch: ${hit_count} signature hit(s)"
        fi
    fi
}
