#!/usr/bin/env bash
# =============================================================================
# stages/static/20-dotnet.sh
# =============================================================================
#
# Synopsis:
#     .NET-specific analysis: disassembly, decompilation, and deobfuscation.
#
# Description:
#     .NET-specific analysis: disassembly, decompilation, and deobfuscation.
#     - EazFixer (Eazfuscator-specific deobfuscator; runs after de4dot)
#     - OldRod (KoiVM/VMProtect.NET devirtualizer; runs after de4dot)
#     - NoFuserEx (opt-in ConfuserEx alternative to de4dot via --use-nofuserex)
#     - DnSpyEx CLI (third decompiler perspective on the original +
#       deobfuscated)
#
#     Specialized deobfuscator selection: EazFixer and OldRod auto-trigger from
#     de4dot's detection output (the de4dot -d pass already runs and reports
#     any recognized obfuscator). NoFuserEx is opt-in only via USE_NOFUSEREX=1
#     because its output usually duplicates de4dot for ConfuserEx targets.
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
#     stage_dotnet()
#
# Output subtrees:
#     ${outdir}/20-dotnet/
#     ${outdir}/22-de4dot/
#     ${outdir}/24-deob/
#     ${outdir}/26-dnspyex/
#
# Skip controls:
#     SKIP_DE4DOT
#     SKIP_DNSPY_EX
#     SKIP_DOTNET
#     SKIP_EAZFIXER
#     SKIP_OLDROD
#     USE_NOFUSEREX
#
# Tools invoked (run_tool labels):
#     de4dot, dnspyex, dnspyex-deobf, eazfixer, ikdasm, ilspycmd,
#     ilspycmd-deobf, monodis, nofuserex, oldrod
#
# Notes:
#     Stage ordering, output-tree layout, and skip-control semantics are
#     documented in the project wiki (Stage-Reference and Configuration).
#     Release-by-release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

stage_dotnet() {
    local target="$1" outdir="$2"
    [[ $SKIP_DOTNET -eq 1 ]] && return 0

    local dn="${outdir}/20-dotnet"
    mkdir -p "$dn"

    # v2.3.0: de4dot-cex obfuscation detection + deobfuscation
    # Run BEFORE ilspy so we can later decompile the deobfuscated output.
    # Detection-only first; if an obfuscator is recognized, run the full
    # deobfuscation pass. Output:
    #   22-de4dot/detection.txt       (always, from `de4dot -d`)
    #   22-de4dot/deobfuscated/...    (if obfuscator detected)
    #   22-de4dot/de4dot.log          (tool log)
    local d4_outdir="${outdir}/22-de4dot"
    local d4_deobf="${d4_outdir}/deobfuscated"
    local d4_detected=0
    local d4_deobf_target=""
    local d4_unknown_obfuscator=0  # v3.0.8 (audit-12 D1)
    if [[ $SKIP_DE4DOT -eq 0 ]] && [[ -f "/opt/de4dot-cex/de4dot.exe" ]] && command -v mono >/dev/null 2>&1; then
        mkdir -p "$d4_outdir"
        # Detect obfuscator (-d: detect only, no deobfuscation). This is
        # fast (~1s per binary). We capture stdout+stderr and parse.
        {
            echo "=== de4dot -d (detect obfuscator) ==="
            timeout 60 mono /opt/de4dot-cex/de4dot.exe -d "$target" 2>&1 || true
        } > "${d4_outdir}/detection.txt"
        # Detection signal: any line of form "Detected X (...)". "Unknown
        # obfuscator" or empty means nothing detected.
        #
        # v3.7.2 (audit-30 A3): de4dot prints "Detected Unknown Obfuscator (...)"
        # when it CANNOT identify the protector. That line starts with
        # "Detected ", so the previous `^Detected ` test matched it and drove
        # the KNOWN-obfuscator branch (which then ran a full deobf as if a
        # protector were identified and typically produced nothing). The
        # dedicated "Unknown Obfuscator" generic-pass branch below was therefore
        # never reached. Require a "Detected " line that is NOT the unknown case
        # so the unknown path routes correctly to the generic pass.
        if grep -qE "^Detected " "${d4_outdir}/detection.txt" 2>/dev/null \
           && ! grep -qiE "^Detected (unknown obfuscator|unknown protection)" "${d4_outdir}/detection.txt" 2>/dev/null; then
            d4_detected=1
            log_step "de4dot: $(grep -E '^Detected ' "${d4_outdir}/detection.txt" | head -1)"
            mkdir -p "$d4_deobf"
            # Full deobfuscation. Flags:
            #   --preserve-tokens : keep metadata-table tokens for traceability
            #   --keep-types      : don't delete types the obfuscator added
            # These make the output easier to cross-reference with the
            # original; they trade a little cleanliness for analyzer value.
            run_tool "de4dot" "${d4_outdir}/de4dot.log" 600 \
                mono /opt/de4dot-cex/de4dot.exe \
                    --preserve-tokens \
                    --keep-types \
                    -f "$target" \
                    -o "${d4_deobf}/$(basename "$target")"
            if [[ -f "${d4_deobf}/$(basename "$target")" ]]; then
                d4_deobf_target="${d4_deobf}/$(basename "$target")"
                log_step "de4dot: deobfuscated -> ${d4_deobf_target}"
            else
                log_warn "de4dot: detected obfuscator but produced no output (see de4dot.log)"
            fi
        elif grep -qiE "unknown obfuscator|unknown protection" "${d4_outdir}/detection.txt" 2>/dev/null; then
            # v3.0.8 (audit-12 D1) - "Unknown Obfuscator" path.
            # Pre-v3.0.8 we skipped deobfuscation entirely on this path. But
            # de4dot's deobfuscation pass (-f without specific obfuscator)
            # still extracts useful assembly metadata: embedded resources,
            # method bodies that were lightly obfuscated by unrecognized
            # tools, string-decryption attempts. Even when de4dot can't
            # identify the protector, running the pass often produces a
            # deobfuscated assembly with cleaner method bodies and
            # extracted resource streams.
            d4_unknown_obfuscator=1
            log_step "de4dot: 'Unknown Obfuscator' detected; attempting generic deobfuscation pass"
            mkdir -p "$d4_deobf"
            run_tool "de4dot" "${d4_outdir}/de4dot.log" 600 \
                mono /opt/de4dot-cex/de4dot.exe \
                    --preserve-tokens \
                    --keep-types \
                    -f "$target" \
                    -o "${d4_deobf}/$(basename "$target")"
            if [[ -f "${d4_deobf}/$(basename "$target")" ]]; then
                d4_deobf_target="${d4_deobf}/$(basename "$target")"
                local _orig_size _deobf_size
                _orig_size=$(stat -c%s "$target" 2>/dev/null || echo 0)
                _deobf_size=$(stat -c%s "$d4_deobf_target" 2>/dev/null || echo 0)
                log_step "de4dot (Unknown Obfuscator pass): produced ${_deobf_size}-byte assembly from ${_orig_size}-byte original"
            else
                log_step "de4dot (Unknown Obfuscator pass): no usable output (this is normal for non-obfuscated or heavily-protected assemblies)"
            fi
        else
            log_step "de4dot: no obfuscation signal detected (this is fine for non-obfuscated assemblies)"
        fi
    fi

    # -------------------------------------------------------------------------
    # v2.5.0: Specialized .NET deobfuscators
    # -------------------------------------------------------------------------
    # de4dot is a generalist; specific obfuscators have purpose-built tools
    # that produce cleaner output. We trigger these conditionally based on
    # what de4dot detected (or, for opt-in tools, on a CLI flag). Each tool
    # writes to its own sub-dir under 24-deob/ so outputs don't collide.
    #
    # Selection logic (each is independent):
    #   - EazFixer   if "Eazfuscator" appears in de4dot detection output
    #   - OldRod     if "KoiVM"        or  "VMProtect"  appears in de4dot detection output
    #   - NoFuserEx  if USE_NOFUSEREX=1 (opt-in via --use-nofuserex)
    #
    # Each writes its deobfuscated assembly into 24-deob/<tool>/. The
    # downstream report stage will pick these up alongside de4dot's output.
    local deob_root="${outdir}/24-deob"
    local d4_det_text=""
    [[ -f "${d4_outdir}/detection.txt" ]] && d4_det_text=$(cat "${d4_outdir}/detection.txt" 2>/dev/null || true)

    # EazFixer - Eazfuscator-specific deobfuscator
    if [[ ${SKIP_EAZFIXER:-0} -eq 0 ]] \
        && [[ -f "/opt/EazFixer/EazFixer.exe" ]] \
        && command -v mono >/dev/null 2>&1 \
        && grep -qiE 'Eazfuscator' <<<"$d4_det_text"; then
        local ez_out="${deob_root}/eazfixer"
        mkdir -p "$ez_out"
        log_step "EazFixer: Eazfuscator detected by de4dot - running dedicated deobfuscator"
        # EazFixer writes <input>-eazfix.exe next to the input. We copy the
        # target into the output dir first so EazFixer's output lands there
        # rather than polluting the original target's directory.
        cp -f "$target" "${ez_out}/$(basename "$target")"
        run_tool "eazfixer" "${ez_out}/eazfixer.log" 600 \
            mono /opt/EazFixer/EazFixer.exe --file "${ez_out}/$(basename "$target")"
        # The output should be at <ez_out>/<basename>-eazfix.exe
        local ez_result="${ez_out}/$(basename "$target" .exe)-eazfix.exe"
        if [[ -f "$ez_result" ]]; then
            log_step "EazFixer: produced $(basename "$ez_result")"
        else
            log_warn "EazFixer: ran but produced no output (see eazfixer.log)"
        fi
    fi

    # OldRod - KoiVM/VMProtect.NET devirtualizer
    if [[ ${SKIP_OLDROD:-0} -eq 0 ]] \
        && [[ -f "/opt/OldRod/OldRod.exe" ]] \
        && command -v mono >/dev/null 2>&1 \
        && grep -qiE 'KoiVM|VMProtect' <<<"$d4_det_text"; then
        local or_out="${deob_root}/oldrod"
        mkdir -p "$or_out"
        log_step "OldRod: KoiVM/VMProtect detected by de4dot - running devirtualizer"
        # OldRod writes its devirtualized output next to the input. Same
        # copy-first pattern as EazFixer to keep outputs scoped.
        cp -f "$target" "${or_out}/$(basename "$target")"
        run_tool "oldrod" "${or_out}/oldrod.log" 600 \
            mono /opt/OldRod/OldRod.exe \
                "${or_out}/$(basename "$target")" \
                --dont-crash --no-errors --no-output-corruption \
                -v --log-file --rename-symbols
    fi

    # NoFuserEx - opt-in ConfuserEx deobfuscator (alternative to de4dot)
    # Default OFF: de4dot already handles ConfuserEx well in most cases.
    # Enable via USE_NOFUSEREX=1 from the driver (--use-nofuserex flag).
    if [[ ${USE_NOFUSEREX:-0} -eq 1 ]] \
        && [[ -f "/opt/NoFuserEx/NoFuserEx.exe" ]] \
        && command -v mono >/dev/null 2>&1; then
        local nf_out="${deob_root}/nofuserex"
        mkdir -p "$nf_out"
        log_step "NoFuserEx: running (opt-in via --use-nofuserex)"
        cp -f "$target" "${nf_out}/$(basename "$target")"
        run_tool "nofuserex" "${nf_out}/nofuserex.log" 600 \
            mono /opt/NoFuserEx/NoFuserEx.exe "${nf_out}/$(basename "$target")"
    fi

    # ilspycmd block follows - unchanged from v2.4.0
    # =========================================================================

    # ilspycmd -- full C# decompilation into a compilable project layout.
    # The `-p` flag is essential: without it, ilspycmd emits a single
    # bundled .cs file (or, depending on version, nothing to the output
    # dir and only stdout). With `-p` we get a .csproj plus one .cs file
    # per type organized by namespace -- which is what we want for
    # follow-on analysis. `-o` is required when using `-p`.
    if [[ -n "$ILSPYCMD" ]]; then
        mkdir -p "${dn}/ilspy"
        # v3.0.10 (audit-14 A4) - --disable-updatecheck suppresses the
        # "You are not using the latest version of the tool, please
        # update. Latest version is '10.0.1.8346'" warning that ilspycmd
        # 9.0.0.7847 (the version pinned by installer LAYER 2) emits on
        # every run. The warning is benign (per ILSpy issue #3101 the
        # tool functions correctly with or without the latest version),
        # but it clutters the per-binary log and worried the operator
        # that decompilation might be failing. Per ilspycmd nuget docs,
        # --disable-updatecheck is intended exactly for "tight loop or
        # fully automated scenarios" like ours.
        run_tool "ilspycmd" "${dn}/ilspycmd.log" "$TOOL_TIMEOUT" \
            "$ILSPYCMD" --disable-updatecheck -p -o "${dn}/ilspy" "$target"
        # Append an output-file manifest to the log. ilspycmd is quiet
        # on stdout when things go well, so an empty log after the header
        # doesn't actually tell us whether it worked. Listing the .cs /
        # .csproj it produced removes that ambiguity in both directions.
        {
            echo ""
            echo "=== Output-file manifest (post-run) ==="
            if [[ -d "${dn}/ilspy" ]]; then
                find "${dn}/ilspy" -maxdepth 6 -type f \
                    \( -name '*.cs' -o -name '*.csproj' -o -name '*.sln' \) \
                    2>/dev/null | sort
                echo ""
                echo "  .cs     files: $(find "${dn}/ilspy" -name '*.cs' 2>/dev/null | wc -l)"
                echo "  .csproj files: $(find "${dn}/ilspy" -name '*.csproj' 2>/dev/null | wc -l)"
                echo "  Total size:    $(du -sh "${dn}/ilspy" 2>/dev/null | cut -f1)"
            else
                echo "  (output directory does not exist)"
            fi
        } >> "${dn}/ilspycmd.log"

        local cs_count csproj_count
        cs_count=$(find "${dn}/ilspy" -name '*.cs' 2>/dev/null | wc -l)
        csproj_count=$(find "${dn}/ilspy" -name '*.csproj' 2>/dev/null | wc -l)
        if [[ $cs_count -gt 0 ]]; then
            log_step "ilspycmd produced $cs_count .cs files + $csproj_count .csproj"
        else
            log_warn "ilspycmd produced 0 .cs files -- decompilation failed"
            log_warn "   tail -40 ${dn}/ilspycmd.log for the error"
            {
                echo ""
                echo "=== ilspycmd FAILED (no .cs output) ==="
                echo "Check that dotnet --version works and the target is a managed assembly."
            } >> "${dn}/ilspycmd.log"
        fi

        # v2.3.0: second ilspy pass on de4dot-deobfuscated output. Per user
        # direction: only re-run ilspy (not the full pipeline) on the cleaned
        # assembly. Output goes into 22-de4dot/deobfuscated-ilspy/.
        if [[ -n "$d4_deobf_target" && -f "$d4_deobf_target" ]]; then
            local d4_ilspy="${d4_outdir}/deobfuscated-ilspy"
            mkdir -p "$d4_ilspy"
            # v3.0.10 (audit-14 A4) - same --disable-updatecheck on the
            # second pass over de4dot-deobfuscated output.
            run_tool "ilspycmd-deobf" "${d4_outdir}/ilspycmd-deobf.log" "$TOOL_TIMEOUT" \
                "$ILSPYCMD" --disable-updatecheck -p -o "$d4_ilspy" "$d4_deobf_target"
            local d4_cs
            d4_cs=$(find "$d4_ilspy" -name '*.cs' 2>/dev/null | wc -l)
            if [[ $d4_cs -gt 0 ]]; then
                log_step "ilspycmd (deobfuscated): $d4_cs .cs files - ${d4_ilspy}"
            else
                log_warn "ilspycmd (deobfuscated): 0 .cs produced"
            fi
        fi
    fi

    # -------------------------------------------------------------------------
    # v2.5.0: dnSpyEx Console - third C# decompiler perspective
    # -------------------------------------------------------------------------
    # dnSpyEx is a maintained fork of the original dnSpy project. The Console
    # variant decompiles to a project layout similar to ilspycmd but uses a
    # different decompiler engine, so disagreements between ilspycmd and
    # dnSpyEx output can flag obfuscation that fooled one but not the other.
    #
    # Decompile the original target. If de4dot produced a deobfuscated
    # assembly, also decompile that. Both go under 26-dnspyex/.
    #
    # v3.0.7 (audit-11 A1) - CRITICAL FIX. Pre-v3.0.7 invocation passed only
    # `-o DIR -l "C#"` which is INSUFFICIENT for dnSpy.Console.
    #
    # v3.0.8 (audit-12 B1) - SECOND CRITICAL FIX. Per dnSpy.Console source
    # (Program.cs), project-layout output requires BOTH:
    #     if (createSlnFile && !string.IsNullOrEmpty(slnName)) {
    #         // write project files to output dir
    #     }
    # createSlnFile is set when --project-guid is passed. slnName is set
    # only when --sln-name NAME is passed. v3.0.7 added --project-guid
    # but did NOT add --sln-name, so the conditional was still false
    # (slnName empty) and dnSpy continued falling through to "write to
    # stdout" behavior. Operator's v3.0.7 install run confirmed dnSpyEx
    # still produced 0 .cs.
    #
    # Both flags are now passed:
    #   --project-guid GUID    (sets createSlnFile=true)
    #   --sln-name NAME        (sets slnName=NAME, satisfies !IsNullOrEmpty)
    #
    # v3.0.10 (audit-14 B1) - dnSpyEx CRITICAL fix attempt #1.
    # v3.0.12 (audit-16 F1) - dnSpyEx fix attempt #2.
    # v3.0.13 (audit-17 C2) - dnSpyEx fix attempt #3 (the right one).
    #
    # History of failed attempts and the reasoning behind audit-17:
    #
    #   audit-13 (v3.0.9): mono + dnSpy-net-win64.zip
    #     -> "not a valid CIL image" - net-win64.zip is .NET 6, mono
    #        only handles .NET Framework 4.x CIL images.
    #
    #   audit-14 (v3.0.10): dotnet + dnSpy-net-win64.zip
    #     -> "libhostpolicy.so missing", "Failed to run as a self-
    #        contained app" - dotnet on Linux can't load Windows-
    #        targeted .NET 6 binaries without runtimeconfig.json +
    #        libhostpolicy.so which the win64 zip doesn't ship.
    #
    #   audit-16 (v3.0.12): wine + dnSpy-net-win64.zip
    #     -> "wine: failed to open .../syswow64/rundll32.exe: c0000135"
    #        Modern wine 9.x experimental WoW64 mode requires explicit
    #        prefix init + winetricks dotnet6 install. Too fragile for
    #        scripted pipeline.
    #
    #   audit-17 (v3.0.13): mono + dnSpy-netframework.zip [THIS]
    #     -> dnSpy-netframework.zip is .NET Framework 4.8 64-bit. mono
    #        on Linux runs .NET Framework 4.8 CIL images natively
    #        without wine prefix or .NET runtime install. This is the
    #        historically-working path that RE-Toolkit had pre-audit-14
    #        BEFORE switching to the .NET 6 zip variant.
    #
    # The decompilation engine (ICSharpCode.Decompiler) is identical
    # across all dnSpyEx zip variants; we lose nothing for our scripted
    # pipeline by using the .NET Framework variant.
    #
    # Lessons L51 (verify CLI flags by source) and L53 (conditional
    # source-flag pairs) still apply. L60 (run smoke-tests) would have
    # caught audit-14, audit-16 attempts had we run a single
    # `mono dnSpy.Console.exe --help` once with each zip variant.
    if [[ ${SKIP_DNSPY_EX:-0} -eq 0 ]] \
        && [[ -f "/opt/dnSpyEx/dnSpy.Console.exe" ]] \
        && command -v mono >/dev/null 2>&1; then
        local dn_root="${outdir}/26-dnspyex"
        mkdir -p "$dn_root/original"
        # GUID format requires 8-4-4-4-12 hex digits. Using a fixed seed;
        # dnSpy auto-increments the last segment per module.
        local DNSPY_GUID="00000000-0000-0000-0000-000000000001"
        local DNSPY_SLN="decompiled.sln"
        run_tool "dnspyex" "${dn_root}/dnspyex.log" "${TOOL_TIMEOUT:-600}" \
            mono /opt/dnSpyEx/dnSpy.Console.exe \
                "$target" \
                -o "${dn_root}/original" \
                --project-guid "$DNSPY_GUID" \
                --sln-name "$DNSPY_SLN" \
                -l "C#"
        local dn_cs
        dn_cs=$(find "${dn_root}/original" -name '*.cs' 2>/dev/null | wc -l)
        if [[ $dn_cs -gt 0 ]]; then
            log_step "dnSpyEx (original): $dn_cs .cs files"
        else
            # v3.0.8 (audit-12 B2) - capture diagnostic when 0 .cs.
            # When dnSpy emits decompiled output to stdout (which run_tool
            # captured to .log) instead of files, the .log will contain
            # the actual C# source text. Surface a short tail so operators
            # can see what dnSpy was producing instead of files.
            log_warn "dnSpyEx (original): 0 .cs produced (see dnspyex.log)"
            local _log_path="${dn_root}/dnspyex.log"
            if [[ -f "$_log_path" ]]; then
                local _log_size
                _log_size=$(wc -c < "$_log_path" 2>/dev/null || echo 0)
                if [[ $_log_size -gt 200 ]]; then
                    log_warn "   (dnspyex.log is ${_log_size} bytes; if it"
                    log_warn "   contains C# text, dnSpy emitted to stdout"
                    log_warn "   instead of files - check --sln-name + "
                    log_warn "   --project-guid invocation)"
                fi
            fi
        fi

        # Run against deobfuscated output if available
        if [[ -n "$d4_deobf_target" && -f "$d4_deobf_target" ]]; then
            mkdir -p "${dn_root}/deobfuscated"
            # v3.0.13 (audit-17 C2) - same wine -> mono switch on the
            # second pass over de4dot-deobfuscated output.
            run_tool "dnspyex-deobf" "${dn_root}/dnspyex-deobf.log" "${TOOL_TIMEOUT:-600}" \
                mono /opt/dnSpyEx/dnSpy.Console.exe \
                    "$d4_deobf_target" \
                    -o "${dn_root}/deobfuscated" \
                    --project-guid "$DNSPY_GUID" \
                    --sln-name "$DNSPY_SLN" \
                    -l "C#"
            local dn_d4_cs
            dn_d4_cs=$(find "${dn_root}/deobfuscated" -name '*.cs' 2>/dev/null | wc -l)
            if [[ $dn_d4_cs -gt 0 ]]; then
                log_step "dnSpyEx (deobfuscated): $dn_d4_cs .cs files"
            fi
        fi
        # v3.0.13 (audit-17 C2): no wine prefix cleanup needed since
        # we reverted to mono. mono runs the .NET Framework 4.8 CIL
        # image directly without any per-invocation state.
    fi

    # monodis
    if command -v monodis >/dev/null 2>&1; then
        run_tool "monodis" "${dn}/monodis.il" "$TOOL_TIMEOUT" \
            monodis "$target"
    fi

    # ikdasm
    if command -v ikdasm >/dev/null 2>&1; then
        run_tool "ikdasm" "${dn}/ikdasm.il" "$TOOL_TIMEOUT" \
            ikdasm "$target"
    fi

    # dnfile
    #
    # v3.7.2 (audit-30 B3): dnfile emits WARNING-level log records like
    # "invalid compressed int: leading byte: 0xfd" when it meets a malformed
    # compressed integer (common in the #US user-strings / #Blob heaps of some
    # assemblies). These are non-fatal -- the metadata root, streams, tables,
    # typedefs and assembly refs all still parse -- but the previous invocation
    # merged stderr into the metadata file with 2>&1, so the warnings floated to
    # the top and made a successful parse look like a failure. Fix: silence
    # dnfile's WARNING logging inside the script AND send stderr to a separate
    # dnfile.log, so dnfile-metadata.txt contains only clean metadata.
    if [[ -n "$VENV_PY" ]]; then
        "$VENV_PY" - "$target" > "${dn}/dnfile-metadata.txt" 2> "${dn}/dnfile.log" <<'PYEOF' || true
import sys, logging
# Suppress dnfile's non-fatal compressed-int / heap warnings (they are noise in
# the metadata output; a separate dnfile.log still captures stderr for debugging).
logging.disable(logging.WARNING)
try:
    import dnfile
except ImportError:
    print("dnfile not available"); sys.exit(0)

f = dnfile.dnPE(sys.argv[1])
f.parse_data_directories()

print("=== .NET Metadata Root ===")
print("Version:  %s" % f.net.metadata.struct.Version.rstrip(b'\x00').decode(errors='replace'))
print("Streams:  %d" % f.net.metadata.struct.NumberOfStreams)

print("\n=== Streams ===")
for sh in f.net.metadata.streams_list:
    print("  %-12s offset=0x%-8x size=%d" % (sh.struct.Name.decode(errors='replace'), sh.struct.Offset, sh.struct.Size))

print("\n=== Tables ===")
if hasattr(f.net, 'mdtables'):
    for table_name, table in sorted(vars(f.net.mdtables).items()):
        if table_name.startswith('_'): continue
        try:
            rows = len(table.rows) if table and hasattr(table, 'rows') else 0
        except Exception:
            rows = 0
        if rows > 0:
            print("  %-24s %5d rows" % (table_name, rows))

print("\n=== TypeDefs (first 50) ===")
try:
    for i, td in enumerate(f.net.mdtables.TypeDef.rows[:50]):
        ns = td.TypeNamespace.value if hasattr(td, 'TypeNamespace') else ""
        nm = td.TypeName.value if hasattr(td, 'TypeName') else ""
        print("  %4d  %s.%s" % (i + 1, ns, nm))
except Exception as e:
    print("  (unavailable: %s)" % e)

print("\n=== AssemblyRefs ===")
try:
    for ar in f.net.mdtables.AssemblyRef.rows:
        nm = ar.Name.value if hasattr(ar, 'Name') else ""
        ver = "%d.%d.%d.%d" % (ar.MajorVersion, ar.MinorVersion, ar.BuildNumber, ar.RevisionNumber)
        print("  %s  %s" % (ver, nm))
except Exception:
    pass

print("\n=== User Strings (#US, first 100) ===")
try:
    us_stream = f.net.user_strings
    for i, s in enumerate(us_stream.get_us_strings() if hasattr(us_stream, 'get_us_strings') else []):
        if i >= 100: break
        print("  %r" % s)
except Exception:
    pass
PYEOF
        log_step "dnfile metadata: $(wc -l < "${dn}/dnfile-metadata.txt" 2>/dev/null || echo 0) lines"
    fi
}
