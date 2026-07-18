#!/usr/bin/env bash
# =============================================================================
# lib/dispatch.sh
# =============================================================================
#
# Synopsis:
#     Master per-binary pipeline dispatcher.
#
# Description:
#     Owns analyze_one(), which drives a single target end to end: it detects
#     the file type, selects the matching branch, and invokes each stage
#     function in the correct runtime order.
#
#     STAGE NUMBERING VERSUS EXECUTION ORDER
#
#     Stage filename numbers reflect OUTPUT-DIRECTORY ordering, not execution
#     order. Summary (85), visualization (89), and report (90) carry lower
#     numbers than the dynamic stages (92 through 98), but at runtime they
#     execute after them, because each consumes upstream results:
#
#         - stage_summary needs all upstream data, static and dynamic, before
#           it can compute the verdict and write _summary.json
#         - stage_viz reads _summary.json and renders the visualization SVGs,
#           so it must follow stage_summary
#         - stage_report renders the composite _report.html from both
#           _summary.json and the viz outputs, so it must run last
#
#     The resulting execution order in every per-type branch is:
#
#         1. Universal triage (always first; feeds type detection)
#         2. Type-specific static stages (PE, ELF, Mach-O, .NET, DEX, others)
#         3. Cross-cutting static stages (LIEF, Ghidra, r2, rizin, LLVM,
#            capa, IOC extraction)
#         4. Dynamic stages, Tier 1 through Tier 4, in number order, subject
#            to auto-tier gating
#         5. stage_summary   (consumes all upstream data)
#         6. stage_viz       (consumes _summary.json)
#         7. stage_report    (consumes _summary.json plus viz outputs)
#
#     Filenames preserve output-directory ordering so a listing of the output
#     tree reads logically: triage first, tool outputs in the middle, and the
#     summary, visualization, and report artifacts grouped where an analyst
#     looks first.
#
#     This separation of numbering from execution order is deliberate but not
#     obvious: a run log shows stages 85, 89, and 90 executing after stages 92
#     through 98, which can read as a misordering bug. It is correct behavior.
#
#     Sourced by analyze-binaries.sh; not directly executable.
#
# Provides:
#     analyze_one <target> <outdir>
#
# Notes:
#     The full routing matrix is documented in the wiki
#     (Architecture-and-Design). Release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

analyze_one() {
    local target="$1" idx="$2" total="$3"
    local fname
    fname=$(basename "$target")
    # v3.0.5 (audit-9 A6): if PRESERVE_TREE is set, mirror the input
    # directory layout under OUTPUT_ROOT so output is organized by
    # source-tree directory. Default flat layout (single subdir per
    # target file) preserves backward compat with v2.x and v3.0.x.
    #
    # The mapping uses TARGET_TREE_ROOT (set by the driver to a common
    # ancestor of all targets when --preserve-tree is on) and computes
    # the relative path from that root. If no common ancestor exists
    # (e.g., absolute paths from different filesystems), fall back to
    # the flat layout.
    local outdir
    if [[ "${PRESERVE_TREE:-0}" -eq 1 && -n "${TARGET_TREE_ROOT:-}" ]]; then
        local rel_dir
        rel_dir=$(dirname "$target")
        # Strip the common ancestor prefix; result is the relative
        # directory path under the input tree.
        if [[ "$rel_dir" == "$TARGET_TREE_ROOT" ]]; then
            outdir="${OUTPUT_ROOT}/${fname}"
        elif [[ "$rel_dir" == "$TARGET_TREE_ROOT"/* ]]; then
            local relpath="${rel_dir#$TARGET_TREE_ROOT/}"
            outdir="${OUTPUT_ROOT}/${relpath}/${fname}"
        else
            # Target outside the common ancestor; fall back to flat.
            outdir="${OUTPUT_ROOT}/${fname}"
        fi
    else
        outdir="${OUTPUT_ROOT}/${fname}"
    fi

    printf "\n%s[%d/%d] %s%s\n" "$C_BOLD" "$idx" "$total" "$fname" "$C_OFF"

    if [[ -d "$outdir" && $OVERWRITE -eq 0 ]]; then
        if [[ -f "${outdir}/00-triage/hashes.txt" ]]; then
            log_step "already analyzed (pass --overwrite to redo)"
            return 0
        fi
    fi

    [[ $OVERWRITE -eq 1 ]] && rm -rf "$outdir"
    mkdir -p "$outdir"

    # v3.1.0 (audit-22 A0.1) -- Input sandboxing.
    # Copy the operator's input into ${outdir}/_input/ and reassign $target
    # to the copy. Every stage_* call below receives the sandboxed path, so
    # no tool can mutate the operator's original file. This closes the L63
    # vulnerability class generically (the audit-20 TrID -ae bug that renamed
    # the operator's input). $target_original preserves the true source path
    # for reporting; $fname and $outdir were already computed from the
    # original above, so naming is unaffected.
    #
    # If sandboxing fails, we FAIL LOUD for this target and skip it. We do
    # NOT fall back to analyzing the original in place -- that would
    # reintroduce the exact vulnerability this exists to close (L28: no
    # unsafe shortcuts).
    local target_original="$target"
    local sandboxed
    if sandboxed=$(prepare_sandboxed_target "$target" "$outdir"); then
        target="$sandboxed"
        export TARGET_ORIGINAL_PATH="$target_original"
    else
        log_err "sandboxing failed for $fname; skipping this target to protect operator input"
        return 1
    fi

    # v3.3.0 (audit-24 A0.4): per-target status ledger. run_tool / run_shell
    # append one JSONL record per invocation to this path. Exported so all
    # stages' tool calls land in the same ledger. Cleared at start so
    # --overwrite runs don't accumulate stale records.
    export TARGET_LEDGER="${outdir}/_ledger.jsonl"
    : > "$TARGET_LEDGER" 2>/dev/null || true

    local type
    type=$(detect_type "$target")
    log_info "Detected type: $type"
    echo "$fname|$type" >> "${OUTPUT_ROOT}/_run-manifest.txt"

    log_info "Stage 00 - Universal triage"
    stage_triage "$target" "$outdir"

    log_info "Stage 12 - LIEF exhaustive dump"
    stage_lief "$target" "$outdir"
    log_info "Stage 18 - bulk_extractor (raw PII/IOC scan)"
    stage_bulk "$target" "$outdir"

    case "$type" in
        pe-native)
            log_info "Stage 10 - PE (native) analysis"
            stage_pe "$target" "$outdir"
            log_info "Stage 14 - pev suite (pedis, pehash, pescan, pesec, pestr)"
            stage_pev "$target" "$outdir"
            log_info "Stage 16 - Manalyze (heuristic PE analyzer)"
            stage_manalyze "$target" "$outdir"
            log_info "Stage 17 - peframe (behavioral PE static analyzer)"
            stage_peframe "$target" "$outdir"
            log_info "Stage 30 - Ghidra comprehensive analysis"
            stage_ghidra "$target" "$outdir" full
            if [[ ${ENABLE_CWE_CHECKER:-0} -eq 1 ]]; then
                log_info "Stage 34 - cwe_checker (opt-in CWE static detection)"
                stage_cwe "$target" "$outdir"
            fi
            log_info "Stage 40 - GNU objdump deep"
            stage_objdump_deep "$target" "$outdir"
            log_info "Stage 40 - radare2 deep analysis"
            stage_r2_deep "$target" "$outdir"
            log_info "Stage 42 - rizin deep analysis"
            stage_rizin_deep "$target" "$outdir"
            log_info "Stage 44 - llvm-objdump"
            stage_llvm_objdump "$target" "$outdir"
            # v3.0.2 (audit-6): RetDec opt-in decompilation (PE native)
            if [[ -x /opt/retdec/decompile.sh ]]; then
                log_info "Stage 26 - RetDec decompilation (opt-in via --with-retdec)"
                stage_retdec "$target" "$outdir"
            fi
            ;;
        pe-dotnet)
            log_info "Stage 10 - PE structure"
            stage_pe "$target" "$outdir"
            log_info "Stage 14 - pev suite"
            stage_pev "$target" "$outdir"
            log_info "Stage 16 - Manalyze (heuristic PE analyzer)"
            stage_manalyze "$target" "$outdir"
            log_info "Stage 17 - peframe (behavioral PE static analyzer)"
            stage_peframe "$target" "$outdir"
            log_info "Stage 20 - .NET decompilation chain"
            log_info "          (ilspycmd + de4dot-cex + EazFixer + OldRod + dnSpyEx + monodis + dnfile)"
            stage_dotnet "$target" "$outdir"
            if [[ $SKIP_GHIDRA_DOTNET -eq 0 ]]; then
                log_info "Stage 30 - Ghidra (native stub + CLR header, LIGHT mode)"
                stage_ghidra "$target" "$outdir" light
            else
                log_info "Stage 30 - Ghidra skipped (.NET, --no-ghidra-dotnet)"
            fi
            # v3.0.7 (audit-11 B1) - Run native disassemblers on .NET PE shell.
            # Pre-v3.0.7 the pe-dotnet dispatch path skipped objdump/r2/rizin/
            # llvm-objdump entirely. Operator could not tell whether tools
            # were skipped intentionally or had failed; the per-binary report
            # showed empty/missing folders for these tools.
            #
            # Native disassemblers DO produce useful output on managed PE:
            #  - PE header / sections / imports (the standard PE structure)
            #  - The native CLR loader stub (the "_CorExeMain" / "_CorDllMain"
            #    bootstrap that hands control to the CLR runtime)
            #  - Resources, version info, manifests embedded in the PE
            # The managed CIL bytecode is in the .text section but appears
            # as raw data to native tools - that's expected. The CIL
            # decompilation lives in stage 20 (.NET Decompilation tab).
            #
            # Running these stages provides cross-verification for the PE
            # shell and ensures the per-binary report shows complete
            # tool coverage instead of empty folders.
            log_info "Stage 40 - GNU objdump deep (PE shell + native stub)"
            stage_objdump_deep "$target" "$outdir"
            log_info "Stage 40 - radare2 deep analysis (PE shell + native stub)"
            stage_r2_deep "$target" "$outdir"
            log_info "Stage 42 - rizin deep analysis (PE shell + native stub)"
            stage_rizin_deep "$target" "$outdir"
            log_info "Stage 44 - llvm-objdump (PE shell + native stub)"
            stage_llvm_objdump "$target" "$outdir"
            ;;
        elf)
            log_info "Stage 50 - ELF structure (readelf, nm, checksec, scanelf, dumpelf, pahole, bloaty)"
            stage_elf "$target" "$outdir"
            log_info "Stage 30 - Ghidra comprehensive analysis"
            stage_ghidra "$target" "$outdir" full
            if [[ ${ENABLE_CWE_CHECKER:-0} -eq 1 ]]; then
                log_info "Stage 34 - cwe_checker (opt-in CWE static detection)"
                stage_cwe "$target" "$outdir"
            fi
            log_info "Stage 40 - GNU objdump deep"
            stage_objdump_deep "$target" "$outdir"
            log_info "Stage 40 - radare2 deep analysis"
            stage_r2_deep "$target" "$outdir"
            log_info "Stage 42 - rizin deep analysis"
            stage_rizin_deep "$target" "$outdir"
            log_info "Stage 44 - llvm-objdump"
            stage_llvm_objdump "$target" "$outdir"
            # v3.0.2 (audit-6): pwntools ROP gadget enumeration
            log_info "Stage 46 - ROP gadgets via pwntools"
            stage_rop_gadgets "$target" "$outdir"
            # v3.0.2 (audit-6): RetDec opt-in decompilation
            if [[ -x /opt/retdec/decompile.sh ]]; then
                log_info "Stage 26 - RetDec decompilation (opt-in via --with-retdec)"
                stage_retdec "$target" "$outdir"
            fi
            ;;
        # v2.6.0: Mach-O dispatch
        macho)
            log_info "Stage 52 - Mach-O structural analysis"
            stage_macho "$target" "$outdir"
            log_info "Stage 30 - Ghidra comprehensive analysis (Mach-O)"
            stage_ghidra "$target" "$outdir" full
            log_info "Stage 40 - GNU objdump deep (with --target=mach-o)"
            stage_objdump_deep "$target" "$outdir"
            log_info "Stage 40 - radare2 deep analysis"
            stage_r2_deep "$target" "$outdir"
            log_info "Stage 42 - rizin deep analysis"
            stage_rizin_deep "$target" "$outdir"
            # v3.0.2 (audit-6): RetDec opt-in decompilation (Mach-O native)
            if [[ -x /opt/retdec/decompile.sh ]]; then
                log_info "Stage 26 - RetDec decompilation (opt-in via --with-retdec)"
                stage_retdec "$target" "$outdir"
            fi
            ;;
        # v2.6.0: WebAssembly dispatch
        wasm)
            log_info "Stage 54 - WebAssembly module analysis"
            stage_wasm "$target" "$outdir"
            ;;
        # v2.6.0: Python bytecode dispatch
        pyc)
            log_info "Stage 56 - Python bytecode analysis"
            stage_pyc "$target" "$outdir"
            ;;
        # v2.6.0: Java JAR/WAR/EAR dispatch
        jar)
            log_info "Stage 58 - JAR/WAR/EAR analysis (CFR + procyon + javap)"
            stage_jar "$target" "$outdir"
            ;;
        # v2.6.0: PDF dispatch
        pdf)
            log_info "Stage 62 - PDF document analysis"
            stage_pdf "$target" "$outdir"
            ;;
        # v2.6.0: OLE / OOXML Office document dispatch
        ole)
            log_info "Stage 64 - OLE / OOXML Office document analysis"
            stage_ole "$target" "$outdir"
            ;;
        # v2.8.0: Android APK container dispatch
        apk)
            log_info "Stage 72 - APK container extraction (apktool)"
            stage_apk "$target" "$outdir"
            log_info "Stage 76 - AndroidManifest.xml decode + permission analysis"
            # Prefer apktool's already-decoded manifest if present, else
            # pass the raw .apk for aapt2 fallback decoding
            local axml_input="$target"
            if [[ -f "${outdir}/72-apk-extracted/AndroidManifest.xml" ]]; then
                axml_input="${outdir}/72-apk-extracted/AndroidManifest.xml"
            fi
            stage_axml "$axml_input" "$outdir"
            log_info "Stage 78 - APK signature verification (apksigner)"
            stage_apksig "$target" "$outdir"
            # Recurse: each classes*.dex extracted by stage_apk gets stage_dex
            if [[ -f "${outdir}/72-apk/dispatch-manifest.txt" && ${SKIP_DEX:-0} -eq 0 ]]; then
                local dex_idx=0
                while IFS= read -r line; do
                    [[ "$line" == dex* ]] || continue
                    local dex_path="${line#dex }"
                    [[ -f "$dex_path" ]] || continue
                    dex_idx=$((dex_idx + 1))
                    local dex_outdir="${outdir}/74-dex-${dex_idx}"
                    log_info "Stage 74 - DEX decompilation (jadx + baksmali + dex2jar) [$dex_idx]"
                    OUTDIR_OVERRIDE="$dex_outdir" stage_dex "$dex_path" "${outdir}"
                    # stage_dex by default writes to <outdir>/74-dex; for
                    # multi-DEX APKs we move it to a numbered dir
                    if [[ -d "${outdir}/74-dex" && $dex_idx -gt 1 ]]; then
                        mv "${outdir}/74-dex" "$dex_outdir"
                    fi
                done < "${outdir}/72-apk/dispatch-manifest.txt"
            fi
            # Recurse: largest .so per ABI under lib/<abi>/ gets stage_elf
            if [[ -f "${outdir}/72-apk/dispatch-manifest.txt" ]]; then
                local elf_idx=0
                while IFS= read -r line; do
                    [[ "$line" == elf* ]] || continue
                    local so_path="${line#elf }"
                    [[ -f "$so_path" ]] || continue
                    elf_idx=$((elf_idx + 1))
                    local abi=$(basename "$(dirname "$so_path")")
                    log_info "Stage 50 - ELF analysis on native lib (lib/$abi/$(basename "$so_path"))"
                    # Per-ABI subdir to avoid clobbering ELF outputs across ABIs
                    local elf_subout="${outdir}/50-elf-native-${abi}"
                    mkdir -p "$elf_subout"
                    # Run stage_elf in a subshell with redirected output dir
                    (
                        # Save and redirect; stage_elf writes to <outdir>/50-elf
                        local _orig_out="$outdir"
                        outdir="$elf_subout"
                        stage_elf "$so_path" "$outdir"
                    )
                done < "${outdir}/72-apk/dispatch-manifest.txt"
            fi
            ;;
        # v2.8.0: standalone DEX dispatch (no enclosing APK)
        dex)
            log_info "Stage 74 - DEX decompilation (jadx + baksmali + dex2jar)"
            stage_dex "$target" "$outdir"
            ;;
        upx-packed)
            log_info "Stage 70 - UPX unpack + rerun on unpacked"
            stage_upx "$target" "$outdir"
            ;;
        config-xml)
            log_info "Stage 60 - Config/XML inspection"
            stage_config "$target" "$outdir"
            ;;
        unknown)
            log_warn "Unknown binary type - only triage will run"
            ;;
    esac

    # v2.2.0 post-processing stages - always run regardless of detected type
    log_info "Stage 80 - IOC extraction"
    stage_iocs "$target" "$outdir"
    # v2.7.0 cross-cutting capability stages
    log_info "Stage 81 - Fuzzy hashing (ssdeep + TLSH)"
    stage_fuzzyhash "$target" "$outdir"
    log_info "Stage 82 - Crypto key & secret extraction"
    stage_cryptokeys "$target" "$outdir"
    log_info "Stage 83 - Authenticode chain validation (PE only)"
    stage_authenticode "$target" "$outdir"

    # v3.3.0 (audit-24 A4.1): finding-driven deepening.
    # When earlier stages produced a DERIVED artifact that may expose signal
    # hidden in the original, re-run the relevant extractors on the derivative.
    #
    # Phase 1 (this release): .NET deobfuscated-assembly re-analysis.
    # If stage_dotnet's de4dot pass produced a deobfuscated assembly at
    # ${outdir}/22-de4dot/deobfuscated/<basename>, obfuscation may have hidden
    # IOCs (C2 URLs, IPs) and crypto material behind string encryption. We
    # re-run IOC + crypto-key extraction on the CLEANED assembly, writing to a
    # _deepened/ subdir so results never collide with the primary run. The
    # report + summary can surface the delta (new IOCs found only after
    # deobfuscation).
    #
    # This is SAFE because of A0.1 sandboxing: the deobfuscated file is a
    # derivative under <outdir>/, never the operator's original. The pass runs
    # ONCE (not recursively; recursive payload analysis is a separate future
    # item A4.2). The A0.4 ledger records the deepening invocations.
    #
    # Phase 2 branches (packer non-UPX re-analysis, carved-overlay recursion,
    # network-import IOC deepening with defang/refang) are documented in
    # deferred to a later release; see CHANGELOG.md.
    local deobf_assembly="${outdir}/22-de4dot/deobfuscated/${fname}"
    if [[ -f "$deobf_assembly" ]]; then
        local deepen_dir="${outdir}/_deepened"
        log_info "Stage 80/82 (deepened) - re-analyzing de4dot-deobfuscated assembly"
        log_step "deepening: cleaned assembly may expose IOCs/keys hidden by obfuscation"
        mkdir -p "$deepen_dir"
        # Record what we're deepening + why, for the report and for diagnosis.
        {
            echo "source_original=${TARGET_ORIGINAL_PATH:-$target}"
            echo "deepened_artifact=${deobf_assembly}"
            echo "reason=de4dot deobfuscated assembly; re-running IOC + crypto-key extraction"
            echo "stages=80-iocs,82-cryptokeys"
        } > "${deepen_dir}/_deepening-manifest.txt"
        stage_iocs "$deobf_assembly" "$deepen_dir"
        stage_cryptokeys "$deobf_assembly" "$deepen_dir"
        log_step "deepening: complete -> ${deepen_dir}/ (see 80-iocs, 82-cryptokeys)"
    fi

    if [[ ${ENABLE_ANGR:-0} -eq 1 ]]; then
        log_info "Stage 86 - angr CFGFast (opt-in symbolic execution)"
        stage_angr "$target" "$outdir"
    fi
    # v3.0.0: dynamic analysis stages. Each stage internally checks DYNAMIC=1
    # and tier-specific gating. All write _dynamic.json with uniform schema;
    # stage_dynamic_trace aggregates them into 98-dynamic-trace/aggregated.json
    # which stage_summary reads.
    #
    # v3.0.9 (audit-13 A1) - AUTO-TIER architectural overhaul. Pre-v3.0.9 each
    # tier skipped itself unless DYNAMIC_MODE matched its name exactly. With
    # `--dynamic` alone (default DYNAMIC_MODE=qiling), only qiling ran. qiling
    # fails on ~80% of real-world Windows PE with SIGILL, and the qiling
    # Windows rootfs is empty per Microsoft EULA (DLLs not bundled). Result:
    # operator's `--dynamic` runs produced 0 syscalls / 0 API calls / 0
    # network across "various dynamic options" tested.
    #
    # The fix is auto-tier: when DYNAMIC_AUTO=1 (set by driver when --dynamic
    # is passed without explicit --dynamic-mode), run ALL applicable tiers
    # in order, capturing output from whichever ones succeed. Each tier
    # internally still respects its hard prerequisites (firejail = ELF only,
    # docker = container image present, etc); auto-tier just removes the
    # "DYNAMIC_MODE != my name" gate so multiple tiers can run.
    #
    # When --dynamic-mode=X is explicitly passed, use legacy "exactly one
    # tier" behavior (backward compat).
    if [[ ${DYNAMIC:-0} -eq 1 ]]; then
        if [[ ${DYNAMIC_AUTO:-0} -eq 1 ]]; then
            log_info "Stage 92-97 - Dynamic analysis (auto-tier mode)"
            log_info "             Running all applicable tiers; each tier"
            log_info "             reports its own skip/run status."
        fi
        log_info "Stage 92 - Dynamic via qiling emulator (Tier 1; no real execution)"
        stage_dynamic_qiling "$target" "$outdir"
        log_info "Stage 94 - Dynamic via firejail sandbox (Tier 2; ELF + real execution)"
        stage_dynamic_firejail "$target" "$outdir"
        log_info "Stage 96 - Dynamic via Docker container (Tier 3; isolated real execution)"
        stage_dynamic_docker "$target" "$outdir"
        log_info "Stage 97 - Dynamic via cuckoo VM-sandbox (Tier 4; hardware virtualization)"
        stage_dynamic_cuckoo "$target" "$outdir"
        log_info "Stage 98 - Dynamic trace aggregation (cross-tier merge)"
        stage_dynamic_trace "$target" "$outdir"
    fi
    log_info "Stage 85 - Summary synthesis"
    stage_summary "$target" "$outdir"
    # v2.7.0 stages that depend on summary having run
    if [[ -n "${DIFF_AGAINST:-}" ]]; then
        log_info "Stage 87 - radiff2 binary diff against $DIFF_AGAINST"
        stage_radiff2 "$target" "$outdir"
        # v3.0.2 (audit-6): stage_binary_diff complements radiff2.
        # radiff2 produces a structural/instruction-level diff;
        # stage_binary_diff produces a bsdiff binary patch + byte-offset
        # snapshot. Both are useful; both consume the same reference binary.
        # Bridge DIFF_AGAINST (driver --diff flag) to the stage's expected
        # RETOOLKIT_REFERENCE_BINARY env var.
        log_info "Stage 91 - Binary diff (bsdiff patch + byte-offset snapshot)"
        RETOOLKIT_REFERENCE_BINARY="$DIFF_AGAINST" stage_binary_diff "$target" "$outdir"
    fi
    if [[ ${ENABLE_YARGEN:-0} -eq 1 ]]; then
        log_info "Stage 88 - yarGen YARA rule generation (opt-in)"
        stage_yargen "$target" "$outdir"
    fi
    # v2.9.0: visualization stage. Reads aggregated _summary.json and emits
    # 5 inline-SVG visualizations to ${outdir}/89-viz/. Always-on (cheap);
    # skip via SKIP_VIZ=1 / --no-viz.
    log_info "Stage 89 - Visualization (inline SVG; sections / imports / capa-MITRE / IOCs / severity)"
    stage_viz "$target" "$outdir"
    log_info "Stage 90 - HTML report"
    stage_report "$target" "$outdir"

    # v3.1.0 (audit-22 A0.1) -- post-run input integrity assertion.
    # Defense in depth: with sandboxing, no stage should ever touch the
    # operator's original file. If this assertion fails, a stage reached
    # outside the sandbox (e.g. via an absolute path) and mutated the
    # original -- a bug we catch loudly rather than let slip silently, as
    # the audit-20 TrID -ae bug did for four releases.
    if ! verify_input_untouched "$outdir"; then
        log_err "Post-run integrity check FAILED for $fname (see errors above)"
        log_err "The operator's original input may have been modified by a stage."
    fi

    log_ok "Completed [$idx/$total]: $fname  ->  $outdir"
}

# =============================================================================
