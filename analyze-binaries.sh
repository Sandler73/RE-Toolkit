#!/usr/bin/env bash
# =============================================================================
# analyze-binaries.sh -- RE-Toolkit master analyzer driver
# =============================================================================
#
# Synopsis:
#     Per-target reverse-engineering pipeline orchestrator. Detects file type,
#     dispatches each target through the appropriate sequence of analysis
#     stages, runs every static analysis tool with deepest output settings,
#     parses results into a per-binary _summary.json, and renders a per-binary
#     _report.html. Emits a codebase-wide index.html across all targets.
#
#     This is the RUN-TIME companion to install-retoolkit.sh. The installer
#     provisions tools (apt + dotnet + Python venv + Ghidra + rules); this
#     driver invokes them. Run install-retoolkit.sh --help for installer flags.
#
# Description:
#
#   ANALYSIS MODES
#
#     Default (no flags): STATIC analysis only. Reads binary data without
#     executing it. Runs ~46 stages (varies by file type) producing per-tool
#     output files, _summary.json, and _report.html under
#     ${OUTPUT_ROOT}/${target_name}/.
#
#     --dynamic: STATIC + DYNAMIC. The --dynamic flag does NOT replace
#     static; it ADDS dynamic-execution stages on top. Order is sequential:
#     for each target, all static stages complete first, then dynamic
#     stages run. Both modalities feed the same per-binary _summary.json
#     and _report.html. There is NO "dynamic-only" mode; static is the
#     foundation that produces the strings, imports, signatures, and IOCs
#     that dynamic stages cross-reference.
#
#     AUTO-TIER MODE is the default behavior of
#     --dynamic. With --dynamic alone (no explicit --dynamic-mode),
#     RE-Toolkit runs ALL applicable dynamic-analysis tiers based on
#     binary type and installed availability:
#         qiling      always runs (no real-execution risk; pure emulator)
#         firejail    runs if --allow-real-execution AND binary is ELF
#                     AND firejail is installed
#         docker      runs if --allow-real-execution AND docker is installed
#                     AND retoolkit-dynamic image is built
#         cuckoo      runs if --allow-real-execution AND cuckoo is configured
#     Each tier reports its own skip/run status. Whichever tier(s) succeed
#     produce output; the others log a clear skip reason.
#
#     LEGACY MODE: --dynamic-mode=X explicitly selects exactly one tier.
#     Useful for automation where exactly-one-tier behavior is desired,
#     or to force a specific tier even when others would also be applicable.
#     Example: --dynamic-mode=qiling forces qiling-only even when docker
#     is available.
#
#     Dynamic-analysis tiers (selected automatically in auto-tier mode,
#     or explicitly via --dynamic-mode=X):
#       Tier 1 qiling   (default; pure CPython emulator over Unicorn engine;
#                        no real syscalls; safest for unknown samples; cross-
#                        architecture; does NOT require --allow-real-execution.
#                        IMPORTANT: qiling's instruction coverage is incomplete -
#                        many real-world Windows PE binaries fail with SIGILL
#                        because Unicorn doesn't implement every instruction
#                        (AVX/AVX2/AVX-512, some SEH/TLS unwind, certain
#                        fast-path syscall stubs). Expect ~50-80% failure rate
#                        on real-world PE; the failure is benign and means
#                        "retry on a real-execution tier" not "this binary
#                        is malicious". Linux ELF works much more reliably
#                        on qiling.)
#       Tier 2 firejail (Linux namespace isolation; ELF only; real execution;
#                        requires --allow-real-execution. RECOMMENDED for
#                        ELF binaries that fail qiling.)
#       Tier 3 docker   (full container isolation with Wine for PE; heavier
#                        setup via --with-docker at install time; requires
#                        --allow-real-execution. RECOMMENDED for PE binaries
#                        that fail qiling.)
#       Tier 4 cuckoo   (VM-based malware sandbox; rare; requires --with-cuckoo
#                        at install time and --allow-real-execution)
#
#     Network defaults to OFF in all real-execution tiers. Override via
#     --dynamic-network=tap or =host. Hard timeout default 60s per target;
#     configure via --dynamic-timeout.
#
#   STAGE PIPELINE
#
#     Each target is dispatched through stages numbered 00 through 98. Stage
#     selection is type-driven (PE-only stages skip non-PE targets, etc.).
#     Operators can disable stages individually via --no-<name> flags or
#     opt into expensive stages via --enable-<name>. The full stage list
#     under stages/static/:
#       00-triage                Magic + entropy + signsrch IOC scan
#       10-pe / 12-lief          PE structural parsing
#       14-pev                   readpe / pedis / pehash / pescan / pesec
#       16-manalyze              Manalyze PE static analyzer
#       17-peframe               peframe behavioral analyzer
#       18-bulk                  bulk_extractor regex + carve
#       20-dotnet                ilspycmd + dnfile + monodis + de4dot-cex
#       30-ghidra                Ghidra headless decompile via GhidraDump.py
#       34-cwe                   cwe_checker (opt-in via --enable-cwe-checker)
#       40-r2 / 40-objdump /
#       40-alternative /
#       42-rizin / 44-llvm       Disassemblers + symbol demanglers
#       50-elf / 52-macho /
#       54-wasm / 56-pyc /
#       58-jar                   Format-specific structural parsers
#       60-config                Config / strings / signature mapping
#       62-pdf / 64-ole          Document analysis (PDF + OLE compound)
#       70-upx                   UPX unpack attempt
#       72-apk / 74-dex /
#       76-axml / 78-apksig      Android (APK + DEX + AndroidManifest + sig)
#       80-iocs                  Cross-stage IOC aggregation
#       81-fuzzyhash             ssdeep + TLSH fuzzy hashing
#       82-cryptokeys            AES key schedule + PEM extraction
#       83-authenticode          PE Authenticode chain validation
#       85-summary               Per-target _summary.json
#       86-angr                  angr CFGFast (opt-in via --enable-angr)
#       87-radiff2               r2 structural diff vs --diff-against
#       88-yargen                yarGen rule generation (opt-in)
#       89-viz                   Inline-SVG visualization layer
#       90-report                Per-target _report.html
#       91-binary-diff           bsdiff + byte-offset snapshot (vs --diff-against)
#       92-dynamic-qiling        Tier 1 emulation (when --dynamic)
#       94-dynamic-firejail      Tier 2 sandbox (when --dynamic-mode=firejail)
#       96-dynamic-docker        Tier 3 container (when --dynamic-mode=docker)
#       97-dynamic-cuckoo        Tier 4 VM sandbox (when --dynamic-mode=cuckoo)
#       98-dynamic-trace         Cross-tier dynamic aggregator
#
#   OUTPUT LAYOUT
#
#     Default (flat):
#       ${OUTPUT_ROOT}/
#         ${target_name}/
#           00-triage/, 10-pe/, ..., 92-dynamic-qiling/   (per-stage dirs)
#           _summary.json
#           _report.html
#         _index.html               (codebase-wide; multiple targets)
#         _similarity-matrix.json   (codebase fuzzy hashes; 2+ targets)
#
#     With --preserve-tree:
#       ${OUTPUT_ROOT}/
#         ${rel_subdir1}/${target_name1}/...
#         ${rel_subdir2}/${target_name2}/...
#       Mirrors the input directory layout. Useful for analyzing a codebase
#       organized by sample family / source / date and wanting the output
#       to preserve that organization.
#
#   FILES SOURCED
#
#     From $RETOOLKIT_LIB_DIR (defaults to $SCRIPT_DIR/lib):
#         common.sh         expand_tilde, absolutize, logging, colors,
#                            safe_grep_count helper
#         tool-runner.sh    run_tool, run_shell with timeout + log capture
#         ghidra-helper.sh  find_ghidra, write_toolkit_versions
#         detect-type.sh    detect_type, detect_go_runtime, detect_rust_runtime
#         viz-helper.sh     SVG primitives
#         dispatch.sh       analyze_one (per-target pipeline; --preserve-tree
#                            output mapping)
#         aggregate.sh      write_run_json_and_index, write_summary,
#                            write_similarity_matrix, write_cluster_graph
#
#     From $RETOOLKIT_STAGES_DIR (defaults to $SCRIPT_DIR/stages):
#         static/00-triage.sh through static/98-dynamic-trace.sh (46 stages
#         as of this release).
#
# Notes:
#     - For Ghidra 11.x: launches postscripts via stock analyzeHeadless.
#     - For Ghidra 12+: launches postscripts via pyghidraRun (CPython 3).
#     - Per-tool invocations are independently timeout-limited.
#     - Sequential mode by default; parallel via --parallel N.
#     - Adds codebase-level _similarity-matrix.json (and .html) when
#       multiple binaries are analyzed; built from each binary's fuzzy hashes.
#     - The -t directory walker recurses fully (previously
#       -maxdepth 1) and no longer filters by an 8-extension whitelist
#       (was *.dll *.exe *.so *.sys *.ocx *.bin *.elf *.out, which silently
#       dropped Mach-O / Java / APK / DEX / PDF / Office / WASM / .NET
#       module / extension-less binaries). detect_type now decides
#       analyzability per file instead of the walker pre-gating.
#
# Execution Parameters:
#
#   TARGET / OUTPUT FLAGS:
#     -t, --target FILE [FILE ...]    Target file(s), glob(s), or directory.
#                                      Multiple targets accepted; consume tokens
#                                      until the next flag (token starting with
#                                      '-'). Use `--` to mark end-of-target list
#                                      explicitly. Directories are recursed
#                                      fully.
#     -o, --output DIR                Output root (default: ./re-analysis-out)
#         --max-depth N                            Limit directory recursion
#                                      depth to N levels. Default: unlimited.
#                                      Useful for "only top-level samples":
#                                        --max-depth=1 limits it to one level.
#         --include-ext EXT[,EXT...]               Allowlist file extensions
#                                      during directory walk. Comma-separated;
#                                      leading dot tolerated. Example:
#                                        --include-ext=exe,dll,sys
#                                      Without this flag, ALL files under the
#                                      target directory are enumerated (then
#                                      detect_type filters at dispatch time).
#         --exclude-ext EXT[,EXT...]               Denylist file extensions.
#                                      Same syntax as --include-ext. Applied
#                                      AFTER --include-ext if both present.
#                                      Example:
#                                        --exclude-ext=txt,log,md
#         --preserve-tree                          Mirror input directory
#                                      layout under -o. Default: flat layout
#                                      (one subdir per target, all under -o).
#                                      Common ancestor of all targets becomes
#                                      the tree root; relative subpaths are
#                                      reproduced under -o.
#         --overwrite                 Overwrite existing per-target outputs
#                                      (default: skip already-analyzed targets
#                                      detected via 00-triage/hashes.txt).
#
#   GHIDRA / JVM TUNING:
#     -g, --ghidra DIR                Override Ghidra install path
#                                      (default: /opt/ghidra symlink)
#     -H, --jvm-heap SIZE             Ghidra JVM heap (default: 4G)
#                                      Format: 4G, 8G, 12G, 1024M.
#     -T, --ghidra-timeout SEC        Ghidra per-file timeout (default: 3600)
#         --keep-project              Keep Ghidra project dirs on disk after
#                                      analysis (default: cleaned up)
#         --use-pyghidra              [deprecated no-op; PyGhidra is auto-
#                                      detected on Ghidra 12+]
#         --force-jython              Skip PyGhidra; use plain analyzeHeadless
#                                      (Ghidra 11 fallback or .py-script
#                                      override edge cases)
#         --script FILE               Override GhidraDump.py location
#                                      (default: $SCRIPT_DIR/GhidraDump.py)
#
#   CONCURRENCY / TIMEOUTS:
#     -j, --parallel N                Parallel workers (default: 1).
#                                      Each worker analyzes one target end-to-
#                                      end before returning. N=4 is a good
#                                      balance for most hosts; N=1 for
#                                      deterministic interactive review.
#         --tool-timeout SEC          Per-tool default timeout (default: 600)
#         --angr-timeout SEC          angr stage timeout when --enable-angr
#                                      (default: 600)
#         --yargen-timeout SEC        yarGen stage timeout when --enable-yargen
#                                      (default: 600)
#
#   STAGE-DISABLE FLAGS (--no-<stage>; static pipeline; opt-out):
#     Cross-format:
#         --no-ghidra                 Skip Ghidra entirely (stage 30)
#         --no-ghidra-dotnet          Skip Ghidra for .NET binaries only
#         --no-dotnet                 Skip ilspycmd / dnfile / monodis (20)
#         --no-de4dot                 Skip de4dot-cex .NET deobfuscation
#         --no-capa                   Skip capa
#         --no-floss                  Skip floss
#         --no-clamav                 Skip ClamAV
#         --no-yara                   Skip YARA
#         --no-r2                     Skip radare2 / rizin (40+42)
#         --no-bulk                   Skip bulk_extractor (18)
#         --no-viz                    Skip stage 89 (inline-SVG visualization)
#     PE-specific:
#         --no-manalyze               Skip Manalyze (16)
#         --no-peframe                Skip peframe (17)
#         --no-signsrch               Skip signsrch (00 sub-step)
#         --no-oldrod                 Skip OldRod .NET deob
#         --no-dnspy-ex               Skip dnSpyEx
#         --no-eazfixer               [no-op: EazFixer is no longer
#                                      installed; flag preserved for
#                                      compatibility]
#         --use-nofuserex             Opt IN to NoFuserEx (alternative deob)
#         --no-authenticode           Skip stage 83 (PE Authenticode)
#     ELF-specific:
#         --no-elf-extras             Skip the ELF extras group (checksec,
#                                      scanelf, dumpelf, pahole, bloaty,
#                                      nm-demangled)
#         --no-checksec, --no-scanelf, --no-dumpelf, --no-pahole,
#         --no-bloaty, --no-nm-demangled  Individual ELF-extras disablers
#     Format-specific (skip whole format pipeline):
#         --no-macho                  Skip Mach-O (52)
#         --no-wasm                   Skip WebAssembly (54)
#         --no-pyc                    Skip Python bytecode (56)
#         --no-jar                    Skip JAR (58)
#         --no-pdf                    Skip PDF (62)
#         --no-ole                    Skip OLE compound docs (64)
#         --no-apk                    Skip Android APK container (72)
#         --no-dex                    Skip DEX decompilation (74)
#         --no-axml                   Skip AndroidManifest.xml decode (76)
#         --no-apksig                 Skip APK signature verify (78)
#     Cross-cutting:
#         --no-fuzzyhash              Skip stage 81 (ssdeep + TLSH)
#         --no-cryptokeys             Skip stage 82 (crypto key extraction)
#         --no-go-detect              Skip Go-runtime auto-detect inside ELF/PE
#         --no-rust-detect            Skip Rust-runtime auto-detect
#     Dynamic-analysis (when --dynamic is on):
#         --no-dynamic-qiling         Skip stage 92 (Tier 1 qiling)
#         --no-dynamic-firejail       Skip stage 94 (Tier 2 firejail)
#         --no-dynamic-docker         Skip stage 96 (Tier 3 docker)
#         --no-dynamic-cuckoo         Skip stage 97 (Tier 4 cuckoo)
#         --no-dynamic-trace          Skip stage 98 (cross-tier aggregator)
#
#   OPT-IN STAGE FLAGS (default-off; explicit enablement required):
#         --enable-cwe-checker        Enable stage 34 (cwe_checker; requires
#                                      --with-cwe-checker at install time;
#                                      Rust-based, ~5-10 min per ELF)
#         --enable-angr               Enable stage 86 (angr CFGFast; Python-
#                                      based; can be slow for large binaries;
#                                      use --angr-timeout to cap)
#         --enable-yargen             Enable stage 88 (yarGen YARA rule
#                                      generation; useful for building
#                                      detection rules from a known-bad
#                                      sample; --yargen-timeout to cap)
#         --diff-against PATH         Run stage 87 (radiff2 structural diff)
#                                      AND stage 91 (bsdiff binary diff +
#                                      byte-offset snapshot) against the
#                                      reference binary at PATH. Single flag,
#                                      two complementary diff perspectives.
#
#         --deep-analysis             r2/rizin use `aaaa` instead of `aaa`
#                                      (deeper but slower analysis; useful
#                                      for binaries with heavy obfuscation)
#         --use-nofuserex             [also listed under PE-specific above]
#                                      NoFuserEx alternative ConfuserEx
#                                      deobfuscator; opt-in because it's
#                                      slower than the default chain.
#
#   DYNAMIC ANALYSIS FLAGS (ADDED ON TOP of static analysis):
#         IMPORTANT - HOW STATIC AND DYNAMIC INTERACT:
#         Static analysis ALWAYS runs. --dynamic does NOT replace static; it
#         ADDS dynamic-execution stages (92-qiling / 94-firejail / 96-docker /
#         97-cuckoo / 98-trace) AFTER the static pipeline completes for each
#         target. Order is sequential: all static stages finish, then dynamic
#         stages run. Both modalities feed the same per-binary _summary.json
#         and the same per-binary _report.html. There is no "dynamic-only"
#         mode; static is the foundation that produces strings/imports/
#         signatures/IOCs that the dynamic stages cross-reference. To run
#         dynamic stages: pass --dynamic. To run static-only (the default):
#         omit --dynamic. To skip individual dynamic tiers when --dynamic
#         is on: use --no-dynamic-qiling / --no-dynamic-firejail / etc.
#
#         AUTO-TIER: --dynamic alone runs ALL applicable
#         tiers based on binary type and installed availability. Each tier
#         reports its own skip/run status. With --allow-real-execution,
#         firejail (ELF) and docker (PE/ELF) run alongside qiling. Without,
#         only qiling runs. Use --dynamic-mode=X for legacy "exactly one
#         tier" behavior.
#
#         --dynamic                   Enable dynamic analysis stack.
#                                      Default: AUTO-TIER mode runs every
#                                      applicable tier (qiling always, plus
#                                      firejail/docker/cuckoo if their
#                                      prereqs are met). Add
#                                      --allow-real-execution to enable the
#                                      real-execution tiers.
#         --dynamic-auto              Explicit alias for --dynamic (auto-tier).
#                                      Equivalent to --dynamic alone.
#         --dynamic-mode MODE         qiling | firejail | docker | cuckoo.
#                                      LEGACY: when set, runs ONLY this tier
#                                      (skips others). Useful for automation
#                                      where exactly-one-tier behavior is
#                                      required. Also accepts --dynamic-mode=X.
#         --dynamic-timeout SEC       Hard timeout per binary (default: 60).
#                                      Stops the dynamic run after SEC seconds
#                                      regardless of completion state.
#         --dynamic-network MODE      none | tap | host (default: none).
#                                      Ignored for qiling tier (no real
#                                      network). For firejail/docker/cuckoo,
#                                      controls network exposure during
#                                      sample execution.
#         --allow-real-execution      REQUIRED for firejail/docker/cuckoo
#                                      tiers. Explicit consent gate; without
#                                      this flag, real-execution tiers refuse
#                                      to start (legacy mode) or skip cleanly
#                                      (auto-tier mode). The qiling tier does
#                                      NOT require this consent (no real
#                                      syscalls).
#
#   RULES / KNOWLEDGE-BASE FLAGS:
#         --yara-rules DIR|FILE       YARA rules directory or master rule file.
#                                      Defaults to $YARA_RULES env var (set by
#                                      install-retoolkit.sh LAYER 5) or
#                                      /opt/yara-rules/_master.yar.
#         --capa-rules DIR            capa rules directory.
#                                      Defaults to $CAPA_RULES env var (set by
#                                      install-retoolkit.sh LAYER 5) or
#                                      /opt/capa-rules.
#
#   LOGGING / METADATA FLAGS:
#     -v, --verbose                   Verbose output. Alias for
#                                      --log-level=debug when LOG_LEVEL is at
#                                      default. If you've explicitly set
#                                      --log-level (e.g., =warn), --verbose
#                                      will NOT override it.
#         --log-level LEVEL                        Set log verbosity. Accepts:
#                                      debug, info (default), warn, error.
#                                      Each level emits its own messages and
#                                      all higher-priority levels:
#                                        debug = log_dbg + log_info + log_warn + log_err
#                                        info  = log_info + log_warn + log_err
#                                        warn  = log_warn + log_err
#                                        error = log_err only
#                                      Also accepts --log-level=LEVEL form.
#         --log-file PATH                          Mirror all log_* output
#                                      to PATH in addition to stdout and the
#                                      per-run log under OUTPUT_ROOT. Useful
#                                      for pipe-friendly capture in CI.
#                                      Also accepts --log-file=PATH form.
#     -V, --version                   Print analyzer version and exit 0
#                                      (currently emits "analyze-binaries.sh
#                                      the version string). Note: -v is --verbose;
#                                      -V is --version.
#     -h, --help                      Show this help and exit 0
#
# RUN-TIME COMPANION TO INSTALL-RETOOLKIT.SH:
#     This driver is the run-time analyzer. To install/configure the toolkit
#     it depends on, run:
#         install-retoolkit.sh --help
#     The installer has its own ~20 install-time flags governing which LAYERs
#     run, which optional components are pulled in (--with-docker, --with-
#     cuckoo, --with-retdec, --with-cwe-checker, etc.), and the standard
#     developmental flags (--log-level, --version) shared with this driver.
#
# Examples:
#     # Most common -- single PE/ELF analysis, default static pipeline:
#     ./analyze-binaries.sh -t suspect.exe -o ~/out
#
#     # Full codebase analysis (multiple files via glob):
#     ./analyze-binaries.sh -t ~/samples/*.dll -o ~/out --jvm-heap 4G
#
#     # Directory recursion:
#     ./analyze-binaries.sh -t ~/codebase -o ~/out
#       (recurses fully; analyzes ALL files; detect_type filters)
#
#     # Directory with extension allowlist (faster than full recursion when
#     # you know your codebase extensions):
#     ./analyze-binaries.sh -t ~/codebase -o ~/out --include-ext=exe,dll,sys
#
#     # Directory with extension denylist:
#     ./analyze-binaries.sh -t ~/codebase -o ~/out --exclude-ext=txt,log,md,sha256
#
#     # Limit recursion depth:
#     ./analyze-binaries.sh -t ~/codebase -o ~/out --max-depth=2
#
#     # Preserve directory tree in output:
#     ./analyze-binaries.sh -t ~/codebase -o ~/out --preserve-tree
#       (output organized as ~/out/${rel_subdir}/${target}/ instead of
#        flat ~/out/${target}/)
#
#     # Triage-only (skip slow stages):
#     ./analyze-binaries.sh -t ~/samples/*.exe -o ~/triage \
#         --no-ghidra --no-floss
#
#     # Deep analysis with opt-in stages:
#     ./analyze-binaries.sh -t firmware.bin -o ~/out \
#         --enable-cwe-checker --enable-angr --deep-analysis
#
#     # Diff a suspected variant against a known reference:
#     ./analyze-binaries.sh -t suspect.exe -o ~/out --diff-against original.exe
#
#     # Codebase fuzzy + cluster (auto-emits _similarity-matrix when 2+ targets):
#     ./analyze-binaries.sh -t ~/codebase/*.exe -o ~/clusters
#
#     # Android (APK) analysis:
#     ./analyze-binaries.sh -t ~/samples/*.apk -o ~/android-out
#
#     # Standalone DEX:
#     ./analyze-binaries.sh -t classes.dex -o ~/dex-only-out
#
#     # Dynamic analysis - safe Tier 1 qiling (no consent gate):
#     ./analyze-binaries.sh -t sample.exe -o ~/out --dynamic
#
#     # Dynamic - Tier 2 firejail (real ELF execution; requires consent):
#     ./analyze-binaries.sh -t elf.bin -o ~/out --dynamic \
#         --dynamic-mode=firejail --allow-real-execution
#
#     # Dynamic - Tier 3 docker (PE via Wine; tap network; 120s timeout):
#     ./analyze-binaries.sh -t pe.exe -o ~/out --dynamic \
#         --dynamic-mode=docker --allow-real-execution \
#         --dynamic-network=tap --dynamic-timeout=120
#
#     # Parallel codebase analysis (4 workers):
#     ./analyze-binaries.sh -t ~/codebase -o ~/out -j 4
#
#     # Quiet mode (errors only):
#     ./analyze-binaries.sh -t sample.exe -o ~/out --log-level=error
#
#     # Debug mode (full trace including log_dbg + log_step):
#     ./analyze-binaries.sh -t sample.exe -o ~/out --log-level=debug
#
#     # Mirror all output to a CI log file:
#     ./analyze-binaries.sh -t ~/codebase -o ~/out --log-file=ci-run.log
#
#     # Print version and exit (no analysis):
#     ./analyze-binaries.sh --version
#
# Version:
#     3.7.3 - 2026-05-03
#
#     Full release history, including per-version fixes, feature additions,
#     and audit batches, is maintained in CHANGELOG.md at the repository
#     root. It is deliberately not duplicated here: this header documents
#     what the script does now, not how it got here.
# =============================================================================

set -uo pipefail

# -----------------------------------------------------------------------------
# Resolve script + lib + stages directories
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RETOOLKIT_LIB_DIR="${RETOOLKIT_LIB_DIR:-$SCRIPT_DIR/lib}"
RETOOLKIT_STAGES_DIR="${RETOOLKIT_STAGES_DIR:-$SCRIPT_DIR/stages}"

for d in "$RETOOLKIT_LIB_DIR" "$RETOOLKIT_STAGES_DIR/static"; do
    if [[ ! -d "$d" ]]; then
        printf 'ERROR: required directory not found: %s\n' "$d" >&2
        printf '       Set RETOOLKIT_LIB_DIR / RETOOLKIT_STAGES_DIR or run\n' >&2
        printf '       analyze-binaries.sh from its install location.\n' >&2
        exit 1
    fi
done

# -----------------------------------------------------------------------------
# Source lib/ modules -- order matters: common.sh first
# -----------------------------------------------------------------------------
# shellcheck disable=SC1091
source "$RETOOLKIT_LIB_DIR/common.sh"
# shellcheck disable=SC1091
source "$RETOOLKIT_LIB_DIR/tool-runner.sh"
# shellcheck disable=SC1091
source "$RETOOLKIT_LIB_DIR/ghidra-helper.sh"
# shellcheck disable=SC1091
source "$RETOOLKIT_LIB_DIR/detect-type.sh"
# v2.9.0: viz helper - shared SVG primitives sourced before dispatch + aggregate
# shellcheck disable=SC1091
source "$RETOOLKIT_LIB_DIR/viz-helper.sh"
# shellcheck disable=SC1091
source "$RETOOLKIT_LIB_DIR/dispatch.sh"
# shellcheck disable=SC1091
source "$RETOOLKIT_LIB_DIR/aggregate.sh"

# -----------------------------------------------------------------------------
# Source stages/static/ -- load order doesn't matter (functions only)
# -----------------------------------------------------------------------------
for stage in "$RETOOLKIT_STAGES_DIR"/static/*.sh; do
    # shellcheck disable=SC1090
    source "$stage"
done

retoolkit_setup_colors

# =============================================================================
# Defaults
# =============================================================================
TARGETS=()
OUTPUT_ROOT="./re-analysis-out"
GHIDRA_INSTALL=""
JVM_HEAP="4G"
GHIDRA_TIMEOUT=3600
TOOL_TIMEOUT=600
PARALLEL_WORKERS=1
OVERWRITE=0
SKIP_GHIDRA=0
SKIP_GHIDRA_DOTNET=0      # default: run LIGHT Ghidra on .NET
SKIP_DOTNET=0
SKIP_CAPA=0
SKIP_FLOSS=0
SKIP_CLAMAV=0
SKIP_YARA=0
SKIP_R2=0
# v2.3.0 additions
SKIP_BULK=0               # bulk_extractor is slow; --no-bulk to skip
SKIP_DE4DOT=0             # de4dot may trip heuristics on non-obfuscated; --no-de4dot to skip
# v2.5.0 additions - new tool skip controls (default OFF = run; --no-X = skip)
SKIP_MANALYZE=0           # Manalyze (PE) - heuristic plugins + JSON output
SKIP_PEFRAME=0            # peframe (PE) - behavioral static analyzer
SKIP_CHECKSEC=0           # checksec / pwn checksec (ELF mitigations)
SKIP_SCANELF=0            # scanelf (PaX-utils ELF flags)
SKIP_DUMPELF=0            # dumpelf (PaX-utils C-struct ELF dump)
SKIP_PAHOLE=0             # pahole (DWARF struct layout when debug present)
SKIP_BLOATY=0             # bloaty (section/segment size breakdown; ELF + PE)
SKIP_NM_DEMANGLED=0       # nm -DC (demangled dynamic symbols; ELF)
SKIP_SIGNSRCH=0           # signsrch (binary crypto/algorithm signatures)
SKIP_EAZFIXER=0           # EazFixer (.NET, Eazfuscator-specific deob)
SKIP_OLDROD=0             # OldRod (.NET, KoiVM/VMProtect.NET devirt)
SKIP_DNSPY_EX=0           # dnSpyEx CLI (.NET, third decompiler perspective)
USE_NOFUSEREX=0           # NoFuserEx (.NET, opt-in alternative to de4dot)
ENABLE_CWE_CHECKER=0      # cwe_checker (opt-in: ~5-10 min/binary; runs Ghidra internally)
# v2.6.0 additions - binary type buckets + Go/Rust sub-detection
SKIP_MACHO=0              # Mach-O analysis stage (52-macho.sh)
SKIP_WASM=0               # WebAssembly analysis stage (54-wasm.sh)
SKIP_PYC=0                # Python bytecode analysis (56-pyc.sh)
SKIP_JAR=0                # Java JAR analysis (58-jar.sh)
SKIP_PDF=0                # PDF analysis (62-pdf.sh)
SKIP_OLE=0                # OLE / OOXML Office analysis (64-ole.sh)
SKIP_GO_DETECT=0          # Go runtime sub-detection inside stage_elf/stage_pe
SKIP_RUST_DETECT=0        # Rust runtime sub-detection inside stage_elf/stage_pe
# v2.7.0 additions - cross-cutting capability stages
SKIP_FUZZYHASH=0          # ssdeep + TLSH fuzzy hashing (81-fuzzyhash.sh)
SKIP_CRYPTOKEYS=0         # crypto key/secret extraction (82-cryptokeys.sh)
SKIP_AUTHENTICODE=0       # PE Authenticode chain validation (83-authenticode.sh)
ENABLE_ANGR=0             # angr CFGFast (86-angr.sh; opt-in due to time cost)
ANGR_TIMEOUT=600          # hard timeout per binary for angr stage (seconds)
DIFF_AGAINST=""           # reference binary for radiff2 (87-radiff2.sh; comparative)
ENABLE_YARGEN=0           # yarGen YARA rule generation (88-yargen.sh; opt-in)
YARGEN_TIMEOUT=600        # hard timeout per binary for yargen stage (seconds)
# v2.8.0 additions - mobile (Android DEX/APK)
SKIP_APK=0                # APK container extraction stage (72-apk.sh)
SKIP_DEX=0                # DEX decompilation stage (74-dex.sh)
SKIP_AXML=0               # AndroidManifest.xml decode stage (76-axml.sh)
SKIP_APKSIG=0             # APK signature verification stage (78-apksig.sh)
# v2.9.0 additions - visualization
SKIP_VIZ=0                # inline-SVG visualization stage (89-viz.sh)
# v3.0.0 additions - dynamic analysis (BREAKING release; default OFF)
DYNAMIC=0                       # master switch; --dynamic enables tier dispatch
DYNAMIC_MODE=""                 # qiling|firejail|docker|cuckoo (empty = auto-tier)
DYNAMIC_AUTO=0                  # v3.0.9 (audit-13): set to 1 by --dynamic when
                                # --dynamic-mode is NOT explicitly passed.
                                # When DYNAMIC_AUTO=1, all applicable tiers run
                                # (gated by their own prereqs); when 0, only
                                # the tier matching DYNAMIC_MODE runs (legacy).
DYNAMIC_TIMEOUT=60              # hard timeout per binary (seconds)
DYNAMIC_NETWORK="none"          # none|tap|host (ignored for qiling tier)
ALLOW_REAL_EXECUTION=0          # required for firejail/docker/cuckoo modes
SKIP_DYNAMIC_QILING=0           # skip stage 92
SKIP_DYNAMIC_FIREJAIL=0         # skip stage 94
SKIP_DYNAMIC_DOCKER=0           # skip stage 96
SKIP_DYNAMIC_CUCKOO=0           # skip stage 97
SKIP_DYNAMIC_TRACE=0            # skip stage 98 aggregator
DEEP_ANALYSIS=0           # r2/rizin default to aaa; --deep-analysis unlocks aaaa
KEEP_PROJECT=0
USE_PYGHIDRA=0            # DEPRECATED in 2.1.3: no longer needed -- PyGhidra
                          # is auto-enabled when Ghidra 12+ detected. Kept
                          # as a no-op flag for backward-compat.
FORCE_JYTHON=0            # NEW in 2.1.3: force use of plain analyzeHeadless
                          # (Jython). Edge case only -- useful for Ghidra 11
                          # or when PyGhidra bootstrap fails for any reason.
SCRIPT_PATH=""
YARA_RULES=""
CAPA_RULES=""
VERBOSE=0

# v3.0.5 (audit-9 B1+B2+B3): standard developmental flags brought to the
# driver to match install-retoolkit.sh's v3.0.3 audit-7 conventions.
# ANALYZER_VERSION is the canonical version constant; --version prints
# it and exits 0. LOG_LEVEL gates log output (debug=0, info=1, warn=2,
# error=3). LOG_FILE optionally mirrors stdout to a file in addition to
# the per-run log under OUTPUT_ROOT.
ANALYZER_VERSION="3.7.3"
LOG_LEVEL="info"          # debug | info | warn | error
LOG_FILE=""               # if set, mirror all log_* output to this file

# v3.0.5 (audit-9 A2-A6): target enumeration controls.
TARGET_MAX_DEPTH=""               # empty = unlimited recursion
TARGET_INCLUDE_EXT_ARR=()         # populated by --include-ext (allowlist)
TARGET_EXCLUDE_EXT_ARR=()         # populated by --exclude-ext (denylist)
PRESERVE_TREE=0                   # --preserve-tree opt-in flag (audit-9 A6)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"


# =============================================================================
# Usage
# =============================================================================
print_help() { sed -n '/^# Synopsis/,/^# Version/p' "$0" | sed 's/^#\s\?//'; exit 0; }

# =============================================================================
# Arg parsing -- accepts variadic targets after -t
# =============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)
            shift
            while [[ $# -gt 0 && "$1" != -* ]]; do
                TARGETS+=("$(expand_tilde "$1")"); shift
            done
            ;;
        -o|--output)         OUTPUT_ROOT="$(expand_tilde "$2")"; shift 2 ;;
        -g|--ghidra)         GHIDRA_INSTALL="$(expand_tilde "$2")"; shift 2 ;;
        -H|--jvm-heap)       JVM_HEAP="$2"; shift 2 ;;
        -T|--ghidra-timeout) GHIDRA_TIMEOUT="$2"; shift 2 ;;
        --tool-timeout)      TOOL_TIMEOUT="$2"; shift 2 ;;
        -j|--parallel)       PARALLEL_WORKERS="$2"; shift 2 ;;
        --overwrite)         OVERWRITE=1; shift ;;
        --no-ghidra)         SKIP_GHIDRA=1; shift ;;
        --no-ghidra-dotnet)  SKIP_GHIDRA_DOTNET=1; shift ;;
        --no-dotnet)         SKIP_DOTNET=1; shift ;;
        --no-capa)           SKIP_CAPA=1; shift ;;
        --no-floss)          SKIP_FLOSS=1; shift ;;
        --no-clamav)         SKIP_CLAMAV=1; shift ;;
        --no-yara)            SKIP_YARA=1; shift ;;
        --no-r2)             SKIP_R2=1; shift ;;
        --no-bulk)           SKIP_BULK=1; shift ;;
        --no-de4dot)         SKIP_DE4DOT=1; shift ;;
        # v2.5.0 flags
        --no-manalyze)       SKIP_MANALYZE=1; shift ;;
        --no-peframe)        SKIP_PEFRAME=1; shift ;;
        --no-checksec)       SKIP_CHECKSEC=1; shift ;;
        --no-scanelf)        SKIP_SCANELF=1; shift ;;
        --no-dumpelf)        SKIP_DUMPELF=1; shift ;;
        --no-pahole)         SKIP_PAHOLE=1; shift ;;
        --no-bloaty)         SKIP_BLOATY=1; shift ;;
        --no-nm-demangled)   SKIP_NM_DEMANGLED=1; shift ;;
        --no-signsrch)       SKIP_SIGNSRCH=1; shift ;;
        --no-eazfixer)       SKIP_EAZFIXER=1; shift ;;
        --no-oldrod)         SKIP_OLDROD=1; shift ;;
        --no-dnspy-ex)       SKIP_DNSPY_EX=1; shift ;;
        --use-nofuserex)     USE_NOFUSEREX=1; shift ;;
        --enable-cwe-checker) ENABLE_CWE_CHECKER=1; shift ;;
        # convenience: --no-elf-extras turns off the v2.5.0 ELF additions
        # but keeps original v2.4.0 readelf + nm
        --no-elf-extras)     SKIP_CHECKSEC=1; SKIP_SCANELF=1; SKIP_DUMPELF=1; \
                             SKIP_PAHOLE=1; SKIP_BLOATY=1; SKIP_NM_DEMANGLED=1; shift ;;
        # v2.6.0 flags
        --no-macho)          SKIP_MACHO=1; shift ;;
        --no-wasm)           SKIP_WASM=1; shift ;;
        --no-pyc)            SKIP_PYC=1; shift ;;
        --no-jar)            SKIP_JAR=1; shift ;;
        --no-pdf)            SKIP_PDF=1; shift ;;
        --no-ole)            SKIP_OLE=1; shift ;;
        --no-go-detect)      SKIP_GO_DETECT=1; shift ;;
        --no-rust-detect)    SKIP_RUST_DETECT=1; shift ;;
        # v2.7.0 flags
        --no-fuzzyhash)      SKIP_FUZZYHASH=1; shift ;;
        --no-cryptokeys)     SKIP_CRYPTOKEYS=1; shift ;;
        --no-authenticode)   SKIP_AUTHENTICODE=1; shift ;;
        --enable-angr)       ENABLE_ANGR=1; shift ;;
        --angr-timeout)      ANGR_TIMEOUT="$2"; shift 2 ;;
        --diff-against)      DIFF_AGAINST="$2"; shift 2 ;;
        --enable-yargen)     ENABLE_YARGEN=1; shift ;;
        --yargen-timeout)    YARGEN_TIMEOUT="$2"; shift 2 ;;
        # v2.8.0 flags
        --no-apk)            SKIP_APK=1; shift ;;
        --no-dex)            SKIP_DEX=1; shift ;;
        --no-axml)           SKIP_AXML=1; shift ;;
        --no-apksig)         SKIP_APKSIG=1; shift ;;
        # v2.9.0 flags
        --no-viz)            SKIP_VIZ=1; shift ;;
        # v3.0.0 flags - dynamic analysis (BREAKING release; default OFF)
        # v3.0.9 (audit-13 B1+B3) - --dynamic alone enables auto-tier mode.
        # --dynamic-mode=X forces legacy "exactly one tier" mode.
        # --dynamic-auto is an explicit alias for --dynamic (auto-tier).
        --dynamic)               DYNAMIC=1; shift ;;
        --dynamic-auto)          DYNAMIC=1; shift ;;
        --dynamic-mode)          DYNAMIC_MODE="$2"; shift 2 ;;
        --dynamic-mode=*)        DYNAMIC_MODE="${1#*=}"; shift ;;
        --dynamic-timeout)       DYNAMIC_TIMEOUT="$2"; shift 2 ;;
        --dynamic-timeout=*)     DYNAMIC_TIMEOUT="${1#*=}"; shift ;;
        --dynamic-network)       DYNAMIC_NETWORK="$2"; shift 2 ;;
        --dynamic-network=*)     DYNAMIC_NETWORK="${1#*=}"; shift ;;
        --allow-real-execution)  ALLOW_REAL_EXECUTION=1; shift ;;
        --no-dynamic-qiling)     SKIP_DYNAMIC_QILING=1; shift ;;
        --no-dynamic-firejail)   SKIP_DYNAMIC_FIREJAIL=1; shift ;;
        --no-dynamic-docker)     SKIP_DYNAMIC_DOCKER=1; shift ;;
        --no-dynamic-cuckoo)     SKIP_DYNAMIC_CUCKOO=1; shift ;;
        --no-dynamic-trace)      SKIP_DYNAMIC_TRACE=1; shift ;;
        --deep-analysis)     DEEP_ANALYSIS=1; shift ;;
        --keep-project)      KEEP_PROJECT=1; shift ;;
        --use-pyghidra)      USE_PYGHIDRA=1; shift ;;
        --force-jython)      FORCE_JYTHON=1; shift ;;
        --script)            SCRIPT_PATH="$(expand_tilde "$2")"; shift 2 ;;
        --yara-rules)        YARA_RULES="$(expand_tilde "$2")"; shift 2 ;;
        --capa-rules)        CAPA_RULES="$(expand_tilde "$2")"; shift 2 ;;
        -v|--verbose)        VERBOSE=1; shift ;;
        # v3.0.5 (audit-9 B1+B2+B3): standard developmental flags.
        --log-level)
            if [[ -z "${2:-}" ]]; then
                echo "--log-level requires a value: debug|info|warn|error" >&2
                exit 2
            fi
            case "$2" in
                debug|info|warn|error) LOG_LEVEL="$2"; shift 2 ;;
                *) echo "Invalid --log-level: $2 (expected: debug|info|warn|error)" >&2; exit 2 ;;
            esac
            ;;
        --log-level=*)
            LOG_LEVEL="${1#*=}"
            case "$LOG_LEVEL" in
                debug|info|warn|error) shift ;;
                *) echo "Invalid --log-level: $LOG_LEVEL (expected: debug|info|warn|error)" >&2; exit 2 ;;
            esac
            ;;
        --log-file)
            if [[ -z "${2:-}" ]]; then
                echo "--log-file requires a path argument" >&2
                exit 2
            fi
            LOG_FILE="$(expand_tilde "$2")"; shift 2 ;;
        --log-file=*)
            LOG_FILE="$(expand_tilde "${1#*=}")"; shift ;;
        -V|--version)
            printf "analyze-binaries.sh v%s\n" "$ANALYZER_VERSION"
            exit 0 ;;
        # v3.0.5 (audit-9 A2-A6): target enumeration controls.
        --max-depth)
            if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "--max-depth requires a positive integer" >&2
                exit 2
            fi
            TARGET_MAX_DEPTH="$2"; shift 2 ;;
        --max-depth=*)
            TARGET_MAX_DEPTH="${1#*=}"
            if [[ ! "$TARGET_MAX_DEPTH" =~ ^[0-9]+$ ]]; then
                echo "--max-depth requires a positive integer" >&2; exit 2
            fi
            shift ;;
        --include-ext)
            if [[ -z "${2:-}" ]]; then
                echo "--include-ext requires comma-separated extensions" >&2
                exit 2
            fi
            IFS=',' read -ra _exts <<< "$2"
            for _e in "${_exts[@]}"; do
                _e="${_e# }"; _e="${_e% }"; _e="${_e#.}"
                [[ -n "$_e" ]] && TARGET_INCLUDE_EXT_ARR+=("$_e")
            done
            shift 2 ;;
        --include-ext=*)
            IFS=',' read -ra _exts <<< "${1#*=}"
            for _e in "${_exts[@]}"; do
                _e="${_e# }"; _e="${_e% }"; _e="${_e#.}"
                [[ -n "$_e" ]] && TARGET_INCLUDE_EXT_ARR+=("$_e")
            done
            shift ;;
        --exclude-ext)
            if [[ -z "${2:-}" ]]; then
                echo "--exclude-ext requires comma-separated extensions" >&2
                exit 2
            fi
            IFS=',' read -ra _exts <<< "$2"
            for _e in "${_exts[@]}"; do
                _e="${_e# }"; _e="${_e% }"; _e="${_e#.}"
                [[ -n "$_e" ]] && TARGET_EXCLUDE_EXT_ARR+=("$_e")
            done
            shift 2 ;;
        --exclude-ext=*)
            IFS=',' read -ra _exts <<< "${1#*=}"
            for _e in "${_exts[@]}"; do
                _e="${_e# }"; _e="${_e% }"; _e="${_e#.}"
                [[ -n "$_e" ]] && TARGET_EXCLUDE_EXT_ARR+=("$_e")
            done
            shift ;;
        --preserve-tree)     PRESERVE_TREE=1; shift ;;
        -h|--help)           print_help ;;
        --)                  shift; while [[ $# -gt 0 ]]; do TARGETS+=("$(expand_tilde "$1")"); shift; done ;;
        *)                   echo "Unknown arg: $1" >&2
                             echo "Hint: all target files must follow -t with no flags between." >&2
                             exit 2 ;;
    esac
done

# v3.0.5 (audit-9 B1): map LOG_LEVEL to numeric for fast compare.
# Backward compat: --verbose still flips LOG_LEVEL to debug when LOG_LEVEL
# is at default (preserves v2.x semantics).
case "$LOG_LEVEL" in
    debug) _LOG_LEVEL_NUM=0 ;;
    info)  _LOG_LEVEL_NUM=1 ;;
    warn)  _LOG_LEVEL_NUM=2 ;;
    error) _LOG_LEVEL_NUM=3 ;;
esac
if [[ $VERBOSE -eq 1 && "$LOG_LEVEL" == "info" ]]; then
    LOG_LEVEL="debug"
    _LOG_LEVEL_NUM=0
fi
export _LOG_LEVEL_NUM LOG_LEVEL LOG_FILE PRESERVE_TREE


# =============================================================================
# v3.0.0 Dynamic-analysis safety gate
# =============================================================================
# Real-execution tiers (firejail / docker / cuckoo) require explicit consent
# via --allow-real-execution. The qiling tier does NOT require it because
# no real syscalls hit the host kernel (pure CPython emulator).
# Failing fast at startup is clearer than partial pipeline runs.
#
# v3.0.9 (audit-13 B1) - auto-tier mode: when --dynamic is passed without
# explicit --dynamic-mode, run all applicable tiers (gated by their own
# prereqs). DYNAMIC_AUTO=1 signals this to the dispatch layer. When
# --dynamic-mode=X is explicit, DYNAMIC_AUTO stays 0 (legacy behavior).
if [[ ${DYNAMIC:-0} -eq 1 ]]; then
    if [[ -z "${DYNAMIC_MODE:-}" ]]; then
        # Auto-tier mode (default for --dynamic alone)
        DYNAMIC_AUTO=1
        # Validate DYNAMIC_NETWORK regardless of mode
        case "${DYNAMIC_NETWORK:-none}" in
            none|tap|host) : ;;
            *)
                echo "ERROR: unknown --dynamic-network='${DYNAMIC_NETWORK}'. Valid: none|tap|host" >&2
                exit 2
                ;;
        esac
    else
        # Legacy mode: DYNAMIC_MODE explicitly set; one tier only.
        DYNAMIC_AUTO=0
        case "${DYNAMIC_MODE}" in
            qiling)
                : # safe; no consent gate needed
                ;;
            firejail|docker|cuckoo)
                if [[ ${ALLOW_REAL_EXECUTION:-0} -ne 1 ]]; then
                    echo "" >&2
                    echo "REFUSED: --dynamic-mode=${DYNAMIC_MODE} requires --allow-real-execution." >&2
                    echo "" >&2
                    echo "  qiling-tier emulation is the safer default and does not require consent." >&2
                    echo "  Real-execution tiers (firejail / docker / cuckoo) actually run the binary" >&2
                    echo "  on this host, even inside isolation. If you have explicitly verified that" >&2
                    echo "  this is appropriate (sample is trusted, host is dedicated to analysis," >&2
                    echo "  network is the intended state), re-run with --allow-real-execution." >&2
                    echo "" >&2
                    echo "  Default:    --dynamic                                # auto-tier (recommended)" >&2
                    echo "  Real exec:  --dynamic --dynamic-mode=firejail \\" >&2
                    echo "              --allow-real-execution                   # ELF only, namespaced" >&2
                    echo "              --dynamic-network=none                   # default" >&2
                    echo "" >&2
                    exit 2
                fi
                ;;
            *)
                echo "ERROR: unknown --dynamic-mode='${DYNAMIC_MODE}'. Valid: qiling|firejail|docker|cuckoo" >&2
                exit 2
                ;;
        esac
        case "${DYNAMIC_NETWORK:-none}" in
            none|tap|host) : ;;
            *)
                echo "ERROR: unknown --dynamic-network='${DYNAMIC_NETWORK}'. Valid: none|tap|host" >&2
                exit 2
                ;;
        esac
    fi
    # Validate DYNAMIC_TIMEOUT is a positive integer (defends against shell
    # injection via the timeout value flowing into arithmetic and printf
    # contexts in stage scripts)
    if ! [[ "${DYNAMIC_TIMEOUT:-60}" =~ ^[1-9][0-9]*$ ]]; then
        echo "ERROR: --dynamic-timeout must be a positive integer (got '${DYNAMIC_TIMEOUT}')" >&2
        exit 2
    fi
    if [[ "${DYNAMIC_TIMEOUT}" -gt 3600 ]]; then
        echo "ERROR: --dynamic-timeout exceeds 3600 (1 hour); refusing as a sanity cap" >&2
        exit 2
    fi
fi


# =============================================================================
# Apply absolutize() to user-supplied paths (function defined in lib/common.sh)
# =============================================================================
OUTPUT_ROOT="$(absolutize "$OUTPUT_ROOT")"
[[ -n "$GHIDRA_INSTALL" ]] && GHIDRA_INSTALL="$(absolutize "$GHIDRA_INSTALL")"
[[ -n "$SCRIPT_PATH"    ]] && SCRIPT_PATH="$(absolutize "$SCRIPT_PATH")"
[[ -n "$YARA_RULES"     ]] && YARA_RULES="$(absolutize "$YARA_RULES")"
[[ -n "$CAPA_RULES"     ]] && CAPA_RULES="$(absolutize "$CAPA_RULES")"


# =============================================================================
# Tool discovery -- runtime; depends on arg-parse globals
# =============================================================================
ANALYZE_HEADLESS=""
PYGHIDRA_AVAILABLE=0
if [[ $SKIP_GHIDRA -eq 0 ]]; then
    if GHIDRA_INSTALL=$(find_ghidra); then
        ANALYZE_HEADLESS="${GHIDRA_INSTALL}/support/analyzeHeadless"
        # Detect PyGhidra headless capability. Two markers:
        #   1. Ghidra ships PyGhidra launcher files in the install tree
        #   2. The 'pyghidra' Python module is importable (venv or system)
        PYGHIDRA_LAUNCHER="${GHIDRA_INSTALL}/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py"
        if [[ -f "$PYGHIDRA_LAUNCHER" ]]; then
            # Confirm the python module is actually available
            PYGHIDRA_PY=""
            for p in "/opt/retools/venv/bin/python" "$(command -v python3 2>/dev/null)"; do
                if [[ -n "$p" && -x "$p" ]] && "$p" -c "import pyghidra" 2>/dev/null; then
                    PYGHIDRA_PY="$p"
                    break
                fi
            done
            [[ -n "$PYGHIDRA_PY" ]] && PYGHIDRA_AVAILABLE=1
        fi
    else
        log_warn "Ghidra not found -- disabling Ghidra pipeline stage"
        log_warn "Install with: sudo ./install-retoolkit.sh"
        SKIP_GHIDRA=1
    fi
fi

# --- Python venv tools ---
RETOOLS_VENV="${RETOOLS_VENV:-/opt/retools/venv}"
VENV_BIN="${RETOOLS_VENV}/bin"

# --- ilspycmd ---
USER_HOME="${SUDO_USER:+/home/$SUDO_USER}"
[[ -z "$USER_HOME" ]] && USER_HOME="$HOME"
ILSPYCMD=""
for p in "$(command -v ilspycmd 2>/dev/null)" "${USER_HOME}/.dotnet/tools/ilspycmd" "/root/.dotnet/tools/ilspycmd"; do
    if [[ -n "$p" && -x "$p" ]]; then ILSPYCMD="$p"; break; fi
done

# --- GhidraDump.py ---
if [[ -z "$SCRIPT_PATH" ]]; then
    for c in "${SCRIPT_DIR}/GhidraDump.py" "$(pwd)/GhidraDump.py" "/opt/retools/GhidraDump.py"; do
        if [[ -f "$c" ]]; then SCRIPT_PATH="$c"; break; fi
    done
fi

# --- YARA rules -- prefer master file, fall back to dir ---
# Priority: --yara-rules arg, $YARA_RULES env, /opt/yara-rules/_master.yar,
#           then any common rules dir.
if [[ -z "$YARA_RULES" ]]; then
    for c in "$(expand_tilde "${YARA_RULES:-}")" "/opt/yara-rules/_master.yar" "/opt/yara-rules" \
             "/var/lib/yara/rules" "/usr/share/yara/rules"; do
        if [[ -e "$c" ]]; then YARA_RULES="$c"; break; fi
    done
fi

# --- capa rules ---
if [[ -z "$CAPA_RULES" ]]; then
    for c in "$(expand_tilde "${CAPA_RULES:-}")" "/opt/capa-rules" \
             "${USER_HOME}/.cache/capa/rules"; do
        if [[ -n "$c" && -d "$c" ]]; then CAPA_RULES="$c"; break; fi
    done
fi

# --- capa binary ---
CAPA_CMD=""
for p in "$(command -v capa 2>/dev/null)" "/opt/retools/bin/capa" "${VENV_BIN}/capa"; do
    if [[ -n "$p" && -x "$p" ]]; then CAPA_CMD="$p"; break; fi
done
[[ $SKIP_CAPA -eq 1 ]] && CAPA_CMD=""

# --- floss ---
FLOSS_CMD=""
for p in "$(command -v floss 2>/dev/null)" "/opt/retools/bin/floss" "${VENV_BIN}/floss"; do
    if [[ -n "$p" && -x "$p" ]]; then FLOSS_CMD="$p"; break; fi
done
[[ $SKIP_FLOSS -eq 1 ]] && FLOSS_CMD=""

# --- Python ---
VENV_PY=""
[[ -x "${VENV_BIN}/python" ]] && VENV_PY="${VENV_BIN}/python"
[[ -z "$VENV_PY" ]] && VENV_PY="$(command -v python3 2>/dev/null || true)"

# =============================================================================
# Target expansion
# =============================================================================
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    log_err "No targets. Use -t to specify files/globs/directories."
    exit 2
fi

EXPANDED=()
# v3.0.5 (audit-9 A2 + A3 + A4 + A5 + A6) -- target-expansion overhaul.
#
# Pre-v3.0.5 directory walker had two design defects (recorded as L47):
#
# 1. -maxdepth 1 hardcoded: only top-level files of the target directory
#    were enumerated; subdirectories were silently dropped. Operators
#    pointing -t at a codebase tree saw most of their files never get
#    analyzed and no warning to indicate why.
#
# 2. Hardcoded extension whitelist: `*.dll *.exe *.so *.sys *.ocx
#    *.bin *.elf *.out`. This silently dropped Mach-O (.dylib or no
#    extension), Java (.jar, .class), Android (.apk, .dex), Python
#    bytecode (.pyc, .pyo), WebAssembly (.wasm), Office (.doc, .xls,
#    .ppt + Office Open XML), PDFs (.pdf), .NET modules (.netmodule),
#    OLE compound docs (.ole), firmware images, and any ELF/PE without
#    a conventional extension. The toolkit's per-file dispatcher (in
#    lib/dispatch.sh > analyze_one > detect_type) handles ALL of these
#    file types via libmagic content sniffing; the directory walker was
#    gating them out before they ever reached the dispatcher.
#
# Audit-9 fix:
#  - Recurse fully (no -maxdepth) by default. Add --max-depth N for
#    operators who want to limit recursion.
#  - Drop the hardcoded extension whitelist. Let detect_type (called
#    by analyze_one) decide whether each file is analyzable. Add
#    --include-ext and --exclude-ext flags for operators who DO want
#    extension filtering at walk-time (faster than letting detect_type
#    skip thousands of irrelevant files later).
#  - Per-spec warning if a directory yielded zero files, so the
#    operator sees which directory was empty.
#  - --preserve-tree (opt-in): mirror input directory layout under -o
#    so output is organized by source-tree directory. Default remains
#    flat (per-target subdir under -o) for backward compatibility.
#
# Non-regular targets (sockets, FIFOs, devices) are silently filtered
# by `find -type f`. Symlinks: `find -type f` follows none by default;
# the existing readlink -f canonicalizes paths but doesn't dereference
# `find`'s symlink behavior. Operators wanting to follow symlinks can
# pass them explicitly as -t arguments.
#
# Note: TARGET_MAX_DEPTH, TARGET_INCLUDE_EXT_ARR, TARGET_EXCLUDE_EXT_ARR
# are initialized in the var-init block above and populated by the parser.
# Do NOT re-initialize them here or parser values will be wiped.

for spec in "${TARGETS[@]}"; do
    if [[ -f "$spec" ]]; then
        EXPANDED+=("$(readlink -f "$spec")")
        continue
    fi

    if [[ -d "$spec" ]]; then
        # Build find arguments dynamically per --max-depth / --include-ext /
        # --exclude-ext flags. We use bash array form so paths with spaces
        # are preserved through to find.
        find_args=("$spec")
        if [[ -n "$TARGET_MAX_DEPTH" ]]; then
            find_args+=(-maxdepth "$TARGET_MAX_DEPTH")
        fi
        find_args+=(-type f)

        # Apply --include-ext (allowlist) and --exclude-ext (denylist).
        # If both are set, include is applied first then exclude refines.
        if [[ ${#TARGET_INCLUDE_EXT_ARR[@]} -gt 0 ]]; then
            find_args+=(\()
            _first=1
            for e in "${TARGET_INCLUDE_EXT_ARR[@]}"; do
                e="${e#.}"
                if [[ $_first -eq 1 ]]; then
                    find_args+=(-iname "*.${e}"); _first=0
                else
                    find_args+=(-o -iname "*.${e}")
                fi
            done
            find_args+=(\))
        fi
        for e in "${TARGET_EXCLUDE_EXT_ARR[@]}"; do
            e="${e#.}"
            find_args+=(! -iname "*.${e}")
        done
        find_args+=(-print0)

        # Walk the directory.
        spec_count_before=${#EXPANDED[@]}
        while IFS= read -r -d '' f; do
            EXPANDED+=("$(readlink -f "$f")")
        done < <(find "${find_args[@]}" 2>/dev/null)

        spec_count_after=${#EXPANDED[@]}
        spec_added=$((spec_count_after - spec_count_before))
        if [[ $spec_added -eq 0 ]]; then
            log_warn "Directory yielded 0 files: $spec"
            log_warn "  (check --include-ext / --exclude-ext / --max-depth filters)"
        else
            log_info "Directory enumerated: $spec ($spec_added file(s))"
        fi
        continue
    fi

    # Glob path (not -f, not -d): bash word-split; -f filter per match.
    # shellcheck disable=SC2206
    matches=($spec)
    for m in "${matches[@]}"; do
        [[ -f "$m" ]] && EXPANDED+=("$(readlink -f "$m")")
    done
done

# Deduplicate preserving order
UNIQUE_TARGETS=()
declare -A seen
for t in "${EXPANDED[@]}"; do
    [[ -z "${seen[$t]:-}" ]] && { UNIQUE_TARGETS+=("$t"); seen[$t]=1; }
done

if [[ ${#UNIQUE_TARGETS[@]} -eq 0 ]]; then
    log_err "No files matched the specified targets"
    exit 2
fi

# v3.0.5 (audit-9 A6) -- compute TARGET_TREE_ROOT for --preserve-tree.
# When PRESERVE_TREE=1, lib/dispatch.sh > analyze_one will mirror the
# input directory layout under OUTPUT_ROOT. To map an input target to
# its output directory, we need the longest common path prefix shared
# by all UNIQUE_TARGETS -- that's the "tree root".
#
# Algorithm: start with the dirname of the first target as the candidate
# root. For each subsequent target, walk up the candidate's path
# components until the candidate is a prefix of (or equal to) the
# target's dirname. If we walk all the way up to "/" without finding a
# common ancestor, fall back to "/" (which means analyze_one's flat-
# fallback path will trigger).
#
# Edge cases handled:
#   - Single target: TARGET_TREE_ROOT = dirname(target). analyze_one
#     sees rel_dir == TARGET_TREE_ROOT and uses flat layout (correct;
#     no tree to preserve with one file).
#   - All targets in same dir: TARGET_TREE_ROOT = that dir. Output is
#     ${OUTPUT_ROOT}/${fname}/ for each (same as flat).
#   - Targets in subdirs of a common parent: TARGET_TREE_ROOT = parent.
#     Output is ${OUTPUT_ROOT}/${rel_subdir}/${fname}/.
#   - Targets across unrelated absolute paths: TARGET_TREE_ROOT = "/".
#     analyze_one falls through to flat (correct; no meaningful tree).
TARGET_TREE_ROOT=""
if [[ ${PRESERVE_TREE:-0} -eq 1 ]]; then
    # Initialize root to dirname of first target
    TARGET_TREE_ROOT=$(dirname "${UNIQUE_TARGETS[0]}")

    for t in "${UNIQUE_TARGETS[@]:1}"; do
        t_dir=$(dirname "$t")
        # Shrink TARGET_TREE_ROOT until it's a prefix of t_dir (or equal).
        # The == "$TARGET_TREE_ROOT/"* pattern checks "is t_dir under root";
        # the equality check handles "is t_dir exactly the root".
        while [[ "$t_dir" != "$TARGET_TREE_ROOT" && "$t_dir" != "$TARGET_TREE_ROOT"/* ]]; do
            local_parent=$(dirname "$TARGET_TREE_ROOT")
            if [[ "$local_parent" == "$TARGET_TREE_ROOT" ]]; then
                # Reached filesystem root; can't shrink further.
                TARGET_TREE_ROOT="/"
                break
            fi
            TARGET_TREE_ROOT="$local_parent"
        done
        # Bail early once we've collapsed to "/"
        [[ "$TARGET_TREE_ROOT" == "/" ]] && break
    done
    log_info "Preserve-tree: rooted at $TARGET_TREE_ROOT"
fi
export TARGET_TREE_ROOT


# -----------------------------------------------------------------------------
# Banner + plan summary (NEW in 2.1.0 -- upfront visibility)
# -----------------------------------------------------------------------------
cat <<BANNER

================================================================
 RE Pipeline (analyze-binaries.sh v${ANALYZER_VERSION})
================================================================
BANNER

log_info "Ghidra              : ${GHIDRA_INSTALL:-DISABLED}"
if [[ $SKIP_GHIDRA -eq 0 ]]; then
    # PyGhidra is required on Ghidra 12+ because PyGhidraScriptProvider
    # shadows Jython for .py postscripts in analyzeHeadless. If we have
    # Ghidra 12+ (detected by presence of the pyghidra_launcher.py file)
    # AND the pyghidra pip module is importable, go that way. Otherwise
    # fall back to plain analyzeHeadless (Jython) which only works on
    # Ghidra 11 and older.
    if [[ $FORCE_JYTHON -eq 1 ]]; then
        log_info "Ghidra Python       : forced Jython via analyzeHeadless (--force-jython)"
        log_warn "                      .py scripts will FAIL on Ghidra 12+ (PyGhidra shadow)"
    elif [[ $PYGHIDRA_AVAILABLE -eq 1 && -n "$PYGHIDRA_PY" ]]; then
        log_info "Ghidra Python       : PyGhidra auto (CPython 3 via $PYGHIDRA_PY)"
    elif [[ -f "${GHIDRA_INSTALL}/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py" ]]; then
        log_err  "Ghidra Python       : Ghidra 12+ detected but pyghidra module not importable"
        log_err  "                      .py postscripts WILL FAIL. Fix: pip install pyghidra"
        log_err  "                      into /opt/retools/venv, or re-run install-retoolkit.sh"
    else
        log_info "Ghidra Python       : Jython 2.7 via analyzeHeadless (Ghidra 11 or older)"
    fi
fi
log_info "PostScript          : ${SCRIPT_PATH:-(not found)}"
log_info "Python venv         : ${VENV_PY:-(not found)}"
log_info "ilspycmd            : ${ILSPYCMD:-(not found)}"
log_info "capa                : ${CAPA_CMD:-(not found)}"
log_info "capa rules          : ${CAPA_RULES:-(none -- capa will output no capabilities)}"
log_info "floss               : ${FLOSS_CMD:-(not found)}"
log_info "YARA rules          : ${YARA_RULES:-(none -- signature scan will no-op)}"
log_info "Output              : $OUTPUT_ROOT"
log_info "Targets             : ${#UNIQUE_TARGETS[@]} unique files"
log_info "Ghidra timeout      : ${GHIDRA_TIMEOUT}s"
log_info "Tool timeout        : ${TOOL_TIMEOUT}s"
log_info "JVM heap            : $JVM_HEAP"
log_info "Parallel            : $PARALLEL_WORKERS worker(s)"
echo ""

# Upfront warnings for likely-confusing situations
if [[ -z "$CAPA_RULES" ]] && [[ -n "$CAPA_CMD" ]]; then
    log_warn "capa is installed but CAPA_RULES is unset. capa will detect zero"
    log_warn "capabilities. Clone rules: git clone https://github.com/mandiant/capa-rules /opt/capa-rules"
fi
if [[ -z "$YARA_RULES" ]] && [[ $SKIP_YARA -eq 0 ]]; then
    log_warn "YARA rules not found. YARA scan will be skipped per target."
    log_warn "Clone rules: git clone https://github.com/Yara-Rules/rules /opt/yara-rules"
fi

mkdir -p "$OUTPUT_ROOT"


# =============================================================================
# PyGhidra headless helper script -- generated when PyGhidra is available
# =============================================================================
PYGHIDRA_HELPER="${OUTPUT_ROOT}/.pyghidra-headless.py"
if [[ $SKIP_GHIDRA -eq 0 && $PYGHIDRA_AVAILABLE -eq 1 && $FORCE_JYTHON -eq 0 ]]; then
    cat > "$PYGHIDRA_HELPER" <<'PYEOF'
#!/usr/bin/env python3
"""Bootstrap PyGhidra and run a Ghidra post-script on a binary.

Written by analyze-binaries.sh (RE-Toolkit RE pipeline).

This uses `pyghidra.run_script()` -- the public pyghidra API that wraps
HeadlessAnalyzer internally. v2.1.3 tried `AnalyzeHeadless.main` directly
through JPype but JPype doesn't expose Java static main methods as Python
callable attributes.

v2.1.6 adds CWD reporting before/after run_script() and a dump-file hunt
if the expected path is missing -- helps diagnose relative-path issues
(pyghidra may change CWD internally, so any relative path in script_args
will resolve against whatever CWD pyghidra has at script-run time).

Usage:
    python pyghidra-headless.py <GHIDRA_INSTALL_DIR> \\
                                <binary_path> \\
                                <script_path> \\
                                <project_location> \\
                                <project_name> \\
                                [script_args...]
"""
import os, sys, glob, traceback

if len(sys.argv) < 6:
    print("usage: pyghidra-headless.py <GHIDRA_INSTALL_DIR> <binary> "
          "<script> <project_loc> <project_name> [script_args...]",
          file=sys.stderr)
    sys.exit(2)

ghidra_install  = sys.argv[1]
binary_path     = sys.argv[2]
script_path     = sys.argv[3]
project_loc     = sys.argv[4]
project_name    = sys.argv[5]
script_args     = sys.argv[6:]

os.environ["GHIDRA_INSTALL_DIR"] = ghidra_install

try:
    import pyghidra
except ImportError as e:
    print(f"ERROR: pyghidra pip module not importable: {e}", file=sys.stderr)
    print("Install with: pip install pyghidra (into /opt/retools/venv)", file=sys.stderr)
    sys.exit(3)

print(f"[pyghidra-headless] install_dir  = {ghidra_install}", file=sys.stderr)
print(f"[pyghidra-headless] binary       = {binary_path}",    file=sys.stderr)
print(f"[pyghidra-headless] script       = {script_path}",    file=sys.stderr)
print(f"[pyghidra-headless] project_loc  = {project_loc}",    file=sys.stderr)
print(f"[pyghidra-headless] project_name = {project_name}",   file=sys.stderr)
print(f"[pyghidra-headless] script_args  = {script_args}",    file=sys.stderr)
print(f"[pyghidra-headless] cwd before   = {os.getcwd()}",    file=sys.stderr)

# Extract dump_path from script_args for post-run verification.
expected_dump = None
for a in script_args:
    if a.startswith("dump-path="):
        expected_dump = a.split("=", 1)[1]
        break
if expected_dump:
    print(f"[pyghidra-headless] expected dump = {expected_dump}", file=sys.stderr)
    print(f"[pyghidra-headless] dump is {'ABSOLUTE' if os.path.isabs(expected_dump) else 'RELATIVE'}",
          file=sys.stderr)

# v3.7.2 (audit-30 A6): bound Ghidra's auto-analysis on the pyghidra path.
# The analyzeHeadless path sets -analysisTimeoutPerFile, but run_script() does
# not, so on a large managed/.NET assembly the auto-analysis (which happens
# BEFORE the dump script) can run until the outer wall-clock kill -- leaving no
# dump at all. We pass an analysis timeout through, but ONLY if this build of
# pyghidra's run_script() actually accepts such a parameter: we introspect the
# signature and match a known parameter name. If none matches, we pass nothing
# and behaviour is exactly as before (so the working native path is never
# disturbed). GHIDRA_ANALYSIS_TIMEOUT is exported by the 30-ghidra stage.
_run_kwargs = dict(
    binary_path       = binary_path,
    script_path       = script_path,
    project_location  = project_loc,
    project_name      = project_name,
    script_args       = script_args,
    verbose           = False,
    analyze           = True,
    nested_project_location = True,
)
try:
    _atimeout = os.environ.get("GHIDRA_ANALYSIS_TIMEOUT", "").strip()
    if _atimeout and _atimeout.isdigit() and int(_atimeout) > 0:
        import inspect as _inspect
        _params = _inspect.signature(pyghidra.run_script).parameters
        for _cand in ("analysis_timeout_per_file", "analysis_timeout",
                      "analysisTimeoutPerFile", "max_cpu", "timeout"):
            if _cand in _params:
                _run_kwargs[_cand] = int(_atimeout)
                print(f"[pyghidra-headless] analysis timeout bound via '{_cand}'={_atimeout}s",
                      file=sys.stderr)
                break
        else:
            print("[pyghidra-headless] run_script() exposes no analysis-timeout "
                  "parameter; auto-analysis is bounded only by the outer wall-clock",
                  file=sys.stderr)
except Exception as _e:
    # Never let timeout wiring break the run; fall back to the prior behaviour.
    print(f"[pyghidra-headless] analysis-timeout wiring skipped: {_e}", file=sys.stderr)

try:
    pyghidra.run_script(**_run_kwargs)
    print("[pyghidra-headless] run_script() returned cleanly", file=sys.stderr)
except SystemExit:
    raise
except Exception as e:
    print(f"ERROR: pyghidra.run_script() raised: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(5)

print(f"[pyghidra-headless] cwd after    = {os.getcwd()}", file=sys.stderr)

# Post-run verification: did the dump actually land where we expected?
if expected_dump:
    if os.path.isfile(expected_dump):
        size = os.path.getsize(expected_dump)
        print(f"[pyghidra-headless] dump OK       = {expected_dump} ({size} bytes)",
              file=sys.stderr)
    else:
        print(f"[pyghidra-headless] dump MISSING  = {expected_dump}", file=sys.stderr)
        print(f"[pyghidra-headless] searching filesystem for the dump by basename…",
              file=sys.stderr)
        basename = os.path.basename(expected_dump)
        search_roots = [os.getcwd(), os.path.dirname(project_loc) or ".",
                        project_loc, ghidra_install, os.path.expanduser("~")]
        found = []
        seen = set()
        for root in search_roots:
            if root in seen or not root or not os.path.isdir(root):
                continue
            seen.add(root)
            try:
                for match in glob.iglob(os.path.join(root, "**", basename), recursive=True):
                    found.append(match)
                    if len(found) >= 10:
                        break
            except Exception:
                pass
            if len(found) >= 10:
                break
        if found:
            print(f"[pyghidra-headless] found matching file(s) at:", file=sys.stderr)
            for m in found:
                try:
                    sz = os.path.getsize(m)
                except OSError:
                    sz = "?"
                print(f"    {m}  ({sz} bytes)", file=sys.stderr)
        else:
            print(f"[pyghidra-headless] no matching file found anywhere we searched",
                  file=sys.stderr)
            print(f"[pyghidra-headless] searched: {list(seen)}", file=sys.stderr)
PYEOF
    chmod +x "$PYGHIDRA_HELPER"
fi

# =============================================================================
# Record toolkit versions (function defined in lib/ghidra-helper.sh)
# =============================================================================
write_toolkit_versions

# =============================================================================
# Dispatch -- main per-target orchestration loop
# =============================================================================
START_TS=$(date +%s)
SUCCESS_COUNT=0
FAIL_COUNT=0
FAILED_FILES=()

# v2.2.0: central run log. Start it now that OUTPUT_ROOT exists.
_RUN_LOG_PATH="${OUTPUT_ROOT}/_run.log"
: > "$_RUN_LOG_PATH"
echo "# RE-Toolkit v${ANALYZER_VERSION} run log -- started $(date -Iseconds)" >> "$_RUN_LOG_PATH"

rm -f "${OUTPUT_ROOT}/_run-manifest.txt"
echo "# Run manifest -- generated $(date -Iseconds)" > "${OUTPUT_ROOT}/_run-manifest.txt"
echo "# filename|detected-type" >> "${OUTPUT_ROOT}/_run-manifest.txt"

log_info "Starting analysis of ${#UNIQUE_TARGETS[@]} target(s)…"

if [[ $PARALLEL_WORKERS -gt 1 ]]; then
    log_warn "Parallel mode: $PARALLEL_WORKERS workers (live output suppressed)"
    log_warn "Per-worker logs: ${OUTPUT_ROOT}/.results/worker-*.log"

    # v3.7.1 (audit-29 hotfix): DO NOT export the pipeline functions through
    # the environment. Exporting a shell function makes bash place its whole
    # body into envp as BASH_FUNC_<name>%%=() { ... }. The largest stage
    # functions are the entire sourced stage files (stage_report ~155KB,
    # stage_summary ~127KB), which individually exceed the Linux per-env-var
    # limit MAX_ARG_STRLEN (128KB = 32 * page size). Once such an oversized
    # variable is in the environment, execve() of EVERY child fails with E2BIG
    # ("Argument list too long") -- even for argument-less commands like
    # date/sleep. Instead, the worker sources the lib + stage files itself (see
    # the worker.sh heredoc below), defining the functions in its own process
    # with no environment-size limit. Only the small SCALAR config below is
    # exported. (Root cause + fix: L72.)
    export RETOOLKIT_LIB_DIR RETOOLKIT_STAGES_DIR
    export OUTPUT_ROOT SKIP_GHIDRA SKIP_GHIDRA_DOTNET SKIP_DOTNET SKIP_CAPA \
           SKIP_FLOSS SKIP_CLAMAV SKIP_YARA SKIP_R2 SKIP_BULK SKIP_DE4DOT \
           SKIP_MANALYZE SKIP_PEFRAME SKIP_CHECKSEC SKIP_SCANELF SKIP_DUMPELF \
           SKIP_PAHOLE SKIP_BLOATY SKIP_NM_DEMANGLED SKIP_SIGNSRCH \
           SKIP_EAZFIXER SKIP_OLDROD SKIP_DNSPY_EX USE_NOFUSEREX \
           ENABLE_CWE_CHECKER \
           SKIP_MACHO SKIP_WASM SKIP_PYC SKIP_JAR SKIP_PDF SKIP_OLE \
           SKIP_GO_DETECT SKIP_RUST_DETECT \
           SKIP_FUZZYHASH SKIP_CRYPTOKEYS SKIP_AUTHENTICODE \
           ENABLE_ANGR ANGR_TIMEOUT DIFF_AGAINST ENABLE_YARGEN YARGEN_TIMEOUT \
           SKIP_APK SKIP_DEX SKIP_AXML SKIP_APKSIG \
           SKIP_VIZ \
           DYNAMIC DYNAMIC_MODE DYNAMIC_AUTO DYNAMIC_TIMEOUT DYNAMIC_NETWORK \
           ALLOW_REAL_EXECUTION \
           SKIP_DYNAMIC_QILING SKIP_DYNAMIC_FIREJAIL \
           SKIP_DYNAMIC_DOCKER SKIP_DYNAMIC_CUCKOO SKIP_DYNAMIC_TRACE \
           SKIP_ROP_GADGETS SKIP_BINARY_DIFF SKIP_RETDEC \
           RETOOLKIT_REFERENCE_BINARY \
           DEEP_ANALYSIS KEEP_PROJECT \
           ANALYZE_HEADLESS SCRIPT_PATH GHIDRA_INSTALL GHIDRA_TIMEOUT \
           TOOL_TIMEOUT JVM_HEAP VENV_PY ILSPYCMD CAPA_CMD CAPA_RULES \
           FLOSS_CMD YARA_RULES RETOOLS_VENV VENV_BIN OVERWRITE VERBOSE \
           PYGHIDRA_AVAILABLE PYGHIDRA_PY USE_PYGHIDRA FORCE_JYTHON \
           PYGHIDRA_HELPER GHIDRA_INSTALL
    export C_INFO C_OK C_WARN C_ERR C_BOLD C_DIM C_OFF

    RESULT_DIR="${OUTPUT_ROOT}/.results"
    mkdir -p "$RESULT_DIR"; rm -f "${RESULT_DIR:?}"/*
    export RESULT_DIR

    WORKER="${RESULT_DIR}/worker.sh"
    cat > "$WORKER" <<'WORKER_EOF'
#!/usr/bin/env bash
set -uo pipefail

# v3.7.1 (audit-29 hotfix): define the pipeline functions by SOURCING the lib
# and stage files in this worker process, rather than inheriting them from the
# parent through the environment. Exported shell functions become environment
# variables (BASH_FUNC_<name>%%=() { ... }); the largest stage functions exceed
# the Linux per-env-var limit (MAX_ARG_STRLEN, 128KB), which makes execve() fail
# with E2BIG for every child. Sourcing keeps the functions in files with no
# size limit. The parent exports RETOOLKIT_LIB_DIR / RETOOLKIT_STAGES_DIR (small
# scalars) plus all the scalar config the stages need. Load order matches the
# driver bootstrap: common.sh first.
source "$RETOOLKIT_LIB_DIR/common.sh"
source "$RETOOLKIT_LIB_DIR/tool-runner.sh"
source "$RETOOLKIT_LIB_DIR/ghidra-helper.sh"
source "$RETOOLKIT_LIB_DIR/detect-type.sh"
source "$RETOOLKIT_LIB_DIR/viz-helper.sh"
source "$RETOOLKIT_LIB_DIR/dispatch.sh"
source "$RETOOLKIT_LIB_DIR/aggregate.sh"
for _stage in "$RETOOLKIT_STAGES_DIR"/static/*.sh; do
    # shellcheck disable=SC1090
    source "$_stage"
done
retoolkit_setup_colors

IFS=$'\t' read -r target idx total
fname=$(basename "$target")
logf="${RESULT_DIR}/worker-${fname}.log"
{
    echo "=== Worker start: $fname ($idx/$total) $(date -Iseconds) ==="
    if analyze_one "$target" "$idx" "$total"; then
        touch "${RESULT_DIR}/ok-${fname}"
    else
        touch "${RESULT_DIR}/fail-${fname}"
    fi
    echo "=== Worker end: $fname $(date -Iseconds) ==="
} >> "$logf" 2>&1
WORKER_EOF
    chmod +x "$WORKER"

    MANIFEST="${RESULT_DIR}/manifest.txt"
    : > "$MANIFEST"
    i=0
    for t in "${UNIQUE_TARGETS[@]}"; do
        i=$((i+1))
        printf '%s\t%d\t%d\n' "$t" "$i" "${#UNIQUE_TARGETS[@]}" >> "$MANIFEST"
    done

    (
        xargs -P "$PARALLEL_WORKERS" -I {} -d '\n' -a "$MANIFEST" \
            bash -c 'echo "$@" | '"$WORKER"' ' _ {}
    ) &
    XARGS_PID=$!

    TOTAL="${#UNIQUE_TARGETS[@]}"
    LAST_DONE=-1
    while kill -0 "$XARGS_PID" 2>/dev/null; do
        sleep 30
        done_ct=$(find "$RESULT_DIR" -maxdepth 1 \( -name 'ok-*' -o -name 'fail-*' \) 2>/dev/null | wc -l)
        if [[ "$done_ct" != "$LAST_DONE" ]]; then
            log_info "Progress: $done_ct / $TOTAL complete"
            LAST_DONE="$done_ct"
        fi
    done
    wait "$XARGS_PID" || true

    for t in "${UNIQUE_TARGETS[@]}"; do
        fname=$(basename "$t")
        if [[ -f "${RESULT_DIR}/ok-${fname}" ]]; then
            SUCCESS_COUNT=$((SUCCESS_COUNT+1))
        else
            FAIL_COUNT=$((FAIL_COUNT+1))
            FAILED_FILES+=("$fname")
        fi
    done
else
    i=0
    for t in "${UNIQUE_TARGETS[@]}"; do
        i=$((i+1))
        if analyze_one "$t" "$i" "${#UNIQUE_TARGETS[@]}"; then
            SUCCESS_COUNT=$((SUCCESS_COUNT+1))
        else
            FAIL_COUNT=$((FAIL_COUNT+1))
            FAILED_FILES+=("$(basename "$t")")
        fi
    done
fi

TOTAL_ELAPSED=$(( $(date +%s) - START_TS ))


# =============================================================================
# Aggregate codebase outputs (functions defined in lib/aggregate.sh)
# =============================================================================
write_summary
write_run_json_and_index
# v2.7.0: codebase-level similarity matrix from per-binary fuzzy hashes
if [[ ${SKIP_FUZZYHASH:-0} -eq 0 ]]; then
    write_similarity_matrix "$OUTPUT_ROOT"
    # v2.9.0: codebase-level cluster graph (force-directed) from same fuzzy hashes
    if [[ ${SKIP_VIZ:-0} -eq 0 ]]; then
        write_cluster_graph "$OUTPUT_ROOT"
    fi
fi
# v3.4.0 (audit-25): depth/integration aggregate outputs.
# A5.6 -- threat-intel export (STIX 2.1 / MISP / flat JSON) for TIP ingestion.
# A5.5 -- composite intelligence view (shared IOCs/packers/imports + campaign
#         ATT&CK heatmap) for multi-sample investigations. Both are pure-
#         additive: they read finished per-binary output and write codebase-
#         level files to OUTPUT_ROOT. A5.5 self-skips for a single target.
write_threat_intel_export "$OUTPUT_ROOT"
if [[ ${SKIP_VIZ:-0} -eq 0 ]]; then
    write_composite_intel "$OUTPUT_ROOT"
fi

# =============================================================================
# Console summary
# =============================================================================
cat <<SUMMARY

================================================================
 Analysis Complete
================================================================
  Total targets   : ${#UNIQUE_TARGETS[@]}
  Successful      : ${C_OK}${SUCCESS_COUNT}${C_OFF}
  Failed          : ${C_ERR}${FAIL_COUNT}${C_OFF}
  Elapsed         : $((TOTAL_ELAPSED / 60))m $((TOTAL_ELAPSED % 60))s
  Output root     : $OUTPUT_ROOT
  Summary (md)    : $OUTPUT_ROOT/_summary.md
  Run manifest    : $OUTPUT_ROOT/_run.json
  Run log         : $OUTPUT_ROOT/_run.log
  Codebase index  : $OUTPUT_ROOT/index.html
  Toolkit versions: $OUTPUT_ROOT/_toolkit-versions.txt

SUMMARY

if [[ $FAIL_COUNT -gt 0 ]]; then
    log_warn "Failed targets:"
    for f in "${FAILED_FILES[@]}"; do printf "    - %s\n" "$f"; done
fi

exit 0
