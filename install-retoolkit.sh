#!/usr/bin/env bash
#
# Synopsis:
#     Install a complete reverse engineering toolkit on Debian/Kali systems.
#
# Description:
#     Debian-native installer for a holistic RE workstation. Installs every
#     tool that adds value for static binary analysis: disassemblers,
#     decompilers, PE/ELF parsers, pattern matchers, decoders, and
#     supporting Python libraries. Uses apt wherever possible, falls back
#     to vendor installers ONLY when a tool isn't packaged.
#
#     Layered architecture:
#
#     LAYER 0 -- Analyzer source installation:
#       /opt/retoolkit/analyze-binaries.sh
#       /opt/retoolkit/lib/{common,tool-runner,ghidra-helper,detect-type,dispatch,aggregate}.sh
#       /opt/retoolkit/stages/static/*.sh (46 stage scripts)
#       /opt/retoolkit/GhidraDump.py
#       /usr/local/bin/analyze-binaries.sh -> /opt/retoolkit/analyze-binaries.sh
#       Skip with --skip-source if you only want dependencies installed.
#
#     LAYER 1 (apt) -- system binaries, pre-packaged for Debian/Kali:
#       Core analysis: radare2, rizin, yara, binwalk, foremost, binutils,
#         upx-ucl, clamav, exiftool, mono-devel + mono-utils,
#         openjdk-21-jdk, xmlstarlet, xmllint, ltrace/strace/gdb, python3.
#       Build deps: cmake, libboost-*-dev, libssl-dev, swig,
#         autoconf/automake/libtool/pkg-config (for ssdeep),
#         build-essential, gcc, make.
#       Format-specific: wabt (WebAssembly), mupdf-tools+qpdf (PDF),
#         default-jdk-headless (Java), bsdiff+vbindiff (binary diff),
#         sleuthkit (forensics), firejail (Tier 2 sandbox).
#       Skip with --skip-apt. NOTE: failures here may be recovered by
#       LAYER 2H source builds; wait for the post-LAYER-2H summary
#       before treating apt-stage misses as final.
#
#     LAYER 2 (Microsoft apt repo) -- .NET SDK:
#       Adds packages-microsoft-prod GPG key and apt source.
#       Installs dotnet-sdk-8.0.
#       Installs ilspycmd as the invoking user (dotnet tool install -g)
#       with version-fallback chain.
#       Skip with --skip-dotnet.
#
#     LAYER 2B -- Detect It Easy (DIE):
#       Packer/compiler/protector fingerprinter. Source build via cmake;
#       ships diec CLI for batch fingerprinting.
#
#     LAYER 2C -- de4dot-cex (.NET deobfuscator):
#       ViRb3 fork of de4dot, the canonical .NET deobfuscator.
#       Source build via dotnet/msbuild/xbuild fallback chain.
#       Handles ConfuserEx, Eazfuscator, .NET Reactor, SmartAssembly,
#       and many others. (Replaces the dropped EazFixer
#       for the Eazfuscator family.)
#
#     LAYER 2D -- TrID signature database bootstrap:
#       Downloads + extracts TrID's signature database (~14k filetype
#       definitions) into /opt/trid/. trid binary install handled by
#       LAYER 2H if apt didn't ship it.
#
#     LAYER 2E -- GitHub-release tools (.NET deob + PE analyzers):
#       dnSpyEx (.NET decompiler) -- release zip
#       OldRod (.NET method-virtualizer deob) -- source build
#       NoFuserEx (ConfuserEx alternative deob) -- source build
#
#       signsrch (binary IOC scanner) -- source build with -std=gnu89
#       Manalyze (PE static analyzer) -- source build with cmake
#       NOTE: EazFixer is no longer installed (build-infra
#       dependency hell unsolvable on Linux without non-redistributable
#       Microsoft Targeting Packs; de4dot-cex covers the same family).
#
#     LAYER 2F -- yarGen (YARA rule generator):
#       Always installs the script. Goodware DB (~913MB) opt-in via
#       --with-yargen-db.
#
#     LAYER 2G -- Mobile RE tools fallback:
#       jadx (Android decompiler), apktool (APK reassembler),
#       baksmali (Dalvik disassembler) -- source builds when not in apt.
#
#     LAYER 2H -- apt-fallback source builds:
#       Recovers tools whose apt packages are missing on Kali Rolling:
#         pev    -> mentebinaria/readpe (project renamed upstream)
#         bloaty -> google/bloaty (cmake build)
#         trid   -> mark0.net direct download (closed-source freeware)
#       On success, removes package from FAILED_APT[] so LAYER 12
#       verification reflects true tool availability.
#
#     LAYER 3 (Python venv at /opt/retools/venv) -- RE-specific Python libs:
#       PE/ELF/Mach-O: pefile, dnfile, lief, capstone, keystone-engine,
#         unicorn==2.1.2, pyghidra (Ghidra 12+ postscripts)
#       Analysis: yara-python, flare-capa, flare-floss, angr, r2pipe,
#         rzpipe, pwntools (with ROP wiring)
#       Office/PDF: oletools, msoffcrypto-tool, peepdf-3
#       Crypto/cert: M2Crypto>=0.47.0 (peframe transitive; source-builds
#         on Linux via SWIG)
#       Fuzzy hashing: ssdeep (with scoped setuptools<81 plus the
#                 autoconf chain), python-tlsh
#       Decompilers: uncompyle6, decompyle3 (Python <= 3.8 bytecode)
#       Behavioral: peframe (PE behavioral static analyzer)
#       Dynamic: qiling (default-safe emulator for LAYER 8)
#       Skip with --skip-python.
#
#     LAYER 4 (NSA GitHub) -- Ghidra latest PUBLIC release:
#       Extracted to /opt/ghidra_<ver>_PUBLIC, stable symlink at
#       /opt/ghidra, GHIDRA_INSTALL_DIR wired into shell rc.
#       Skip with --skip-ghidra.
#
#     LAYER 4B -- cwe_checker (OPT-IN via --with-cwe-checker):
#       Rust-based static CWE detector that runs on top of Ghidra.
#       Cost: ~5-10 min Rust build via rustup/cargo. Opt-in because
#       of build cost AND because cwe_checker is itself opt-in at run
#       time (--enable-cwe-checker on the analyzer).
#
#     LAYER 4C -- redress (OPT-IN via --with-redress):
#       Go binary analyzer (Go-Reverse Engineering toolkit). Builds
#       via 'go install github.com/goretk/redress@latest'. Sets a
#       GOTMPDIR override (Go's $WORK on tmpfs /tmp can exhaust
#       RAM despite host having TBs free) plus 2GB disk-space gate.
#
#     LAYER 4D -- rustfilt (OPT-IN via --with-rustfilt):
#       Rust-mangled-symbol demangler. Built via 'cargo install rustfilt';
#       piggybacks on the rustup install used by LAYER 4B.
#
#     LAYER 4E -- findaes (OPT-IN via --with-findaes):
#       AES key schedule memory scanner. Earlier hardcoded GitHub URLs
#       404'd and triggered git auth prompts; the install now uses a
#       verified SourceForge tarball
#       (canonical findaes 1.2 release) with makomk/aeskeyfind GitHub
#       fallback.
#
#     LAYER 5 -- RULES population:
#       /opt/capa-rules    via git clone mandiant/capa-rules
#       /opt/yara-rules    via git clone Yara-Rules/rules (+ master.yar index)
#       Exported as CAPA_RULES and YARA_RULES env vars in
#       /etc/profile.d/retools.sh so the analyzer picks them up.
#       Skip with --skip-rules.
#
#     LAYER 6 -- INTENTIONALLY SKIPPED (number was renamed to LAYER 12;
#       earlier versions had post-install
#       verification at LAYER 6 which was misleading because that
#       layer ran LAST after LAYERs 7-11).
#
#     LAYER 7 -- INTENTIONALLY SKIPPED (never used; reserved for future).
#
#     LAYER 8 -- Dynamic analysis: qiling emulator (Tier 1):
#       Default-safe dynamic-analysis tier. qiling emulates syscalls
#       in pure Python without making real OS calls. No host risk.
#       qiling-rootfs cloned to /opt/qiling-rootfs for x86/x86_64/ARM
#       PE and ELF emulation. Active by default when --dynamic is passed
#       to the analyzer; --dynamic-mode=qiling explicitly selects it.
#
#     LAYER 9 (opt-in via --with-docker) -- Docker tier (Tier 3):
#       retoolkit-dynamic image built from Debian bookworm + strace +
#       ltrace + wine + wine64. NOTE: wine32 is not installed
#       (replaced by libwine in bookworm). Container runs with
#       --network=none and a read-only sample mount; provides
#       isolation for actually-running PE binaries via Wine. Activated
#       at run time via --dynamic-mode=docker (requires
#       --allow-real-execution).
#
#     LAYER 10 -- Cuckoo tier
#       (Tier 4): Verifies cuckoo presence and provides install hints.
#       Full cuckoo setup is environment-specific (requires hypervisor +
#       analyst-VM + agent setup); the installer does NOT attempt
#       automated cuckoo install. Activated at run time via
#       --dynamic-mode=cuckoo (requires --allow-real-execution + cuckoo
#       configured). Skip-friendly: if cuckoo absent, the dynamic-mode
#       degrades gracefully to docker or qiling.
#
#     LAYER 11 -- RetDec
#       decompiler: Avast's open-source machine-code decompiler.
#       Docker-based (requires --with-docker or pre-installed Docker).
#       The image was switched from the non-existent retdec/retdec to
#       bannsec/retdec (primary) with remnux/retdec (fallback).
#       Wrapper installed at /opt/retdec/decompile.sh; activates
#       stage_retdec at analyzer run time.
#
#     LAYER 12 (renumbered from LAYER 6) -- Post-install
#       verification:
#       Every tool the installer claims to have installed is INVOKED
#       (--version / -h / -v) and a PASS/FAIL table is printed at the
#       end, along with the path to the per-phase install log for any
#       failures. Runs LAST after every other LAYER (1-11) so the
#       summary reflects the true post-install state. Originally numbered
#       6 when the toolkit had only 6 layers; later renumbered to 12
#       because additional layers (7-11) were added over time and the
#       original "6" was misleading about execution order.
#
# Notes:
#     - Targets Kali Rolling 2024+ and Debian 12+
#     - Idempotent: re-run safely; existing installs detected and skipped
#     - Requires sudo (system-wide install by design)
#     - Every install phase writes its stdout+stderr to /var/log/retoolkit/
#       so NO error is silently swallowed -- a key change from 2.0.0
#     - Ghidrathon is NOT installed by default (breaks GUI on some Java 21
#       builds). Pass --install-ghidrathon to opt in anyway.
#
# Execution Parameters:
#
#   PHASE-SKIP FLAGS (for partial / incremental installs):
#     --skip-apt            Skip LAYER 1 apt package install phase
#     --skip-dotnet         Skip LAYER 2 Microsoft .NET SDK + ilspycmd
#     --skip-python         Skip LAYER 3 Python venv + libraries
#     --skip-ghidra         Skip LAYER 4 Ghidra install (leaves existing /opt/ghidra)
#     --skip-rules          Skip LAYER 5 capa/yara rules cloning
#     --skip-source         Skip LAYER 0 analyzer source install to /opt/retoolkit/
#                            (use this if you only want dependencies installed
#                            and intend to run analyze-binaries.sh from a
#                            developer checkout instead of /opt/retoolkit/)
#
#   OPT-IN COMPONENT FLAGS (extra capabilities, off by default):
#     --with-cwe-checker    Install cwe_checker (LAYER 4B; ~5-10 min Rust build;
#                            installs rustup if not present)
#     --with-redress        Install redress for Go binary analysis (LAYER 4C;
#                            uses GOTMPDIR=/var/cache/retoolkit/go-build-tmp
#                                           to avoid tmpfs /tmp exhaustion)
#     --with-rustfilt       Install rustfilt for Rust name demangling (LAYER 4D;
#                            piggybacks on --with-cwe-checker's rustup install)
#     --with-findaes        Build findaes AES key memory scanner (LAYER 4E;
#                                        SourceForge tarball + makomk/aeskeyfind
#                            fallback; no GitHub auth prompts)
#     --with-yargen-db      Download yarGen goodware DB (~913MB, LAYER 2F;
#                            without this, yarGen runs but cannot generate
#                            rules that rely on goodware filtering)
#
#   DYNAMIC-ANALYSIS TIER FLAGS (opt-in due to runtime cost and risk):
#     --with-docker         Install docker + build retoolkit-dynamic image
#                            (LAYER 9; required for analyzer --dynamic-mode=docker;
#                                       dropped wine32 from Dockerfile because
#                            Debian bookworm replaced it with libwine)
#     --with-cuckoo         Verify cuckoo presence + provide install hints
#                            (LAYER 10; full setup is environment-specific
#                            requiring hypervisor + analyst-VM + agent setup;
#                            installer does NOT attempt automated cuckoo install)
#     --with-retdec         Pull RetDec Docker image + install wrapper
#                            (LAYER 11; image is bannsec/retdec
#                            primary with remnux/retdec fallback;
#                            note that retdec/retdec:latest was a
#                            non-existent image name previously)
#
#   BEHAVIORAL FLAGS:
#     --force               Reinstall everything (overwrite existing).
#                            Use when source-builds need to be redone after
#                            an upstream patch or an environment change.
#                            Without --force, idempotency means existing
#                            installations are detected and skipped.
#     --verify              Run ONLY the post-install verification (LAYER 12)
#                            against an existing install; skip all install
#                            work (LAYERs 0-11). Produces a PASS/FAIL matrix
#                            of every tool. Use to health-check an install
#                            without reinstalling, or to confirm a silently-
#                            failed install (the failure mode that started
#                            the investigation).
#     --install-ghidrathon  Install Ghidrathon (Ghidra Python 3 scripting).
#                            OPT-IN because Ghidrathon may break the Ghidra
#                            GUI on some Java 21 builds. Not needed for
#                            command-line analyzer use (which uses pyghidra
#                            from LAYER 3 instead).
#
#   LOGGING / METADATA FLAGS (standard developmental conventions):
#     --verbose | -v        Verbose output. Alias for --log-level=debug
#                            when LOG_LEVEL is at default. If you've
#                            explicitly set --log-level (e.g. =warn),
#                            --verbose will NOT override it.
#     --log-level LEVEL     Set log verbosity. Accepts: debug, info (default),
#                            warn, error. Each level emits its own messages
#                            and all higher-priority levels:
#                              debug = log_dbg + log_info + log_warn + log_err
#                              info  = log_info + log_warn + log_err
#                              warn  = log_warn + log_err
#                              error = log_err only
#                            Also accepts --log-level=LEVEL (equals form).
#                            log_ok and log_hdr emit at info-level.
#     --version | -V        Print installer version and exit 0
#     --help    | -h        Show this help and exit 0
#
# RUN-TIME ANALYZER FLAGS (separate program; not parsed by this installer):
#     The analyzer (analyze-binaries.sh) has its own ~63 run-time flags
#     for stage selection, dynamic-analysis tier choice, output paths,
#     and per-tool toggles. They are NOT documented here. After install,
#     run:
#         analyze-binaries.sh --help
#     for the full analyzer flag reference. Key analyzer flags include:
#         --dynamic, --dynamic-mode={qiling|firejail|docker|cuckoo}
#         --allow-real-execution, --dynamic-timeout, --dynamic-network
#         --enable-cwe-checker, --enable-yargen, --enable-angr
#         --no-<stage>     to disable individual stages (~30 stages opt-out)
#         --diff-against   for binary diff against a reference sample
#         --capa-rules, --keep-project, --deep-analysis
#     See the Usage and Configuration wiki pages for the analyzer reference.
#
# Examples:
#     # Most common -- full install with default tiers:
#     sudo ./install-retoolkit.sh
#
#     # Kitchen-sink install (everything opt-in):
#     sudo ./install-retoolkit.sh --with-docker --with-cuckoo --with-retdec \
#         --with-redress --with-rustfilt --with-findaes --with-yargen-db \
#         --with-cwe-checker --install-ghidrathon
#
#     # Static analysis only, no Docker / dynamic tiers:
#     sudo ./install-retoolkit.sh
#     # (default: dynamic Tier 1 qiling is installed; Tiers 2-4 require
#     #  --with-* flags)
#
#     # Skip the Ghidra download (e.g., if you have a private Ghidra build):
#     sudo ./install-retoolkit.sh --skip-ghidra
#
#     # Dependencies only (no analyzer source files; you have your own checkout):
#     sudo ./install-retoolkit.sh --skip-source
#
#     # Reinstall all from scratch (after an environment change):
#     sudo ./install-retoolkit.sh --force
#
#     # Quiet mode (only errors):
#     sudo ./install-retoolkit.sh --log-level=error
#
#     # Debug mode (full trace including log_dbg):
#     sudo ./install-retoolkit.sh --log-level=debug
#
#     # Print version and exit (no install):
#     ./install-retoolkit.sh --version
#
# Version:
#     3.7.3 - 2026-05-03
#
#     Full release history, including per-version fixes, feature additions,
#     and audit batches, is maintained in CHANGELOG.md at the repository
#     root. It is deliberately not duplicated here: this header documents
#     what the script does now, not how it got here.
# =============================================================================

set -uo pipefail     # deliberately NO -e: installer must survive individual
                     # package failures and report them at the end.

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
SKIP_APT=0
SKIP_DOTNET=0
SKIP_PYTHON=0
SKIP_GHIDRA=0
SKIP_RULES=0
SKIP_SOURCE=0
WITH_CWE_CHECKER=0
WITH_REDRESS=0
WITH_RUSTFILT=0
WITH_YARGEN_DB=0
WITH_FINDAES=0
# v3.0.0: dynamic-analysis tier installation flags
WITH_DOCKER=0           # LAYER 9: docker + retoolkit-dynamic image
WITH_CUCKOO=0           # LAYER 10: cuckoo sandbox (rare; opt-in)
# v3.0.2 (audit-6): retdec opt-in via Docker
WITH_RETDEC=0           # LAYER 11: retdec decompiler (Docker-based; opt-in)
FORCE=0
INSTALL_GHIDRATHON=0
VERBOSE=0
# v3.1.0 (audit-22 A3.2): --verify runs ONLY the post-install verification
# (LAYER 12) against an existing install, skipping LAYERs 0-11. Lets the
# operator check tool health any time without a full reinstall. This reuses
# the existing, tested verify_tool harness rather than duplicating it -- the
# audit-20 investigation started from a silently-failed install, so a
# re-runnable verification mode catches that class immediately.
VERIFY_ONLY=0

# v3.0.3 (audit-7): standard developmental flags. RETOOLKIT_VERSION is the
# canonical version constant; --version prints it and exits 0. LOG_LEVEL
# gates log output: levels are debug=0, info=1, warn=2, error=3.
# log_dbg/log_info/log_warn/log_err each compare their level against
# LOG_LEVEL and suppress if too low. Default level is info (1) which
# matches v3.0.2 behavior so existing scripts behave identically.
RETOOLKIT_VERSION="3.7.3"
LOG_LEVEL="info"  # debug | info | warn | error

RETOOLS_BASE="/opt/retools"
RETOOLS_VENV="${RETOOLS_BASE}/venv"
GHIDRA_BASE="/opt"
GHIDRA_LINK="${GHIDRA_BASE}/ghidra"
CAPA_RULES_DIR="/opt/capa-rules"
YARA_RULES_DIR="/opt/yara-rules"
RETOOLKIT_INSTALL_DIR="/opt/retoolkit"
RETOOLKIT_BIN_LINK="/usr/local/bin/analyze-binaries.sh"
LOG_ROOT="/var/log/retoolkit"

# -----------------------------------------------------------------------------
# Arg parsing
# -----------------------------------------------------------------------------
print_help() { sed -n '/^# Synopsis/,/^# Version/p' "$0" | sed 's/^#\s\?//'; exit 0; }
print_version() { printf "RE-Toolkit installer v%s\n" "$RETOOLKIT_VERSION"; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-apt)            SKIP_APT=1; shift ;;
        --skip-dotnet)         SKIP_DOTNET=1; shift ;;
        --skip-python)         SKIP_PYTHON=1; shift ;;
        --skip-ghidra)         SKIP_GHIDRA=1; shift ;;
        --skip-rules)          SKIP_RULES=1; shift ;;
        --skip-source)         SKIP_SOURCE=1; shift ;;
        --with-cwe-checker)    WITH_CWE_CHECKER=1; shift ;;
        --with-redress)        WITH_REDRESS=1; shift ;;
        --with-rustfilt)       WITH_RUSTFILT=1; shift ;;
        --with-yargen-db)      WITH_YARGEN_DB=1; shift ;;
        --with-findaes)        WITH_FINDAES=1; shift ;;
        --with-docker)         WITH_DOCKER=1; shift ;;
        --with-cuckoo)         WITH_CUCKOO=1; shift ;;
        --with-retdec)         WITH_RETDEC=1; shift ;;
        --force)               FORCE=1; shift ;;
        --verify)              VERIFY_ONLY=1; shift ;;
        --install-ghidrathon)  INSTALL_GHIDRATHON=1; shift ;;
        --verbose|-v)          VERBOSE=1; shift ;;
        # v3.0.3 (audit-7): --log-level and --version standard developmental flags
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
        --version|-V)          print_version ;;
        --help|-h)             print_help ;;
        *)                     echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

# v3.0.3 (audit-7): map LOG_LEVEL string to numeric for fast compare in
# the log_* functions. _LOG_LEVEL_NUM is set once at parse time, then
# log_dbg/log_info/log_warn/log_err compare against it.
case "$LOG_LEVEL" in
    debug) _LOG_LEVEL_NUM=0 ;;
    info)  _LOG_LEVEL_NUM=1 ;;
    warn)  _LOG_LEVEL_NUM=2 ;;
    error) _LOG_LEVEL_NUM=3 ;;
esac
# Backward compatibility: --verbose flips to debug if LOG_LEVEL still default
if [[ $VERBOSE -eq 1 && "$LOG_LEVEL" == "info" ]]; then
    LOG_LEVEL="debug"
    _LOG_LEVEL_NUM=0
fi

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_INFO=$'\033[36m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'
    C_ERR=$'\033[31m';  C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
    C_DBG=$'\033[35m'
else
    C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_BOLD=""; C_DIM=""; C_OFF=""
    C_DBG=""
fi
# v3.0.3 (audit-7): log_* functions honor $LOG_LEVEL via $_LOG_LEVEL_NUM.
# Numeric comparison: 0=debug, 1=info, 2=warn, 3=error. A function emits
# only if its level is >= _LOG_LEVEL_NUM. log_ok and log_hdr are
# treated as info-level (always emit at info or below).
log_dbg()  { [[ ${_LOG_LEVEL_NUM:-1} -le 0 ]] && printf "%s[debug]%s %s\n" "$C_DBG" "$C_OFF" "$*"; return 0; }
log_info() { [[ ${_LOG_LEVEL_NUM:-1} -le 1 ]] && printf "%s[info]%s %s\n" "$C_INFO" "$C_OFF" "$*"; return 0; }
log_ok()   { [[ ${_LOG_LEVEL_NUM:-1} -le 1 ]] && printf "%s[ok]%s   %s\n" "$C_OK"   "$C_OFF" "$*"; return 0; }
log_warn() { [[ ${_LOG_LEVEL_NUM:-1} -le 2 ]] && printf "%s[warn]%s %s\n" "$C_WARN" "$C_OFF" "$*"; return 0; }
log_err()  { [[ ${_LOG_LEVEL_NUM:-1} -le 3 ]] && printf "%s[error]%s %s\n" "$C_ERR" "$C_OFF" "$*" >&2; return 0; }
log_hdr()  { [[ ${_LOG_LEVEL_NUM:-1} -le 1 ]] && printf "\n%s=== %s ===%s\n" "$C_BOLD" "$*" "$C_OFF"; return 0; }

# =============================================================================
# v3.0.15 (audit-19) -- safe_apt wrapper for concurrent apt locking
# =============================================================================
# On fresh Debian/Kali VMs, unattended-upgrades or the apt-daily systemd timer
# often runs concurrently with our installer, holding the dpkg-frontend lock.
# Pre-v3.0.15 our apt-get invocations failed silently when this happened:
# - LAYER 1 main install loop: failed packages went to FAILED_APT[] and
#   install continued without them. A failed openjdk-21-jdk install meant
#   no JVM at run-time, surfacing later as Stage 30 "NO DUMP PRODUCED (2s)
#   -- module-top never reached" because Ghidra/JVM couldn't even start.
# - LAYER 2B DIE: visible failure with helpful warning, but only because the
#   error message happened to be recognizable.
# - LAYER 2 .NET, LAYER 9 docker.io: similar silent failures possible.
#
# Audit-17's LAYER 1 expansion (10 added packages: cabextract, unrar-free,
# arj, lhasa, lzop, sleuthkit, cpio, cramfsswap, squashfs-tools, zstd)
# made LAYER 1 run longer, widening the window during which unattended-
# upgrades can be running concurrently. The contention probability went
# from "rare" to "frequent" on operator's fresh-VM tests.
#
# Fix: wait for /var/lib/dpkg/lock-frontend + /var/lib/dpkg/lock +
# /var/lib/apt/lists/lock + /var/cache/apt/archives/lock to all be free
# before invoking apt-get. Default timeout 600s (10 min). On timeout,
# log a warning and proceed anyway (may still fail but at least we tried).

wait_for_apt_lock() {
    local timeout="${1:-600}"
    local waited=0
    local interval=5
    local lock_files=(
        "/var/lib/dpkg/lock-frontend"
        "/var/lib/dpkg/lock"
        "/var/lib/apt/lists/lock"
        "/var/cache/apt/archives/lock"
    )
    local announced=0
    while true; do
        local any_held=0
        for lf in "${lock_files[@]}"; do
            if [[ -e "$lf" ]] && fuser "$lf" >/dev/null 2>&1; then
                any_held=1
                if [[ $announced -eq 0 ]]; then
                    local holder
                    holder=$(fuser "$lf" 2>&1 | awk '{print $NF}' | head -1)
                    log_info "Waiting for apt lock on $lf (held by PID ${holder:-?})"
                    log_info "  Common cause: unattended-upgrades or apt-daily systemd timer."
                    log_info "  Will check every ${interval}s up to ${timeout}s."
                    announced=1
                fi
                break
            fi
        done
        if [[ $any_held -eq 0 ]]; then
            [[ $announced -eq 1 ]] && log_ok "apt lock released after ${waited}s"
            return 0
        fi
        if [[ $waited -ge $timeout ]]; then
            log_warn "Timed out waiting for apt lock after ${timeout}s; proceeding anyway"
            return 1
        fi
        sleep $interval
        waited=$((waited + interval))
    done
}

# safe_apt: wrapper around apt-get that first waits for any concurrent
# apt/dpkg process to finish. All the rest of this installer's apt-get
# invocations are routed through here as of v3.0.15 (audit-19).
safe_apt() {
    wait_for_apt_lock 600 || true
    # v3.7.3 (audit-31 B1): force non-interactive apt. On Kali / Debian 12+,
    # installing packages that restart services (e.g. docker.io in LAYER 9)
    # triggers needrestart's interactive "which services should be restarted?"
    # prompt, which blocks on stdin and hangs the installer until the operator
    # presses Enter. DEBIAN_FRONTEND=noninteractive suppresses debconf prompts;
    # NEEDRESTART_MODE=a auto-restarts services; NEEDRESTART_SUSPEND=1 disables
    # the needrestart hook entirely as a belt-and-suspenders. stdin is also
    # redirected from /dev/null so nothing can block on a read.
    DEBIAN_FRONTEND=noninteractive \
    NEEDRESTART_MODE=a \
    NEEDRESTART_SUSPEND=1 \
        apt-get "$@" </dev/null
}
# =============================================================================
# end v3.0.15 (audit-19) safe_apt wrapper
# =============================================================================


# -----------------------------------------------------------------------------
# Sudo handling
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_err "This installer must run as root (system-wide install by design)"
    log_err "Usage: sudo ./install-retoolkit.sh"
    exit 1
fi

INVOKING_USER="${SUDO_USER:-root}"
if [[ "$INVOKING_USER" == "root" ]]; then
    INVOKING_HOME="/root"
else
    INVOKING_HOME=$(getent passwd "$INVOKING_USER" | cut -d: -f6)
fi
log_info "Invoking user: $INVOKING_USER  (home: $INVOKING_HOME)"

as_user() {
    if [[ "$INVOKING_USER" == "root" ]]; then
        "$@"
    else
        sudo -u "$INVOKING_USER" -H "$@"
    fi
}

# -----------------------------------------------------------------------------
# Per-phase log files. We never discard stderr; every phase writes to a
# dedicated log so failures stay diagnosable after the run.
# -----------------------------------------------------------------------------
mkdir -p "$LOG_ROOT"
RUN_TS=$(date +%Y%m%d-%H%M%S)
APT_LOG="${LOG_ROOT}/apt-${RUN_TS}.log"
DOTNET_LOG="${LOG_ROOT}/dotnet-${RUN_TS}.log"
PY_LOG="${LOG_ROOT}/pip-${RUN_TS}.log"
GHIDRA_LOG="${LOG_ROOT}/ghidra-${RUN_TS}.log"
RULES_LOG="${LOG_ROOT}/rules-${RUN_TS}.log"
VERIFY_LOG="${LOG_ROOT}/verify-${RUN_TS}.log"
SOURCE_LOG="${LOG_ROOT}/source-${RUN_TS}.log"
# v3.0.0: log path for dynamic-analysis tier installs (LAYER 8/9/10).
# Captures qiling pip install output, qiling rootfs git clone output,
# docker.io apt install output, docker build output, and cuckoo verification.
DYNAMIC_LOG="${LOG_ROOT}/dynamic-${RUN_TS}.log"
: > "$APT_LOG" "$DOTNET_LOG" "$PY_LOG" "$GHIDRA_LOG" "$RULES_LOG" "$VERIFY_LOG" "$SOURCE_LOG"

# Collect failures so they can be summarized at the end
FAILED_APT=()
FAILED_PY=()
FAILED_DOTNET=()
FAILED_RULES=()
FAILED_VERIFY=()
FAILED_SOURCE=()

# -----------------------------------------------------------------------------
# Banner
# -----------------------------------------------------------------------------
cat <<BANNER

================================================================
 RE Toolkit Installer for Debian/Kali  v3.0.0
================================================================

  Installs Ghidra + radare2 + rizin + yara + binwalk + capa +
  floss + pefile + dnfile + ilspycmd + monodis + angr + more.
  Clones capa rules + YARA rules. Verifies every tool post-install.

  Installation layout:
    /opt/retoolkit                   RE-Toolkit analyzer + lib + stages (NEW in 2.4.0)
    /usr/local/bin/analyze-binaries.sh  -> /opt/retoolkit/analyze-binaries.sh
    /opt/ghidra                      Ghidra (symlinked to versioned dir)
    /opt/retools/venv                Python RE tools (pefile, capa, etc.)
    /opt/capa-rules                  mandiant/capa-rules clone
    /opt/yara-rules                  Yara-Rules/rules clone
    ${INVOKING_HOME}/.dotnet/tools   dotnet tools (ilspycmd)

  Logs: ${LOG_ROOT}/*-${RUN_TS}.log

BANNER

# =============================================================================
# v3.1.0 (audit-22 A3.2) -- install-layers guard.
# When --verify is passed, skip ALL install work (LAYERs 0-11) and jump
# straight to LAYER 12 verification. This lets the operator health-check an
# existing install without reinstalling anything. The guard wraps exactly
# LAYERs 0-11; LAYER 12 (verification) always runs. The matching `fi` is just
# before LAYER 12 below.
# =============================================================================
if [[ ${VERIFY_ONLY:-0} -eq 0 ]]; then

# =============================================================================
# LAYER 0 -- Analyzer source installation (NEW in v2.4.0)
# =============================================================================
# Copies analyze-binaries.sh + lib/*.sh + stages/static/*.sh + GhidraDump.py
# to /opt/retoolkit/, then creates /usr/local/bin/analyze-binaries.sh symlink.
# Uses the directory containing this installer as the source location (so the
# installer ships alongside the analyzer in the source distribution).
# =============================================================================
if [[ $SKIP_SOURCE -eq 0 ]]; then
    log_hdr "LAYER 0 -- Analyzer source -> /opt/retoolkit/"

    # The installer assumes it sits next to analyze-binaries.sh, lib/, stages/,
    # and GhidraDump.py in the source tree. Resolve the installer's own dir.
    INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    log_info "Source directory: $INSTALLER_DIR"

    # Validate every required source asset exists before doing anything
    REQUIRED_FILES=(
        "${INSTALLER_DIR}/analyze-binaries.sh"
        "${INSTALLER_DIR}/GhidraDump.py"
        "${INSTALLER_DIR}/lib/common.sh"
        "${INSTALLER_DIR}/lib/tool-runner.sh"
        "${INSTALLER_DIR}/lib/ghidra-helper.sh"
        "${INSTALLER_DIR}/lib/detect-type.sh"
        "${INSTALLER_DIR}/lib/dispatch.sh"
        "${INSTALLER_DIR}/lib/aggregate.sh"
    )
    REQUIRED_DIRS=(
        "${INSTALLER_DIR}/stages/static"
    )
    missing=0
    for f in "${REQUIRED_FILES[@]}"; do
        if [[ ! -f "$f" ]]; then
            log_err "Required source file missing: $f"
            missing=$((missing + 1))
        fi
    done
    for d in "${REQUIRED_DIRS[@]}"; do
        if [[ ! -d "$d" ]]; then
            log_err "Required source directory missing: $d"
            missing=$((missing + 1))
        fi
    done
    # stages/static/ must contain at least one .sh file
    if [[ -d "${INSTALLER_DIR}/stages/static" ]]; then
        stage_count=$(find "${INSTALLER_DIR}/stages/static" -maxdepth 1 -name '*.sh' -type f | wc -l)
        if [[ $stage_count -lt 1 ]]; then
            log_err "stages/static/ contains no .sh files"
            missing=$((missing + 1))
        fi
    fi

    if [[ $missing -gt 0 ]]; then
        log_err "$missing required source asset(s) missing -- aborting LAYER 0"
        log_err "Run from a complete RE-Toolkit source tree, or pass --skip-source"
        FAILED_SOURCE+=("missing-source-assets")
    else
        # Per --force semantics: clear /opt/retoolkit/ first if it exists.
        # If --force is NOT passed and the install dir exists, refuse to
        # overwrite (operator may have local edits).
        if [[ -d "$RETOOLKIT_INSTALL_DIR" ]]; then
            if [[ $FORCE -eq 1 ]]; then
                log_info "Removing existing $RETOOLKIT_INSTALL_DIR (--force)"
                rm -rf "$RETOOLKIT_INSTALL_DIR" 2>>"$SOURCE_LOG"
            else
                log_warn "$RETOOLKIT_INSTALL_DIR already exists -- preserving"
                log_warn "Pass --force to overwrite, or --skip-source to skip"
                FAILED_SOURCE+=("install-dir-exists")
            fi
        fi

        if [[ ${#FAILED_SOURCE[@]} -eq 0 ]]; then
            # Install layout. Use install(1) for permissions + ownership control.
            mkdir -p "$RETOOLKIT_INSTALL_DIR/lib" "$RETOOLKIT_INSTALL_DIR/stages/static" \
                2>>"$SOURCE_LOG"

            # Driver: 0755 (executable)
            install -m 0755 "${INSTALLER_DIR}/analyze-binaries.sh" \
                "$RETOOLKIT_INSTALL_DIR/analyze-binaries.sh" 2>>"$SOURCE_LOG" \
                && log_ok "Installed analyze-binaries.sh -> $RETOOLKIT_INSTALL_DIR/" \
                || { log_err "Failed to install analyze-binaries.sh (see $SOURCE_LOG)"; FAILED_SOURCE+=("analyze-binaries.sh"); }

            # Ghidra postscript: 0644 (read-only data; invoked by Ghidra not directly)
            install -m 0644 "${INSTALLER_DIR}/GhidraDump.py" \
                "$RETOOLKIT_INSTALL_DIR/GhidraDump.py" 2>>"$SOURCE_LOG" \
                && log_ok "Installed GhidraDump.py" \
                || { log_err "Failed to install GhidraDump.py"; FAILED_SOURCE+=("GhidraDump.py"); }

            # lib/*.sh: 0644 (sourced, not executed standalone)
            for libfile in "${INSTALLER_DIR}/lib/"*.sh; do
                lf=$(basename "$libfile")
                install -m 0644 "$libfile" "$RETOOLKIT_INSTALL_DIR/lib/$lf" 2>>"$SOURCE_LOG" \
                    || { log_err "Failed to install lib/$lf"; FAILED_SOURCE+=("lib/$lf"); }
            done
            log_ok "Installed lib/ ($(find "$RETOOLKIT_INSTALL_DIR/lib" -maxdepth 1 -name '*.sh' | wc -l) files)"

            # stages/static/*.sh: 0644 (sourced, not executed standalone)
            for stagefile in "${INSTALLER_DIR}/stages/static/"*.sh; do
                sf=$(basename "$stagefile")
                install -m 0644 "$stagefile" "$RETOOLKIT_INSTALL_DIR/stages/static/$sf" 2>>"$SOURCE_LOG" \
                    || { log_err "Failed to install stages/static/$sf"; FAILED_SOURCE+=("stages/static/$sf"); }
            done
            log_ok "Installed stages/static/ ($(find "$RETOOLKIT_INSTALL_DIR/stages/static" -maxdepth 1 -name '*.sh' | wc -l) files)"

            # Symlink at /usr/local/bin/. Replace if --force or doesn't exist.
            if [[ -e "$RETOOLKIT_BIN_LINK" || -L "$RETOOLKIT_BIN_LINK" ]]; then
                if [[ $FORCE -eq 1 ]]; then
                    rm -f "$RETOOLKIT_BIN_LINK" 2>>"$SOURCE_LOG"
                else
                    log_warn "$RETOOLKIT_BIN_LINK already exists -- preserving"
                    log_warn "Pass --force to replace, or remove manually"
                fi
            fi
            if [[ ! -e "$RETOOLKIT_BIN_LINK" && ! -L "$RETOOLKIT_BIN_LINK" ]]; then
                ln -s "$RETOOLKIT_INSTALL_DIR/analyze-binaries.sh" \
                    "$RETOOLKIT_BIN_LINK" 2>>"$SOURCE_LOG" \
                    && log_ok "Symlink created: $RETOOLKIT_BIN_LINK -> $RETOOLKIT_INSTALL_DIR/analyze-binaries.sh" \
                    || { log_err "Failed to create symlink at $RETOOLKIT_BIN_LINK"; FAILED_SOURCE+=("symlink"); }
            fi

            # Sanity check: source the analyzer's deps and confirm key functions
            # are defined. This catches a broken install before the user hits it.
            log_info "Validating install: sourcing analyzer deps from $RETOOLKIT_INSTALL_DIR..."
            if bash -c "
                set -uo pipefail
                export RETOOLKIT_LIB_DIR='$RETOOLKIT_INSTALL_DIR/lib'
                export RETOOLKIT_STAGES_DIR='$RETOOLKIT_INSTALL_DIR/stages'
                source \"\$RETOOLKIT_LIB_DIR/common.sh\"
                source \"\$RETOOLKIT_LIB_DIR/tool-runner.sh\"
                source \"\$RETOOLKIT_LIB_DIR/ghidra-helper.sh\"
                source \"\$RETOOLKIT_LIB_DIR/detect-type.sh\"
                source \"\$RETOOLKIT_LIB_DIR/dispatch.sh\"
                source \"\$RETOOLKIT_LIB_DIR/aggregate.sh\"
                for s in \"\$RETOOLKIT_STAGES_DIR\"/static/*.sh; do source \"\$s\"; done
                declare -F log_info > /dev/null && \\
                declare -F detect_type > /dev/null && \\
                declare -F analyze_one > /dev/null && \\
                declare -F stage_triage > /dev/null && \\
                declare -F stage_report > /dev/null
            " >>"$SOURCE_LOG" 2>&1; then
                log_ok "Install validated: key functions sourced successfully"
            else
                log_err "Install validation FAILED -- see $SOURCE_LOG"
                FAILED_SOURCE+=("validation")
            fi
        fi
    fi
else
    log_hdr "LAYER 0 -- Analyzer source install (SKIPPED via --skip-source)"
fi

# =============================================================================
# LAYER 1 -- apt packages
# =============================================================================
APT_PKGS=(
    # Essentials
    curl wget ca-certificates apt-transport-https gnupg
    unzip zip tar xz-utils
    git build-essential
    python3 python3-pip python3-venv python3-dev

    # Java for Ghidra
    openjdk-21-jdk

    # Disassemblers / decompilers / analyzers
    radare2
    rizin
    binutils

    # Pattern matching / scanning
    yara
    clamav clamav-freshclam

    # PE / binary analysis
    binwalk
    foremost
    upx-ucl
    exiftool
    osslsigncode    # Authenticode signature verification (v2.2.0 +)
    pev             # v2.3.0: readpe/pedis/pehash/pescan/pesec/pestr suite
    trid            # v2.3.0: file-signature identifier
    bulk-extractor  # v2.3.0: raw-binary PII/IOC scanner
    llvm            # v2.3.0: provides llvm-objdump (complements GNU objdump)

    # v2.5.0: ELF security/structure analyzers
    pax-utils       # provides scanelf, dumpelf
    dwarves         # provides pahole, codiff (DWARF struct layout)
    bloaty          # section/segment size breakdown (PE + ELF)
    checksec        # ELF security mitigations (NX, PIE, RELRO, Canary, ...)
    python3-pwntools # provides `pwn checksec` as fallback to standalone checksec

    # v2.5.0: Manalyze build dependencies (cmake + boost + openssl)
    cmake
    libboost-dev
    libboost-system-dev
    libboost-program-options-dev
    libboost-regex-dev
    libboost-filesystem-dev
    libssl-dev

    # v2.6.0: WebAssembly Binary Toolkit (wasm2wat, wasm-objdump,
    # wasm-decompile, wasm-validate)
    wabt

    # v2.6.0: PDF analysis tooling (mutool from mupdf, qpdf structural check)
    mupdf-tools
    qpdf

    # v2.6.0: ZIP / OOXML container tooling (7z for OOXML internal listing)
    p7zip-full

    # v3.0.13 (audit-17 B1) - operator F2: binwalk-extract emits
    # "WARNING: One or more files failed to extract" when extraction
    # utilities for embedded format types are missing. The packages
    # below cover the most common formats binwalk encounters in PE
    # firmware/installer analysis. Some are already installed via
    # other dependencies (gzip, bzip2, tar, unzip are core); listed
    # here for visibility / explicitness. Adding these reduces the
    # frequency of partial-success WARNINGs without eliminating them
    # (some custom firmware formats have no Linux extractor at all).
    #
    # Already provided by base-system or earlier list:
    #   gzip, bzip2, xz-utils, tar, unzip, file
    # Added here:
    cabextract              # CAB archives (Windows installer/firmware)
    unrar-free              # RAR archives (or `unrar` if non-free OK)
    arj                     # ARJ archives (legacy malware samples)
    lhasa                   # LZH/LHA archives (legacy)
    lzop                    # LZO compressed (some firmware)
    sleuthkit               # filesystem image extraction (FAT/NTFS/EXT)
    cpio                    # CPIO archives (initramfs)
    cramfsswap              # CramFS filesystem images
    squashfs-tools          # SquashFS (router/firmware filesystems)
    zstd                    # Zstandard compressed (modern firmware)
    # Notes on extractors NOT added:
    #   jefferson  - JFFS2 extractor; not in Debian apt; pip-only
    #   sasquatch  - non-standard squashfs; source build; skip
    #   ubi_reader - UBIFS; pip-only; skip per low malware-analysis ROI

    # v2.6.0: Java JDK headless for javap (jar bytecode disassembler).
    # Note: mono-devel above provides .NET tooling, not JVM tooling; we
    # need a real JDK for javap and to run CFR / procyon decompiler jars.
    default-jdk-headless

    # v2.6.0: Go toolchain (for `go install github.com/goretk/redress` in
    # LAYER 4C). Adds ~200MB; users who don't analyze Go binaries can
    # skip LAYER 4C and apt-remove golang-go after install.
    golang-go

    # v2.7.0: fuzzy hashing primitives
    ssdeep            # standalone CLI + libfuzzy
    libfuzzy-dev      # required to build python-ssdeep wheel

    # v2.8.0: Android mobile RE tooling
    # jadx (DEX/APK Java decompiler), apktool (APK structural decompiler +
    # AXML decoder), apksigner (v1/v2/v3/v4 signature verifier), aapt2
    # (AXML xmltree fallback when apktool fails), dex2jar (provides
    # d2j-dex2jar wrapper for tertiary DEX decompilation path).
    jadx
    apktool
    apksigner
    aapt
    dex2jar

    # General binary inspection
    file
    xxd
    bsdmainutils   # provides hexdump

    # .NET on Linux (for monodis, ikdasm, running managed assemblies)
    mono-devel
    mono-utils

    # XML / config inspection
    libxml2-utils
    xmlstarlet

    # Dynamic analysis tools (installed but NOT auto-run)
    ltrace
    strace
    gdb

    # v3.0.0: firejail (Tier 2 dynamic-analysis sandbox; --dynamic-mode=firejail)
    # Earlier versions documented it as "already installed in v2.x" but it
    # was never explicitly added to APT_PKGS. Adding here so dynamic-tier
    # verification at LAYER 12 (was LAYER 6 pre-v3.0.4) passes on fresh installs.
    firejail

    # v3.0.2 (audit-6): binary diff tools for stage_binary_diff.
    # bsdiff produces compact binary patches (Colin Percival's algorithm)
    # used for firmware-version comparison and patch reverse-engineering.
    # vbindiff is a curses-based visual byte-level diff for analyst-driven
    # interactive review. Both apt-installable on Kali / Debian.
    bsdiff
    vbindiff

    # v3.0.4 (audit-8 A2 + A3) -- build deps for Python C-extension wheels
    # whose PyPI source releases compile against system libraries on
    # Linux (and ship wheels only for Windows, hence the source build).
    #
    # swig: required by M2Crypto's source build to generate the OpenSSL
    #   binding shim from src/SWIG/_m2crypto.i. Without swig:
    #     error: command 'swig' failed: No such file or directory
    #   M2Crypto 0.47.0+ ships cp313 wheels for Windows ONLY; Linux
    #   Python 3.13 must source-build (peframe transitively requires
    #   M2Crypto for X.509 cert parsing).
    #
    # autoconf, automake, libtool, pkg-config: required by ssdeep's
    #   in-tree libfuzzy build. ssdeep's setup.py invokes the autoreconf
    #   chain on first build to bootstrap the libfuzzy autotools sources;
    #   without these:
    #     sh: 0: cannot open configure: No such file
    #     /bin/sh: 1: libtoolize: not found
    #     /bin/sh: 1: automake: not found
    #     Failed while building ssdeep lib with configure and make.
    #
    # libssl-dev: already present above for Manalyze; M2Crypto needs it
    #   for OpenSSL headers during the SWIG-generated wrapper compile.
    swig
    autoconf
    automake
    libtool
    pkg-config

    # v3.0.6 (audit-10 A1): graphviz renders .dot graphs to SVG.
    # Used by:
    #   stages/static/40-r2.sh    renders r2's `agC` global-call-graph.dot
    #                              to global-call-graph.svg for inline display
    #                              in the per-binary report (was emitted but
    #                              never rendered pre-v3.0.6).
    #   stages/static/86-angr.sh  renders angr's CFGFast graph (dumped via
    #                              networkx.drawing.nx_pydot.write_dot) to
    #                              cfg.svg for inline display.
    # Both stages skip cleanly if `dot` (the graphviz binary) is unavailable;
    # graphviz adds ~5 MB on Debian/Kali and ships a robust .dot -> .svg
    # toolchain that's been stable for 20+ years.
    graphviz

    # Forensics helpers
    sleuthkit
)

if [[ $SKIP_APT -eq 1 ]]; then
    log_info "Skipping apt packages (--skip-apt)"
else
    log_hdr "LAYER 1 -- apt packages"
    log_info "Per-phase log: $APT_LOG"

    {
        echo "=== apt update ==="
        safe_apt update
    } >> "$APT_LOG" 2>&1

    log_info "Installing ${#APT_PKGS[@]} apt packages…"
    # v3.7.3 (audit-31 A1-A3): packages that are NOT apt-installable on this
    # distro but are recovered later by LAYER 2H (pev -> readpe source build,
    # bloaty -> cmake source build, trid -> mark0.net download). An apt miss on
    # these is EXPECTED, so we report it as an expected source-build rather than
    # a scary "failed", while still queueing it for LAYER 2H via FAILED_APT.
    KNOWN_SOURCE_BUILD=" pev bloaty trid "
    for pkg in "${APT_PKGS[@]}"; do
        # Use dpkg-query -W with status filter rather than `dpkg -l` because
        # `dpkg -l` returns success for packages in 'rc' state (removed but
        # config files retained) - these are not actually installed and the
        # binary is missing. dpkg-query -W -f='${db:Status-Abbrev}' returns
        # 'ii' only when the package is fully installed.
        # L30b: this avoids the cmake-skip bug where the operator had cmake removed
        # without --purge, causing dpkg -l cmake to succeed but cmake binary
        # to be absent, breaking LAYER 2E Manalyze/pycdc builds.
        pkg_status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$pkg" 2>/dev/null || echo "")
        if [[ "$pkg_status" == "ii " || "$pkg_status" == "ii" ]]; then
            [[ $VERBOSE -eq 1 ]] && log_info "  $pkg: already installed"
            continue
        fi
        {
            echo ""
            echo "=== apt-get install $pkg ==="
        } >> "$APT_LOG"
        # Route stderr to the log so failures are preserved.
        if safe_apt install -y "$pkg" >>"$APT_LOG" 2>&1; then
            log_ok "  installed: $pkg"
        else
            # v3.7.3 (audit-31 A4): boost dev metapackages are sometimes only
            # published under a versioned name (or via the libboost-all-dev
            # umbrella) on rolling distros, so a specific libboost-*-dev can be
            # "Unable to locate". Fall back to libboost-all-dev once; if that
            # lands, the specific package's headers/libs are satisfied.
            if [[ "$pkg" == libboost-*-dev ]]; then
                echo "=== apt fallback: libboost-all-dev (for $pkg) ===" >> "$APT_LOG"
                if safe_apt install -y libboost-all-dev >>"$APT_LOG" 2>&1; then
                    log_ok "  installed: libboost-all-dev (covers $pkg)"
                    continue
                fi
            fi
            if [[ "$KNOWN_SOURCE_BUILD" == *" $pkg "* ]]; then
                log_info "  not in apt (expected) -- $pkg will be built/downloaded in LAYER 2H"
            else
                log_warn "  failed: $pkg -- details in $APT_LOG"
            fi
            FAILED_APT+=("$pkg")
        fi
    done

    if [[ ${#FAILED_APT[@]} -gt 0 ]]; then
        # v3.0.4 (audit-8 A12): soften the wording. Several of these
        # packages (pev, bloaty, trid) are recovered by LAYER 2H source
        # builds shortly after this point. Calling them "apt failures"
        # at this stage misleads the operator into thinking these are
        # final outcomes. Phrase as "apt-stage misses; LAYER 2H may
        # rebuild from source" so the operator waits for the post-LAYER-2H
        # summary before drawing conclusions.
        log_info "apt-stage misses (may be recovered by LAYER 2H): ${FAILED_APT[*]}"
        log_info "Full apt log: $APT_LOG"
    fi
fi

# =============================================================================
# LAYER 2 -- Microsoft .NET SDK via their official Debian repo
# =============================================================================
if [[ $SKIP_DOTNET -eq 1 ]]; then
    log_info "Skipping .NET SDK (--skip-dotnet)"
else
    log_hdr "LAYER 2 -- Microsoft .NET SDK (for ilspycmd)"
    log_info "Per-phase log: $DOTNET_LOG"

    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
    fi

    # v2.1.3 FIX -- Kali is derived from Debian Testing; Microsoft's apt
    # repo only carries dotnet packages for Debian stable releases. On
    # Kali, the apt install will fail with "Unable to locate package
    # dotnet-sdk-8.0". Detect this upfront and skip straight to the
    # dotnet-install.sh user-space installer.
    FORCE_DOTNET_INSTALL_SH=0
    case "${ID:-unknown}" in
        kali)
            log_info "Kali detected -- Microsoft's apt repo doesn't ship dotnet packages"
            log_info "for Kali's base. Skipping apt attempt, using dotnet-install.sh."
            FORCE_DOTNET_INSTALL_SH=1
            ;;
        debian|ubuntu|linuxmint|pop|elementary)
            : # proceed with apt attempt
            ;;
        *)
            log_info "Distro '${ID:-unknown}' not in Microsoft's apt repo matrix -- using dotnet-install.sh"
            FORCE_DOTNET_INSTALL_SH=1
            ;;
    esac

    MS_REPO_INSTALLED=0
    if [[ $FORCE_DOTNET_INSTALL_SH -eq 0 ]]; then
    if [[ -f /etc/apt/sources.list.d/microsoft-prod.list ]] && [[ $FORCE -eq 0 ]]; then
        log_ok "Microsoft apt repo already configured"
        MS_REPO_INSTALLED=1
    else
        log_info "Adding Microsoft packages-microsoft-prod apt repo…"

        # Kali Rolling is Debian-based; Debian 12 (bookworm) repo works on both.
        MS_DEB_VERSION="12"
        MS_DEB_URL="https://packages.microsoft.com/config/debian/${MS_DEB_VERSION}/packages-microsoft-prod.deb"
        TMPDEB="/tmp/packages-microsoft-prod.deb"

        if curl -fsSL -o "$TMPDEB" "$MS_DEB_URL" >>"$DOTNET_LOG" 2>&1; then
            if dpkg -i "$TMPDEB" >>"$DOTNET_LOG" 2>&1; then
                safe_apt update >>"$DOTNET_LOG" 2>&1
                MS_REPO_INSTALLED=1
                log_ok "Microsoft apt repo installed"
            else
                log_warn "dpkg -i packages-microsoft-prod.deb failed -- see $DOTNET_LOG"
                FAILED_DOTNET+=("ms-repo-dpkg")
            fi
            rm -f "$TMPDEB"
        else
            log_warn "Could not download packages-microsoft-prod.deb -- see $DOTNET_LOG"
            FAILED_DOTNET+=("ms-repo-download")
        fi
    fi

    if [[ $MS_REPO_INSTALLED -eq 1 ]]; then
        log_info "Installing dotnet-sdk-8.0 from Microsoft's repo…"
        if safe_apt install -y dotnet-sdk-8.0 >>"$DOTNET_LOG" 2>&1; then
            DOTNET_VER=$(dotnet --version 2>/dev/null | head -1)
            log_ok ".NET SDK 8.0 installed: ${DOTNET_VER:-(version unknown)}"
        else
            # Repo was added but package isn't available -- Microsoft removed
            # some versions from older Debian repos, or this distro is in a
            # grey zone. Fall through to dotnet-install.sh without a scary
            # FAIL summary entry.
            log_info "dotnet-sdk-8.0 not in configured apt repo -- using dotnet-install.sh"
            MS_REPO_INSTALLED=0
        fi
    fi
    fi   # end of `if [[ $FORCE_DOTNET_INSTALL_SH -eq 0 ]]`

    if [[ $MS_REPO_INSTALLED -eq 0 ]]; then
        log_info "Installing .NET 8 via dotnet-install.sh (user-space)…"
        DOTNET_SH=/tmp/dotnet-install.sh
        if curl -fsSL -o "$DOTNET_SH" https://dot.net/v1/dotnet-install.sh >>"$DOTNET_LOG" 2>&1; then
            chmod +x "$DOTNET_SH"
            as_user "$DOTNET_SH" --channel 8.0 --install-dir "${INVOKING_HOME}/.dotnet" \
                >>"$DOTNET_LOG" 2>&1 \
                && log_ok ".NET 8 installed in ${INVOKING_HOME}/.dotnet" \
                || { log_warn "dotnet-install.sh failed -- see $DOTNET_LOG"; FAILED_DOTNET+=("dotnet-install-sh"); }
            if ! grep -q '\.dotnet' "${INVOKING_HOME}/.bashrc" 2>/dev/null; then
                cat >> "${INVOKING_HOME}/.bashrc" <<EOF

# === .NET (RE-Toolkit) ===
export DOTNET_ROOT="\$HOME/.dotnet"
export PATH="\$HOME/.dotnet:\$HOME/.dotnet/tools:\$PATH"
EOF
                chown "$INVOKING_USER:$INVOKING_USER" "${INVOKING_HOME}/.bashrc"
            fi
        else
            log_warn "Could not download dotnet-install.sh -- see $DOTNET_LOG"
            FAILED_DOTNET+=("dotnet-install-sh-download")
        fi
    fi

    if command -v dotnet >/dev/null 2>&1 || [[ -x "${INVOKING_HOME}/.dotnet/dotnet" ]]; then
        log_info "Installing ilspycmd as $INVOKING_USER…"
        DOTNET_CMD="dotnet"
        [[ -x "${INVOKING_HOME}/.dotnet/dotnet" ]] && DOTNET_CMD="${INVOKING_HOME}/.dotnet/dotnet"

        # Detect installed SDK major version. We use this to pick a
        # framework-compatible ilspycmd version because the latest ilspycmd
        # on NuGet may target a runtime not present (yields a misleading
        # "DotnetToolSettings.xml was not found" error, which is actually
        # a target-framework mismatch per dotnet/sdk#38172).
        SDK_MAJOR=$(as_user "$DOTNET_CMD" --list-sdks 2>/dev/null \
            | awk '{print $1}' | head -1 | cut -d. -f1)
        SDK_MAJOR="${SDK_MAJOR:-8}"

        # Fallback chain: try latest first; if that fails with the
        # version-mismatch signature, retry with the highest-known-good
        # ilspycmd version compatible with the installed SDK major.
        ILSPYCMD_INSTALLED=0
        if [[ -x "${INVOKING_HOME}/.dotnet/tools/ilspycmd" ]]; then
            log_ok "ilspycmd already installed at ${INVOKING_HOME}/.dotnet/tools/ilspycmd"
            ILSPYCMD_INSTALLED=1
        elif as_user "$DOTNET_CMD" tool install -g ilspycmd >>"$DOTNET_LOG" 2>&1; then
            log_ok "ilspycmd installed (latest)"
            ILSPYCMD_INSTALLED=1
        else
            # First attempt failed. Determine fallback version by SDK major.
            # ilspycmd version map (latest known per SDK major):
            #   net10.0+: 10.0.x  (ilspycmd 10.0.1.8346 or newer)
            #   net9.0:   9.0.x   (ilspycmd 9.0.0.7876 or 9.0.0.7660-preview2)
            #   net8.0:   8.x     (ilspycmd 8.1.0.7455 - last 8.x stable)
            #   net6.0:   7.x     (ilspycmd 7.1.0.6543)
            case "$SDK_MAJOR" in
                10|11|12) ILSPYCMD_FALLBACK="" ;;  # latest should work; if it didn't, no fallback helps
                9)        ILSPYCMD_FALLBACK="9.0.0.7876" ;;
                8)        ILSPYCMD_FALLBACK="8.1.0.7455" ;;
                7|6)      ILSPYCMD_FALLBACK="7.1.0.6543" ;;
                *)        ILSPYCMD_FALLBACK="" ;;
            esac
            if [[ -n "$ILSPYCMD_FALLBACK" ]]; then
                log_warn "ilspycmd latest failed (likely SDK ${SDK_MAJOR}.0 vs tool target mismatch);"
                log_warn "         retrying with version $ILSPYCMD_FALLBACK pinned for net${SDK_MAJOR}.0"
                if as_user "$DOTNET_CMD" tool install -g ilspycmd \
                        --version "$ILSPYCMD_FALLBACK" >>"$DOTNET_LOG" 2>&1; then
                    log_ok "ilspycmd installed (pinned to $ILSPYCMD_FALLBACK)"
                    ILSPYCMD_INSTALLED=1
                fi
            fi
        fi

        if [[ $ILSPYCMD_INSTALLED -eq 0 ]]; then
            log_warn "ilspycmd install failed even with fallback -- see $DOTNET_LOG"
            log_warn "         .NET decompilation will be unavailable; non-fatal"
            FAILED_DOTNET+=("ilspycmd")
        fi

        if ! grep -q 'dotnet/tools' "${INVOKING_HOME}/.bashrc" 2>/dev/null; then
            as_user bash -c "echo 'export PATH=\"\$HOME/.dotnet/tools:\$PATH\"' >> ~/.bashrc"
        fi
    else
        log_warn "dotnet not available; skipping ilspycmd"
        FAILED_DOTNET+=("ilspycmd-no-dotnet")
    fi
fi

# =============================================================================
# LAYER 2B -- Detect It Easy (DIE) -- packer/compiler/protector fingerprinter
# =============================================================================
# DIE is sometimes in Kali apt as `detect-it-easy`, sometimes not at all.
# Binary name is `diec` (CLI) or `die` (GUI). We only want the CLI for scripting.
# Strategy:
#   1. Try apt first -- cheapest, versioned, auto-updated.
#   2. If apt fails, download the latest release tarball from GitHub and install
#      to /opt/die/ with a shim at /usr/local/bin/diec.
# The fallback requires an internet connection; skip on --offline.
if [[ $SKIP_APT -eq 1 ]]; then
    log_info "Skipping Detect It Easy (--skip-apt)"
else
    log_hdr "LAYER 2B -- Detect It Easy (DIE)"

    if command -v diec >/dev/null 2>&1; then
        log_ok "diec already installed at $(command -v diec)"
    else
        # Attempt apt install first (silent; may not be in this repo).
        DIE_LOG="${LOG_ROOT}/die.log"
        log_info "Attempting apt install detect-it-easy…"
        if safe_apt install -y detect-it-easy >"$DIE_LOG" 2>&1 && command -v diec >/dev/null 2>&1; then
            log_ok "diec installed via apt"
        else
            log_info "apt path unavailable; trying GitHub release…"
            DIE_INSTALL_DIR="/opt/die"
            mkdir -p "$DIE_INSTALL_DIR"
            # Latest release deb for Debian-based systems. The repo publishes
            # .deb files per release at horsicq/DIE-engine/releases.
            # We fetch the deb via GitHub API to follow "latest release".
            DIE_DEB_URL=$(curl -fsSL https://api.github.com/repos/horsicq/DIE-engine/releases/latest 2>/dev/null \
                | grep -oE '"browser_download_url":\s*"[^"]*_amd64\.deb"' \
                | head -1 | sed -E 's/.*"(https[^"]+)"/\1/')
            if [[ -z "$DIE_DEB_URL" ]]; then
                log_warn "Could not find DIE .deb in latest GitHub release."
                log_warn "Packer/compiler detection will be unavailable."
                log_warn "Manual install: https://github.com/horsicq/DIE-engine/releases"
                FAILED_APT+=("detect-it-easy")
            else
                DIE_DEB="/tmp/die.deb"
                log_info "Downloading $DIE_DEB_URL"
                if curl -fsSL -o "$DIE_DEB" "$DIE_DEB_URL" >>"$DIE_LOG" 2>&1; then
                    if safe_apt install -y "$DIE_DEB" >>"$DIE_LOG" 2>&1; then
                        log_ok "DIE installed via downloaded .deb"
                    else
                        log_warn "DIE .deb install failed -- details in $DIE_LOG"
                        FAILED_APT+=("detect-it-easy")
                    fi
                    rm -f "$DIE_DEB"
                else
                    log_warn "DIE .deb download failed -- details in $DIE_LOG"
                    FAILED_APT+=("detect-it-easy")
                fi
            fi
        fi
    fi
fi

# =============================================================================
# LAYER 2C -- de4dot-cex (.NET deobfuscator, ViRb3 fork)
# =============================================================================
# The upstream de4dot at github.com/de4dot/de4dot has been unmaintained since
# ~2020; the actively-used fork is ViRb3/de4dot-cex which adds ConfuserEx
# support (the obfuscator most modern commercial .NET products ship with).
# Installed to /opt/de4dot-cex/. Invoked via `mono de4dot.exe …` on Linux.
#
# mono-runtime is already pulled in via LAYER 1's mono-devel (v2.2.0). The
# install flow here is apt-first / GitHub-release fallback, same as DIE.
if [[ $SKIP_APT -eq 1 ]]; then
    log_info "Skipping de4dot-cex (--skip-apt)"
else
    log_hdr "LAYER 2C -- de4dot-cex (.NET deobfuscator)"
    DE4DOT_DIR="/opt/de4dot-cex"
    DE4DOT_EXE="${DE4DOT_DIR}/de4dot.exe"
    DE4DOT_LOG="${LOG_ROOT}/de4dot.log"

    if [[ -f "$DE4DOT_EXE" ]]; then
        log_ok "de4dot-cex already installed at $DE4DOT_EXE"
    elif ! command -v mono >/dev/null 2>&1; then
        log_warn "mono not available; skipping de4dot-cex"
        FAILED_APT+=("de4dot-cex-no-mono")
    else
        mkdir -p "$DE4DOT_DIR"
        log_info "Fetching latest de4dot-cex release metadata from GitHub…"
        # Follow 'latest release' URL; fetch the first .zip asset.
        DE4DOT_URL=$(curl -fsSL https://api.github.com/repos/ViRb3/de4dot-cex/releases/latest 2>>"$DE4DOT_LOG" \
            | grep -oE '"browser_download_url":\s*"[^"]*\.zip"' \
            | head -1 | sed -E 's/.*"(https[^"]+)"/\1/')
        if [[ -z "$DE4DOT_URL" ]]; then
            log_warn "Could not find de4dot-cex .zip in latest GitHub release."
            log_warn ".NET deobfuscation will be unavailable."
            log_warn "Manual install: https://github.com/ViRb3/de4dot-cex/releases"
            FAILED_APT+=("de4dot-cex")
        else
            DE4DOT_ZIP="/tmp/de4dot-cex.zip"
            log_info "Downloading $DE4DOT_URL"
            if curl -fsSL -o "$DE4DOT_ZIP" "$DE4DOT_URL" >>"$DE4DOT_LOG" 2>&1; then
                if unzip -q -o "$DE4DOT_ZIP" -d "$DE4DOT_DIR" >>"$DE4DOT_LOG" 2>&1; then
                    chmod -R a+r "$DE4DOT_DIR"
                    # Some releases nest the binaries in a sub-dir (net8.0/,
                    # net48/, etc.). If de4dot.exe isn't at the top level,
                    # look for the most-modern framework build and symlink it.
                    if [[ ! -f "$DE4DOT_EXE" ]]; then
                        FOUND_EXE=$(find "$DE4DOT_DIR" -name 'de4dot.exe' -type f 2>/dev/null | sort -V | tail -1)
                        if [[ -n "$FOUND_EXE" ]]; then
                            ln -sf "$FOUND_EXE" "$DE4DOT_EXE"
                            log_ok "de4dot-cex installed (symlinked: $FOUND_EXE → $DE4DOT_EXE)"
                        else
                            log_warn "de4dot-cex zip extracted but no de4dot.exe found -- details in $DE4DOT_LOG"
                            FAILED_APT+=("de4dot-cex")
                        fi
                    else
                        log_ok "de4dot-cex installed at $DE4DOT_EXE"
                    fi
                else
                    log_warn "de4dot-cex unzip failed -- details in $DE4DOT_LOG"
                    FAILED_APT+=("de4dot-cex")
                fi
                rm -f "$DE4DOT_ZIP"
            else
                log_warn "de4dot-cex download failed -- details in $DE4DOT_LOG"
                FAILED_APT+=("de4dot-cex")
            fi
        fi
    fi
fi

# =============================================================================
# LAYER 2E -- v2.5.0 GitHub-release tools (.NET deobfuscators + analyzers)
# =============================================================================
# Six tools land here, all built from source or fetched as release zips:
#   - dnSpyEx Console (.NET decompiler) - release zip → /opt/dnSpyEx/
#   - OldRod          (.NET KoiVM/VMProtect.NET devirt) - release zip → /opt/OldRod/
#   - EazFixer        (.NET Eazfuscator deob) - source build → /opt/EazFixer/
#   - NoFuserEx       (.NET ConfuserEx deob alt) - source build → /opt/NoFuserEx/
#   - signsrch        (binary signature scanner) - source build → /usr/local/bin/
#   - Manalyze        (PE static analyzer) - source build → /usr/local/bin/
#
# The .NET binaries (dnSpyEx, OldRod, EazFixer, NoFuserEx) are run via mono
# on Linux. EazFixer and NoFuserEx require msbuild/xbuild for source build;
# we use mono's xbuild path. Manalyze and signsrch are native C/C++ builds.
# =============================================================================
LAYER25_LOG="${LOG_ROOT}/layer25-${RUN_TS}.log"
: > "$LAYER25_LOG"

if [[ $SKIP_APT -eq 1 ]]; then
    log_info "Skipping LAYER 2E (--skip-apt)"
else
    log_hdr "LAYER 2E -- v2.5.0 GitHub-release tools"

    # ----- dnSpyEx Console (.NET decompiler) ---------------------------------
    # v3.0.13 (audit-17 C1) - operator F3 (CRITICAL): dnSpyEx via wine
    # failed in v3.0.12 with "wine: failed to open .../syswow64/
    # rundll32.exe: c0000135" (STATUS_DLL_NOT_FOUND). Modern wine 9.x
    # uses experimental WoW64 mode by default which requires explicit
    # prefix initialization + .NET 6 runtime install via winetricks
    # for the .NET 6 dnSpy build.
    #
    # The honest fix is to switch from dnSpy-net-win64.zip (.NET 6,
    # needs full Windows runtime) to dnSpy-netframework.zip (.NET
    # Framework 4.8, native CIL image that mono runs directly without
    # any wine prefix or winetricks .NET install).
    #
    # dnSpyEx releases consistently ship BOTH variants:
    #   dnSpy-net-win32.zip    (.NET Framework 4.8, 32-bit; less common)
    #   dnSpy-net-win64.zip    (.NET 6, 64-bit; needs Windows .NET runtime)
    #   dnSpy-netframework.zip (.NET Framework 4.8, 64-bit; mono-friendly)
    #
    # The decompilation engine (ICSharpCode.Decompiler) is identical
    # across all three; we lose nothing by using the netframework
    # variant for our scripted pipeline. The differences (debugger UI,
    # plugin host, etc.) are GUI features irrelevant to dnSpy.Console.
    #
    # This reverts to the pre-audit-14 path with the CORRECT zip:
    # audit-13 used mono+net-win64.zip (failed: .NET 6 not CIL).
    # audit-14 used dotnet+net-win64.zip (failed: missing libhostpolicy).
    # audit-15 didn't touch dnSpyEx.
    # audit-16 used wine+net-win64.zip (failed: c0000135 prefix init).
    # audit-17 uses mono+netframework.zip (the historically-working path).
    if [[ -f "/opt/dnSpyEx/dnSpy.Console.exe" && $FORCE -eq 0 ]]; then
        log_info "dnSpyEx already at /opt/dnSpyEx/dnSpy.Console.exe (use --force to refresh)"
    else
        log_info "Fetching dnSpyEx (latest release, .NET Framework variant)..."
        DNSPY_API="https://api.github.com/repos/dnSpyEx/dnSpy/releases/latest"
        DNSPY_URL=$(curl -sSL "$DNSPY_API" 2>>"$LAYER25_LOG" | \
            grep -oE '"browser_download_url":\s*"[^"]+dnSpy-netframework\.zip"' | \
            head -1 | sed 's/.*: *"\(.*\)"/\1/')
        if [[ -n "$DNSPY_URL" ]]; then
            mkdir -p /opt/dnSpyEx
            DNSPY_ZIP="/tmp/dnSpyEx.zip"
            if curl -sSL -o "$DNSPY_ZIP" "$DNSPY_URL" 2>>"$LAYER25_LOG"; then
                rm -rf /opt/dnSpyEx/*
                if unzip -q -o "$DNSPY_ZIP" -d /opt/dnSpyEx/ 2>>"$LAYER25_LOG"; then
                    rm -f "$DNSPY_ZIP"
                    if [[ -f "/opt/dnSpyEx/dnSpy.Console.exe" ]]; then
                        log_ok "dnSpyEx (netframework) installed → /opt/dnSpyEx/dnSpy.Console.exe"
                    else
                        log_warn "dnSpyEx zip extracted but dnSpy.Console.exe not at expected path"
                        FAILED_APT+=("dnSpyEx-console-missing")
                    fi
                else
                    log_warn "dnSpyEx zip extraction failed"; FAILED_APT+=("dnSpyEx-extract")
                fi
            else
                log_warn "dnSpyEx download failed"; FAILED_APT+=("dnSpyEx-download")
            fi
        else
            log_warn "dnSpyEx-netframework release URL not resolvable from GitHub API"
            FAILED_APT+=("dnSpyEx-url")
        fi
    fi

    # ----- OldRod (.NET KoiVM/VMProtect.NET devirtualizer) -------------------
    # Two install paths:
    #   1. Prefer pre-built release asset from GitHub (faster, no build deps)
    #   2. Fall back to source build with msbuild/xbuild when release has no
    #      .zip asset (some OldRod releases only ship source archives)
    if [[ -f "/opt/OldRod/OldRod.exe" && $FORCE -eq 0 ]]; then
        log_info "OldRod already at /opt/OldRod/OldRod.exe (use --force to refresh)"
    else
        log_info "Fetching OldRod (latest release)..."
        OLDROD_API="https://api.github.com/repos/Washi1337/OldRod/releases/latest"
        OLDROD_URL=$(curl -sSL "$OLDROD_API" 2>>"$LAYER25_LOG" | \
            grep -oE '"browser_download_url":\s*"[^"]+\.zip"' | head -1 | \
            sed 's/.*: *"\(.*\)"/\1/')
        if [[ -n "$OLDROD_URL" ]]; then
            mkdir -p /opt/OldRod
            OLDROD_ZIP="/tmp/OldRod.zip"
            if curl -sSL -o "$OLDROD_ZIP" "$OLDROD_URL" 2>>"$LAYER25_LOG"; then
                rm -rf /opt/OldRod/*
                if unzip -q -o "$OLDROD_ZIP" -d /opt/OldRod/ 2>>"$LAYER25_LOG"; then
                    rm -f "$OLDROD_ZIP"
                    # OldRod releases sometimes nest under a sub-dir; flatten
                    if [[ ! -f "/opt/OldRod/OldRod.exe" ]]; then
                        FOUND=$(find /opt/OldRod -name 'OldRod.exe' -type f 2>/dev/null | head -1)
                        [[ -n "$FOUND" ]] && ln -sf "$FOUND" /opt/OldRod/OldRod.exe
                    fi
                    [[ -f "/opt/OldRod/OldRod.exe" ]] && \
                        log_ok "OldRod installed → /opt/OldRod/OldRod.exe" || \
                        { log_warn "OldRod.exe not located post-extract"; FAILED_APT+=("OldRod-missing"); }
                else
                    log_warn "OldRod zip extraction failed"; FAILED_APT+=("OldRod-extract")
                fi
            else
                log_warn "OldRod download failed"; FAILED_APT+=("OldRod-download")
            fi
        else
            # No .zip asset in latest release: fall back to source build.
            # OldRod source builds via dotnet build (preferred) or xbuild
            # (legacy fallback). Note: OldRod uses SDK-style csproj
            # (<Project Sdk="Microsoft.NET.Sdk">) which mono's xbuild does
            # NOT support; xbuild only handles MSBuild 2003 format.
            # Output lands at src/OldRod/bin/Release/<TFM>/OldRod.exe.
            log_info "No .zip release asset; falling back to source build (OldRod from master)"
            # Prefer dotnet (handles SDK-style); fall back to mono msbuild;
            # xbuild is last resort and will likely fail on SDK-style.
            ORBUILDER=""
            ORBUILD_TOOL=""
            if command -v dotnet >/dev/null 2>&1; then
                ORBUILDER="dotnet"
                ORBUILD_TOOL="dotnet"
            elif command -v msbuild >/dev/null 2>&1; then
                ORBUILDER=$(command -v msbuild)
                ORBUILD_TOOL="msbuild"
            elif command -v xbuild >/dev/null 2>&1; then
                ORBUILDER=$(command -v xbuild)
                ORBUILD_TOOL="xbuild"
            fi

            if [[ -n "$ORBUILDER" ]]; then
                OR_SRC="/tmp/OldRod-src"
                rm -rf "$OR_SRC"
                if git clone --depth=1 --recurse-submodules \
                    https://github.com/Washi1337/OldRod.git \
                    "$OR_SRC" >>"$LAYER25_LOG" 2>&1; then
                    pushd "$OR_SRC" >/dev/null
                    # Build invocation differs per tool. dotnet build
                    # auto-detects SDK-style; msbuild/xbuild use
                    # /p:Configuration=Release.
                    BUILD_OK=0
                    if [[ "$ORBUILD_TOOL" == "dotnet" ]]; then
                        if dotnet build -c Release OldRod.sln >>"$LAYER25_LOG" 2>&1; then
                            BUILD_OK=1
                        fi
                    else
                        if "$ORBUILDER" /p:Configuration=Release OldRod.sln >>"$LAYER25_LOG" 2>&1; then
                            BUILD_OK=1
                        fi
                    fi
                    if [[ $BUILD_OK -eq 1 ]]; then
                        # find the OldRod.exe in any TFM subdir under bin/Release/
                        OR_OUT=$(find . -name 'OldRod.exe' -path '*/bin/Release/*' 2>/dev/null | head -1)
                        if [[ -n "$OR_OUT" ]]; then
                            mkdir -p /opt/OldRod
                            cp -f "$OR_OUT" /opt/OldRod/OldRod.exe
                            cp -f "$(dirname "$OR_OUT")"/*.dll /opt/OldRod/ 2>/dev/null || true
                            log_ok "OldRod built from source via $ORBUILD_TOOL → /opt/OldRod/OldRod.exe"
                        else
                            log_warn "OldRod build succeeded but OldRod.exe not located"
                            FAILED_APT+=("OldRod-build-missing")
                        fi
                    else
                        log_warn "OldRod source build failed via $ORBUILD_TOOL"
                        if [[ "$ORBUILD_TOOL" == "xbuild" ]]; then
                            log_warn "  (xbuild does not support SDK-style csproj; install dotnet SDK to fix)"
                        fi
                        FAILED_APT+=("OldRod-build")
                    fi
                    popd >/dev/null
                else
                    log_warn "OldRod git clone failed"; FAILED_APT+=("OldRod-clone")
                fi
            else
                log_warn "OldRod release URL not resolvable AND no dotnet/msbuild/xbuild for source fallback"
                FAILED_APT+=("OldRod-url")
            fi
        fi
    fi

    # ----- EazFixer DROPPED in v3.0.4 (audit-8 A9) ---------------------------
    # EazFixer (Ahmadmansoor/EazFixer) is a .NET Eazfuscator deobfuscator.
    # It has been DROPPED from the installer for the following reasons:
    #
    # 1. Build infrastructure dependency hell:
    #    - EazFixer.csproj originally targeted net462 which Kali's dotnet SDK
    #      6.0 cannot build (no Developer Pack reference assemblies).
    #    - Audit-6 retargeted to net48; Kali's mono-devel ships .NET Framework
    #      4.8 reference assemblies under /usr/lib/mono/4.8-api but dotnet
    #      SDK 6.0's MSBuild does not search there. Build fails with:
    #        error MSB3644: The reference assemblies for
    #        .NETFramework,Version=v4.8 were not found.
    #    - Audit-7 verified the audit-6 retarget via syntax checking only;
    #      audit-8 confirmed via actual install run that the retarget does
    #      not work end-to-end on Kali Rolling 6.19+ with dotnet SDK 6.0.
    #
    # 2. Functional overlap with de4dot-cex:
    #    - de4dot-cex (LAYER 2D, apt-installed) handles the same Eazfuscator
    #      family of obfuscators that EazFixer targets, and is actively
    #      maintained as a Debian package.
    #    - stage_dotnet already invokes de4dot-cex as the primary deob path;
    #      EazFixer was a backup that rarely produced different output.
    #
    # 3. Per-attempt brittleness:
    #    - Even when the build succeeded, EazFixer's runtime invocation via
    #      mono required Harmony shim DLLs to load correctly which itself
    #      was unreliable across mono-devel versions.
    #
    # If you specifically need EazFixer for a research workflow, the manual
    # path was documented in the development notes ("EazFixer manual build
    # for research use"). The RE-Toolkit pipeline does not attempt this build
    # automatically as of v3.0.4.
    #
    # stage_dotnet's configuration was updated in audit-8 to mark EazFixer
    # as optional: stage logic checks for /opt/EazFixer/EazFixer.exe, and
    # if absent, proceeds with de4dot-cex only and notes the absence in
    # the per-binary report rather than treating it as a stage failure.

    # ----- NoFuserEx (ConfuserEx alternative deobfuscator, source build) -----
    # undebel/NoFuserEx layout: the .sln lives at NoFuserEx/NoFuserEx/NoFuserEx.sln
    # (yes, doubly nested). Cloning to /tmp/NoFuserEx-src puts the .sln at
    # /tmp/NoFuserEx-src/NoFuserEx/NoFuserEx.sln. Earlier versions of this
    # block ran the build from /tmp/NoFuserEx-src/ and got
    #   MSBUILD: error MSBUILD0003: Please specify the project or solution
    #   file to build, as none was found in the current directory.
    # because there's no .sln at the top level. Audit-7 fix: pushd into the
    # inner NoFuserEx/ subdir where the .sln actually is.
    #
    # Build tool selection: prefer dotnet build (modern, supported); fall
    # back to msbuild; xbuild is deprecated by mono. Audit-5 (L31) recorded
    # this preference order.
    if [[ -f "/opt/NoFuserEx/NoFuserEx.exe" && $FORCE -eq 0 ]]; then
        log_info "NoFuserEx already at /opt/NoFuserEx/NoFuserEx.exe (use --force to refresh)"
    else
        log_info "Building NoFuserEx from source (undebel/NoFuserEx)..."
        # Pick build tool: dotnet build first, then msbuild, then xbuild
        NFBUILD_TOOL=""
        NFBUILDER=""
        if command -v dotnet >/dev/null 2>&1; then
            NFBUILD_TOOL="dotnet"
            NFBUILDER="dotnet"
        elif command -v msbuild >/dev/null 2>&1; then
            NFBUILD_TOOL="msbuild"
            NFBUILDER="$(command -v msbuild)"
        elif command -v xbuild >/dev/null 2>&1; then
            NFBUILD_TOOL="xbuild"
            NFBUILDER="$(command -v xbuild)"
        fi

        if [[ -z "$NFBUILD_TOOL" ]]; then
            log_warn "No build tool available (dotnet/msbuild/xbuild) -- cannot build NoFuserEx"
            FAILED_APT+=("NoFuserEx-builder")
        else
            NF_SRC="/tmp/NoFuserEx-src"
            rm -rf "$NF_SRC"
            # v3.0.4 (audit-8 A8): the undebel/NoFuserEx .sln references
            # dnlib as a submodule at NoFuserEx/dnlib/src/dnlib.csproj.
            # Without --recurse-submodules the dnlib directory exists but
            # is empty, causing dotnet build to fail with:
            #   error MSB3202: The project file
            #   "/tmp/NoFuserEx-src/dnlib/src/dnlib.csproj" was not found
            # Mirror the EazFixer audit-4 fix (L31): clone with submodules
            # so dnlib is actually populated. --depth=1 still applies to
            # the main repo; we let submodules clone fully (small).
            if git clone --depth=1 --recurse-submodules https://github.com/undebel/NoFuserEx.git \
                "$NF_SRC" >>"$LAYER25_LOG" 2>&1; then

                # Locate the .sln. The undebel layout puts it at
                # NoFuserEx/NoFuserEx.sln (one level under the repo root).
                # Use find with maxdepth so we don't pick up nested test slns.
                NF_SLN=$(find "$NF_SRC" -maxdepth 3 -name '*.sln' -print 2>/dev/null | head -1)
                if [[ -z "$NF_SLN" ]]; then
                    log_warn "NoFuserEx: no .sln found under $NF_SRC (upstream layout changed?)"
                    FAILED_APT+=("NoFuserEx-no-sln")
                else
                    log_info "  Found .sln: $NF_SLN"
                    NF_BUILD_DIR="$(dirname "$NF_SLN")"
                    pushd "$NF_BUILD_DIR" >/dev/null
                    NF_BUILD_OK=0
                    case "$NFBUILD_TOOL" in
                        dotnet)
                            if dotnet build -c Release "$(basename "$NF_SLN")" \
                                >>"$LAYER25_LOG" 2>&1; then
                                NF_BUILD_OK=1
                            fi
                            ;;
                        msbuild|xbuild)
                            if "$NFBUILDER" /p:Configuration=Release \
                                "$(basename "$NF_SLN")" \
                                >>"$LAYER25_LOG" 2>&1; then
                                NF_BUILD_OK=1
                            fi
                            ;;
                    esac
                    if [[ $NF_BUILD_OK -eq 1 ]]; then
                        NF_OUT=$(find . -name 'NoFuserEx.exe' -path '*/bin/Release/*' 2>/dev/null | head -1)
                        if [[ -n "$NF_OUT" ]]; then
                            mkdir -p /opt/NoFuserEx
                            cp -f "$NF_OUT" /opt/NoFuserEx/NoFuserEx.exe
                            cp -f "$(dirname "$NF_OUT")"/*.dll /opt/NoFuserEx/ 2>/dev/null || true
                            log_ok "NoFuserEx built ($NFBUILD_TOOL) → /opt/NoFuserEx/NoFuserEx.exe"
                        else
                            log_warn "NoFuserEx build succeeded but NoFuserEx.exe not located"
                            FAILED_APT+=("NoFuserEx-missing")
                        fi
                    else
                        log_warn "NoFuserEx build failed via $NFBUILD_TOOL (see $LAYER25_LOG)"
                        log_warn "  undebel fork is unmaintained; consider a different fork"
                        FAILED_APT+=("NoFuserEx-build")
                    fi
                    popd >/dev/null
                fi
            else
                log_warn "NoFuserEx git clone failed"; FAILED_APT+=("NoFuserEx-clone")
            fi
        fi
    fi

    # ----- signsrch (binary signature scanner, source build) -----------------
    # Build from sandsmark/signsrch (active fork on GitHub) rather than
    # aluigi.altervista.org for URL stability. Installs to /usr/local/bin/.
    # Note: signsrch's older C code uses pthread but lacks -lpthread in
    # default Makefile. Modern glibc requires -pthread CFLAGS for implicit
    # pthread_create declaration. Pass CFLAGS via env override.
    if command -v signsrch >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
        log_info "signsrch already in PATH (use --force to rebuild)"
    else
        log_info "Building signsrch from source (sandsmark/signsrch fork)..."
        SS_SRC="/tmp/signsrch-src"
        rm -rf "$SS_SRC"
        if git clone --depth=1 https://github.com/sandsmark/signsrch.git \
            "$SS_SRC" >>"$LAYER25_LOG" 2>&1; then
            pushd "$SS_SRC" >/dev/null
            # Audit-6 fix (L38): -pthread CFLAGS handles linking but signsrch's
            # threads.h does not #include <pthread.h> directly, so the
            # pthread_create / pthread_join symbols are not declared at compile
            # time. Modern GCC treats implicit declarations as errors. Patch
            # threads.h to include <pthread.h> at the top.
            if [[ -f threads.h ]] && ! grep -q '#include <pthread.h>' threads.h; then
                sed -i '1i #include <pthread.h>' threads.h 2>>"$LAYER25_LOG" || true
            fi
            # Audit-7 fix (L43): signsrch's crc.c uses a forward declaration
            # `add_func()` (empty parens). In K&R / pre-C99 / -std=gnu89, this
            # means "function with unspecified args" and accepts any call. In
            # modern C (gnu17+ default in GCC 14), empty parens mean
            # `(void)`, so the call site `add_func(op, &len, num, bits, endian)`
            # produces:
            #   crc.c:125:18: error: too many arguments to function 'add_func';
            #     expected 0, have 5
            # The fix is to compile with -std=gnu89 which restores K&R
            # empty-paren semantics. Combined with belt-and-suspenders
            # -Wno-error flags, signsrch's legacy code now builds on
            # GCC 14+. We also pass -fcommon to handle multiple-definition
            # of common symbols (legacy linkage rules).
            SIGNSRCH_CFLAGS="-O2 -pthread -std=gnu89 -fcommon"
            SIGNSRCH_CFLAGS="$SIGNSRCH_CFLAGS -Wno-error=implicit-function-declaration"
            SIGNSRCH_CFLAGS="$SIGNSRCH_CFLAGS -Wno-implicit-function-declaration"
            SIGNSRCH_CFLAGS="$SIGNSRCH_CFLAGS -Wno-error=int-conversion"
            SIGNSRCH_CFLAGS="$SIGNSRCH_CFLAGS -Wno-error=incompatible-pointer-types"
            if CFLAGS="$SIGNSRCH_CFLAGS" LDFLAGS="-pthread" \
                make CFLAGS="$SIGNSRCH_CFLAGS" LDFLAGS="-pthread" >>"$LAYER25_LOG" 2>&1; then
                if make install >>"$LAYER25_LOG" 2>&1 || \
                   { cp -f signsrch /usr/local/bin/ && \
                     mkdir -p /usr/local/etc && cp -f signsrch.sig /usr/local/etc/ 2>/dev/null; }; then
                    log_ok "signsrch installed → $(command -v signsrch)"
                else
                    log_warn "signsrch built but install failed"
                    FAILED_APT+=("signsrch-install")
                fi
            else
                log_warn "signsrch build failed (sandsmark fork is unmaintained;"
                log_warn "  see $LAYER25_LOG for details)"
                log_warn "  Non-fatal: signsrch is rarely-used and stage_iocs has alternative IOC paths"
                FAILED_APT+=("signsrch-build")
            fi
            popd >/dev/null
        else
            log_warn "signsrch git clone failed"; FAILED_APT+=("signsrch-clone")
        fi
    fi

    # ----- Manalyze (PE static analyzer, source build) -----------------------
    if command -v manalyze >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
        log_info "Manalyze already in PATH (use --force to rebuild)"
    else
        log_info "Building Manalyze from source (JusticeRage/Manalyze)..."
        MZ_SRC="/tmp/Manalyze-src"
        rm -rf "$MZ_SRC"
        if git clone --recursive --depth=1 https://github.com/JusticeRage/Manalyze.git \
            "$MZ_SRC" >>"$LAYER25_LOG" 2>&1; then
            pushd "$MZ_SRC" >/dev/null
            if cmake . >>"$LAYER25_LOG" 2>&1 && make -j"$(nproc)" >>"$LAYER25_LOG" 2>&1; then
                if make install >>"$LAYER25_LOG" 2>&1; then
                    log_ok "Manalyze installed → $(command -v manalyze)"
                else
                    log_warn "Manalyze built but make install failed"
                    FAILED_APT+=("Manalyze-install")
                fi
            else
                log_warn "Manalyze cmake/make failed (deps: libboost-dev libssl-dev)"
                FAILED_APT+=("Manalyze-build")
            fi
            popd >/dev/null
        else
            log_warn "Manalyze git clone failed"; FAILED_APT+=("Manalyze-clone")
        fi
    fi

    # v3.0.12 (audit-16 E1) - operator F11: manalyze emits a warning
    # banner on every scan if ClamAV-derived yara rules haven't been
    # generated. The conversion script is shipped with manalyze at
    # /usr/local/share/manalyze/yara_rules/update_clamav_signatures.py.
    # It reads ClamAV's .cvd databases (placed by freshclam) and
    # converts the signatures into yara rules manalyze can consume.
    # Without this step, manalyze still scans but with reduced
    # detection coverage. Run the script once post-install if both
    # ClamAV and manalyze are available.
    MZ_CLAMAV_SCRIPT="/usr/local/share/manalyze/yara_rules/update_clamav_signatures.py"
    if [[ -f "$MZ_CLAMAV_SCRIPT" ]] && command -v manalyze >/dev/null 2>&1; then
        log_info "Generating manalyze ClamAV-derived yara rules (one-time post-install)…"
        # Ensure ClamAV signatures are present; if freshclam never ran,
        # invoke it once. freshclam has its own mutex so this is safe.
        if [[ ! -f /var/lib/clamav/main.cvd && ! -f /var/lib/clamav/main.cld ]]; then
            log_info "ClamAV main.cvd missing; running freshclam first…"
            freshclam --quiet >>"$LAYER25_LOG" 2>&1 || \
                log_warn "freshclam failed; manalyze ClamAV rules may be empty"
        fi
        # The script is python2 in older manalyze, python3 in newer; try python3 first
        if python3 "$MZ_CLAMAV_SCRIPT" >>"$LAYER25_LOG" 2>&1; then
            log_ok "manalyze ClamAV yara rules generated"
        elif python2 "$MZ_CLAMAV_SCRIPT" >>"$LAYER25_LOG" 2>&1; then
            log_ok "manalyze ClamAV yara rules generated (python2 fallback)"
        else
            log_warn "manalyze update_clamav_signatures.py failed; warning banner will persist"
            FAILED_APT+=("manalyze-clamav-rules")
        fi
    fi

    # ===== v2.6.0 LAYER 2E additions ========================================
    # The v2.5.0 GitHub-release block above handles .NET deobfuscators and
    # Manalyze + signsrch. The v2.6.0 additions below handle the new binary
    # type buckets (Python bytecode, Java archives, PDF analysis).

    # ----- pycdc + pycdas (Python bytecode decompiler/disasm, source build) -
    # Builds via cmake + make from zrax/pycdc. Installs both binaries to
    # /usr/local/bin. No precompiled releases exist; source build is the
    # only path. The build is fast (~30s) and has no special deps beyond
    # cmake which is already installed for Manalyze.
    if command -v pycdc >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
        log_info "pycdc already in PATH (use --force to rebuild)"
    else
        log_info "Building pycdc from source (zrax/pycdc)..."
        PYCDC_SRC="/tmp/pycdc-src"
        rm -rf "$PYCDC_SRC"
        if git clone --depth=1 https://github.com/zrax/pycdc.git \
            "$PYCDC_SRC" >>"$LAYER25_LOG" 2>&1; then
            pushd "$PYCDC_SRC" >/dev/null
            if cmake . >>"$LAYER25_LOG" 2>&1 && make -j"$(nproc)" >>"$LAYER25_LOG" 2>&1; then
                cp -f pycdc /usr/local/bin/  2>/dev/null && \
                cp -f pycdas /usr/local/bin/ 2>/dev/null && \
                    log_ok "pycdc + pycdas installed -> /usr/local/bin/" || {
                    log_warn "pycdc built but copy to /usr/local/bin failed"
                    FAILED_APT+=("pycdc-install")
                }
            else
                log_warn "pycdc build failed"; FAILED_APT+=("pycdc-build")
            fi
            popd >/dev/null
        else
            log_warn "pycdc git clone failed"; FAILED_APT+=("pycdc-clone")
        fi
    fi

    # ----- CFR (Java decompiler, release jar) -------------------------------
    if [[ -f "/opt/cfr/cfr.jar" && $FORCE -eq 0 ]]; then
        log_info "CFR already at /opt/cfr/cfr.jar (use --force to refresh)"
    else
        log_info "Fetching CFR (latest release)..."
        CFR_API="https://api.github.com/repos/leibnitz27/cfr/releases/latest"
        CFR_URL=$(curl -sSL "$CFR_API" 2>>"$LAYER25_LOG" | \
            grep -oE '"browser_download_url":\s*"[^"]+cfr[^"]*\.jar"' | \
            head -1 | sed 's/.*: *"\(.*\)"/\1/')
        if [[ -n "$CFR_URL" ]]; then
            mkdir -p /opt/cfr
            if curl -sSL -o /opt/cfr/cfr.jar "$CFR_URL" 2>>"$LAYER25_LOG"; then
                log_ok "CFR installed -> /opt/cfr/cfr.jar"
            else
                log_warn "CFR download failed"; FAILED_APT+=("CFR-download")
            fi
        else
            log_warn "CFR release URL not resolvable from GitHub API"
            FAILED_APT+=("CFR-url")
        fi
    fi

    # ----- procyon (Java decompiler, release jar) ---------------------------
    if [[ -f "/opt/procyon/procyon.jar" && $FORCE -eq 0 ]]; then
        log_info "procyon already at /opt/procyon/procyon.jar (use --force to refresh)"
    else
        log_info "Fetching procyon-decompiler (latest release)..."
        PROC_API="https://api.github.com/repos/mstrobel/procyon/releases/latest"
        PROC_URL=$(curl -sSL "$PROC_API" 2>>"$LAYER25_LOG" | \
            grep -oE '"browser_download_url":\s*"[^"]+procyon-decompiler[^"]*\.jar"' | \
            head -1 | sed 's/.*: *"\(.*\)"/\1/')
        if [[ -n "$PROC_URL" ]]; then
            mkdir -p /opt/procyon
            if curl -sSL -o /opt/procyon/procyon.jar "$PROC_URL" 2>>"$LAYER25_LOG"; then
                log_ok "procyon installed -> /opt/procyon/procyon.jar"
            else
                log_warn "procyon download failed"; FAILED_APT+=("procyon-download")
            fi
        else
            log_warn "procyon release URL not resolvable from GitHub API"
            FAILED_APT+=("procyon-url")
        fi
    fi

    # ----- DidierStevensSuite (pdfid, pdf-parser, oledump, etc.) -----------
    # Cloned to /opt/DidierStevensSuite/. The Python scripts there are
    # invoked directly by stage_pdf and stage_ole (no install step;
    # they're standalone scripts).
    if [[ -d "/opt/DidierStevensSuite/.git" && $FORCE -eq 0 ]]; then
        log_info "DidierStevensSuite already at /opt/DidierStevensSuite (use --force to refresh)"
    else
        log_info "Cloning DidierStevensSuite (pdfid, pdf-parser, oledump, ...)..."
        rm -rf /opt/DidierStevensSuite
        if git clone --depth=1 https://github.com/DidierStevens/DidierStevensSuite.git \
            /opt/DidierStevensSuite >>"$LAYER25_LOG" 2>&1; then
            chmod +x /opt/DidierStevensSuite/*.py 2>/dev/null || true
            log_ok "DidierStevensSuite installed -> /opt/DidierStevensSuite"
        else
            log_warn "DidierStevensSuite git clone failed"
            FAILED_APT+=("DidierStevensSuite-clone")
        fi
    fi
fi

# =============================================================================
# LAYER 2F -- yarGen (YARA rule generator; NEW in v2.7.0)
# =============================================================================
# yarGen extracts strings from samples, filters them against a goodware
# database, and emits YARA rules containing the most distinctive
# non-goodware strings. The tool itself is small (single Python script);
# the goodware database is large (~913MB) and is separately downloaded
# only when the user opts in via --with-yargen-db.
#
# Without the goodware DB, yarGen still works but rule quality drops
# (more false positives, less specificity). The dedicated stage
# (88-yargen.sh) checks for /opt/yarGen/dbs/good-strings*.db and warns
# when absent.
# =============================================================================
log_hdr "LAYER 2F -- yarGen (always installs script; goodware DB opt-in)"
LAYER2F_LOG="${LOG_ROOT}/layer2f-yargen-${RUN_TS}.log"
: > "$LAYER2F_LOG"

if [[ -d "/opt/yarGen/.git" && $FORCE -eq 0 ]]; then
    log_info "yarGen already at /opt/yarGen (use --force to refresh)"
else
    log_info "Cloning yarGen (Neo23x0/yarGen)..."
    rm -rf /opt/yarGen
    if git clone --depth=1 https://github.com/Neo23x0/yarGen.git \
        /opt/yarGen >>"$LAYER2F_LOG" 2>&1; then
        log_ok "yarGen cloned to /opt/yarGen"
    else
        log_warn "yarGen git clone failed (see $LAYER2F_LOG)"
        FAILED_APT+=("yarGen-clone")
    fi
fi

# Optional: download the ~913MB goodware database. This is a one-time
# operation; --force won't redownload (the user can wipe /opt/yarGen/dbs
# manually if they want to refresh).
if [[ ${WITH_YARGEN_DB:-0} -eq 1 ]]; then
    if [[ -d "/opt/yarGen/dbs" ]] && \
       ls /opt/yarGen/dbs/good-strings*.db >/dev/null 2>&1 && \
       [[ $FORCE -eq 0 ]]; then
        log_info "yarGen goodware DB already present (use --force to refresh)"
    elif [[ ! -d "/opt/yarGen" ]]; then
        log_warn "yarGen goodware DB requested but yarGen not cloned; skipping"
    else
        log_info "Downloading yarGen goodware database (~913MB; one-time)..."
        # yarGen's --update fetches DBs from bsk-consulting and unpacks
        # them. Run as the invoking user so artifacts land with correct
        # ownership.
        if (cd /opt/yarGen && as_user "${VENV_PY:-python3}" yarGen.py --update) \
            >>"$LAYER2F_LOG" 2>&1; then
            log_ok "yarGen goodware DB downloaded -> /opt/yarGen/dbs/"
        else
            log_warn "yarGen --update failed (see $LAYER2F_LOG)"
            FAILED_APT+=("yarGen-db-update")
        fi
    fi
else
    log_info "Skipping yarGen goodware DB (pass --with-yargen-db to download ~913MB)"
fi

# =============================================================================
# LAYER 2G -- Mobile RE tools fallback (NEW in v2.8.0)
# =============================================================================
# Apt should already have installed jadx + apktool + apksigner + aapt +
# dex2jar (LAYER 1). This layer provides source-build fallbacks for
# distributions where those packages are missing or stale:
#   - jadx       : github.com/skylot/jadx releases (Java app; needs JDK)
#   - apktool    : iBotPeaches/Apktool releases (Java jar + wrapper script)
#   - baksmali   : separately-published jar from JesusFreke/smali (apktool
#                   bundles its own copy but standalone is useful)
#
# Each fallback is non-fatal: failure to install a fallback only matters
# if the apt version is also missing, in which case stage_dex / stage_apk
# will silently skip that tier.
# =============================================================================
log_hdr "LAYER 2G - Mobile RE tools fallback (jadx / apktool / baksmali)"
LAYER2G_LOG="${LOG_ROOT}/layer2g-mobile-${RUN_TS}.log"
: > "$LAYER2G_LOG"

# ---- jadx fallback -----------------------------------------------------------
if command -v jadx >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
    log_info "jadx already in PATH (apt or earlier install); skipping fallback"
else
    log_info "Installing jadx via GitHub release tarball..."
    JADX_VER="1.5.0"
    JADX_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip"
    JADX_TMP="/tmp/jadx-${JADX_VER}.zip"
    if curl -fsSL -o "$JADX_TMP" "$JADX_URL" >>"$LAYER2G_LOG" 2>&1; then
        rm -rf /opt/jadx
        mkdir -p /opt/jadx
        if unzip -q "$JADX_TMP" -d /opt/jadx >>"$LAYER2G_LOG" 2>&1; then
            # jadx ships bin/jadx + bin/jadx-gui shell launchers; symlink
            # to /usr/local/bin so the binary lands in PATH.
            if [[ -x /opt/jadx/bin/jadx ]]; then
                ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
                ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui 2>/dev/null || true
                log_ok "jadx installed via fallback (/opt/jadx, symlinked to /usr/local/bin)"
            else
                log_warn "jadx unpacked but bin/jadx not executable"
                FAILED_APT+=("jadx-fallback")
            fi
        else
            log_warn "jadx unzip failed (see $LAYER2G_LOG)"
            FAILED_APT+=("jadx-fallback")
        fi
        rm -f "$JADX_TMP"
    else
        log_warn "jadx download failed (see $LAYER2G_LOG)"
        FAILED_APT+=("jadx-download")
    fi
fi

# ---- apktool fallback --------------------------------------------------------
if command -v apktool >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
    log_info "apktool already in PATH (apt or earlier install); skipping fallback"
else
    log_info "Installing apktool via GitHub release jar..."
    APKTOOL_VER="2.11.1"
    APKTOOL_JAR_URL="https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VER}/apktool_${APKTOOL_VER}.jar"
    APKTOOL_WRAPPER_URL="https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"
    rm -rf /opt/apktool
    mkdir -p /opt/apktool
    if curl -fsSL -o /opt/apktool/apktool.jar "$APKTOOL_JAR_URL" >>"$LAYER2G_LOG" 2>&1; then
        if curl -fsSL -o /usr/local/bin/apktool "$APKTOOL_WRAPPER_URL" >>"$LAYER2G_LOG" 2>&1; then
            chmod +x /usr/local/bin/apktool
            # The apktool wrapper expects /usr/local/bin/apktool.jar; symlink
            ln -sf /opt/apktool/apktool.jar /usr/local/bin/apktool.jar
            log_ok "apktool installed via fallback (/opt/apktool, wrapper at /usr/local/bin/apktool)"
        else
            log_warn "apktool wrapper download failed (jar present but no launcher)"
            FAILED_APT+=("apktool-wrapper")
        fi
    else
        log_warn "apktool jar download failed (see $LAYER2G_LOG)"
        FAILED_APT+=("apktool-jar")
    fi
fi

# ---- baksmali fallback (standalone jar) --------------------------------------
# apktool bundles baksmali, but a standalone /usr/local/bin/baksmali is
# convenient for stage_dex when called directly on a .dex without going
# through apktool.
if command -v baksmali >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
    log_info "baksmali already in PATH (apt or apktool bundle); skipping fallback"
else
    log_info "Installing baksmali via GitHub release jar..."
    BAKSMALI_VER="2.5.2"
    BAKSMALI_URL="https://bitbucket.org/JesusFreke/smali/downloads/baksmali-${BAKSMALI_VER}.jar"
    rm -rf /opt/baksmali
    mkdir -p /opt/baksmali
    if curl -fsSL -o /opt/baksmali/baksmali.jar "$BAKSMALI_URL" >>"$LAYER2G_LOG" 2>&1; then
        # Build a wrapper script that invokes the jar
        cat > /usr/local/bin/baksmali <<'WRAPEOF'
#!/bin/sh
exec java -jar /opt/baksmali/baksmali.jar "$@"
WRAPEOF
        chmod +x /usr/local/bin/baksmali
        log_ok "baksmali installed via fallback (/opt/baksmali, wrapper at /usr/local/bin/baksmali)"
    else
        log_warn "baksmali jar download failed (see $LAYER2G_LOG)"
        log_warn "       NOTE: apktool's bundled baksmali still works for"
        log_warn "       APK extraction; this only affects standalone DEX"
        log_warn "       analysis without an enclosing APK"
        FAILED_APT+=("baksmali-jar")
    fi
fi

# =============================================================================
# LAYER 2D - TrID signature database bootstrap
# =============================================================================
# The `trid` apt package ships the binary but NOT the signature database
# (`triddefs.trd`), which is separately maintained by Marco Pontello and
# updated frequently. Without it, `trid` errors out. We download the
# latest `triddefs.trd` from mark0.net to /usr/share/trid/.
#
# The definition file is hand-curated over years; bootstrapping it at
# install time is the honest path.
if [[ $SKIP_APT -eq 1 ]]; then
    log_info "Skipping TrID definitions (--skip-apt)"
elif ! command -v trid >/dev/null 2>&1; then
    log_info "trid binary not installed; skipping definition bootstrap"
else
    log_hdr "LAYER 2D -- TrID definition database"
    TRID_LOG="${LOG_ROOT}/trid.log"
    TRID_DEFS_URLS=(
        "https://mark0.net/download/triddefs.trd"
        "https://mark0.net/download/triddefs.zip"
    )
    # Possible install locations -- apt's trid looks in the first path it finds.
    TRID_INSTALL_CANDIDATES=(
        "/usr/share/trid"
        "/etc/trid"
        "/opt/trid"
    )
    TRID_DIR=""
    for d in "${TRID_INSTALL_CANDIDATES[@]}"; do
        if [[ -d "$d" ]] || mkdir -p "$d" 2>/dev/null; then
            TRID_DIR="$d"; break
        fi
    done

    if [[ -z "$TRID_DIR" ]]; then
        log_warn "No writable TrID install directory available"
        FAILED_APT+=("trid-defs")
    elif [[ -f "${TRID_DIR}/triddefs.trd" ]]; then
        DEF_AGE_DAYS=$(( ($(date +%s) - $(stat -c %Y "${TRID_DIR}/triddefs.trd" 2>/dev/null || echo 0)) / 86400 ))
        if [[ $DEF_AGE_DAYS -lt 180 && $FORCE -eq 0 ]]; then
            log_ok "TrID definitions already present (age: ${DEF_AGE_DAYS}d, < 180d threshold)"
        else
            log_info "TrID definitions are ${DEF_AGE_DAYS}d old; refreshing…"
            TRID_FETCH_OK=0
            for url in "${TRID_DEFS_URLS[@]}"; do
                TMPF="/tmp/$(basename "$url")"
                if curl -fsSL -o "$TMPF" "$url" >>"$TRID_LOG" 2>&1; then
                    if [[ "$url" =~ \.zip$ ]]; then
                        unzip -q -o "$TMPF" -d "$TRID_DIR" >>"$TRID_LOG" 2>&1 || true
                    else
                        cp "$TMPF" "${TRID_DIR}/triddefs.trd"
                    fi
                    rm -f "$TMPF"
                    if [[ -f "${TRID_DIR}/triddefs.trd" ]]; then TRID_FETCH_OK=1; break; fi
                fi
            done
            if [[ $TRID_FETCH_OK -eq 1 ]]; then
                log_ok "TrID definitions refreshed in $TRID_DIR"
            else
                log_warn "TrID definition refresh failed -- details in $TRID_LOG"
                FAILED_APT+=("trid-defs")
            fi
        fi
    else
        log_info "Bootstrapping TrID definitions into $TRID_DIR…"
        TRID_FETCH_OK=0
        for url in "${TRID_DEFS_URLS[@]}"; do
            TMPF="/tmp/$(basename "$url")"
            if curl -fsSL -o "$TMPF" "$url" >>"$TRID_LOG" 2>&1; then
                if [[ "$url" =~ \.zip$ ]]; then
                    unzip -q -o "$TMPF" -d "$TRID_DIR" >>"$TRID_LOG" 2>&1 || true
                else
                    cp "$TMPF" "${TRID_DIR}/triddefs.trd"
                fi
                rm -f "$TMPF"
                if [[ -f "${TRID_DIR}/triddefs.trd" ]]; then TRID_FETCH_OK=1; break; fi
            fi
        done
        if [[ $TRID_FETCH_OK -eq 1 ]]; then
            log_ok "TrID definitions bootstrapped in $TRID_DIR"
        else
            log_warn "TrID definition bootstrap failed -- tool will not work without it"
            log_warn "Manual: curl -O https://mark0.net/download/triddefs.trd; mv triddefs.trd $TRID_DIR/"
            FAILED_APT+=("trid-defs")
        fi
    fi

    # v3.0.12 (audit-16 D1) - operator F9: TrID looks for triddefs.trd
    # in /usr/local/bin/ (alongside the trid binary per official
    # mark0.net install instructions). When apt-installed trid is in
    # /usr/local/bin/, the binary's search path doesn't include
    # /usr/share/trid/. Without the symlink, every trid invocation
    # emits "File /usr/local/bin/triddefs.trd not found! No definitions
    # available!" The symlink makes the canonical /usr/share/trid/
    # location available where TrID actually looks. Both paths now
    # resolve to the same physical file.
    if [[ -f "${TRID_DIR}/triddefs.trd" ]] && [[ ! -e /usr/local/bin/triddefs.trd ]]; then
        if ln -sf "${TRID_DIR}/triddefs.trd" /usr/local/bin/triddefs.trd 2>>"$TRID_LOG"; then
            log_ok "TrID symlink: /usr/local/bin/triddefs.trd -> ${TRID_DIR}/triddefs.trd"
        else
            # Fallback: copy if symlink fails (e.g., /usr/local/bin readonly)
            if cp "${TRID_DIR}/triddefs.trd" /usr/local/bin/triddefs.trd 2>>"$TRID_LOG"; then
                log_ok "TrID definitions copied to /usr/local/bin/triddefs.trd"
            else
                log_warn "Could not place triddefs.trd in /usr/local/bin/ (TrID may not find it)"
            fi
        fi
    fi
fi

# =============================================================================
# LAYER 2H -- apt-fallback source builds for PE/binary analysis tools (v3.0.0+)
# =============================================================================
# Some apt packages (pev, bloaty) are missing from certain distros' default
# repos:
#   - pev: project moved to mentebinaria/readpe; original Kali/Debian
#     'pev' package may be deprecated or absent.
#   - bloaty: Google's binary-size analyzer; available in Debian Bookworm
#     but may be missing from Kali Rolling at certain points.
#
# This layer provides GitHub-source-build fallbacks. It runs ONLY when the
# corresponding apt package is in FAILED_APT[] - if apt succeeded, we skip
# the rebuild to save time.
#
# Cost: roughly 30-90 seconds per tool. Build deps (gcc, make, autoconf,
# libtool, libssl-dev) are already in LAYER 1 apt list.
# =============================================================================
if [[ $SKIP_APT -eq 0 ]]; then
    LAYER2H_LOG="${LOG_ROOT}/layer2h-${RUN_TS}.log"
    : > "$LAYER2H_LOG"

    # Detect which apt failures need source-build fallback. We check
    # FAILED_APT[] from LAYER 1 with array membership, not string contains,
    # so 'pev' doesn't match 'pev-clone' or similar.
    NEED_PEV=0
    NEED_BLOATY=0
    NEED_TRID=0
    for failed in "${FAILED_APT[@]}"; do
        case "$failed" in
            pev)    NEED_PEV=1 ;;
            bloaty) NEED_BLOATY=1 ;;
            trid)   NEED_TRID=1 ;;
        esac
    done

    if [[ $NEED_PEV -eq 1 || $NEED_BLOATY -eq 1 || $NEED_TRID -eq 1 ]]; then
        log_hdr "LAYER 2H -- Source-build fallbacks for failed apt packages"
    fi

    # ----- pev / readpe (mentebinaria/readpe) --------------------------------
    if [[ $NEED_PEV -eq 1 ]]; then
        log_info "Building readpe (formerly pev) from mentebinaria/readpe..."
        # readpe ships readpe, pedis, pehash, pescan, pesec, pestr binaries.
        # Build with make + sudo make install (lands in /usr/local/bin/).
        # libpe is bundled (no separate submodule needed since absorption).
        if command -v make >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1; then
            PEV_SRC="/tmp/readpe-src"
            rm -rf "$PEV_SRC"
            if git clone --depth=1 https://github.com/mentebinaria/readpe.git \
                "$PEV_SRC" >>"$LAYER2H_LOG" 2>&1; then
                pushd "$PEV_SRC" >/dev/null
                if make >>"$LAYER2H_LOG" 2>&1 && make install >>"$LAYER2H_LOG" 2>&1; then
                    # Update libpe ldconfig
                    echo "/usr/local/lib" > /etc/ld.so.conf.d/libpe.conf
                    ldconfig 2>>"$LAYER2H_LOG" || true
                    log_ok "readpe built/installed → /usr/local/bin/readpe (+ pedis, pehash, pescan, pesec, pestr)"
                    # Remove pev from FAILED_APT now that readpe replaces it
                    NEW_FAILED=()
                    for f in "${FAILED_APT[@]}"; do
                        [[ "$f" != "pev" ]] && NEW_FAILED+=("$f")
                    done
                    FAILED_APT=("${NEW_FAILED[@]}")
                else
                    log_warn "readpe build/install failed; check $LAYER2H_LOG"
                fi
                popd >/dev/null
            else
                log_warn "readpe git clone failed"
            fi
        else
            log_warn "readpe needs make+gcc; skipping (build-essential missing?)"
        fi
    fi

    # ----- bloaty (google/bloaty) --------------------------------------------
    if [[ $NEED_BLOATY -eq 1 ]]; then
        log_info "Building bloaty from google/bloaty..."
        # bloaty uses cmake; LAYER 1 should have installed it (per audit-4 fix).
        if command -v cmake >/dev/null 2>&1; then
            BLOATY_SRC="/tmp/bloaty-src"
            rm -rf "$BLOATY_SRC"
            # bloaty has multiple submodules (capstone, protobuf, re2, zlib);
            # --recurse-submodules is required.
            if git clone --depth=1 --recurse-submodules \
                https://github.com/google/bloaty.git \
                "$BLOATY_SRC" >>"$LAYER2H_LOG" 2>&1; then
                pushd "$BLOATY_SRC" >/dev/null
                mkdir -p build
                pushd build >/dev/null
                if cmake -G "Unix Makefiles" .. >>"$LAYER2H_LOG" 2>&1 && \
                   make -j"$(nproc)" >>"$LAYER2H_LOG" 2>&1 && \
                   { cp -f bloaty /usr/local/bin/ 2>>"$LAYER2H_LOG" || \
                     make install >>"$LAYER2H_LOG" 2>&1; }; then
                    log_ok "bloaty built/installed → $(command -v bloaty)"
                    NEW_FAILED=()
                    for f in "${FAILED_APT[@]}"; do
                        [[ "$f" != "bloaty" ]] && NEW_FAILED+=("$f")
                    done
                    FAILED_APT=("${NEW_FAILED[@]}")
                else
                    log_warn "bloaty build/install failed; check $LAYER2H_LOG"
                fi
                popd >/dev/null
                popd >/dev/null
            else
                log_warn "bloaty git clone failed"
            fi
        else
            log_warn "bloaty needs cmake; skipping"
        fi
    fi

    # ----- trid (Marco Pontello, mark0.net) ----------------------------------
    # TrID is closed-source freeware. Per the author's license:
    # "freeware for non commercial, personal, research and educational use".
    # This toolkit's RE/security-research use fits that scope. We download
    # the linux_64 zip from the official mark0.net URL and install both
    # the binary and triddefs.trd to /usr/local/bin and /usr/share/trid.
    if [[ $NEED_TRID -eq 1 ]]; then
        log_info "Downloading trid binary from mark0.net..."
        TRID_TMP=$(mktemp -d)
        TRID_BIN_URL="https://mark0.net/download/trid_linux_64.zip"
        TRID_DEFS_URL="https://mark0.net/download/triddefs.zip"
        if curl -sSL -o "$TRID_TMP/trid.zip" "$TRID_BIN_URL" 2>>"$LAYER2H_LOG"; then
            if unzip -q -o "$TRID_TMP/trid.zip" -d "$TRID_TMP/" 2>>"$LAYER2H_LOG"; then
                if [[ -f "$TRID_TMP/trid" ]]; then
                    chmod +x "$TRID_TMP/trid"
                    # Audit-6 fix (L39): mark0.net's trid_linux_64 binary
                    # segfaults on locale init under modern glibc:
                    #   trid: loadlocale.c:129: _nl_intern_locale_data:
                    #   Assertion `cnt < (sizeof (_nl_value_type_LC_TIME) /
                    #   sizeof (_nl_value_type_LC_TIME[0]))' failed.
                    # The binary was compiled against an older glibc whose
                    # LC_TIME value-type table layout has since changed.
                    # Wrap with LC_ALL=C to bypass locale loading entirely.
                    # Install raw binary and create a wrapper that prefixes
                    # LC_ALL=C; PATH lookup will hit the wrapper first.
                    install -m 0755 "$TRID_TMP/trid" /usr/local/bin/trid.bin
                    cat > /usr/local/bin/trid <<'TRIDWRAP'
#!/usr/bin/env bash
# Wrapper for mark0.net trid binary (LAYER 2H install) to bypass glibc
# locale-init segfault. Installed by install-retoolkit.sh audit-6 L39.
LC_ALL=C exec /usr/local/bin/trid.bin "$@"
TRIDWRAP
                    chmod 0755 /usr/local/bin/trid
                    # Also fetch the defs (LAYER 2D would later refresh these
                    # but bootstrap them now so trid is immediately usable)
                    mkdir -p /usr/share/trid
                    if curl -sSL -o "$TRID_TMP/triddefs.zip" "$TRID_DEFS_URL" 2>>"$LAYER2H_LOG" && \
                       unzip -q -o "$TRID_TMP/triddefs.zip" -d "$TRID_TMP/" 2>>"$LAYER2H_LOG" && \
                       [[ -f "$TRID_TMP/triddefs.trd" ]]; then
                        cp -f "$TRID_TMP/triddefs.trd" /usr/share/trid/
                        log_ok "trid binary + LC_ALL=C wrapper + defs installed → /usr/local/bin/trid + /usr/share/trid/triddefs.trd"
                    else
                        log_ok "trid binary + LC_ALL=C wrapper installed → /usr/local/bin/trid (defs will be fetched in LAYER 2D)"
                    fi
                    NEW_FAILED=()
                    for f in "${FAILED_APT[@]}"; do
                        [[ "$f" != "trid" ]] && NEW_FAILED+=("$f")
                    done
                    FAILED_APT=("${NEW_FAILED[@]}")
                else
                    log_warn "trid binary not found in extracted zip"
                fi
            else
                log_warn "trid zip extraction failed"
            fi
        else
            log_warn "trid download from mark0.net failed (network issue?)"
        fi
        rm -rf "$TRID_TMP"
    fi
fi

# v3.0.4 (audit-8 A12): post-LAYER-2H reconciliation summary.
# After LAYER 2H runs (or skips), FAILED_APT[] reflects the final state
# of LAYER 1 + LAYER 2H combined. Print a summary so the operator sees
# what's actually unresolved vs what was recovered. This replaces the
# pre-LAYER-2H warning with a definitive post-recovery status line.
if [[ $SKIP_APT -eq 0 ]]; then
    if [[ ${#FAILED_APT[@]} -eq 0 ]]; then
        log_ok "LAYER 1 + LAYER 2H complete: all apt packages installed or recovered via source build"
    else
        # v3.7.3 (audit-31 B5): partition the residual list. Some entries are
        # not "failures" at all -- they are OPT-IN components that were never
        # requested, or known-degraded optional tools. Reporting them under
        # "unresolved" alarmed operators. Separate them out:
        #   NoFuserEx-build  -- opt-in (USE_NOFUSEREX=1); unmaintained fork whose
        #                       dnlib submodule targets .NET Framework v2.0.
        #   yarGen-db-update -- the ~913MB goodware DB is opt-in via
        #                       --with-yargen-db; absent by default is expected.
        _OPT_IN_EXPECTED=" NoFuserEx-build yarGen-db-update "
        _unresolved=(); _optin=()
        for _f in "${FAILED_APT[@]}"; do
            if [[ "$_OPT_IN_EXPECTED" == *" $_f "* ]]; then
                _optin+=("$_f")
            else
                _unresolved+=("$_f")
            fi
        done
        if [[ ${#_unresolved[@]} -gt 0 ]]; then
            log_warn "LAYER 1 + LAYER 2H complete: unresolved apt-stage packages: ${_unresolved[*]}"
            log_warn "  These were not installed by apt and not recovered by LAYER 2H."
            log_warn "  Subsequent LAYERs may degrade gracefully; check the verify summary at the end."
        else
            log_ok "LAYER 1 + LAYER 2H complete: all required apt packages installed or recovered"
        fi
        if [[ ${#_optin[@]} -gt 0 ]]; then
            log_info "Skipped (opt-in / known-degraded, not failures): ${_optin[*]}"
            log_info "  NoFuserEx is opt-in via USE_NOFUSEREX=1 (unmaintained fork); yarGen goodware"
            log_info "  DB is opt-in via --with-yargen-db (~913MB). Both are safe to ignore unless needed."
        fi
    fi
fi

# =============================================================================
# LAYER 3 -- Python venv with RE stack
# =============================================================================
if [[ $SKIP_PYTHON -eq 1 ]]; then
    log_info "Skipping Python tooling (--skip-python)"
else
    log_hdr "LAYER 3 -- Python RE stack"
    log_info "Per-phase log: $PY_LOG"

    mkdir -p "$RETOOLS_BASE"

    if [[ -d "$RETOOLS_VENV" && $FORCE -eq 0 ]]; then
        log_ok "Python venv exists at $RETOOLS_VENV"
    else
        [[ -d "$RETOOLS_VENV" ]] && rm -rf "$RETOOLS_VENV"
        log_info "Creating Python venv at $RETOOLS_VENV"
        python3 -m venv "$RETOOLS_VENV" >>"$PY_LOG" 2>&1
    fi

    VENV_PIP="${RETOOLS_VENV}/bin/pip"
    "$VENV_PIP" install --upgrade pip wheel setuptools >>"$PY_LOG" 2>&1

    PY_PKGS=(
        # PE / binary parsing
        pefile
        dnfile
        lief
        # Disassembly / assembly / emulation
        capstone
        keystone-engine
        unicorn
        # Pattern matching
        yara-python
        # Mandiant FLARE tools
        flare-capa
        flare-floss
        # Symbolic execution
        angr
        # r2/rz bindings
        r2pipe
        rzpipe
        # CTF helpers (includes utilities used elsewhere)
        pwntools
        # OLE / Office document inspection
        oletools
        # Hex / diff helpers
        hexdump
        # Ghidra 12+ Python 3 postscript execution -- REQUIRED for
        # analyze-binaries.sh to run GhidraDump.py via pyghidraRun.
        # Without this, Ghidra's PyGhidraScriptProvider throws
        # "Ghidra was not started with PyGhidra. Python is not available".
        pyghidra
        # v3.0.3 (audit-7) -- peframe transitive dep M2Crypto.
        # peframe's setup.py specifies M2Crypto without an upper bound but
        # pip's resolver pulls older versions which require a source build
        # against OpenSSL via SWIG. On Python 3.13 the source build fails:
        #   Building wheel for M2Crypto (pyproject.toml): finished with status 'error'
        # M2Crypto 0.47.0+ ships prebuilt cp313 wheels on PyPI. By pinning
        # M2Crypto>=0.47.0 BEFORE peframe in PY_PKGS, the wheel is fetched
        # and installed first; peframe's later install then sees M2Crypto
        # already satisfied and skips the broken source build path.
        'M2Crypto>=0.47.0'
        # v2.5.0: peframe - PE behavioral static analyzer.
        # Installed as a tarball URL (not from PyPI) because the PyPI
        # package is stale; the GitHub master is the maintained reference.
        https://github.com/guelfoweb/peframe/archive/master.zip
        # v2.6.0: Python bytecode decompilers (covers Python <= 3.8)
        uncompyle6
        decompyle3
        # v2.6.0: peepdf-3 - the maintained fork of peepdf on PyPI
        # (jesparza/peepdf is stale; jesparza/peepdf-3 supersedes it)
        peepdf-3
        # v2.7.0: fuzzy hashing Python wrappers
        ssdeep            # python wrapper for libfuzzy (apt: libfuzzy-dev)
        python-tlsh       # Trend Micro Locality Sensitive Hash
    )

    log_info "Installing ${#PY_PKGS[@]} Python packages (stderr captured in $PY_LOG)…"
    for pkg in "${PY_PKGS[@]}"; do
        [[ $VERBOSE -eq 1 ]] && log_info "  pip install $pkg"
        {
            echo ""
            echo "=== pip install $pkg ==="
        } >> "$PY_LOG"
        # Per-package env-var overrides for known build issues:
        # - ssdeep: requires BUILD_LIB=1 to bundle libfuzzy at build time;
        #   Python 3.13's stricter setuptools rejects the in-tree fuzzy.h
        #   discovery without this. Documented at python-ssdeep.readthedocs.io.
        #
        #   Audit-6 fix (L40): Even with BUILD_LIB=1, ssdeep's setup.py uses
        #   `pkg_resources` from setuptools, which Python 3.13 + modern
        #   setuptools deprecated. Build fails with:
        #     ModuleNotFoundError: No module named 'pkg_resources'
        #   The fix is two-fold:
        #     1. Use --no-build-isolation so the build sees the venv's
        #        setuptools (which still includes pkg_resources via the
        #        installed setuptools-pkg-resources path), AND
        #     2. Pre-install setuptools<81 in the venv (modern setuptools
        #        81+ removed pkg_resources entirely).
        #   If both fail, fall back gracefully to TLSH-only (already in
        #   PY_PKGS as python-tlsh which works on Python 3.13).
        if [[ "$pkg" == "ssdeep" ]]; then
            # v3.0.3 (audit-7) -- scoped setuptools<81 pin.
            # Audit-6 pinned setuptools<81 in the venv before installing
            # ssdeep, but the pin REMAINED in the venv after, which can
            # break subsequent packages (e.g. python-tlsh, oletools) that
            # require setuptools features removed in modern releases or
            # need pyproject build-system==setuptools>=68. Audit-7 fix:
            # capture the current setuptools version, install <81 just
            # for ssdeep build, then restore the original version after.
            log_dbg "  ssdeep: capturing current setuptools version for restore"
            ORIG_SETUPTOOLS_VER=$("$VENV_PIP" show setuptools 2>/dev/null \
                | awk -F': ' '/^Version:/ {print $2}' | head -1)
            log_dbg "  ssdeep: original setuptools = ${ORIG_SETUPTOOLS_VER:-unknown}"

            # Step 1: pin setuptools<81 to keep pkg_resources for ssdeep build
            "$VENV_PIP" install --quiet 'setuptools<81' >>"$PY_LOG" 2>&1 || true

            # Step 2: try with --no-build-isolation + BUILD_LIB=1
            SSDEEP_OK=0
            if BUILD_LIB=1 "$VENV_PIP" install --no-build-isolation "$pkg" >>"$PY_LOG" 2>&1; then
                log_ok "  $pkg (with BUILD_LIB=1 + --no-build-isolation + scoped setuptools<81)"
                SSDEEP_OK=1
            elif BUILD_LIB=1 "$VENV_PIP" install "$pkg" >>"$PY_LOG" 2>&1; then
                log_ok "  $pkg (with BUILD_LIB=1; build-isolation path)"
                SSDEEP_OK=1
            fi

            # Step 3: ALWAYS restore setuptools to the version we found at
            # the top of this block (or upgrade to latest if we didn't
            # capture it). This must run even if ssdeep failed - the pin
            # must NOT bleed into subsequent packages.
            if [[ -n "$ORIG_SETUPTOOLS_VER" ]]; then
                "$VENV_PIP" install --quiet "setuptools==${ORIG_SETUPTOOLS_VER}" \
                    >>"$PY_LOG" 2>&1 || \
                "$VENV_PIP" install --quiet --upgrade setuptools >>"$PY_LOG" 2>&1 || true
                log_dbg "  ssdeep: restored setuptools to ${ORIG_SETUPTOOLS_VER}"
            else
                "$VENV_PIP" install --quiet --upgrade setuptools >>"$PY_LOG" 2>&1 || true
                log_dbg "  ssdeep: restored setuptools to latest (no original captured)"
            fi

            if [[ $SSDEEP_OK -eq 0 ]]; then
                log_warn "  failed: $pkg -- details in $PY_LOG"
                log_warn "    (ssdeep on Python 3.13 needs pkg_resources from setuptools<81;"
                log_warn "     even with that pin, the wheel build can fail. Fuzzy hashing"
                log_warn "     falls back to TLSH which is already installed and Python-3.13-clean.)"
                FAILED_PY+=("$pkg")
            fi
            continue
        fi
        if "$VENV_PIP" install "$pkg" >>"$PY_LOG" 2>&1; then
            log_ok "  $pkg"
        else
            log_warn "  failed: $pkg -- details in $PY_LOG"
            FAILED_PY+=("$pkg")
        fi
    done

    if [[ ${#FAILED_PY[@]} -gt 0 ]]; then
        log_warn "Python package failures: ${FAILED_PY[*]}"
        log_warn "Common cause: flare-capa/flare-floss depend on vivisect, which"
        log_warn "sometimes has transient pin conflicts on Kali Rolling. Retry with"
        log_warn "'pip install --pre $pkg' in the venv, or check $PY_LOG."
    fi

    # Wrappers at /opt/retools/bin for tools users will call directly
    WRAPPER_DIR="${RETOOLS_BASE}/bin"
    mkdir -p "$WRAPPER_DIR"
    for tool in capa floss; do
        if [[ -x "${RETOOLS_VENV}/bin/${tool}" ]]; then
            cat > "${WRAPPER_DIR}/${tool}" <<EOF
#!/bin/sh
exec "${RETOOLS_VENV}/bin/${tool}" "\$@"
EOF
            chmod +x "${WRAPPER_DIR}/${tool}"
            log_ok "Wrapper: ${WRAPPER_DIR}/${tool}"
        fi
    done
fi

# =============================================================================
# LAYER 4 -- Ghidra
# =============================================================================
GHIDRA_DIR=""
if [[ $SKIP_GHIDRA -eq 1 ]]; then
    log_info "Skipping Ghidra (--skip-ghidra)"
else
    log_hdr "LAYER 4 -- Ghidra"
    log_info "Per-phase log: $GHIDRA_LOG"

    if [[ -L "$GHIDRA_LINK" && $FORCE -eq 0 ]]; then
        TARGET=$(readlink -f "$GHIDRA_LINK")
        if [[ -x "${TARGET}/support/analyzeHeadless" ]]; then
            log_ok "Existing Ghidra: $TARGET (symlinked at $GHIDRA_LINK)"
            GHIDRA_DIR="$TARGET"
        fi
    fi

    if [[ -z "$GHIDRA_DIR" ]]; then
        log_info "Resolving latest Ghidra PUBLIC from NSA/GitHub…"
        LATEST_URL=$(curl -sLI --max-redirs 3 -o /dev/null -w '%{url_effective}' \
            https://github.com/NationalSecurityAgency/ghidra/releases/latest 2>>"$GHIDRA_LOG")
        LATEST_TAG=$(basename "$LATEST_URL")
        log_info "Latest release tag: $LATEST_TAG"

        ASSET_URL=$(curl -sL "https://github.com/NationalSecurityAgency/ghidra/releases/expanded_assets/${LATEST_TAG}" 2>>"$GHIDRA_LOG" \
            | grep -oE '/NationalSecurityAgency/ghidra/releases/download/[^"]+\.zip' | head -1)
        if [[ -z "$ASSET_URL" ]]; then
            log_err "Could not find Ghidra ZIP asset URL (see $GHIDRA_LOG)"
            exit 1
        fi
        ASSET_NAME=$(basename "$ASSET_URL")
        DL_URL="https://github.com${ASSET_URL}"
        TARGET_DIR_NAME=$(echo "$ASSET_NAME" | sed -E 's/^(ghidra_[0-9.]+_PUBLIC).*\.zip$/\1/')
        TARGET_DIR="${GHIDRA_BASE}/${TARGET_DIR_NAME}"

        if [[ -d "$TARGET_DIR" && $FORCE -eq 0 ]]; then
            log_ok "Already extracted: $TARGET_DIR"
            GHIDRA_DIR="$TARGET_DIR"
        else
            DL_PATH="/tmp/${ASSET_NAME}"
            if [[ ! -f "$DL_PATH" || $FORCE -eq 1 ]]; then
                # v2.1.0 FIX: the 2.0.0 line here was:
                #   log_info "Downloading $(echo "$ASSET_NAME" -- ~400MB, may take several minutes)…"
                # which had an unclosed $() with an em-dash mid-string and was a bash
                # syntax error that aborted the installer under `set -e`.
                log_info "Downloading ${ASSET_NAME} -- ~400MB, may take several minutes…"
                curl -L --progress-bar -o "$DL_PATH" "$DL_URL"
            else
                log_info "Using cached: $DL_PATH"
            fi

            log_info "Extracting to $GHIDRA_BASE…"
            [[ -d "$TARGET_DIR" && $FORCE -eq 1 ]] && rm -rf "$TARGET_DIR"
            unzip -q "$DL_PATH" -d "$GHIDRA_BASE" >>"$GHIDRA_LOG" 2>&1
            GHIDRA_DIR="$TARGET_DIR"
            log_ok "Extracted: $GHIDRA_DIR"
        fi

        if [[ -L "$GHIDRA_LINK" ]]; then rm -f "$GHIDRA_LINK"; fi
        ln -s "$GHIDRA_DIR" "$GHIDRA_LINK"
        log_ok "Symlink: $GHIDRA_LINK -> $GHIDRA_DIR"
    fi

    # System-wide profile
    cat > /etc/profile.d/ghidra.sh <<EOF
# Added by install-retoolkit.sh v2.1.3
export GHIDRA_INSTALL_DIR="$GHIDRA_LINK"
export PATH="\$GHIDRA_INSTALL_DIR:\$GHIDRA_INSTALL_DIR/support:\$PATH"
EOF
    chmod +x /etc/profile.d/ghidra.sh
    log_ok "System profile: /etc/profile.d/ghidra.sh"

    # Report on PyGhidra headless launcher availability (Ghidra 12+)
    PYGHIDRA_LAUNCHER="${GHIDRA_DIR}/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py"
    PYGHIDRA_RUN="${GHIDRA_DIR}/support/pyghidraRun"
    if [[ -f "$PYGHIDRA_LAUNCHER" ]]; then
        log_ok "PyGhidra launcher detected: $PYGHIDRA_LAUNCHER"
        log_info "analyze-binaries.sh will use PyGhidra mode for .py postscripts"
    else
        log_warn "PyGhidra launcher not found -- Ghidra 11.x or older layout?"
        log_warn "analyze-binaries.sh will fall back to disabling PyGhidra via -D flag"
    fi
    [[ -x "$PYGHIDRA_RUN" ]] && log_ok "pyghidraRun shim present: $PYGHIDRA_RUN"

    # Ghidrathon -- opt-in only
    if [[ $INSTALL_GHIDRATHON -eq 1 ]]; then
        log_warn "Installing Ghidrathon (opt-in) -- known to break GUI on Java 21 builds"
        GTHON_DIR="/tmp/ghidrathon-install"
        rm -rf "$GTHON_DIR"; mkdir -p "$GTHON_DIR"
        GTHON_URL=$(curl -sL https://api.github.com/repos/mandiant/Ghidrathon/releases/latest \
            | grep -oE '"browser_download_url":\s*"[^"]+\.zip"' | head -1 \
            | sed 's/"browser_download_url":\s*"//; s/"$//')
        if [[ -n "$GTHON_URL" ]]; then
            curl -L --silent -o "${GTHON_DIR}/ghidrathon.zip" "$GTHON_URL"
            unzip -q "${GTHON_DIR}/ghidrathon.zip" -d "$GTHON_DIR" >>"$GHIDRA_LOG" 2>&1
            EXT_DIR="${GHIDRA_DIR}/Extensions/Ghidra"
            if [[ -d "$EXT_DIR" ]]; then
                cp "${GTHON_DIR}"/*.zip "$EXT_DIR/" 2>/dev/null || true
                log_ok "Ghidrathon dropped in $EXT_DIR"
                log_warn "If GUI breaks: remove $EXT_DIR/ghidrathon*.zip and clear ~/.ghidra"
            fi
        fi
    else
        log_info "Ghidrathon NOT installed (default). Pass --install-ghidrathon to enable."
    fi

    if [[ ! -x "${GHIDRA_DIR}/support/analyzeHeadless" ]]; then
        log_err "analyzeHeadless not found/executable at ${GHIDRA_DIR}/support/analyzeHeadless"
        exit 1
    fi
fi

# =============================================================================
# LAYER 4B -- cwe_checker (NEW in v2.5.0; OPT-IN due to build cost)
# =============================================================================
# cwe_checker is a Rust-based static CWE detector that runs on top of Ghidra
# IR. The build requires:
#   - rustup + cargo (install via rustup.rs official installer)
#   - Ghidra v11.2+ (handled by LAYER 4 above)
#   - GHIDRA_PATH env var pointing at the Ghidra install
#
# cwe_checker is opt-in at INSTALL TIME via --with-cwe-checker because:
#   1. The Rust build adds ~5-10 minutes to install time
#   2. cwe_checker is itself opt-in at RUN TIME (--enable-cwe-checker)
#   3. Most RE-Toolkit users don't need it
#
# Default: skipped. Pass --with-cwe-checker to install. Note that even
# without this layer, the analyzer's stage_cwe is still defined; it just
# warns and skips at runtime if cwe_checker isn't on PATH.
# =============================================================================
if [[ ${WITH_CWE_CHECKER:-0} -eq 1 ]]; then
    log_hdr "LAYER 4B -- cwe_checker (opt-in via --with-cwe-checker)"
    LAYER4B_LOG="${LOG_ROOT}/layer4b-cwe_checker-${RUN_TS}.log"
    : > "$LAYER4B_LOG"

    if command -v cwe_checker >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
        log_info "cwe_checker already in PATH (use --force to rebuild)"
    elif [[ ! -d "${GHIDRA_DIR:-/opt/ghidra}" ]]; then
        log_warn "cwe_checker requires Ghidra; /opt/ghidra not found. Skipping."
        FAILED_APT+=("cwe_checker-no-ghidra")
    else
        # Ensure rustup/cargo are present
        if ! command -v cargo >/dev/null 2>&1; then
            log_info "Installing rustup (cargo) via official installer..."
            if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
                as_user sh -s -- -y --default-toolchain stable >>"$LAYER4B_LOG" 2>&1; then
                # cargo lands in $INVOKING_HOME/.cargo/bin
                export PATH="${INVOKING_HOME}/.cargo/bin:$PATH"
                log_ok "rustup/cargo installed for $INVOKING_USER"
            else
                log_warn "rustup install failed -- see $LAYER4B_LOG"
                FAILED_APT+=("cwe_checker-rustup")
            fi
        fi

        if command -v cargo >/dev/null 2>&1 || \
           [[ -x "${INVOKING_HOME}/.cargo/bin/cargo" ]]; then
            CWE_SRC="/tmp/cwe_checker-src"
            rm -rf "$CWE_SRC"
            if git clone --depth=1 https://github.com/fkie-cad/cwe_checker.git \
                "$CWE_SRC" >>"$LAYER4B_LOG" 2>&1; then
                pushd "$CWE_SRC" >/dev/null
                # `make all GHIDRA_PATH=...` builds and installs cwe_checker
                # into $HOME/.cargo/bin and writes config to ~/.config/cwe_checker.
                #
                # v3.0.4 (audit-8 A4): rustup just installed cargo into
                # $INVOKING_HOME/.cargo/bin, but the make subprocess inherits
                # a fresh login shell environment via `as_user` which does NOT
                # have rustup's env file sourced -- cargo is not yet on PATH.
                # The Makefile then fails:
                #   make: cargo: No such file or directory
                # Fix: explicitly prepend $HOME/.cargo/bin to PATH so cargo
                # is visible to make and any cargo-invoking sub-makes. Use
                # the user's cargo home rather than root's because rustup
                # installed there.
                if as_user env "PATH=${INVOKING_HOME}/.cargo/bin:${PATH}" \
                    make all GHIDRA_PATH="${GHIDRA_DIR:-/opt/ghidra}" \
                    >>"$LAYER4B_LOG" 2>&1; then
                    # Symlink the user-installed cwe_checker into /usr/local/bin
                    if [[ -x "${INVOKING_HOME}/.cargo/bin/cwe_checker" ]]; then
                        ln -sf "${INVOKING_HOME}/.cargo/bin/cwe_checker" \
                            /usr/local/bin/cwe_checker
                        log_ok "cwe_checker installed → /usr/local/bin/cwe_checker"
                    else
                        log_warn "cwe_checker built but binary not found in ~/.cargo/bin"
                        FAILED_APT+=("cwe_checker-missing")
                    fi
                else
                    log_warn "cwe_checker build failed (see $LAYER4B_LOG)"
                    FAILED_APT+=("cwe_checker-build")
                fi
                popd >/dev/null
            else
                log_warn "cwe_checker git clone failed"
                FAILED_APT+=("cwe_checker-clone")
            fi
        fi
    fi
else
    log_info "Skipping LAYER 4B (cwe_checker; pass --with-cwe-checker to enable)"
fi

# =============================================================================
# LAYER 4C -- redress (Go binary analyzer; NEW in v2.6.0)
# =============================================================================
# redress is a Go program that analyzes stripped Go binaries. Build via:
#   go install github.com/goretk/redress@latest
# This requires golang-go (added to LAYER 1 apt list in v2.6.0). The
# resulting binary lands at $HOME/go/bin/redress (or $GOPATH/bin/redress)
# which we symlink into /usr/local/bin so stage_elf and stage_pe can find
# it on the user's PATH.
#
# Cost: ~30 seconds for the go install (downloads + compiles redress and
# its dependencies). LAYER 4C is OPT-IN via --with-redress flag because:
#   1. Many users never analyze Go binaries
#   2. The golang-go apt package adds ~200MB even when not used for redress
#   3. Detection happens at runtime; if redress isn't installed, stage_elf
#      and stage_pe just skip Go-specific analysis without breaking
# =============================================================================
if [[ ${WITH_REDRESS:-0} -eq 1 ]]; then
    log_hdr "LAYER 4C -- redress (opt-in via --with-redress)"
    LAYER4C_LOG="${LOG_ROOT}/layer4c-redress-${RUN_TS}.log"
    : > "$LAYER4C_LOG"

    if command -v redress >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
        log_info "redress already in PATH (use --force to rebuild)"
    elif ! command -v go >/dev/null 2>&1; then
        log_warn "redress requires Go toolchain; golang-go not installed. Skipping."
        FAILED_APT+=("redress-no-go")
    else
        # v3.0.4 (audit-8 A5) -- disk-space gate AND GOTMPDIR override.
        #
        # The Go toolchain writes its build cache to $WORK, which defaults
        # to a TMPDIR-derived directory under /tmp. On Kali Rolling installs
        # where /tmp is mounted as tmpfs (RAM-backed, default 50% of RAM),
        # the redress build can fail with:
        #   compile: writing output: write $WORK/b193/_pkg_.a: no space left on device
        # even when the host has hundreds of GB free on the rootfs. The Go
        # build creates many small intermediate .a files in parallel and
        # tmpfs's RAM-backed allocation runs out before disk does. The
        # error message is misleading because it reports "no space left
        # on device" against a tmpfs ramdisk, not a filesystem.
        #
        # Two-part fix:
        #   1. Override GOTMPDIR to a directory under /var/cache/retoolkit
        #      which is on the rootfs (real disk, not tmpfs), so Go's $WORK
        #      gets the host's full free space.
        #   2. Defensive disk-space gate: if the rootfs partition has less
        #      than 2 GB free, warn and skip cleanly. redress's build
        #      cache typically peaks around 800 MB, so 2 GB gives 2.5x
        #      headroom for parallel compile jobs.
        #
        # Per L42 / L45: this fix is logic-validated; the GOTMPDIR override
        # is the primary fix (addresses the actual root cause). The
        # disk-space gate is a safety net for genuinely-low-disk scenarios.
        REDRESS_GOTMPDIR="/var/cache/retoolkit/go-build-tmp"
        mkdir -p "$REDRESS_GOTMPDIR" 2>>"$LAYER4C_LOG" || true
        chown "${INVOKING_USER}:${INVOKING_USER}" "$REDRESS_GOTMPDIR" 2>>"$LAYER4C_LOG" || true

        # Free space on the partition holding our GOTMPDIR (in KB).
        # df -P gives POSIX-format single-line output; field 4 is "Available".
        REDRESS_FREE_KB=$(df -P "$REDRESS_GOTMPDIR" 2>/dev/null | awk 'NR==2 {print $4}')
        REDRESS_FREE_GB=$(( ${REDRESS_FREE_KB:-0} / 1024 / 1024 ))
        if [[ -n "$REDRESS_FREE_KB" && $REDRESS_FREE_KB -lt 2097152 ]]; then
            log_warn "redress: only ${REDRESS_FREE_GB}GB free on partition holding $REDRESS_GOTMPDIR"
            log_warn "  redress build needs ~2GB of build-cache scratch; skipping."
            log_warn "  Free up disk space and re-run with --with-redress to retry."
            FAILED_APT+=("redress-low-disk")
        else
            log_info "Installing redress via 'go install github.com/goretk/redress@latest'..."
            log_dbg "  GOTMPDIR=$REDRESS_GOTMPDIR (${REDRESS_FREE_GB}GB free)"
            # Run as the invoking user so the build artifacts land in their
            # $HOME, not /root. Redirect GOPATH explicitly to avoid surprises,
            # AND redirect GOTMPDIR to non-tmpfs scratch so the Go build
            # cache doesn't blow out a tmpfs /tmp. TMPDIR is also exported
            # because some Go internals consult TMPDIR rather than GOTMPDIR.
            if as_user env \
                GOPATH="${INVOKING_HOME}/go" \
                GOTMPDIR="$REDRESS_GOTMPDIR" \
                TMPDIR="$REDRESS_GOTMPDIR" \
                go install github.com/goretk/redress@latest \
                >>"$LAYER4C_LOG" 2>&1; then
                REDRESS_BIN="${INVOKING_HOME}/go/bin/redress"
                if [[ -x "$REDRESS_BIN" ]]; then
                    ln -sf "$REDRESS_BIN" /usr/local/bin/redress
                    log_ok "redress installed -> /usr/local/bin/redress (-> $REDRESS_BIN)"
                else
                    log_warn "redress build succeeded but binary not at $REDRESS_BIN"
                    FAILED_APT+=("redress-missing")
                fi
            else
                log_warn "redress build failed (see $LAYER4C_LOG)"
                FAILED_APT+=("redress-build")
            fi
        fi
    fi
else
    log_info "Skipping LAYER 4C (redress; pass --with-redress to enable)"
fi

# =============================================================================
# LAYER 4D -- rustfilt (Rust name demangler; NEW in v2.6.0)
# =============================================================================
# rustfilt is a Rust-mangled-symbol demangler installed via cargo:
#   cargo install rustfilt
# This piggybacks on the same rustup/cargo install used by LAYER 4B
# (cwe_checker). When LAYER 4B has already installed rustup/cargo, this
# layer is essentially free; otherwise it triggers the rustup install
# inline.
#
# rustfilt is OPT-IN via --with-rustfilt because the Rust name demangling
# pass in stage_elf is supplementary; nm output is still readable without
# it (just less pretty for templated/generic Rust types). Default OFF.
# =============================================================================
if [[ ${WITH_RUSTFILT:-0} -eq 1 ]]; then
    log_hdr "LAYER 4D -- rustfilt (opt-in via --with-rustfilt)"
    LAYER4D_LOG="${LOG_ROOT}/layer4d-rustfilt-${RUN_TS}.log"
    : > "$LAYER4D_LOG"

    if command -v rustfilt >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
        log_info "rustfilt already in PATH (use --force to rebuild)"
    else
        # Ensure cargo is available; install rustup if not
        CARGO_BIN=""
        if command -v cargo >/dev/null 2>&1; then
            CARGO_BIN=$(command -v cargo)
        elif [[ -x "${INVOKING_HOME}/.cargo/bin/cargo" ]]; then
            CARGO_BIN="${INVOKING_HOME}/.cargo/bin/cargo"
        else
            log_info "Installing rustup (for cargo) via official installer..."
            if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
                as_user sh -s -- -y --default-toolchain stable \
                >>"$LAYER4D_LOG" 2>&1; then
                CARGO_BIN="${INVOKING_HOME}/.cargo/bin/cargo"
                log_ok "rustup/cargo installed for $INVOKING_USER"
            else
                log_warn "rustup install failed"; FAILED_APT+=("rustfilt-rustup")
            fi
        fi

        if [[ -n "$CARGO_BIN" ]]; then
            log_info "Installing rustfilt via 'cargo install rustfilt'..."
            if as_user "$CARGO_BIN" install rustfilt >>"$LAYER4D_LOG" 2>&1; then
                RUSTFILT_BIN="${INVOKING_HOME}/.cargo/bin/rustfilt"
                if [[ -x "$RUSTFILT_BIN" ]]; then
                    ln -sf "$RUSTFILT_BIN" /usr/local/bin/rustfilt
                    log_ok "rustfilt installed -> /usr/local/bin/rustfilt"
                else
                    log_warn "rustfilt build succeeded but binary not at $RUSTFILT_BIN"
                    FAILED_APT+=("rustfilt-missing")
                fi
            else
                log_warn "rustfilt build failed (see $LAYER4D_LOG)"
                FAILED_APT+=("rustfilt-build")
            fi
        fi
    fi
else
    log_info "Skipping LAYER 4D (rustfilt; pass --with-rustfilt to enable)"
fi

# =============================================================================
# LAYER 4E -- findaes (AES key memory scanner; NEW in v2.7.0)
# =============================================================================
# findaes scans a binary for AES key schedules. It detects AES round-key
# expansions even when the keys aren't stored in obvious PEM/DER format.
# Used by stage_cryptokeys (82-cryptokeys.sh) alongside the custom
# entropy walker.
#
# OPT-IN via --with-findaes because:
#   1. The official source repo is sparse and the package isn't on apt.
#   2. The custom entropy walker in 82-cryptokeys.sh covers the
#      most common cases without findaes.
#   3. Binary correctness on edge cases (32-bit vs 64-bit, big-endian)
#      is uneven across forks.
#
# When --with-findaes is passed, we attempt to clone a maintained fork
# and build via make. Failure to build is non-fatal; the stage falls
# back to the custom walker.
# =============================================================================
if [[ ${WITH_FINDAES:-0} -eq 1 ]]; then
    log_hdr "LAYER 4E -- findaes (opt-in via --with-findaes)"
    LAYER4E_LOG="${LOG_ROOT}/layer4e-findaes-${RUN_TS}.log"
    : > "$LAYER4E_LOG"

    if command -v findaes >/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
        log_info "findaes already in PATH (use --force to rebuild)"
    else
        log_info "Building findaes from source..."
        # v3.0.4 (audit-8 A10): the previous URL list (DerrickInGenova,
        # cmacc89, jbsteinberg) was a list of GitHub repos that DO NOT
        # EXIST. git clone of a 404 GitHub URL prompts for HTTP basic
        # auth credentials, which (a) hangs the install if stdin is a tty,
        # and (b) was the source of "Username for GitHub" prompts users
        # reported. Per L45: validate upstream resources EXPLICITLY.
        #
        # Verified-existent sources:
        #   1. SourceForge tarball: https://sourceforge.net/projects/findaes/
        #      (the original Aurelio's findaes 1.2 release; canonical source)
        #   2. makomk/aeskeyfind on GitHub: a maintained fork of the original
        #      aeskeyfind that is closely related to findaes and provides
        #      the same key-schedule scanning capability.
        #
        # Strategy: try the SourceForge tarball first (canonical, tagged
        # version), fall back to makomk/aeskeyfind if SourceForge is
        # unreachable or the tarball is removed. Both build via plain
        # `make` without external deps.
        FINDAES_SRC="/tmp/findaes-src"
        rm -rf "$FINDAES_SRC"
        mkdir -p "$FINDAES_SRC"
        FA_FETCHED=0
        FA_KIND=""

        # Try SourceForge tarball first.
        FA_TARBALL_URL="https://sourceforge.net/projects/findaes/files/findaes/1.2/findaes-1.2.tar.bz2/download"
        FA_TMP_TARBALL="/tmp/findaes-1.2.tar.bz2"
        log_info "  Trying SourceForge findaes 1.2 tarball..."
        if curl -fsSL --max-time 60 -o "$FA_TMP_TARBALL" "$FA_TARBALL_URL" \
                >>"$LAYER4E_LOG" 2>&1; then
            if tar -xjf "$FA_TMP_TARBALL" -C "$FINDAES_SRC" --strip-components=1 \
                    >>"$LAYER4E_LOG" 2>&1; then
                rm -f "$FA_TMP_TARBALL"
                FA_FETCHED=1
                FA_KIND="findaes-1.2"
                log_info "  findaes 1.2 tarball extracted from SourceForge"
            else
                log_warn "  findaes tarball downloaded but tar extraction failed"
                rm -f "$FA_TMP_TARBALL"
            fi
        else
            log_info "  SourceForge tarball unreachable; trying GitHub fallback"
        fi

        # Fall back to makomk/aeskeyfind (verified GitHub repo, maintained
        # fork of original aeskeyfind with extended key-schedule formats).
        if [[ $FA_FETCHED -eq 0 ]]; then
            log_info "  Trying makomk/aeskeyfind (GitHub fallback)..."
            rm -rf "$FINDAES_SRC"
            if git clone --depth=1 https://github.com/makomk/aeskeyfind.git \
                    "$FINDAES_SRC" >>"$LAYER4E_LOG" 2>&1; then
                FA_FETCHED=1
                FA_KIND="aeskeyfind-makomk"
                log_info "  aeskeyfind cloned from makomk/aeskeyfind"
            fi
        fi

        if [[ $FA_FETCHED -eq 1 ]]; then
            pushd "$FINDAES_SRC" >/dev/null
            # Both findaes-1.2 (SourceForge) and aeskeyfind (GitHub) build
            # via plain `make`. The output binary is named `findaes` for
            # the SourceForge tarball and `aeskeyfind` for the GitHub
            # repo; copy whichever was produced and symlink to /usr/local/bin/findaes.
            if make >>"$LAYER4E_LOG" 2>&1; then
                if [[ -x ./findaes ]]; then
                    cp -f findaes /usr/local/bin/findaes && \
                        log_ok "findaes installed -> /usr/local/bin/findaes ($FA_KIND)" || {
                        log_warn "findaes built but copy to /usr/local/bin failed"
                        FAILED_APT+=("findaes-install")
                    }
                elif [[ -x ./aeskeyfind ]]; then
                    cp -f aeskeyfind /usr/local/bin/findaes && \
                        log_ok "aeskeyfind installed as findaes -> /usr/local/bin/findaes ($FA_KIND)" || {
                        log_warn "aeskeyfind built but copy to /usr/local/bin failed"
                        FAILED_APT+=("findaes-install")
                    }
                else
                    log_warn "findaes/aeskeyfind build succeeded but no binary located"
                    FAILED_APT+=("findaes-missing")
                fi
            else
                log_warn "findaes build failed (see $LAYER4E_LOG)"
                FAILED_APT+=("findaes-build")
            fi
            popd >/dev/null
        else
            log_warn "findaes fetch failed: SourceForge tarball + makomk/aeskeyfind both unreachable"
            log_warn "  See $LAYER4E_LOG for network details"
            FAILED_APT+=("findaes-clone")
        fi
    fi
else
    log_info "Skipping LAYER 4E (findaes; pass --with-findaes to enable)"
fi

# =============================================================================
# LAYER 5 -- capa rules + YARA rules (NEW in 2.1.0)
# =============================================================================
# Rationale: `pip install flare-capa` installs the capa binary but NOT the
# rule set. capa with no rules outputs zero capabilities and misleads the
# user into thinking the tool is broken. Same for yara -- the binary alone
# is useless without rules to match against.
# =============================================================================
if [[ $SKIP_RULES -eq 1 ]]; then
    log_info "Skipping rules cloning (--skip-rules)"
else
    log_hdr "LAYER 5 -- Capability + YARA rules"
    log_info "Per-phase log: $RULES_LOG"

    clone_or_update() {
        # clone_or_update <url> <dest>
        local url="$1" dest="$2"
        if [[ -d "$dest/.git" ]]; then
            if [[ $FORCE -eq 1 ]]; then
                log_info "  refreshing: $dest"
                (cd "$dest" && git pull --ff-only) >>"$RULES_LOG" 2>&1
                return $?
            else
                log_ok "  exists: $dest (pass --force to refresh)"
                return 0
            fi
        elif [[ -d "$dest" ]]; then
            log_warn "  $dest exists but is not a git clone -- skipping"
            return 1
        fi
        log_info "  cloning: $url -> $dest"
        git clone --depth 1 "$url" "$dest" >>"$RULES_LOG" 2>&1
    }

    # capa rules
    if clone_or_update "https://github.com/mandiant/capa-rules" "$CAPA_RULES_DIR"; then
        CAPA_RULES_COUNT=$(find "$CAPA_RULES_DIR" -name '*.yml' 2>/dev/null | wc -l)
        log_ok "capa rules: $CAPA_RULES_COUNT .yml files at $CAPA_RULES_DIR"
    else
        log_warn "capa rules clone failed -- see $RULES_LOG"
        FAILED_RULES+=("capa-rules")
    fi

    # YARA rules -- use Yara-Rules/rules as the base (high-signal, wide coverage)
    if clone_or_update "https://github.com/Yara-Rules/rules" "$YARA_RULES_DIR"; then
        # Build a master index so yara can be invoked with a single file.
        # Yara-Rules/rules ships per-category subdirs with many .yar files;
        # some have mutual-exclusion imports that can't coexist, so we use
        # only the consolidated "packers" / "capabilities" / "malware" tiers
        # and skip the known-problematic ones.
        MASTER="${YARA_RULES_DIR}/_master.yar"
        # v3.7.3 (audit-31 B4): the master.yar `include`s every rule file into a
        # single namespace, so two files defining a rule with the same name
        # (common across the Yara-Rules collection) collide at compile time and
        # yara prints "error: duplicated identifier" -- hundreds of them,
        # cluttering the log and making the master look broken. yara `include`
        # cannot namespace, so we DEDUPLICATE at include time: track every rule
        # identifier already contributed, and skip any file that would redefine
        # one. Genuinely-redundant redefinitions are dropped; every unique rule
        # is retained, and the master compiles cleanly.
        declare -A _YARA_SEEN_RULES=()
        _yara_dupe_skipped=0
        {
            echo "// Auto-generated by install-retoolkit.sh on $(date -Iseconds)"
            echo "// Includes high-signal, syntactically-valid rules from Yara-Rules/rules."
            echo "// v3.7.3 (audit-31 B4): rule-identifier de-duplicated to avoid"
            echo "// 'duplicated identifier' compile errors from cross-file name collisions."
            while IFS= read -r -d '' rf; do
                case "$rf" in
                    # Known-problematic: rules that require specific module
                    # imports (pe/magic/hash/math) not enabled in distro yara,
                    # or that have overlapping identifiers. Skip.
                    *malware/MALW_Gootkit*) continue ;;
                    *webshells/WShell_Generic*) continue ;;
                esac
                # Extract this file's rule identifiers. yara rule declarations
                # are: [global] [private] rule <ident> [: tags] {
                _rf_rules=$(grep -oE '^[[:space:]]*(global[[:space:]]+)?(private[[:space:]]+)?rule[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' "$rf" 2>/dev/null \
                            | sed -E 's/.*rule[[:space:]]+//')
                # If any rule name in this file was already contributed by an
                # earlier file, skip this whole file to avoid the collision.
                _dupe=0
                for _rn in $_rf_rules; do
                    if [[ -n "${_YARA_SEEN_RULES[$_rn]:-}" ]]; then
                        _dupe=1
                        break
                    fi
                done
                if [[ $_dupe -eq 1 ]]; then
                    _yara_dupe_skipped=$((_yara_dupe_skipped + 1))
                    continue
                fi
                # Register this file's rule names and include it.
                for _rn in $_rf_rules; do
                    _YARA_SEEN_RULES[$_rn]=1
                done
                echo "include \"${rf#${YARA_RULES_DIR}/}\""
            done < <(find "$YARA_RULES_DIR" -type f \( -name '*.yar' -o -name '*.yara' \) \
                        -not -path '*/utils/*' -not -path '*/.git/*' -print0 2>/dev/null)
        } > "$MASTER"
        YARA_RULES_COUNT=$(grep -c '^include' "$MASTER" 2>/dev/null || echo 0)
        log_ok "YARA rules: $YARA_RULES_COUNT includes in $MASTER (dedup skipped ${_yara_dupe_skipped} name-colliding files)"

        # Sanity-compile the master. If it fails, strip problematic lines
        # until it compiles or we give up. This avoids shipping a broken
        # master.yar that makes every YARA invocation error out.
        if command -v yara >/dev/null 2>&1; then
            COMPILE_OUT="${LOG_ROOT}/yara-compile-${RUN_TS}.log"
            # v2.1.3: drop `--threads 1`. Some yara builds' getopt_long
            # rejects the space variant; default threading is correct for
            # a compile-only sanity check anyway.
            if yara "$MASTER" /dev/null >"$COMPILE_OUT" 2>&1; then
                log_ok "YARA master rules compile cleanly"
            else
                log_warn "Some rules fail to compile -- see $COMPILE_OUT"
                log_warn "yara will still run; it will skip failing rules at load time"
            fi
        fi
    else
        log_warn "YARA rules clone failed -- see $RULES_LOG"
        FAILED_RULES+=("yara-rules")
    fi

    # Update the system-wide profile with rule locations.
    PROFILE_D="/etc/profile.d/retools.sh"
    cat > "$PROFILE_D" <<EOF
# Added by install-retoolkit.sh v2.1.3
export PATH="${RETOOLS_BASE}/bin:\$PATH"
export RETOOLS_VENV="${RETOOLS_VENV}"
export CAPA_RULES="${CAPA_RULES_DIR}"
export YARA_RULES="${YARA_RULES_DIR}"
EOF
    chmod +x "$PROFILE_D"
    log_ok "System profile: $PROFILE_D (PATH + CAPA_RULES + YARA_RULES)"
fi

# =============================================================================
# ClamAV: signatures refresh
# =============================================================================
if command -v freshclam >/dev/null 2>&1; then
    log_hdr "ClamAV: updating virus signatures"
    systemctl stop clamav-freshclam 2>/dev/null || true
    # Check real exit, not just parse of last 5 lines.
    if freshclam >>"$RULES_LOG" 2>&1; then
        log_ok "ClamAV signatures updated"
    else
        FC_RC=$?
        log_warn "freshclam exit $FC_RC (signatures may be stale) -- see $RULES_LOG"
    fi
    systemctl start clamav-freshclam 2>/dev/null || true
fi

# =============================================================================
# LAYER 8 -- Dynamic analysis: qiling emulator (NEW in v3.0.0)
# =============================================================================
# qiling is a Python-based binary emulator over Unicorn. Required when the
# user passes --dynamic to the analyzer. Always installed in LAYER 8 (no
# opt-in flag) because the qiling tier is the safest default and the
# install cost is small (pure Python wheel + rootfs git clone).
#
# Two parts:
#   1. pip install qiling unicorn  (into the existing RE venv)
#   2. git clone qiling rootfs into /opt/qiling-rootfs
#
# Microsoft Windows DLLs are NOT bundled (license restriction). For PE
# emulation, the user must run qiling/examples/scripts/dllscollector.bat
# on a Windows machine and copy results to
# /opt/qiling-rootfs/x86_windows/Windows/SysWOW64 or
# /opt/qiling-rootfs/x8664_windows/Windows/System32. The analyzer handles
# the missing-DLL case gracefully (qiling falls back to bare emulation).
log_hdr "LAYER 8 -- Dynamic analysis: qiling emulator (v3.0.0)"

if [[ -n "${RETOOLS_VENV:-}" ]] && [[ -x "${RETOOLS_VENV}/bin/pip" ]]; then
    log_info "Installing qiling + unicorn into RE venv"
    # Pin unicorn to a version compatible with pwntools 4.15+, which excludes
    # unicorn 2.1.3 and 2.1.4 due to known instability/security issues.
    # Per pwntools' install_requires constraint: unicorn!=2.1.3,!=2.1.4,>=2.0.1
    # The latest acceptable version is 2.1.2 (released Feb 13, 2025).
    # If pip can't satisfy the qiling+unicorn combo, fall back to qiling
    # alone (qiling will pull its own compatible unicorn as a transitive dep).
    if "${RETOOLS_VENV}/bin/pip" install --upgrade --quiet \
            qiling 'unicorn==2.1.2' 2>&1 \
            | tee -a "$DYNAMIC_LOG"; then
        :
    else
        log_warn "qiling+unicorn==2.1.2 install reported errors; trying qiling alone"
        "${RETOOLS_VENV}/bin/pip" install --upgrade --quiet qiling 2>&1 \
            | tee -a "$DYNAMIC_LOG" || \
            log_warn "qiling pip install failed; check $DYNAMIC_LOG"
    fi
    if "${RETOOLS_VENV}/bin/python" -c "import qiling" 2>/dev/null; then
        log_ok "qiling Python module importable"
    else
        log_warn "qiling import failed; --dynamic-mode=qiling will not work"
    fi
else
    log_warn "RE venv not found; cannot install qiling. Run LAYER 3 first."
fi

# qiling rootfs (community-maintained collection of OS rootfs files)
QILING_ROOTFS_DIR="/opt/qiling-rootfs"
if [[ ! -d "$QILING_ROOTFS_DIR" ]]; then
    log_info "Cloning qiling rootfs to $QILING_ROOTFS_DIR (~50MB)"
    if git clone --depth 1 https://github.com/qilingframework/rootfs "$QILING_ROOTFS_DIR" \
        >> "$DYNAMIC_LOG" 2>&1; then
        log_ok "qiling rootfs at $QILING_ROOTFS_DIR"
    else
        log_warn "qiling rootfs clone failed; --dynamic-mode=qiling will fall back to bare emulation"
    fi
else
    log_ok "qiling rootfs already present at $QILING_ROOTFS_DIR"
fi
echo ""
echo "  NOTE for Windows PE emulation:"
echo "  Microsoft DLLs are NOT bundled (license). To emulate Windows binaries,"
echo "  run qiling/examples/scripts/dllscollector.bat on a Windows machine"
echo "  (under Administrator) and copy results to:"
echo "    $QILING_ROOTFS_DIR/x86_windows/Windows/SysWOW64/  (32-bit DLLs)"
echo "    $QILING_ROOTFS_DIR/x8664_windows/Windows/System32/  (64-bit DLLs)"
echo "  Without DLLs, qiling falls back to bare emulation (less informative)."
echo ""

# =============================================================================
# LAYER 9 -- Dynamic analysis: docker + retoolkit-dynamic image (NEW in v3.0.0)
# =============================================================================
# OPT-IN via --with-docker. Heavier than qiling (full container runtime).
# Builds retoolkit-dynamic:latest image bundling strace/ltrace/Wine and a
# /entrypoint.sh that detects target type and runs the appropriate trace.
if [[ ${WITH_DOCKER:-0} -eq 1 ]]; then
    log_hdr "LAYER 9 -- Dynamic analysis: docker + retoolkit-dynamic image"

    if ! command -v docker >/dev/null 2>&1; then
        log_info "Installing docker.io via apt"
        safe_apt install -y docker.io >> "$DYNAMIC_LOG" 2>&1 \
            || safe_apt install -y docker-ce >> "$DYNAMIC_LOG" 2>&1 \
            || { log_warn "docker install failed; LAYER 9 incomplete"; }
    fi
    if command -v docker >/dev/null 2>&1; then
        log_ok "docker installed: $(docker --version 2>/dev/null | head -1)"

        # Build retoolkit-dynamic:latest image. We embed the Dockerfile
        # via heredoc to keep the installer single-file. The image is
        # Debian-based, includes strace + ltrace + wine, and the
        # /entrypoint.sh script writes uniform-schema _dynamic.json.
        #
        # v3.0.4 (audit-8 A6): drop `wine32` from the apt list. In Debian
        # bookworm and later, wine32 is no longer published as a binary
        # package -- it's been replaced by `libwine` (the multi-arch wine
        # runtime). The build was failing with:
        #   E: Package 'wine32' has no installation candidate
        # `wine` (meta) and `wine64` cover most PE-binary dynamic-analysis
        # use cases; 32-bit PE samples can still be analyzed via wine's
        # WoW64 path which `wine64` provides on amd64. If a true 32-bit
        # wine binary is needed, the user can `dpkg --add-architecture
        # i386 && apt install wine32:i386` manually after build.
        BUILD_DIR=$(mktemp -d)
        cat > "$BUILD_DIR/Dockerfile" <<'DOCKERFILE'
FROM debian:bookworm-slim
# v3.0.12 (audit-16 G1) - operator F14: many 32-bit Windows
# executables (older PE32, common for malware samples and legacy
# applications) require wine32 to run under wine. Without it, wine
# emits "wine32 is missing" and fails to chdir to ~/.wine. The
# multiarch-i386 enable + wine32:i386 install must run BEFORE the
# regular wine packages so dpkg's package resolver pulls the right
# 32/64 split.
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        strace ltrace wine wine64 wine32:i386 file python3 python3-minimal \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Pre-create the wine prefix and initialize it so first-execution
# of a target binary doesn't trigger wineboot during the timeout
# window (wineboot can take 20-30 seconds; with TIMEOUT=60 that
# leaves only 30 seconds for actual binary execution).
ENV WINEPREFIX=/root/.wine
ENV WINEDEBUG=-all
RUN mkdir -p /root/.wine && wineboot --init 2>/dev/null || true
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
DOCKERFILE

        cat > "$BUILD_DIR/entrypoint.sh" <<'ENTRYPOINT_EOF'
#!/bin/bash
# retoolkit-dynamic container entrypoint. Reads RT_TARGET (volume-mounted
# binary) and RT_TIMEOUT (seconds), runs strace/ltrace/Wine as appropriate,
# writes uniform-schema /out/_dynamic.json.
set +e
TARGET="${RT_TARGET:-/sample}"
TIMEOUT="${RT_TIMEOUT:-60}"
mkdir -p /out

# Detect type
TYPE="unknown"
HEAD=$(head -c 4 "$TARGET" 2>/dev/null | od -An -tx1 | tr -d ' \n')
case "$HEAD" in
    7f454c46*) TYPE="elf" ;;
    4d5a*)     TYPE="pe"  ;;
    *)         TYPE="unknown" ;;
esac

START=$(date +%s.%N)
if [[ "$TYPE" == "elf" ]]; then
    timeout "$TIMEOUT" strace -f -e trace=all -o /out/strace.log "$TARGET" \
        > /out/stdout.log 2> /out/stderr.log
    EXIT=$?
    timeout "$TIMEOUT" ltrace -f -o /out/ltrace.log "$TARGET" \
        > /dev/null 2>&1 || true
elif [[ "$TYPE" == "pe" ]]; then
    timeout "$TIMEOUT" strace -f -e trace=all -o /out/strace.log \
        wine "$TARGET" > /out/wine.log 2>&1
    EXIT=$?
elif [[ "$TYPE" == "unknown" ]]; then
    EXIT=126
    echo "unknown binary type" > /out/stderr.log
fi
END=$(date +%s.%N)
DURATION=$(echo "$END - $START" | bc 2>/dev/null || echo "0")

# Export to environment so the inline Python heredoc below can read them
export DOCKER_EXIT="$EXIT"
export DOCKER_DURATION="$DURATION"

# Synthesize uniform _dynamic.json from strace.log
python3 - <<'PYEOF'
import json, os, re
syscalls = []; network = []; file_writes = []; spawned = []
strace_path = "/out/strace.log"
if os.path.exists(strace_path):
    with open(strace_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"^(?:\[pid \d+\]\s+)?(\w+)\((.*?)\)\s*=\s*(-?\d+|\?)", line)
            if not m: continue
            name, args, retval = m.groups()
            syscalls.append({"name": name, "args": args[:200], "result": retval, "tier": "docker"})
            if name in ("connect", "sendto"):
                hp = re.search(r'"(\d+\.\d+\.\d+\.\d+)"|sin_port=htons\((\d+)\)', args)
                if hp: network.append({"protocol": "tcp", "host": hp.group(1) or "?", "port": int(hp.group(2) or 0), "tier": "docker"})
            if name in ("openat", "open") and "O_WRONLY" in args.upper():
                pm = re.search(r'"([^"]+)"', args)
                if pm: file_writes.append({"path": pm.group(1), "tier": "docker"})
            if name in ("execve", "fork", "vfork", "clone"):
                spawned.append({"argv": args[:200], "tier": "docker"})

exit_code = int(os.environ.get("DOCKER_EXIT", "0") or "0")
duration = float(os.environ.get("DOCKER_DURATION", "0") or "0")
out = {
    "ran": True, "tier": "docker", "tool": "docker",
    "real_execution": True, "exit_status": exit_code,
    "duration_sec": round(duration, 3),
    "syscall_count": len(syscalls), "api_call_count": 0,
    "file_writes": file_writes[:100], "registry_writes": [],
    "network_attempts": network[:100],
    "spawned_processes": spawned[:50],
    "syscalls": syscalls[:300], "api_calls": [],
    "errors": [],
}
with open("/out/_dynamic.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"docker-entrypoint: exit={exit_code}, syscalls={len(syscalls)}, network={len(network)}")
PYEOF

# Container's entrypoint exits cleanly; the actual exit code is recorded
# inside _dynamic.json above
exit 0
ENTRYPOINT_EOF

        chmod +x "$BUILD_DIR/entrypoint.sh"

        log_info "Building retoolkit-dynamic:latest image (~3-5min on first build)"
        if docker build -t retoolkit-dynamic:latest "$BUILD_DIR" >> "$DYNAMIC_LOG" 2>&1; then
            log_ok "retoolkit-dynamic:latest image built"
        else
            log_warn "Docker image build failed; --dynamic-mode=docker will not work. Check $DYNAMIC_LOG"
        fi
        rm -rf "$BUILD_DIR"
    else
        log_warn "docker not available after install attempt"
    fi
else
    log_info "LAYER 9 skipped (--with-docker not specified). For docker tier:"
    log_info "  sudo ./install-retoolkit.sh --with-docker"
fi

# =============================================================================
# LAYER 10 -- Dynamic analysis: cuckoo sandbox (NEW in v3.0.0; rare opt-in)
# =============================================================================
# OPT-IN via --with-cuckoo. Cuckoo is a heavyweight VM-based malware sandbox.
# Most analysts have an existing cuckoo deployment; this layer only verifies
# presence and provides install hints rather than fully automating install
# (cuckoo install is environment-specific - VirtualBox, KVM, hypervisor).
if [[ ${WITH_CUCKOO:-0} -eq 1 ]]; then
    log_hdr "LAYER 10 -- Dynamic analysis: cuckoo sandbox"

    if command -v cuckoo >/dev/null 2>&1 || [[ -x /opt/cuckoo/bin/cuckoo ]]; then
        log_ok "cuckoo binary located on PATH or at /opt/cuckoo"
    else
        log_warn "cuckoo not installed. Cuckoo install is environment-specific:"
        log_warn "  https://cuckoo.readthedocs.io/en/latest/installation/"
        log_warn "  (requires hypervisor + analyst-VM + agent setup)"
        log_warn "  RE-Toolkit's --dynamic-mode=cuckoo will skip when cuckoo absent"
    fi
else
    log_info "LAYER 10 skipped (--with-cuckoo not specified)."
fi

# =============================================================================
# LAYER 11 -- RetDec decompiler (NEW in v3.0.2 audit-6; opt-in via --with-retdec)
# =============================================================================
# OPT-IN via --with-retdec. RetDec is Avast's open-source machine-code
# decompiler. The maintained build path is Docker-only; source build takes
# ~1 hour and ~4GB disk. Per audit-6 D64, the calculus changed: Docker is
# now an acceptable runtime dependency (already used for LAYER 9 dynamic
# tier), so RetDec joins as a parallel native-binary decompiler offering a
# different perspective from Ghidra and r2/rizin.
#
# stage_retdec consumes /opt/retdec/decompile.sh which is a small wrapper
# around `docker run retdec/retdec:latest decompile <binary>` writing to
# the per-target outdir.
if [[ ${WITH_RETDEC:-0} -eq 1 ]]; then
    log_hdr "LAYER 11 -- RetDec decompiler"

    if [[ ${WITH_DOCKER:-0} -eq 0 ]] && ! command -v docker >/dev/null 2>&1; then
        log_warn "RetDec requires Docker. Either:"
        log_warn "  - Re-run with --with-docker --with-retdec, or"
        log_warn "  - Install docker manually first, then re-run with --with-retdec"
        log_warn "RetDec install skipped."
    else
        # v3.0.4 (audit-8 A7) -- image rename. The audit-6 LAYER 11 referenced
        # `retdec/retdec:latest` which DOES NOT EXIST on Docker Hub. Avast
        # publishes the source + Dockerfile but no official image to Docker
        # Hub. Verified via docker pull failing with:
        #   Error response from daemon: pull access denied for retdec/retdec,
        #   repository does not exist or may require 'docker login'
        # The actual community-maintained images on Docker Hub are:
        #   bannsec/retdec    (primary; has retdec-decompiler wrapper)
        #   remnux/retdec     (REMnux-maintained; bundled in REMnux distro)
        # Per L45: validate upstream resources EXPLICITLY. Using bannsec/retdec
        # as primary with remnux/retdec as fallback. The wrapper script paths
        # are different between the two; we detect which one was pulled and
        # write the wrapper accordingly.
        RETDEC_IMAGE=""
        for candidate in "bannsec/retdec" "remnux/retdec"; do
            log_info "Trying docker pull $candidate ..."
            if docker pull "$candidate" >>"$DYNAMIC_LOG" 2>&1; then
                RETDEC_IMAGE="$candidate"
                log_ok "Pulled $candidate Docker image"
                break
            fi
        done

        if [[ -z "$RETDEC_IMAGE" ]]; then
            log_warn "RetDec image pull failed for all candidates (bannsec/retdec, remnux/retdec)"
            log_warn "  Check Docker daemon and network. Manual:"
            log_warn "    docker pull bannsec/retdec"
            log_warn "    OR docker pull remnux/retdec"
        else
            # Install the wrapper script that stage_retdec invokes. Both
            # images expose retdec-decompiler in PATH; the working dir
            # convention differs slightly (bannsec uses /mount, remnux
            # uses /home/retdec/workdir). Use a portable approach:
            # bind-mount input file readonly + output dir read-write, then
            # invoke retdec-decompiler with explicit absolute paths inside
            # the container.
            mkdir -p /opt/retdec
            cat > /opt/retdec/decompile.sh <<RETDECWRAP
#!/usr/bin/env bash
# RetDec decompiler wrapper installed by RE-Toolkit LAYER 11.
# Usage: /opt/retdec/decompile.sh <input-binary> <output-dir>
# Emits <output-dir>/decompiled.c, decompiled.ll, config.json, dsm.txt.
# v3.0.4: uses ${RETDEC_IMAGE} (was retdec/retdec:latest pre-v3.0.4).
set -euo pipefail
BIN="\${1:?missing input binary}"
OUT="\${2:?missing output dir}"
mkdir -p "\$OUT"
BIN_ABS=\$(realpath "\$BIN")
OUT_ABS=\$(realpath "\$OUT")
docker run --rm --network=none \\
    -v "\$BIN_ABS:/sample:ro" \\
    -v "\$OUT_ABS:/out" \\
    ${RETDEC_IMAGE} \\
    retdec-decompiler /sample -o /out/decompiled.c 2>&1 | tee "\$OUT_ABS/retdec.log"
RETDECWRAP
            chmod 0755 /opt/retdec/decompile.sh
            # Record which image we pulled so verify can confirm it.
            echo "$RETDEC_IMAGE" > /opt/retdec/.image
            log_ok "RetDec wrapper installed → /opt/retdec/decompile.sh (image: $RETDEC_IMAGE)"
        fi
    fi
else
    log_info "LAYER 11 skipped (--with-retdec not specified)."
fi

# v3.1.0 (audit-22 A3.2) -- end install-layers guard (opened before LAYER 0).
# Everything from LAYER 0 through LAYER 11 is skipped when --verify is set.
fi  # end: if [[ ${VERIFY_ONLY:-0} -eq 0 ]]

if [[ ${VERIFY_ONLY:-0} -eq 1 ]]; then
    log_hdr "RE-Toolkit --verify: checking existing install (skipping LAYERs 0-11)"
    log_info "Running post-install verification only. No install work performed."
fi

# =============================================================================
# LAYER 12 -- Post-install verification (NEW in 2.1.0; renumbered from LAYER 6
# in v3.0.4 audit-8 A13 because this layer runs LAST after all other LAYERs
# including LAYER 11 RetDec; the original "LAYER 6" name was historically
# correct when the toolkit had only 6 layers but became misleading once more
# layers were added after it. LAYER 12 = sequentially next after LAYER 11.)
# =============================================================================
log_hdr "LAYER 12 -- Post-install verification"
log_info "Invoking every installed tool with --version/-h to confirm it actually runs"
log_info "Per-phase log: $VERIFY_LOG"

verify_tool() {
    # verify_tool <label> <path-or-command> <arg...>
    # Prints a padded PASS/FAIL row. Appends full output to $VERIFY_LOG.
    local label="$1" exe="$2"; shift 2
    local args=("$@")
    local status rc

    if [[ -z "$exe" ]]; then
        printf "  %-22s %sSKIP%s  (not configured)\n" "$label" "$C_DIM" "$C_OFF"
        return
    fi

    # Allow bare command names as well as absolute paths.
    if [[ "$exe" != /* ]]; then
        if ! command -v "$exe" >/dev/null 2>&1; then
            printf "  %-22s %sFAIL%s  (not on PATH)\n" "$label" "$C_ERR" "$C_OFF"
            FAILED_VERIFY+=("$label:not-found")
            return
        fi
    elif [[ ! -x "$exe" ]]; then
        printf "  %-22s %sFAIL%s  (%s not executable)\n" "$label" "$C_ERR" "$C_OFF" "$exe"
        FAILED_VERIFY+=("$label:not-exec")
        return
    fi

    {
        echo ""
        echo "=== verify: $label ==="
        echo "cmd: $exe ${args[*]}"
    } >> "$VERIFY_LOG"

    # Many tools print help to stderr; accept either. Capture combined.
    if timeout 20 "$exe" "${args[@]}" >>"$VERIFY_LOG" 2>&1; then
        rc=0
    else
        rc=$?
    fi

    # Some tools (like capa --version) exit 0 on success; others exit 1
    # for --help. Accept 0..2 as "alive". 124 is timeout = hung.
    if [[ $rc -le 2 ]]; then
        printf "  %-22s %sPASS%s\n" "$label" "$C_OK" "$C_OFF"
    else
        printf "  %-22s %sFAIL%s  (exit %d, see %s)\n" "$label" "$C_ERR" "$C_OFF" "$rc" "$VERIFY_LOG"
        FAILED_VERIFY+=("$label:exit-$rc")
    fi
}

# Disassembly core
echo "  --- Core disassembly / RE ---"
verify_tool "analyzeHeadless"  "$GHIDRA_LINK/support/analyzeHeadless" -help
verify_tool "radare2"          radare2 -v
verify_tool "rizin"            rizin -v
verify_tool "objdump"          objdump --version
# v3.0.6 (audit-10 A2): graphviz dot for rendering call/CFG graphs to SVG.
# When this is PASS, stages 40-r2 and 86-angr will produce inline-renderable
# .svg alongside their .dot outputs. When FAIL/missing, the stages still
# produce .dot files; users can render manually with `dot -Tsvg input.dot`
# after installing graphviz.
verify_tool "graphviz"         dot -V

# Triage
echo "  --- Binary inspection ---"
verify_tool "file"             file --version
verify_tool "strings"          strings --version
verify_tool "readelf"          readelf --version
verify_tool "nm"               nm --version
verify_tool "xxd"              xxd -v
verify_tool "hexdump"          hexdump -V
verify_tool "binwalk"          binwalk --help
verify_tool "exiftool"         exiftool -ver
verify_tool "upx"              upx --version
# v2.2.0 additions
verify_tool "diec"             diec --version
verify_tool "osslsigncode"     osslsigncode --version
# v2.3.0 additions -- static tool expansion
verify_tool "readpe"           readpe --version
verify_tool "pedis"            pedis --version
verify_tool "pehash"           pehash --version
verify_tool "pescan"           pescan --version
verify_tool "pesec"            pesec --version
verify_tool "pestr"            pestr --version
verify_tool "trid"             trid
verify_tool "bulk_extractor"   bulk_extractor -V
verify_tool "llvm-objdump"     llvm-objdump --version
# de4dot: mono-hosted, so verify differently. de4dot.exe exits 1 when called
# without input file but still prints its banner+help. With `set -o pipefail`,
# `mono X | head` returns 1 from mono and the pipeline trips. Workaround:
# capture output to a temp file (no pipe), check that output exists and
# contains the de4dot banner.
if [[ -f "$DE4DOT_EXE" ]] && command -v mono >/dev/null 2>&1; then
    {
        echo ""
        echo "=== verify: de4dot-cex ==="
    } >> "$VERIFY_LOG"
    DE4DOT_VERIFY_TMP=$(mktemp)
    timeout 15 mono "$DE4DOT_EXE" >"$DE4DOT_VERIFY_TMP" 2>&1 || true
    head -20 "$DE4DOT_VERIFY_TMP" >> "$VERIFY_LOG"
    if grep -q "de4dot v" "$DE4DOT_VERIFY_TMP" 2>/dev/null; then
        printf "  %-22s %sPASS%s\n" "de4dot-cex" "$C_OK" "$C_OFF"
    else
        printf "  %-22s %sFAIL%s  (see %s)\n" "de4dot-cex" "$C_ERR" "$C_OFF" "$VERIFY_LOG"
        FAILED_VERIFY+=("de4dot-cex")
    fi
    rm -f "$DE4DOT_VERIFY_TMP"
else
    printf "  %-22s %sSKIP%s  (not installed or mono missing)\n" "de4dot-cex" "$C_DIM" "$C_OFF"
fi

# v2.5.0: .NET deobfuscator chain + dnSpyEx Console
# v3.0.4 (audit-8 A9): EazFixer dropped from installer; not verified here.
# v3.0.10 (audit-14 B2): dnSpyEx now invoked via dotnet (not mono).
# Modern dnSpyEx (v6.2+) targets .NET 6 which mono cannot run; mono only
# handles .NET Framework 4.x. dnSpyEx uses dotnet; OldRod and NoFuserEx
# remain on mono since they are .NET Framework 4.x assemblies.
echo "  --- v2.5.0: .NET deobfuscator chain ---"
# dnSpyEx: requires dotnet (audit-14 fix)
if [[ -f "/opt/dnSpyEx/dnSpy.Console.exe" ]] && command -v dotnet >/dev/null 2>&1; then
    printf "  %-22s %sPASS%s  (/opt/dnSpyEx/dnSpy.Console.exe; runtime=dotnet)\n" \
        "dnSpyEx" "$C_OK" "$C_OFF"
elif [[ -f "/opt/dnSpyEx/dnSpy.Console.exe" ]]; then
    printf "  %-22s %sWARN%s  (file present but dotnet runtime missing;\n" \
        "dnSpyEx" "$C_WARN" "$C_OFF"
    printf "  %-22s         install via dotnet-sdk-8.0 - LAYER 2 should\n" ""
    printf "  %-22s         have done this; check $LAYER2_LOG)\n" ""
else
    printf "  %-22s %sSKIP%s  (not installed; build failed or skipped)\n" \
        "dnSpyEx" "$C_DIM" "$C_OFF"
fi
# OldRod + NoFuserEx: still .NET Framework 4.x; mono is the right runtime
for dn_pair in \
    "OldRod:/opt/OldRod/OldRod.exe" \
    "NoFuserEx:/opt/NoFuserEx/NoFuserEx.exe"; do
    label="${dn_pair%%:*}"
    path="${dn_pair#*:}"
    if [[ -f "$path" ]] && command -v mono >/dev/null 2>&1; then
        printf "  %-22s %sPASS%s  (%s)\n" "$label" "$C_OK" "$C_OFF" "$path"
    elif [[ -f "$path" ]]; then
        printf "  %-22s %sWARN%s  (file present but mono missing)\n" "$label" "$C_WARN" "$C_OFF"
    else
        printf "  %-22s %sSKIP%s  (not installed; build failed or skipped)\n" "$label" "$C_DIM" "$C_OFF"
    fi
done

# v2.5.0: signsrch + Manalyze (native binaries)
echo "  --- v2.5.0: PE/binary analyzers ---"
verify_tool "signsrch"         signsrch -h
# manalyze --version requires a PE arg and exits 255 without one. Same class
# of false-FAIL as de4dot-cex pipefail (audit-5 L33). Use tempfile capture
# + content-string check instead of relying on exit code.
if command -v manalyze >/dev/null 2>&1; then
    {
        echo ""
        echo "=== verify: manalyze ==="
    } >> "$VERIFY_LOG"
    MANALYZE_VERIFY_TMP=$(mktemp)
    timeout 15 manalyze --help >"$MANALYZE_VERIFY_TMP" 2>&1 || true
    head -10 "$MANALYZE_VERIFY_TMP" >> "$VERIFY_LOG"
    # v3.0.4 (audit-8 A1): manalyze --help emits "Usage:" (capital U) and
    # "POSITIONALS:" / "OPTIONS:" sections under recent CLI11-based builds;
    # earlier builds used "Allowed options:" (boost::program_options).
    # Use case-insensitive grep so EITHER pattern matches. Expand the
    # match set to cover all observed manalyze help-banner variants:
    #   - "Usage:" / "usage:"
    #   - "Manalyze" (the tool's own name in the banner)
    #   - "POSITIONALS:" / "OPTIONS:" (CLI11 sections)
    #   - "Allowed options" (boost::program_options sections, legacy builds)
    if grep -qiE "manalyze|usage:|allowed options|POSITIONALS:|OPTIONS:" "$MANALYZE_VERIFY_TMP" 2>/dev/null; then
        printf "  %-22s %sPASS%s\n" "manalyze" "$C_OK" "$C_OFF"
    else
        printf "  %-22s %sFAIL%s  (see %s)\n" "manalyze" "$C_ERR" "$C_OFF" "$VERIFY_LOG"
        FAILED_VERIFY+=("manalyze")
    fi
    rm -f "$MANALYZE_VERIFY_TMP"
else
    printf "  %-22s %sFAIL%s  (not on PATH)\n" "manalyze" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("manalyze:not-found")
fi

# v2.5.0: ELF analysis tools (apt-installed)
echo "  --- v2.5.0: ELF analysis tools ---"
verify_tool "checksec"         checksec --version
verify_tool "scanelf"          scanelf -V
verify_tool "dumpelf"          dumpelf -V
verify_tool "pahole"           pahole --version
verify_tool "bloaty"           bloaty --version
# pwntools is verified via the venv (provides `pwn checksec` fallback)

# v2.5.0: peframe (pip-installed in venv)
if [[ -x "${RETOOLS_VENV}/bin/peframe" ]]; then
    {
        echo ""
        echo "=== verify: peframe (in venv) ==="
    } >> "$VERIFY_LOG"
    if timeout 15 "${RETOOLS_VENV}/bin/peframe" --help >>"$VERIFY_LOG" 2>&1; then
        printf "  %-22s %sPASS%s\n" "peframe" "$C_OK" "$C_OFF"
    else
        printf "  %-22s %sFAIL%s\n" "peframe" "$C_ERR" "$C_OFF"
        FAILED_VERIFY+=("peframe")
    fi
else
    printf "  %-22s %sSKIP%s  (not installed via pip)\n" "peframe" "$C_DIM" "$C_OFF"
fi

# v2.5.0: cwe_checker (only when --with-cwe-checker was used)
if [[ ${WITH_CWE_CHECKER:-0} -eq 1 ]]; then
    if command -v cwe_checker >/dev/null 2>&1; then
        printf "  %-22s %sPASS%s\n" "cwe_checker" "$C_OK" "$C_OFF"
    else
        printf "  %-22s %sFAIL%s\n" "cwe_checker" "$C_ERR" "$C_OFF"
        FAILED_VERIFY+=("cwe_checker")
    fi
else
    printf "  %-22s %sSKIP%s  (--with-cwe-checker not specified)\n" "cwe_checker" "$C_DIM" "$C_OFF"
fi

# v2.6.0: WebAssembly Binary Toolkit (apt-installed, always-on once apt ran)
echo "  --- v2.6.0: binary type bucket tools ---"
verify_tool "wasm2wat"         wasm2wat --version
verify_tool "wasm-objdump"     wasm-objdump --version
verify_tool "wasm-decompile"   wasm-decompile --version
verify_tool "wasm-validate"    wasm-validate --version

# v2.6.0: PDF analysis (apt-installed)
verify_tool "mutool"           mutool -v
verify_tool "qpdf"             qpdf --version

# v2.6.0: Java JDK headless for jar analysis
verify_tool "javap"            javap -version
verify_tool "java"             java -version

# v2.6.0: 7z (for OOXML container introspection)
verify_tool "7z"               7z

# v2.6.0: pycdc / pycdas (Python bytecode tools, source-built)
verify_tool "pycdc"            pycdc --help
verify_tool "pycdas"           pycdas --help

# v2.6.0: peepdf (pip-installed)
if [[ -x "${RETOOLS_VENV}/bin/peepdf" ]]; then
    printf "  %-22s %sPASS%s\n" "peepdf" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sSKIP%s  (not installed via pip)\n" "peepdf" "$C_DIM" "$C_OFF"
fi

# v2.6.0: uncompyle6 / decompyle3 (pip-installed)
for label in uncompyle6 decompyle3; do
    if [[ -x "${RETOOLS_VENV}/bin/$label" ]]; then
        printf "  %-22s %sPASS%s\n" "$label" "$C_OK" "$C_OFF"
    else
        printf "  %-22s %sSKIP%s  (not installed via pip)\n" "$label" "$C_DIM" "$C_OFF"
    fi
done

# v2.6.0: CFR + procyon (jar files at /opt/cfr + /opt/procyon)
for pair in "CFR:/opt/cfr/cfr.jar" "procyon:/opt/procyon/procyon.jar"; do
    label="${pair%%:*}"; path="${pair#*:}"
    if [[ -f "$path" ]] && command -v java >/dev/null 2>&1; then
        printf "  %-22s %sPASS%s  (%s)\n" "$label" "$C_OK" "$C_OFF" "$path"
    elif [[ -f "$path" ]]; then
        printf "  %-22s %sWARN%s  (file present but java missing)\n" "$label" "$C_WARN" "$C_OFF"
    else
        printf "  %-22s %sSKIP%s  (jar not installed)\n" "$label" "$C_DIM" "$C_OFF"
    fi
done

# v2.6.0: DidierStevensSuite (PDF + OLE scripts)
if [[ -d "/opt/DidierStevensSuite" ]] && [[ -f "/opt/DidierStevensSuite/pdfid.py" ]]; then
    DSS_COUNT=$(ls /opt/DidierStevensSuite/*.py 2>/dev/null | wc -l)
    printf "  %-22s %sPASS%s  (%d Python scripts)\n" "DidierStevensSuite" "$C_OK" "$C_OFF" "$DSS_COUNT"
else
    printf "  %-22s %sSKIP%s  (not cloned)\n" "DidierStevensSuite" "$C_DIM" "$C_OFF"
fi

# v2.6.0: redress (only when --with-redress was used)
if [[ ${WITH_REDRESS:-0} -eq 1 ]]; then
    if command -v redress >/dev/null 2>&1; then
        printf "  %-22s %sPASS%s\n" "redress" "$C_OK" "$C_OFF"
    else
        printf "  %-22s %sFAIL%s\n" "redress" "$C_ERR" "$C_OFF"
        FAILED_VERIFY+=("redress")
    fi
else
    printf "  %-22s %sSKIP%s  (--with-redress not specified)\n" "redress" "$C_DIM" "$C_OFF"
fi

# v2.6.0: rustfilt (only when --with-rustfilt was used)
if [[ ${WITH_RUSTFILT:-0} -eq 1 ]]; then
    if command -v rustfilt >/dev/null 2>&1; then
        printf "  %-22s %sPASS%s\n" "rustfilt" "$C_OK" "$C_OFF"
    else
        printf "  %-22s %sFAIL%s\n" "rustfilt" "$C_ERR" "$C_OFF"
        FAILED_VERIFY+=("rustfilt")
    fi
else
    printf "  %-22s %sSKIP%s  (--with-rustfilt not specified)\n" "rustfilt" "$C_DIM" "$C_OFF"
fi

# v2.7.0: cross-cutting capability tools
echo "  --- v2.7.0: cross-cutting capability tools ---"
verify_tool "ssdeep"           ssdeep -V

# python-ssdeep (pip-installed in venv)
if [[ -n "${RETOOLS_VENV:-}" ]] && \
   "${RETOOLS_VENV}/bin/python" -c "import ssdeep" 2>/dev/null; then
    printf "  %-22s %sPASS%s\n" "python-ssdeep" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sFAIL%s  (python -c 'import ssdeep' failed)\n" "python-ssdeep" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("python-ssdeep")
fi

# python-tlsh (pip-installed in venv)
if [[ -n "${RETOOLS_VENV:-}" ]] && \
   "${RETOOLS_VENV}/bin/python" -c "import tlsh" 2>/dev/null; then
    printf "  %-22s %sPASS%s\n" "python-tlsh" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sFAIL%s  (python -c 'import tlsh' failed)\n" "python-tlsh" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("python-tlsh")
fi

# yarGen (cloned to /opt/yarGen in LAYER 2F)
if [[ -f "/opt/yarGen/yarGen.py" ]]; then
    printf "  %-22s %sPASS%s  (/opt/yarGen/yarGen.py)\n" "yarGen" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sFAIL%s  (not at /opt/yarGen/yarGen.py)\n" "yarGen" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("yarGen")
fi

# yarGen goodware DB (only when --with-yargen-db was used)
if [[ ${WITH_YARGEN_DB:-0} -eq 1 ]]; then
    if ls /opt/yarGen/dbs/good-strings*.db >/dev/null 2>&1; then
        DB_COUNT=$(ls /opt/yarGen/dbs/good-*.db 2>/dev/null | wc -l)
        printf "  %-22s %sPASS%s  (%d DB files)\n" "yarGen-goodware-db" "$C_OK" "$C_OFF" "$DB_COUNT"
    else
        printf "  %-22s %sFAIL%s  (no good-*.db files in /opt/yarGen/dbs/)\n" "yarGen-goodware-db" "$C_ERR" "$C_OFF"
        FAILED_VERIFY+=("yarGen-goodware-db")
    fi
else
    printf "  %-22s %sSKIP%s  (--with-yargen-db not specified)\n" "yarGen-goodware-db" "$C_DIM" "$C_OFF"
fi

# findaes (only when --with-findaes was used)
if [[ ${WITH_FINDAES:-0} -eq 1 ]]; then
    if command -v findaes >/dev/null 2>&1; then
        printf "  %-22s %sPASS%s\n" "findaes" "$C_OK" "$C_OFF"
    else
        printf "  %-22s %sFAIL%s\n" "findaes" "$C_ERR" "$C_OFF"
        FAILED_VERIFY+=("findaes")
    fi
else
    printf "  %-22s %sSKIP%s  (--with-findaes not specified)\n" "findaes" "$C_DIM" "$C_OFF"
fi

# osslsigncode is already in v2.4.0 LAYER 1 apt; verify it's accessible
# for stage_authenticode to use
verify_tool "osslsigncode"     osslsigncode --help

# radiff2 ships with radare2; verify it's accessible for stage_radiff2
verify_tool "radiff2"          radiff2 -v

# angr (pip-installed in venv since v2.4.0; stage 86 uses it opt-in)
if [[ -n "${RETOOLS_VENV:-}" ]] && \
   "${RETOOLS_VENV}/bin/python" -c "import angr" 2>/dev/null; then
    printf "  %-22s %sPASS%s\n" "angr" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sFAIL%s  (python -c 'import angr' failed)\n" "angr" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("angr")
fi

# v2.8.0: mobile RE tools (Android DEX/APK)
echo "  --- v2.8.0: mobile RE tools (Android DEX/APK) ---"
verify_tool "jadx"             jadx --version
verify_tool "apktool"          apktool --version
verify_tool "apksigner"        apksigner --version

# aapt2 OR aapt are acceptable (aapt2 preferred but aapt suffices for AXML xmltree)
if command -v aapt2 >/dev/null 2>&1; then
    printf "  %-22s %sPASS%s  (aapt2 present)\n" "aapt2" "$C_OK" "$C_OFF"
elif command -v aapt >/dev/null 2>&1; then
    printf "  %-22s %sPASS%s  (legacy aapt present; aapt2 preferred)\n" "aapt" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sFAIL%s  (neither aapt2 nor aapt found)\n" "aapt2/aapt" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("aapt2-or-aapt")
fi

# baksmali either as standalone bin or via apktool bundle
if command -v baksmali >/dev/null 2>&1; then
    printf "  %-22s %sPASS%s\n" "baksmali" "$C_OK" "$C_OFF"
elif [[ -f /opt/baksmali/baksmali.jar ]]; then
    printf "  %-22s %sPASS%s  (jar at /opt/baksmali)\n" "baksmali" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sWARN%s  (no standalone baksmali; apktool bundle used)\n" "baksmali" "$C_WARN" "$C_OFF"
fi

# dex2jar provides d2j-dex2jar (or d2j-dex2jar.sh on some distros)
if command -v d2j-dex2jar >/dev/null 2>&1 || command -v d2j-dex2jar.sh >/dev/null 2>&1 || command -v dex2jar >/dev/null 2>&1; then
    printf "  %-22s %sPASS%s\n" "dex2jar" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sFAIL%s\n" "dex2jar" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("dex2jar")
fi

# v2.9.0: visualization layer (no apt deps; verifies Python stdlib support)
echo "  --- v2.9.0: visualization layer (inline-SVG; pure Python) ---"
# Python ElementTree XML support - used by stage_viz to validate generated SVG
if [[ -n "${RETOOLS_VENV:-}" ]] && \
   "${RETOOLS_VENV}/bin/python" -c "import xml.etree.ElementTree" 2>/dev/null; then
    printf "  %-22s %sPASS%s  (xml.etree.ElementTree; needed for SVG validation)\n" \
        "py-xml-etree" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sFAIL%s  (xml.etree.ElementTree missing)\n" \
        "py-xml-etree" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("py-xml-etree")
fi
# Python math + random - used by force-directed layout in viz-helper.sh
if [[ -n "${RETOOLS_VENV:-}" ]] && \
   "${RETOOLS_VENV}/bin/python" -c "import math, random, json" 2>/dev/null; then
    printf "  %-22s %sPASS%s  (math, random, json; needed for force-directed layout)\n" \
        "py-stdlib-viz" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sFAIL%s  (math/random/json import failed)\n" \
        "py-stdlib-viz" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("py-stdlib-viz")
fi
# stage_viz file presence (sanity check that the install copied it correctly)
if [[ -f "${RETOOLKIT_HOME:-/opt/retoolkit}/stages/static/89-viz.sh" ]] || \
   [[ -f "$(dirname "${BASH_SOURCE[0]}")/stages/static/89-viz.sh" ]]; then
    printf "  %-22s %sPASS%s\n" "stage-viz-script" "$C_OK" "$C_OFF"
else
    # Can't reliably check post-extraction location; informational only
    printf "  %-22s %sSKIP%s  (stage 89-viz.sh location varies post-install)\n" \
        "stage-viz-script" "$C_DIM" "$C_OFF"
fi

# v3.0.0: dynamic analysis layer (qiling always; docker/cuckoo opt-in)
echo "  --- v3.0.0: dynamic analysis tiers ---"
# Tier 1: qiling (Python module + rootfs)
if [[ -n "${RETOOLS_VENV:-}" ]] && \
   "${RETOOLS_VENV}/bin/python" -c "import qiling" 2>/dev/null; then
    QILING_VER=$("${RETOOLS_VENV}/bin/python" -c "import qiling; print(getattr(qiling, '__version__', 'unknown'))" 2>/dev/null)
    printf "  %-22s %sPASS%s  (qiling %s)\n" \
        "qiling-py" "$C_OK" "$C_OFF" "$QILING_VER"
else
    printf "  %-22s %sFAIL%s  (qiling import failed; --dynamic-mode=qiling unavailable)\n" \
        "qiling-py" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("qiling-py")
fi
if [[ -d /opt/qiling-rootfs ]] && [[ -d /opt/qiling-rootfs/x8664_linux ]]; then
    printf "  %-22s %sPASS%s  (/opt/qiling-rootfs)\n" \
        "qiling-rootfs" "$C_OK" "$C_OFF"
elif [[ -d /opt/qiling-rootfs ]]; then
    printf "  %-22s %sWARN%s  (rootfs present but x8664_linux missing; partial coverage)\n" \
        "qiling-rootfs" "$C_WARN" "$C_OFF"
else
    printf "  %-22s %sFAIL%s  (rootfs not at /opt/qiling-rootfs; qiling falls back to bare emulation)\n" \
        "qiling-rootfs" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("qiling-rootfs")
fi
# v3.0.9 (audit-13 E2) - per-architecture rootfs population verification.
# qiling-rootfs/x8664_windows is created by the clone but Microsoft Windows
# DLLs are NOT bundled per Microsoft EULA. Without DLLs, qiling cannot
# emulate Windows PE imports. Operators previously had no signal that
# Windows emulation was unavailable until they ran --dynamic on a PE
# binary and got 0 syscalls. Now: log per-arch population status so the
# operator immediately knows which architectures qiling can actually
# handle, and is told what to do for the architectures it can't.
if [[ -d /opt/qiling-rootfs ]]; then
    for _arch_dir in /opt/qiling-rootfs/x8664_linux \
                     /opt/qiling-rootfs/x86_linux \
                     /opt/qiling-rootfs/x8664_windows \
                     /opt/qiling-rootfs/x86_windows \
                     /opt/qiling-rootfs/x8664_macos; do
        _arch_name=$(basename "$_arch_dir")
        if [[ -d "$_arch_dir" ]]; then
            # Count files (any depth) to detect "directory exists but empty"
            _file_count=$(find "$_arch_dir" -type f 2>/dev/null | head -100 | wc -l)
            case "$_arch_name" in
                *_windows)
                    # Windows arches: count specifically DLLs (not bundled per EULA)
                    _dll_count=$(find "$_arch_dir" -maxdepth 4 -iname '*.dll' 2>/dev/null | head -10 | wc -l)
                    if [[ $_dll_count -gt 0 ]]; then
                        printf "    %-20s %sPASS%s  (populated; %d DLLs found)\n" \
                            "$_arch_name" "$C_OK" "$C_OFF" "$_dll_count"
                    else
                        printf "    %-20s %sEMPTY%s (Microsoft DLLs not bundled per EULA;\n" \
                            "$_arch_name" "$C_WARN" "$C_OFF"
                        printf "    %-20s        qiling cannot emulate Windows PE; use\n" ""
                        printf "    %-20s        --dynamic-mode=docker for PE binaries)\n" ""
                    fi
                    ;;
                *)
                    # Linux/macOS arches: should have some files from the clone
                    if [[ $_file_count -gt 0 ]]; then
                        printf "    %-20s %sPASS%s  (populated; %d+ files)\n" \
                            "$_arch_name" "$C_OK" "$C_OFF" "$_file_count"
                    else
                        printf "    %-20s %sEMPTY%s (no files; qiling cannot emulate this architecture)\n" \
                            "$_arch_name" "$C_WARN" "$C_OFF"
                    fi
                    ;;
            esac
        fi
    done
fi
# Tier 2: firejail (already installed in v2.x; reverify with v3.0.0 messaging)
if command -v firejail >/dev/null 2>&1; then
    FJ_VER=$(firejail --version 2>/dev/null | head -1 | awk '{print $NF}')
    printf "  %-22s %sPASS%s  (firejail %s; --dynamic-mode=firejail tier)\n" \
        "firejail" "$C_OK" "$C_OFF" "$FJ_VER"
else
    printf "  %-22s %sFAIL%s  (firejail missing; --dynamic-mode=firejail unavailable)\n" \
        "firejail" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("firejail")
fi
# Tier 3: docker (only verified when --with-docker passed)
if [[ ${WITH_DOCKER:-0} -eq 1 ]]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        if docker image inspect retoolkit-dynamic:latest >/dev/null 2>&1; then
            printf "  %-22s %sPASS%s  (docker + retoolkit-dynamic:latest image)\n" \
                "docker-tier" "$C_OK" "$C_OFF"
        else
            printf "  %-22s %sFAIL%s  (docker present but retoolkit-dynamic:latest missing; rebuild)\n" \
                "docker-tier" "$C_ERR" "$C_OFF"
            FAILED_VERIFY+=("docker-tier")
        fi
    else
        printf "  %-22s %sFAIL%s  (docker daemon not running or not accessible)\n" \
            "docker-tier" "$C_ERR" "$C_OFF"
        FAILED_VERIFY+=("docker-tier")
    fi
else
    printf "  %-22s %sSKIP%s  (not requested; --with-docker to enable)\n" \
        "docker-tier" "$C_DIM" "$C_OFF"
fi
# Tier 4: cuckoo (only when --with-cuckoo)
if [[ ${WITH_CUCKOO:-0} -eq 1 ]]; then
    if command -v cuckoo >/dev/null 2>&1 || [[ -x /opt/cuckoo/bin/cuckoo ]]; then
        printf "  %-22s %sPASS%s\n" "cuckoo-tier" "$C_OK" "$C_OFF"
    else
        printf "  %-22s %sWARN%s  (cuckoo not installed; manual setup required)\n" \
            "cuckoo-tier" "$C_WARN" "$C_OFF"
    fi
else
    printf "  %-22s %sSKIP%s  (not requested; --with-cuckoo to enable; manual setup)\n" \
        "cuckoo-tier" "$C_DIM" "$C_OFF"
fi
# strace/ltrace (used inside firejail and docker tiers)
if command -v strace >/dev/null 2>&1; then
    printf "  %-22s %sPASS%s\n" "strace" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sFAIL%s  (firejail/docker tiers degraded without strace)\n" \
        "strace" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("strace")
fi
if command -v ltrace >/dev/null 2>&1; then
    printf "  %-22s %sPASS%s\n" "ltrace" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sWARN%s  (library-call trace unavailable; non-fatal)\n" \
        "ltrace" "$C_WARN" "$C_OFF"
fi

# TrID definition database check
TRID_DEFS_FOUND=""
for d in /usr/share/trid /etc/trid /opt/trid; do
    if [[ -f "$d/triddefs.trd" ]]; then TRID_DEFS_FOUND="$d/triddefs.trd"; break; fi
done
if [[ -n "$TRID_DEFS_FOUND" ]]; then
    printf "  %-22s %sPASS%s  (%s, %d KB)\n" "trid-defs" "$C_OK" "$C_OFF" \
        "$TRID_DEFS_FOUND" "$(du -k "$TRID_DEFS_FOUND" | cut -f1)"
else
    printf "  %-22s %sFAIL%s  (triddefs.trd not found; trid will not work)\n" "trid-defs" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("trid-defs")
fi

# v3.0.2 (audit-6): binary-diff stage tools
echo "  --- v3.0.2: binary-diff stage tools ---"
verify_tool "bsdiff"           bsdiff
verify_tool "bspatch"          bspatch
verify_tool "vbindiff"         vbindiff --version

# v3.0.2 (audit-6): pwntools ROP stage. pwntools is in the venv; verify
# the import works since the stage script invokes a Python heredoc.
if [[ -x "${RETOOLS_VENV}/bin/python" ]] && \
   "${RETOOLS_VENV}/bin/python" -c "from pwn import ROP" 2>/dev/null; then
    printf "  %-22s %sPASS%s  (pwntools ROP class importable; stage_rop_gadgets ready)\n" \
        "pwntools-rop" "$C_OK" "$C_OFF"
else
    printf "  %-22s %sFAIL%s  (pwntools ROP unavailable; stage_rop_gadgets degraded)\n" \
        "pwntools-rop" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("pwntools-rop")
fi

# v3.0.2 (audit-6): retdec tier (when --with-retdec)
# v3.0.4 (audit-8 A7): image name is now bannsec/retdec or remnux/retdec
# (retdec/retdec:latest never existed on Docker Hub). The actual pulled
# image was recorded in /opt/retdec/.image during LAYER 11 install.
if [[ ${WITH_RETDEC:-0} -eq 1 ]]; then
    if [[ -x /opt/retdec/decompile.sh ]] && command -v docker >/dev/null 2>&1; then
        # Read the recorded image name; fall back to checking both candidates
        # if the marker file is missing (idempotent re-run after manual fix).
        RETDEC_VERIFY_IMAGE=""
        if [[ -f /opt/retdec/.image ]]; then
            RETDEC_VERIFY_IMAGE=$(cat /opt/retdec/.image 2>/dev/null | head -1)
        fi
        if [[ -n "$RETDEC_VERIFY_IMAGE" ]] && \
           docker image inspect "$RETDEC_VERIFY_IMAGE" >/dev/null 2>&1; then
            printf "  %-22s %sPASS%s  (%s image pulled; stage_retdec ready)\n" \
                "retdec-tier" "$C_OK" "$C_OFF" "$RETDEC_VERIFY_IMAGE"
        elif docker image inspect bannsec/retdec >/dev/null 2>&1; then
            printf "  %-22s %sPASS%s  (bannsec/retdec image pulled; stage_retdec ready)\n" \
                "retdec-tier" "$C_OK" "$C_OFF"
        elif docker image inspect remnux/retdec >/dev/null 2>&1; then
            printf "  %-22s %sPASS%s  (remnux/retdec image pulled; stage_retdec ready)\n" \
                "retdec-tier" "$C_OK" "$C_OFF"
        else
            printf "  %-22s %sWARN%s  (wrapper installed but image not pulled)\n" \
                "retdec-tier" "$C_WARN" "$C_OFF"
        fi
    else
        printf "  %-22s %sFAIL%s  (wrapper or docker missing; LAYER 11 install failed?)\n" \
            "retdec-tier" "$C_ERR" "$C_OFF"
        FAILED_VERIFY+=("retdec-tier")
    fi
else
    printf "  %-22s %sSKIP%s  (not requested; --with-retdec to enable; needs Docker)\n" \
        "retdec-tier" "$C_DIM" "$C_OFF"
fi

# Pattern matching / scanning -- crucial to verify these actually have rules
echo "  --- Pattern matching / scanning ---"
verify_tool "yara-binary"      yara --version
# Real test for yara: compile the master rules and scan /dev/null.
if [[ -f "${YARA_RULES_DIR}/_master.yar" ]] && command -v yara >/dev/null 2>&1; then
    {
        echo ""
        echo "=== verify: yara-rules (compile + scan empty) ==="
    } >> "$VERIFY_LOG"
    if yara "${YARA_RULES_DIR}/_master.yar" /dev/null >>"$VERIFY_LOG" 2>&1; then
        printf "  %-22s %sPASS%s  (%d rule files)\n" "yara-rules" "$C_OK" "$C_OFF" \
            "$(grep -c '^include' "${YARA_RULES_DIR}/_master.yar")"
    else
        printf "  %-22s %sWARN%s  (some rules may fail)\n" "yara-rules" "$C_WARN" "$C_OFF"
    fi
else
    printf "  %-22s %sSKIP%s  (rules not cloned)\n" "yara-rules" "$C_DIM" "$C_OFF"
fi
verify_tool "clamscan"         clamscan --version

# capa needs BOTH the binary AND a rules directory. Test both.
CAPA_BIN=""
for p in "${RETOOLS_BASE}/bin/capa" "${RETOOLS_VENV}/bin/capa" "$(command -v capa 2>/dev/null)"; do
    if [[ -n "$p" && -x "$p" ]]; then CAPA_BIN="$p"; break; fi
done
verify_tool "capa-binary"      "$CAPA_BIN" --version
if [[ -n "$CAPA_BIN" && -d "$CAPA_RULES_DIR" ]]; then
    # Running capa against an empty file with rules is the fastest
    # round-trip smoke test. capa exits with 0/1/something small when
    # rules load OK; it errors loudly if they don't.
    {
        echo ""
        echo "=== verify: capa-rules (load test) ==="
    } >> "$VERIFY_LOG"
    # Touch a tiny stub file -- capa needs *something* as a target.
    STUB=$(mktemp); printf 'MZ\x90\x00' > "$STUB"
    if timeout 30 "$CAPA_BIN" -r "$CAPA_RULES_DIR" "$STUB" >>"$VERIFY_LOG" 2>&1; then
        :
    fi
    # "rules loaded OK" == capa printed its standard "no capabilities
    # detected" or similar; failures we care about are stack traces.
    if grep -q "Traceback\|ERROR" "$VERIFY_LOG" 2>/dev/null | tail -40 >/dev/null; then
        # Scan the last 40 lines for tracebacks; if present we report FAIL
        if tail -40 "$VERIFY_LOG" | grep -q "Traceback"; then
            printf "  %-22s %sFAIL%s  (traceback -- see %s)\n" "capa-rules" "$C_ERR" "$C_OFF" "$VERIFY_LOG"
            FAILED_VERIFY+=("capa-rules:traceback")
        else
            printf "  %-22s %sPASS%s  (%d rule files)\n" "capa-rules" "$C_OK" "$C_OFF" \
                "$(find "$CAPA_RULES_DIR" -name '*.yml' | wc -l)"
        fi
    else
        printf "  %-22s %sPASS%s  (%d rule files)\n" "capa-rules" "$C_OK" "$C_OFF" \
            "$(find "$CAPA_RULES_DIR" -name '*.yml' | wc -l)"
    fi
    rm -f "$STUB"
else
    printf "  %-22s %sSKIP%s  (binary or rules missing)\n" "capa-rules" "$C_DIM" "$C_OFF"
fi

# floss
FLOSS_BIN=""
for p in "${RETOOLS_BASE}/bin/floss" "${RETOOLS_VENV}/bin/floss" "$(command -v floss 2>/dev/null)"; do
    if [[ -n "$p" && -x "$p" ]]; then FLOSS_BIN="$p"; break; fi
done
verify_tool "floss"            "$FLOSS_BIN" --version

# .NET
echo "  --- .NET tooling ---"
verify_tool "monodis"          monodis --help
verify_tool "ikdasm"           ikdasm --help
verify_tool "dotnet"           dotnet --version
ILSPY_BIN=""
for p in "$(command -v ilspycmd 2>/dev/null)" "${INVOKING_HOME}/.dotnet/tools/ilspycmd" "/root/.dotnet/tools/ilspycmd"; do
    if [[ -n "$p" && -x "$p" ]]; then ILSPY_BIN="$p"; break; fi
done
verify_tool "ilspycmd"         "$ILSPY_BIN" --version

# Python venv -- report what we have
echo "  --- Python venv ---"
if [[ -x "${RETOOLS_VENV}/bin/python" ]]; then
    PY_COUNT=$("${RETOOLS_VENV}/bin/pip" list 2>/dev/null | wc -l)
    printf "  %-22s %sPASS%s  (%d packages)\n" "venv-python" "$C_OK" "$C_OFF" "$PY_COUNT"
    # Verify the key imports actually import (installed != functional)
    for mod in pefile dnfile capa floss pyghidra; do
        if "${RETOOLS_VENV}/bin/python" -c "import $mod" 2>>"$VERIFY_LOG"; then
            printf "  %-22s %sPASS%s\n" "py:$mod" "$C_OK" "$C_OFF"
        else
            printf "  %-22s %sFAIL%s  (import error -- see %s)\n" "py:$mod" "$C_ERR" "$C_OFF" "$VERIFY_LOG"
            FAILED_VERIFY+=("py:$mod")
        fi
    done
else
    printf "  %-22s %sFAIL%s\n" "venv-python" "$C_ERR" "$C_OFF"
    FAILED_VERIFY+=("venv-python")
fi

# =============================================================================
# Final summary
# =============================================================================
log_hdr "Installation Summary"

echo ""
echo "Environment (source ~/.bashrc or log out/in to activate):"
echo "  GHIDRA_INSTALL_DIR=$GHIDRA_LINK"
echo "  CAPA_RULES=$CAPA_RULES_DIR"
echo "  YARA_RULES=$YARA_RULES_DIR"
echo "  PATH includes ${RETOOLS_BASE}/bin"
if [[ -d "${INVOKING_HOME}/.dotnet/tools" ]]; then
    echo "  PATH includes ${INVOKING_HOME}/.dotnet/tools"
fi

echo ""
total_failures=$(( ${#FAILED_APT[@]} + ${#FAILED_DOTNET[@]} + ${#FAILED_PY[@]} + ${#FAILED_RULES[@]} + ${#FAILED_VERIFY[@]} + ${#FAILED_SOURCE[@]} ))
if [[ $total_failures -eq 0 ]]; then
    log_ok "All install + verification steps PASSED."
else
    log_warn "Installation completed with $total_failures issue(s):"
    [[ ${#FAILED_SOURCE[@]} -gt 0 ]] && echo "    source:    ${FAILED_SOURCE[*]}    (log: $SOURCE_LOG)"
    [[ ${#FAILED_APT[@]}    -gt 0 ]] && echo "    apt:       ${FAILED_APT[*]}       (log: $APT_LOG)"
    [[ ${#FAILED_DOTNET[@]} -gt 0 ]] && echo "    dotnet:    ${FAILED_DOTNET[*]}    (log: $DOTNET_LOG)"
    [[ ${#FAILED_PY[@]}     -gt 0 ]] && echo "    pip:       ${FAILED_PY[*]}        (log: $PY_LOG)"
    [[ ${#FAILED_RULES[@]}  -gt 0 ]] && echo "    rules:     ${FAILED_RULES[*]}     (log: $RULES_LOG)"
    [[ ${#FAILED_VERIFY[@]} -gt 0 ]] && echo "    verify:    ${FAILED_VERIFY[*]}    (log: $VERIFY_LOG)"
    echo ""
    echo "  Review the relevant log(s) under $LOG_ROOT/ for the exact error output."
    echo "  The toolkit will work for tools that passed verification; missing tools"
    echo "  will be reported by analyze-binaries.sh and gracefully skipped there."
fi

echo ""
if [[ $SKIP_SOURCE -eq 0 && ${#FAILED_SOURCE[@]} -eq 0 ]]; then
    echo "Next: source /etc/profile.d/retools.sh (or log out/in), then run"
    echo "      analyze-binaries.sh -t <target(s)> -o <output-dir>"
    echo "      (resolves via $RETOOLKIT_BIN_LINK -> $RETOOLKIT_INSTALL_DIR/)"
else
    echo "Next: source /etc/profile.d/retools.sh (or log out/in), then run"
    echo "      ./analyze-binaries.sh -t <target(s)> -o <output-dir>"
    echo "      (from your RE-Toolkit source checkout; LAYER 0 was skipped)"
fi
echo ""

exit 0
