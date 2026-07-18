#!/usr/bin/env bash
# =============================================================================
# lib/common.sh
# =============================================================================
#
# Synopsis:
#     Shared primitives: path handling, logging, colors, and input sandboxing.
#
# Description:
#     Provides the foundation every other module and stage depends on. Three
#     concerns live here:
#
#     Path handling. Scripts receive paths from arguments and the environment
#     without shell tilde expansion, so paths are normalized explicitly before
#     use. Skipping that step once caused an output path to be passed through
#     literally to Ghidra, which created its project at an unexpected location.
#
#     Logging. A leveled logger writes to both the console and the per-run log
#     file, so no diagnostic is lost to a redirect. Color setup is a callable
#     wrapper rather than source-time work, which lets the driver decide when
#     and whether to enable color.
#
#     Input sandboxing. This is the safety-critical part of the module.
#     prepare_sandboxed_target() copies the operator's original file into
#     <outdir>/_input/ exactly once, and the caller then reassigns its target
#     to the returned path, so every subsequent stage operates on the copy. The
#     operator's original becomes untouchable by anything RE-Toolkit runs.
#     verify_input_untouched() asserts afterward that the original still has
#     the SHA-256 it had before analysis, which catches any tool that mutates
#     its input despite the sandbox. The two together are defense in depth: the
#     copy prevents damage, and the hash check proves prevention held.
#
#     Sourced by analyze-binaries.sh; not directly executable.
#
# Provides:
#     expand_tilde <path>              Expand a leading ~ to $HOME.
#     absolutize <path>                Resolve a path to absolute form.
#     sanitize_path_str <string>       Normalize a path string for safe use.
#     retoolkit_setup_colors           Initialize terminal color codes.
#     log_dbg, log_info, log_ok,       Leveled logging to console and file.
#     log_warn, log_err, log_step,
#     log_hdr
#     safe_grep_count <args>           Count matches without failing the run.
#     prepare_sandboxed_target <original> <outdir>
#                                      Copy the target into the run sandbox
#                                      and print the sandboxed path.
#     verify_input_untouched <original> <sha>
#                                      Confirm the original was not modified.
#
# Notes:
#     The trust boundaries this module enforces are described in the wiki
#     (Security-Model). Release history is recorded in CHANGELOG.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

expand_tilde() {
    local p="$1"
    [[ -z "$p" ]] && { echo ""; return; }
    echo "${p/#\~/$HOME}"
}

# absolutize: resolve a relative path to an absolute one.
# pyghidra.run_script() may change the process working directory internally,
# so relative paths like `-o ./re-out` end up resolving against pyghidra's
# CWD (usually the Ghidra project or install dir) when GhidraDump.py opens
# the dump file -- not the shell's CWD. The dump silently lands somewhere
# unexpected and the shell's "-f $dump" check fails. `readlink -m` resolves
# symlinks + normalizes, and works even when the target doesn't exist yet.
absolutize() {
    local p="$1"
    [[ -z "$p" ]] && { echo ""; return; }
    if [[ "$p" = /* ]]; then
        echo "$p"
    else
        readlink -m "$p" 2>/dev/null || echo "$(pwd)/${p#./}"
    fi
}

# Color codes -- populated by retoolkit_setup_colors based on TTY detection.
# Globals C_INFO, C_OK, C_WARN, C_ERR, C_DIM, C_BOLD, C_OFF are consumed by
# the log_* functions below.
C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_BOLD=""; C_OFF=""

# sanitize_path_str: v3.7.2 (audit-30 A4). Redact operator-identifying absolute
# paths from strings that get WRITTEN into artifacts (per-tool output-file
# "Command:" headers, the run ledger, and -- via a separate pass -- the report).
# It replaces the two known absolute roots with stable placeholders:
#   $OUTPUT_ROOT              -> <output>     (all analysis artifacts + inputs)
#   the RE-Toolkit install dir -> <retoolkit>   (GhidraDump.py, helper, lib paths)
# so a leaked line like
#   objdump ... /home/alice/Desktop/retoolkit/out/bin.exe/_input/bin.exe
# becomes
#   objdump ... <output>/bin.exe/_input/bin.exe
# with no home directory or username. Pure Bash parameter expansion (no
# subprocess), so it is cheap enough to call on every tool invocation and works
# identically in the parallel workers (which source this file). This only ever
# rewrites the DISPLAYED/RECORDED copy of a command -- never the command that is
# actually executed. Nothing downstream parses these strings for paths (verified
# audit-30), so the redaction is safe. The install dir is resolved from
# $SCRIPT_DIR when set, else from the exported $RETOOLKIT_LIB_DIR (its parent),
# so it is available in both the driver and the workers.
sanitize_path_str() {
    local s="$1"
    if [[ -n "${OUTPUT_ROOT:-}" ]]; then
        s="${s//${OUTPUT_ROOT}/<output>}"
    fi
    local _inst="${SCRIPT_DIR:-}"
    if [[ -z "$_inst" && -n "${RETOOLKIT_LIB_DIR:-}" ]]; then
        _inst="${RETOOLKIT_LIB_DIR%/lib}"
    fi
    if [[ -n "$_inst" ]]; then
        s="${s//${_inst}/<retoolkit>}"
    fi
    printf '%s' "$s"
}

# retoolkit_setup_colors: TTY-detect and populate ANSI color globals.
# Body identical to v2.3.0 lines 447-451 (inline if-block); wrapped in a
# function for v2.4.0's source-then-call architecture.
retoolkit_setup_colors() {
    if [[ -t 1 ]]; then
        C_INFO=$'\033[36m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'
        C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
    else
        C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_BOLD=""; C_DIM=""; C_OFF=""
    fi
}

# v3.0.5 (audit-9 B1+B2+B4): log_* functions now honor LOG_LEVEL via
# _LOG_LEVEL_NUM and optionally mirror to LOG_FILE.
# Numeric levels: 0=debug, 1=info, 2=warn, 3=error. A function emits
# only if its level is >= _LOG_LEVEL_NUM. log_ok/log_step/log_hdr emit
# at info-level.
# log_dbg is NEW; previously the driver had no debug-level emit at all.
#
# LOG_FILE (when set by --log-file) receives a plain-text mirror of every
# log_* call, in addition to the per-run log under OUTPUT_ROOT.
_log_to_file() {
    local level="$1"; shift
    [[ -z "${LOG_FILE:-}" ]] && return 0
    local msg="$*"
    msg=$(printf '%s' "$msg" | sed $'s/\033\\[[0-9;]*m//g')
    printf "%s [%-5s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$msg" \
        >> "$LOG_FILE" 2>/dev/null || true
}
log_dbg()  { [[ ${_LOG_LEVEL_NUM:-1} -le 0 ]] && { printf "%s[debug]%s %s\n" "$C_DIM" "$C_OFF" "$*"; _run_log "debug" "$*"; _log_to_file "debug" "$*"; }; return 0; }
log_info() { [[ ${_LOG_LEVEL_NUM:-1} -le 1 ]] && { printf "%s[info]%s %s\n" "$C_INFO" "$C_OFF" "$*"; _run_log "info" "$*"; _log_to_file "info" "$*"; }; return 0; }
log_ok()   { [[ ${_LOG_LEVEL_NUM:-1} -le 1 ]] && { printf "%s[ok]%s   %s\n" "$C_OK"   "$C_OFF" "$*"; _run_log "ok"   "$*"; _log_to_file "ok"   "$*"; }; return 0; }
log_warn() { [[ ${_LOG_LEVEL_NUM:-1} -le 2 ]] && { printf "%s[warn]%s %s\n" "$C_WARN" "$C_OFF" "$*"; _run_log "warn" "$*"; _log_to_file "warn" "$*"; }; return 0; }
log_err()  { [[ ${_LOG_LEVEL_NUM:-1} -le 3 ]] && { printf "%s[error]%s %s\n" "$C_ERR" "$C_OFF" "$*" >&2; _run_log "error" "$*"; _log_to_file "error" "$*"; }; return 0; }
log_step() { [[ ${_LOG_LEVEL_NUM:-1} -le 1 ]] && { printf "  %s→%s %s\n" "$C_DIM" "$C_OFF" "$*"; _run_log "step" "$*"; _log_to_file "step" "$*"; }; return 0; }
log_hdr()  { [[ ${_LOG_LEVEL_NUM:-1} -le 1 ]] && { printf "\n%s=== %s ===%s\n" "$C_BOLD" "$*" "$C_OFF"; _run_log "hdr" "=== $* ==="; _log_to_file "hdr" "=== $* ==="; }; return 0; }

# v2.2.0: central run log. OUTPUT_ROOT may not exist at the moment the first
# log_info fires (during arg parsing / env probe), so we silently skip if it
# isn't writable yet. The variable is set in 'Dispatch' once OUTPUT_ROOT
# exists, and the aggregate log gets every subsequent message.
# Body byte-identical to v2.3.0 lines 464-471.
_run_log() {
    [[ -z "${_RUN_LOG_PATH:-}" ]] && return 0
    local level="$1"; shift
    local msg="$*"
    # Strip ANSI escape sequences via sed (portable).
    msg=$(printf '%s' "$msg" | sed $'s/\033\\[[0-9;]*m//g')
    printf "%s [%-5s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$msg" >> "$_RUN_LOG_PATH" 2>/dev/null || true
}

# v3.0.5 (audit-9 A1): safe_grep_count - defensive counter.
# Replaces the `grep -c PATTERN FILE 2>/dev/null || echo 0` anti-pattern
# which is subtly broken: when the file is missing or grep fails, the
# capture becomes the two-line string "0\n0" because `grep -c` writes
# "0" to stdout AND returns non-zero, so the `|| echo 0` ALSO appends
# "0". Subsequent arithmetic comparisons then fail with:
#   line N: [[: 0 0: arithmetic syntax error in expression
# (operator-reported on stage 00-triage.sh line 233 in v3.0.4 install run).
# This helper guards the file existence, captures only the first line of
# grep's output, and strips non-digits so the result is always exactly
# one integer.
#
# Usage:  safe_grep_count <pattern> <file>
# Echoes: integer count (>= 0). Always exits 0.
safe_grep_count() {
    local pattern="$1"
    local file="$2"
    if [[ -s "$file" ]]; then
        local count
        count=$(grep -cE "$pattern" "$file" 2>/dev/null | head -1 | tr -dc '0-9')
        printf '%s' "${count:-0}"
    else
        printf '0'
    fi
    return 0
}

# =============================================================================
# v3.1.0 (audit-22 A0.1) -- Input sandboxing
# =============================================================================
# Synopsis:
#     Copy the operator's input file into the per-target output directory so
#     that NO analysis stage can mutate the operator's original file.
# Description:
#     The audit-20 TrID `-ae` bug renamed the operator's input file
#     (sample.exe -> sample.exe.exe), breaking every downstream
#     stage. The v3.0.16 hotfix removed that specific flag, but the
#     architectural vulnerability remained: any of the 71 external tools could
#     mutate the operator's input in place, and RE-Toolkit would cascade-fail.
#
#     prepare_sandboxed_target() copies the original to
#     <outdir>/_input/<basename> exactly once. The caller reassigns its
#     `$target` to the returned sandboxed path, so every subsequent stage
#     operates on the copy. The operator's original file becomes untouchable
#     by anything RE-Toolkit runs.
#
#     verify_input_untouched() asserts (post-run) that the operator's original
#     file has the same SHA-256 it had before analysis, catching any future
#     tool that mutates its input despite the sandbox (defense in depth).
# Notes:
#     This is the deferred architectural follow-up from audit-20 (v3.0.16).
#     It closes the L63 vulnerability class generically: even if a future
#     tool has another destructive flag like `-ae`, the operator's data is
#     safe because the tool operates on the sandboxed copy.
# Version:
#     1.0 - 2026-05-03 - audit-22 A0.1
# =============================================================================

# _sha256_of: echo the SHA-256 of a file, or empty string on failure.
# Uses sha256sum (coreutils, always present on Kali/Debian).
_sha256_of() {
    local f="$1"
    [[ -f "$f" ]] || { printf ''; return 1; }
    sha256sum "$f" 2>/dev/null | awk '{print $1}'
}

# prepare_sandboxed_target: copy the operator's input into the output dir.
#
# Usage:  sandboxed_path=$(prepare_sandboxed_target <original> <outdir>)
# Echoes: the sandboxed copy's absolute path on success (stdout).
# Return: 0 on success; non-zero on failure (caller MUST check and fail loud).
#
# Side effects:
#   - Creates <outdir>/_input/
#   - Copies <original> -> <outdir>/_input/<basename>
#   - Writes <outdir>/_input/.original-sha256 (for verify_input_untouched)
#   - Writes <outdir>/_input/.original-path   (the true source location)
#
# On ANY failure (source unreadable, copy failed, hash mismatch), returns
# non-zero and echoes nothing. The caller must treat that as fatal for the
# target and MUST NOT fall back to analyzing the original in place (that
# would reintroduce the exact vulnerability this function exists to close).
prepare_sandboxed_target() {
    local original="$1"
    local outdir="$2"

    # Input validation (input-validation skill): both args required, source
    # must exist and be a readable regular file.
    if [[ -z "$original" || -z "$outdir" ]]; then
        log_err "prepare_sandboxed_target: missing argument (original='$original' outdir='$outdir')"
        return 1
    fi
    if [[ ! -f "$original" ]]; then
        log_err "prepare_sandboxed_target: source not a regular file: $original"
        return 1
    fi
    if [[ ! -r "$original" ]]; then
        log_err "prepare_sandboxed_target: source not readable: $original"
        return 1
    fi

    local sandbox_dir="${outdir}/_input"
    local fname
    fname=$(basename "$original")
    local sandboxed="${sandbox_dir}/${fname}"

    # Create the sandbox directory. mkdir -p is idempotent.
    if ! mkdir -p "$sandbox_dir" 2>/dev/null; then
        log_err "prepare_sandboxed_target: cannot create sandbox dir: $sandbox_dir"
        return 1
    fi

    # Hash the original BEFORE copying, so we can (a) verify the copy is
    # faithful and (b) later assert the original was never mutated.
    local orig_hash
    orig_hash=$(_sha256_of "$original")
    if [[ -z "$orig_hash" ]]; then
        log_err "prepare_sandboxed_target: cannot hash source: $original"
        return 1
    fi

    # Copy. Use cp with --preserve to keep mtime/mode (helps tools that read
    # timestamps and keeps the copy faithful). -f to overwrite a stale copy
    # from a prior --overwrite run.
    if ! cp -f --preserve=mode,timestamps "$original" "$sandboxed" 2>/dev/null; then
        log_err "prepare_sandboxed_target: copy failed: $original -> $sandboxed"
        return 1
    fi

    # Verify the copy is byte-faithful (defense against partial copy / disk
    # full / silent truncation).
    local copy_hash
    copy_hash=$(_sha256_of "$sandboxed")
    if [[ "$copy_hash" != "$orig_hash" ]]; then
        log_err "prepare_sandboxed_target: copy hash mismatch (orig=$orig_hash copy=$copy_hash)"
        log_err "  sandboxed copy is NOT faithful; refusing to proceed"
        rm -f "$sandboxed" 2>/dev/null
        return 1
    fi

    # Record provenance for verify_input_untouched() and for report labeling.
    printf '%s' "$orig_hash" > "${sandbox_dir}/.original-sha256"
    printf '%s' "$original"  > "${sandbox_dir}/.original-path"

    # IMPORTANT: this function echoes the sandboxed path to stdout for command
    # substitution ($(prepare_sandboxed_target ...)). Any status logging MUST
    # go to stderr, or it pollutes the captured path. log_step writes to
    # stdout, so we redirect it to stderr here.
    log_step "input sandboxed: original preserved, analysis runs on copy" >&2

    # Echo the sandboxed path (the ONLY thing on stdout, so command
    # substitution captures exactly this).
    printf '%s' "$sandboxed"
    return 0
}

# verify_input_untouched: assert the operator's original file is unchanged.
#
# Usage:  verify_input_untouched <outdir>
# Return: 0 if original's SHA-256 matches the pre-analysis hash (or if there
#         is nothing to check); non-zero (and a loud log_err) on mismatch.
#
# This is defense in depth. With sandboxing in place, no stage should ever
# touch the original. If this assertion EVER fails, it means a tool reached
# outside the sandbox (e.g. followed an absolute path, or a stage was passed
# the original path by mistake) -- a bug we want to catch loudly, not ignore.
verify_input_untouched() {
    local outdir="$1"
    local sandbox_dir="${outdir}/_input"
    local hash_file="${sandbox_dir}/.original-sha256"
    local path_file="${sandbox_dir}/.original-path"

    # If sandboxing wasn't used for this target (e.g. a type that bypasses it),
    # there's nothing to verify. Silently succeed.
    [[ -f "$hash_file" && -f "$path_file" ]] || return 0

    local expected_hash original_path
    expected_hash=$(cat "$hash_file" 2>/dev/null)
    original_path=$(cat "$path_file" 2>/dev/null)

    # If the original no longer exists at its recorded path, that itself is a
    # red flag (something renamed/moved/deleted it).
    if [[ ! -f "$original_path" ]]; then
        log_err "INPUT INTEGRITY: original file missing after analysis: $original_path"
        log_err "  A stage may have moved/renamed/deleted the operator's input."
        return 1
    fi

    local current_hash
    current_hash=$(_sha256_of "$original_path")
    if [[ "$current_hash" != "$expected_hash" ]]; then
        log_err "INPUT INTEGRITY: original file was MODIFIED during analysis: $original_path"
        log_err "  expected SHA-256: $expected_hash"
        log_err "  current  SHA-256: $current_hash"
        log_err "  A stage reached outside the sandbox and mutated the operator's input."
        return 1
    fi

    return 0
}
# =============================================================================
# end v3.1.0 (audit-22 A0.1) input sandboxing
# =============================================================================
