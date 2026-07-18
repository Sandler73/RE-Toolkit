#!/usr/bin/env python3
# =============================================================================
# Synopsis:
#     Standalone diagnostic for the v3.0.14 / v3.0.15 Stage-30 Ghidra failure.
# Description:
#     Captures every layer between the bash driver and Ghidra's java.io.IOException
#     "File not found" symptom, so we can identify where the failure actually
#     originates. Runs a 7-step probe in order, printing PASS/FAIL for each.
#     No RE-Toolkit dependencies; uses only Python stdlib and pyghidra.
# Notes:
#     Created by RE-Toolkit audit-19 v3.0.15 hotfix follow-up to gather
#     evidence for v3.0.16 root-cause fix. Operator: run from the same
#     environment that produced the Stage-30 failure (same venv, same user,
#     same cwd RE-Toolkit was invoked from).
# Execution Parameters:
#     Argument 1: path to binary that fails (e.g. /path/to/samples/Sample.Shared.dll)
#     Argument 2 (optional): path to Ghidra install. Defaults to GHIDRA_INSTALL_DIR or auto-detect.
# Examples:
#     /opt/retools/venv/bin/python ./ghidra-diagnostic.py \
#         /path/to/samples/Sample.Shared.dll
# Version:
#     1.1 - 2026-05-03 - audit-19 follow-up; auto-re-execs into /opt/retools/venv if pyghidra missing
#     1.2 - 2026-05-03 - audit-19 follow-up; fixes Step 7 cleanup; adds Step 8 in-process repro
#     1.3 - 2026-05-03 - audit-19 follow-up; adds Step 9 fresh-subprocess repro (mirrors RE-Toolkit helper)
# =============================================================================

import os
import sys
import stat
import shutil
import subprocess
import traceback
from pathlib import Path

# -----------------------------------------------------------------------------
# v1.1 (2026-05-03): if pyghidra isn't in the current interpreter, look for a
# RE-Toolkit venv and re-exec there. Avoids the common "ran with system python
# instead of the venv" trap.
# -----------------------------------------------------------------------------
def _ensure_venv():
    try:
        import pyghidra  # noqa: F401
        return  # current interpreter has it; we're good
    except ImportError:
        pass
    candidates = [
        "/opt/retools/venv/bin/python",
        "/opt/retools/venv/bin/python3",
        os.path.expanduser("~/.retools/venv/bin/python"),
    ]
    for cand in candidates:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            print(f"[diag] pyghidra not in current Python ({sys.executable}).")
            print(f"[diag] Re-executing under {cand} ...\n")
            os.execv(cand, [cand, __file__] + sys.argv[1:])
    # Fall through; diagnostic will still run and Step 3 will report missing.

_ensure_venv()

def section(n, title):
    print(f"\n{'=' * 70}")
    print(f"STEP {n}: {title}")
    print('=' * 70)

def ok(msg):    print(f"  [PASS] {msg}")
def fail(msg):  print(f"  [FAIL] {msg}")
def info(msg):  print(f"  [info] {msg}")

# -----------------------------------------------------------------------------
# Args
# -----------------------------------------------------------------------------
if len(sys.argv) < 2:
    print("usage: ghidra-diagnostic.py <binary-path> [<ghidra-install-dir>]")
    sys.exit(2)

binary_path = sys.argv[1]
ghidra_install = sys.argv[2] if len(sys.argv) >= 3 else os.environ.get("GHIDRA_INSTALL_DIR", "")
if not ghidra_install:
    # Try to auto-detect
    for candidate in sorted(Path("/opt").glob("ghidra_*_PUBLIC"), reverse=True):
        if candidate.is_dir():
            ghidra_install = str(candidate)
            break
if not ghidra_install:
    print("ERROR: cannot find Ghidra install. Set GHIDRA_INSTALL_DIR or pass arg 2.")
    sys.exit(2)

print("=" * 70)
print(" RE-Toolkit Ghidra Stage-30 diagnostic v1.3")
print("=" * 70)
print(f"  binary         = {binary_path}")
print(f"  ghidra_install = {ghidra_install}")
print(f"  python         = {sys.executable} ({sys.version.split()[0]})")
print(f"  cwd            = {os.getcwd()}")
print(f"  user           = {os.environ.get('USER', '?')}")

# -----------------------------------------------------------------------------
# Step 1: file system reality check on the binary
# -----------------------------------------------------------------------------
section(1, "Filesystem reality check on binary")
p = Path(binary_path)
issues = 0
try:
    if not p.exists():
        fail(f"path does not exist: {p}")
        issues += 1
    elif not p.is_file():
        fail(f"path exists but is not a regular file (is_dir={p.is_dir()}, is_symlink={p.is_symlink()})")
        issues += 1
    else:
        ok(f"file exists: {p}")
        st = p.stat()
        ok(f"size = {st.st_size} bytes")
        ok(f"mode = {oct(st.st_mode)} ({stat.filemode(st.st_mode)})")
        ok(f"uid:gid = {st.st_uid}:{st.st_gid}")
        if not os.access(p, os.R_OK):
            fail("file exists but is NOT readable by current user")
            issues += 1
        else:
            ok("file is readable by current user")
        if p.is_symlink():
            target = p.resolve()
            info(f"is symlink -> {target}")
            if not target.exists():
                fail(f"symlink target does NOT exist: {target}")
                issues += 1
        # First 4 bytes (PE: MZ; ELF: 7f 45 4c 46; .NET PE has MZ stub)
        with open(p, "rb") as f:
            magic = f.read(8)
        info(f"first 8 bytes (hex) = {magic.hex(' ')}")
except Exception as e:
    fail(f"unexpected exception during stat: {e!r}")
    issues += 1

if issues > 0:
    print(f"\n>>> Step 1 found {issues} issue(s); the file simply isn't accessible. <<<")
    print(">>> This is the root cause. Verify path and permissions. <<<")
    sys.exit(3)

# -----------------------------------------------------------------------------
# Step 2: Java version
# -----------------------------------------------------------------------------
section(2, "Java version")
try:
    r = subprocess.run(["java", "--version"], capture_output=True, text=True, timeout=10)
    if r.returncode == 0:
        ok(f"java --version output:\n{r.stdout.strip()}")
    else:
        fail(f"java --version exited {r.returncode}: {r.stderr.strip()}")
except FileNotFoundError:
    fail("java not on PATH")
except Exception as e:
    fail(f"java check failed: {e!r}")

# -----------------------------------------------------------------------------
# Step 3: pyghidra version
# -----------------------------------------------------------------------------
section(3, "pyghidra package version")
try:
    import pyghidra
    pyghidra_version = getattr(pyghidra, "__version__", "?")
    ok(f"pyghidra import OK")
    info(f"pyghidra.__version__ = {pyghidra_version}")
    info(f"pyghidra.__file__    = {pyghidra.__file__}")
    # JPype version
    try:
        import jpype
        info(f"jpype.__version__    = {jpype.__version__}")
    except Exception as e:
        info(f"jpype version unknown: {e!r}")
except ImportError as e:
    fail(f"pyghidra not importable: {e!r}")
    sys.exit(4)

# -----------------------------------------------------------------------------
# Step 4: pyghidra.start() raw JVM init
# -----------------------------------------------------------------------------
section(4, "pyghidra.start() (raw JVM init, no project, no script)")
os.environ["GHIDRA_INSTALL_DIR"] = ghidra_install
try:
    pyghidra.start()
    ok("pyghidra.start() succeeded; JVM is up and Ghidra is initialized")
except Exception as e:
    fail(f"pyghidra.start() raised: {e!r}")
    traceback.print_exc()
    sys.exit(5)

# -----------------------------------------------------------------------------
# Step 5: Java's view of the file (does Java's File.exists() see it?)
# -----------------------------------------------------------------------------
section(5, "Java-side file visibility")
try:
    from java.io import File as JFile
    jf = JFile(str(p.absolute()))
    info(f"java.io.File.getAbsolutePath() = {jf.getAbsolutePath()}")
    if jf.exists():
        ok("java.io.File.exists() = true")
    else:
        fail("java.io.File.exists() = FALSE -- Java cannot see the file")
        fail("This means the JVM has a different filesystem view than Python.")
        fail("Possible causes: container/sandbox isolation, SELinux, AppArmor, namespace.")
    if jf.canRead():
        ok("java.io.File.canRead() = true")
    else:
        fail("java.io.File.canRead() = FALSE")
    info(f"java.io.File.length() = {jf.length()}")
    info(f"java.io.File.toURI() = {jf.toURI().toString()}")
except Exception as e:
    fail(f"Java File check raised: {e!r}")
    traceback.print_exc()

# -----------------------------------------------------------------------------
# Step 6: Ghidra's FileSystemService view (FSRL probe)
# -----------------------------------------------------------------------------
section(6, "Ghidra FileSystemService (FSRL) view")
try:
    from ghidra.formats.gfilesystem import FileSystemService
    fs = FileSystemService.getInstance()
    fsrl = fs.getLocalFSRL(JFile(str(p.absolute())))
    info(f"FSRL = {fsrl}")
    info(f"FSRL.getPath() = {fsrl.getPath()}")
    if fs.isLocal(fsrl):
        ok("FileSystemService.isLocal(fsrl) = true")
    else:
        fail("FileSystemService.isLocal(fsrl) = FALSE")
    # Try to actually open the file via FSRL
    try:
        rfile = fs.getRefdFile(fsrl, None)
        ok(f"FileSystemService.getRefdFile(fsrl) succeeded -- gfile = {rfile.file}")
        rfile.close()
    except Exception as e2:
        fail(f"FileSystemService.getRefdFile(fsrl) raised: {e2!r}")
        info("This is the layer that produces the 'File not found: file://...' error.")
except Exception as e:
    fail(f"FileSystemService probe raised: {e!r}")
    traceback.print_exc()

# -----------------------------------------------------------------------------
# Step 7: Try the actual import via deprecated GhidraProject.importProgram
# -----------------------------------------------------------------------------
section(7, "GhidraProject.importProgram (deprecated path used by run_script)")
try:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        from ghidra.base.project import GhidraProject
        proj = GhidraProject.createProject(tmp, "diag_project", True)
        program = None
        try:
            program = proj.importProgram(JFile(str(p.absolute())))
            if program is None:
                fail("importProgram returned None")
            else:
                ok(f"importProgram succeeded -- program name = {program.getName()}")
                ok(f"  language = {program.getLanguage().getLanguageID()}")
                ok(f"  format   = {program.getExecutableFormat()}")
        finally:
            # v1.2 fix: GhidraProject's close() releases programs with the project
            # itself as consumer; do NOT call program.release() separately.
            try:
                proj.close()
            except Exception as e_close:
                # Cosmetic cleanup error; the import probe above is what matters.
                info(f"(ignored) project.close() complaint: {e_close!r}")
except Exception as e:
    fail(f"GhidraProject.importProgram raised: {e!r}")
    traceback.print_exc()

# -----------------------------------------------------------------------------
# Step 8: Reproduce pyghidra.run_script() with RE-Toolkit's exact project layout
# -----------------------------------------------------------------------------
section(8, "pyghidra.run_script() reproduction (the actual failure path)")
import tempfile

# Build a project_location that mirrors RE-Toolkit's structure: a directory
# whose path contains a multi-dot component matching the binary's filename.
# This is the layout that produces the original failure in Stage 30.
binary_basename = p.name  # e.g. "sample.exe" or "Sample.Shared.dll"
diag_root = tempfile.mkdtemp(prefix="ghidra_diag_step8_")
project_loc  = os.path.join(diag_root, "rca64test", binary_basename, "30-ghidra", "project")
project_name = f"auto-{binary_basename}"
os.makedirs(project_loc, exist_ok=True)

info(f"binary       = {p.absolute()}")
info(f"project_loc  = {project_loc}")
info(f"project_name = {project_name}")
info(f"nested_project_location = True (matches RE-Toolkit helper)")

# Write a minimal no-op postScript that just prints a sentinel.
# If run_script reaches the script phase, we'll see "MODULE TOP REACHED".
# If it fails at importProgram, we'll see the same error as Stage 30.
script_path = os.path.join(diag_root, "step8_noop.py")
with open(script_path, "w") as f:
    f.write(
        "# Minimal sentinel script for diagnostic step 8\n"
        "import sys\n"
        "print('MODULE TOP REACHED', file=sys.stderr)\n"
        "print('script_args =', list(getScriptArgs()), file=sys.stderr)\n"
    )
info(f"script_path  = {script_path}")

try:
    pyghidra.run_script(
        binary_path             = str(p.absolute()),
        script_path             = script_path,
        project_location        = project_loc,
        project_name            = project_name,
        script_args             = ["dump-path=/tmp/step8_dummy.txt"],
        verbose                 = False,
        analyze                 = True,
        nested_project_location = True,
    )
    ok("pyghidra.run_script() returned without exception")
    ok("--> If you saw 'MODULE TOP REACHED' above, the script ran")
    ok("--> If not, run_script returned silently without invoking the script")
except Exception as e:
    fail(f"pyghidra.run_script() raised: {e!r}")
    fail("--> THIS REPRODUCES the Stage-30 failure path.")
    info("Full traceback follows for analysis:")
    traceback.print_exc()

# Cleanup
try:
    shutil.rmtree(diag_root)
except Exception:
    pass

# -----------------------------------------------------------------------------
# Step 9: Fresh-subprocess reproducer that mimics RE-Toolkit's helper EXACTLY
# -----------------------------------------------------------------------------
# Step 8 succeeds, but it runs after Step 4 has already done pyghidra.start().
# Retoolkit's actual helper runs in a fresh Python process where run_script()
# is the first pyghidra call -- JVM is bootstrapped inside run_script. If
# pyghidra 3.0.2 has different behavior on cold-start, this will catch it.
section(9, "Fresh-subprocess reproducer (matches RE-Toolkit helper exactly)")

import tempfile
diag_root2 = tempfile.mkdtemp(prefix="ghidra_diag_step9_")
project_loc2  = os.path.join(diag_root2, "rca64test", p.name, "30-ghidra", "project")
project_name2 = f"auto-{p.name}"
os.makedirs(project_loc2, exist_ok=True)

helper_path = os.path.join(diag_root2, "step9-helper.py")
script_path2 = os.path.join(diag_root2, "step9_noop.py")
with open(script_path2, "w") as f:
    f.write(
        "import sys\n"
        "print('STEP9 MODULE TOP REACHED', file=sys.stderr)\n"
    )

# Write a helper that mirrors RE-Toolkit's `.pyghidra-headless.py` exactly:
# fresh import pyghidra, then run_script with no prior start().
helper_src = '''\
import os, sys, traceback

ghidra_install  = sys.argv[1]
binary_path     = sys.argv[2]
script_path     = sys.argv[3]
project_loc     = sys.argv[4]
project_name    = sys.argv[5]
script_args     = sys.argv[6:]

os.environ["GHIDRA_INSTALL_DIR"] = ghidra_install

print(f"[step9-helper] install_dir  = {ghidra_install}", file=sys.stderr)
print(f"[step9-helper] binary       = {binary_path}",    file=sys.stderr)
print(f"[step9-helper] script       = {script_path}",    file=sys.stderr)
print(f"[step9-helper] project_loc  = {project_loc}",    file=sys.stderr)
print(f"[step9-helper] project_name = {project_name}",   file=sys.stderr)
print(f"[step9-helper] script_args  = {script_args}",    file=sys.stderr)
print(f"[step9-helper] cwd before   = {os.getcwd()}",    file=sys.stderr)

try:
    import pyghidra
except ImportError as e:
    print(f"ERROR: pyghidra import failed: {e}", file=sys.stderr)
    sys.exit(3)

try:
    pyghidra.run_script(
        binary_path             = binary_path,
        script_path             = script_path,
        project_location        = project_loc,
        project_name            = project_name,
        script_args             = script_args,
        verbose                 = False,
        analyze                 = True,
        nested_project_location = True,
    )
    print("[step9-helper] run_script returned cleanly", file=sys.stderr)
    sys.exit(0)
except Exception as e:
    print(f"ERROR: pyghidra.run_script() raised: {e!r}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(4)
'''
with open(helper_path, "w") as f:
    f.write(helper_src)

info(f"helper       = {helper_path}")
info(f"binary       = {p.absolute()}")
info(f"project_loc  = {project_loc2}")
info(f"project_name = {project_name2}")
info("(launching FRESH subprocess so pyghidra.run_script is the first pyghidra call)")
info("")

# Mirror RE-Toolkit's env: set JAVA_TOOL_OPTIONS like 30-ghidra.sh does.
sub_env = os.environ.copy()
sub_env["JAVA_TOOL_OPTIONS"] = "-Xmx4G -XX:+UseG1GC -Dfile.encoding=UTF-8"
sub_env["GHIDRA_INSTALL_DIR"] = ghidra_install
sub_env.pop("RETOOLKIT_SENTINEL_DIR", None)  # not needed for noop script

import subprocess as _sub
try:
    r = _sub.run(
        [sys.executable, helper_path,
         ghidra_install,
         str(p.absolute()),
         script_path2,
         project_loc2,
         project_name2,
         "dump-path=/tmp/step9_dummy.txt"],
        capture_output=True, text=True, timeout=120, env=sub_env,
    )
    print(f"  subprocess exit code = {r.returncode}")
    print("  --- subprocess stderr ---")
    for line in (r.stderr or "").splitlines():
        print(f"  | {line}")
    print("  --- subprocess stdout ---")
    for line in (r.stdout or "").splitlines():
        print(f"  | {line}")
    print("  --- end ---")
    if r.returncode == 0:
        ok("Fresh-subprocess run_script succeeded")
        ok("--> Stage 30 SHOULD work too. The actual failure is environment-specific.")
        ok("--> Check 30-ghidra.sh logs for differences (env vars, cwd, args).")
    else:
        fail(f"Fresh-subprocess run_script failed with exit {r.returncode}")
        fail("--> THIS REPRODUCES Stage 30. Compare stderr above to ghidra.log.")
except _sub.TimeoutExpired:
    fail("Subprocess timed out after 120s")
except Exception as e:
    fail(f"Subprocess invocation raised: {e!r}")

try:
    shutil.rmtree(diag_root2)
except Exception:
    pass

# -----------------------------------------------------------------------------
print(f"\n{'=' * 70}")
print(" Diagnostic complete. Please share the FULL output above.")
print(f"{'=' * 70}")
