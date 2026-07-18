"""
Synopsis:
    Ghidra PostScript -- comprehensive analysis dump of a single loaded
    program into a plain-text report.

Description:
    Runs after Ghidra's auto-analysis completes. Walks the current program
    and emits a single richly-structured text file containing every
    artifact a downstream analyst would want:

        Section 01 -- Program metadata (name, format, language, compiler,
                     image base, entry point, analysis options)
        Section 02 -- PE/ELF header (executable format, architecture,
                     subsystem, linker, timestamp, CLR bit)
        Section 03 -- Memory map (every memory block with permissions)
        Section 05 -- Imports (library, function, address, ordinal where
                     applicable) -- CRITICAL for interop analysis
        Section 06 -- Exports (name, address, ordinal)
        Section 07 -- Symbols (defined, external; excludes default labels
                     to keep size manageable unless VERBOSE_SYMBOLS=1)
        Section 08 -- Strings (ASCII + Unicode, with addresses and
                     cross-references)
        Section 09 -- Data types (structs, enums, typedefs, function
                     signatures)
        Section 10 -- Relocations
        Section 11 -- Function inventory (every function: address, name,
                     size in bytes, parameter count, calling convention)
        Section 12 -- Function details with DISASSEMBLY for every function
                     (all instructions, operands, references)
        Section 13 -- Function details with DECOMPILATION (C-like pseudocode
                     from the Decompiler API) for every function
        Section 14 -- Call graph (caller → callees edges for every function)
        Section 15 -- Cross-references summary (for addresses referenced by
                     >= 2 other locations)
        Section 17 -- Bookmarks, comments (pre, post, plate, EOL, repeatable)
        Section 18 -- Analysis tool trace (which Ghidra analyzers ran)
        Section 19 -- CLR / .NET metadata (memory blocks, entry points,
                     runtime references -- populated only for managed PEs)
        Section 20 -- Auxiliary tool output placeholder (capa / ilspycmd --
                     filled in by analyze-with-ghidra.sh if aux tools ran)

    The report is plain text with Markdown-style section headers so you
    can grep, page through it, or feed it directly to an LLM for
    higher-level analysis.

Notes:
    - Written for Ghidra >= 11.x. Uses only stable public APIs.
    - Compatible with both Jython 2.7 (stock Ghidra) and Ghidrathon's
      CPython 3. No Python-3-only syntax is used.
    - Honors overrides via (a) PostScript key=value arguments, (b) Java
      system properties `ghidra.dump.<n>`:
        verbose_symbols = 1  -- include default labels
        max_func_bytes  = N  -- skip decomp on bigger funcs (default 65536)
        decomp_timeout  = N  -- per-function decomp timeout in seconds (default 60)
        skip_decomp     = 1  -- skip Section 13 entirely (fast triage)
    - Writes a single UTF-8 file at the path supplied either as the bare
      first arg or via `dump-path=<path>` key=value arg.
    - If called without any output path, writes to
      <program-path>.ghidra-dump.txt alongside the binary, or
      ./ghidra-dump-<program-name>.txt if the path is unwritable.

Execution Parameters (Ghidra headless):
    -postScript GhidraDump.py <output-file-path>
    -postScript GhidraDump.py dump-path=<path> skip-decomp=<0|1>

Examples:
    # Linux/Kali (via analyze-with-ghidra.sh driver)
    analyzeHeadless /tmp/proj myproj \\
        -import /path/to/target.exe \\
        -scriptPath /path/to/scripts \\
        -postScript GhidraDump.py dump-path=/dumps/target.dump.txt \\
        -overwrite -deleteProject

    # Windows (legacy; prefer Linux for stability)
    analyzeHeadless.bat C:\\proj Project ^
        -import C:\\path\\to\\target.exe ^
        -postScript GhidraDump.py C:\\dumps\\target.ghidra-dump.txt ^
        -scriptPath C:\\path\\to\\scripts ^
        -overwrite -deleteProject

Version:
    3.7.3 - 2026-05-03

    Full release history is maintained in CHANGELOG.md at the repository
    root. It is deliberately not duplicated here: this docstring documents
    what the script does now, not how it got here.
"""

# ----------------------------------------------------------------------
# EARLY DIAGNOSTIC SENTINEL (v1.3.1)
# ----------------------------------------------------------------------
# This block runs BEFORE any Ghidra/Java import. If this script reaches
# the filesystem at all (i.e., pyghidra actually loaded and began to
# execute it), the sentinel file will exist regardless of whether any
# subsequent step fails. Driver uses this to distinguish:
#   - script never executed at all (no sentinel file)
#   - script started but failed at a known stage (partial trace in file)
#   - script completed successfully (all stages present)
# All sentinel writes are best-effort; failure never breaks the dump.
# ----------------------------------------------------------------------
import os as _os_early
import sys as _sys_early
import time as _time_early

_SENTINEL_PATH = None
_SENTINEL_DIR = _os_early.environ.get("RETOOLKIT_SENTINEL_DIR")
if _SENTINEL_DIR:
    try:
        if not _os_early.path.isdir(_SENTINEL_DIR):
            _os_early.makedirs(_SENTINEL_DIR)
        _SENTINEL_PATH = _os_early.path.join(
            _SENTINEL_DIR,
            "ghidra-dump-%d.trace" % _os_early.getpid())
    except Exception:
        _SENTINEL_PATH = None

def _trace(stage, extra=""):
    """Append one timestamped line to the sentinel file. Best-effort."""
    if _SENTINEL_PATH is None:
        return
    try:
        ts = _time_early.strftime("%Y-%m-%dT%H:%M:%S", _time_early.gmtime())
        line = "%sZ %s %s\n" % (ts, stage, extra)
        # Append mode; open fresh each time so even a crash mid-execution
        # flushes the previous lines.
        with open(_SENTINEL_PATH, "a") as _f:
            _f.write(line)
    except Exception:
        pass

_trace("module-top",
       "pid=%d python=%s cwd=%s" %
       (_os_early.getpid(), _sys_early.version.split()[0], _os_early.getcwd()))

# Record which Ghidra-injected globals are present in module scope.
# Under analyzeHeadless+Jython, these are bound before the module body runs.
# Under pyghidra.run_script(), behavior may differ.
_injected = []
for _name in ("currentProgram", "println", "monitor", "state",
              "getScriptArgs", "currentAddress"):
    if _name in globals():
        _injected.append(_name)
_trace("injected-globals", "present=%s" % ",".join(_injected) if _injected
                                          else "present=(none)")


# ----------------------------------------------------------------------
# Imports (Java side via Ghidra's scripting framework)
# ----------------------------------------------------------------------
# ghidra.app.script.GhidraScript -- implicit base; all symbols (currentProgram,
# println, monitor, state, getScriptArgs, etc.) are injected at runtime.

try:
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor

    from java.lang import System
    _trace("after-java-imports", "ok")
except Exception as _imp_err:
    _trace("after-java-imports", "FAILED: %s" % str(_imp_err))
    raise

import time
import io
import os

# ----------------------------------------------------------------------
# Configuration (read from Java system properties so PowerShell can pass
# overrides via -D flags)
# ----------------------------------------------------------------------
def _prop(name, default):
    v = System.getProperty(name)
    if v is None:
        return default
    return v


def _parse_script_args():
    """Parse PostScript args. Accepts both bare-positional (legacy) and
    KEY=VALUE form. Returns (dump_path_override, overrides_dict)."""
    try:
        args = getScriptArgs()
    except Exception:
        args = []

    dump_path = None
    overrides = {}
    if not args:
        return dump_path, overrides

    for a in args:
        if a is None:
            continue
        s = str(a)
        if "=" in s:
            k, v = s.split("=", 1)
            k = k.strip().lower().replace("-", "_")
            v = v.strip()
            if k in ("dump_path", "output", "out", "path"):
                dump_path = v
            else:
                overrides[k] = v
        else:
            # First bare arg is the dump path (legacy)
            if dump_path is None:
                dump_path = s
    return dump_path, overrides


_trace("before-getScriptArgs", "")
try:
    _ARG_DUMP_PATH, _ARG_OVERRIDES = _parse_script_args()
    _trace("after-getScriptArgs",
           "dump_path=%s overrides=%s" %
           (_ARG_DUMP_PATH, list(_ARG_OVERRIDES.keys())))
except Exception as _e:
    _trace("after-getScriptArgs", "FAILED: %s" % str(_e))
    _ARG_DUMP_PATH, _ARG_OVERRIDES = None, {}


def _cfg(name, default):
    """Resolve a config value, checking (1) PostScript args, (2) Java system
    property ghidra.dump.<name>, (3) hard-coded default."""
    if name in _ARG_OVERRIDES:
        return _ARG_OVERRIDES[name]
    return _prop("ghidra.dump." + name, default)


_trace("before-cfg", "")
try:
    VERBOSE_SYMBOLS = _cfg("verbose_symbols", "0") == "1"
    MAX_FUNC_BYTES  = int(_cfg("max_func_bytes", "65536"))   # skip > 64 KB funcs in decomp
    DECOMP_TIMEOUT  = int(_cfg("decomp_timeout", "60"))       # seconds
    SKIP_DECOMP     = _cfg("skip_decomp", "0") == "1"
    _trace("after-cfg", "ok")
except Exception as _e:
    _trace("after-cfg", "FAILED: %s" % str(_e))
    VERBOSE_SYMBOLS = False
    MAX_FUNC_BYTES = 65536
    DECOMP_TIMEOUT = 60
    SKIP_DECOMP = False

# ----------------------------------------------------------------------
# Output routing
# ----------------------------------------------------------------------
def resolve_output_path():
    """Resolve where to write the dump based on script args, fallbacks."""
    if _ARG_DUMP_PATH:
        return _ARG_DUMP_PATH

    # Fallback 1: next to the program file
    try:
        exec_path = currentProgram.getExecutablePath()
        if exec_path:
            return exec_path + ".ghidra-dump.txt"
    except Exception:
        pass

    # Fallback 2: current directory
    prog_name = currentProgram.getName()
    return "./ghidra-dump-" + prog_name + ".txt"


# ----------------------------------------------------------------------
# Utility: safe UTF-8 writer (pure Python -- no JPype bridge)
# ----------------------------------------------------------------------
class Writer(object):
    """Pure-Python UTF-8 file writer with helpers for section headers
    and separators.

    v1.3.0: switched from java.io.PrintWriter to Python's io.open().
    Previous versions used a full Java I/O chain (FileOutputStream →
    OutputStreamWriter → BufferedWriter → PrintWriter) and called
    `self._pw.print(s)` to emit text. That broke under PyGhidra/JPype
    because JPype renames Java's `print()` method to `print_()` (to
    avoid a historical Python 2 keyword conflict), and there is no
    `print` attribute on the exposed class wrapper. Using pure Python
    I/O avoids the bridge, works identically in Jython 2.7 and CPython
    3, and is measurably faster per write (no JVM round-trip).
    """
    def __init__(self, path):
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            try:
                os.makedirs(parent)
            except Exception:
                # Parent may exist but not be listable by this process;
                # open() below will raise the real error if creation
                # actually failed.
                pass
        self._path = path
        # io.open (not builtins.open) for Jython 2.7 compat: its encoding=
        # kwarg works in both Jython 2.7 and CPython 3. builtins.open in
        # Python 2 doesn't accept encoding=.
        # errors='replace' means malformed characters become U+FFFD
        # instead of raising, which is preferable for a diagnostic dump.
        self._fh = io.open(path, 'w', encoding='utf-8', errors='replace')
        self._bytes = 0

    def write(self, s):
        if s is None:
            return
        try:
            # Accept any str-like input. In Jython 2.7 this also handles
            # unicode since io.open opens a text stream.
            if not isinstance(s, str):
                try:
                    s = s.decode('utf-8', 'replace')  # bytes in Py2/Jython
                except Exception:
                    s = str(s)
            self._fh.write(s)
            self._bytes += len(s)
        except Exception as e:
            try:
                println("Writer.write failure: " + str(e))
            except Exception:
                pass

    def line(self, s=""):
        self.write(s)
        self.write("\n")

    def section(self, num, title):
        self.line("")
        self.line("")
        self.line("================================================================")
        self.line("  SECTION %02d - %s" % (num, title))
        self.line("================================================================")
        self.line("")

    def sub(self, title):
        self.line("")
        self.line("--- " + title + " ---")

    def close(self):
        try:
            self._fh.flush()
        except Exception:
            pass
        try:
            self._fh.close()
        except Exception:
            pass

    def path(self):
        return self._path

    def bytes_written(self):
        return self._bytes


# ----------------------------------------------------------------------
# Helper: compact address / value formatting
# ----------------------------------------------------------------------
def fmt_addr(addr):
    if addr is None:
        return "None"
    return addr.toString()

def fmt_int(v):
    if v is None: return "-"
    try:
        return "0x%x (%d)" % (v, v)
    except Exception:
        return str(v)

def safe_str(s):
    if s is None:
        return ""
    if isinstance(s, str):
        return s
    return str(s)


# ======================================================================
#  Section emitters
# ======================================================================

def emit_01_program_metadata(w, prog):
    w.section(1, "Program Metadata")
    w.line("Name            : " + safe_str(prog.getName()))
    w.line("Executable path : " + safe_str(prog.getExecutablePath()))
    w.line("Executable md5  : " + safe_str(prog.getExecutableMD5()))
    w.line("Executable sha256: " + safe_str(prog.getExecutableSHA256()))
    w.line("Executable format: " + safe_str(prog.getExecutableFormat()))
    lang = prog.getLanguage()
    w.line("Language        : " + safe_str(lang.getLanguageID()))
    w.line("Processor       : " + safe_str(lang.getProcessor()))
    w.line("Pointer size    : " + str(lang.getLanguageDescription().getSize()) + " bits")
    w.line("Endianness      : " + safe_str(lang.getLanguageDescription().getEndian()))
    w.line("Compiler spec   : " + safe_str(prog.getCompilerSpec().getCompilerSpecID()))
    w.line("Image base      : " + fmt_addr(prog.getImageBase()))
    w.line("Creation date   : " + safe_str(prog.getCreationDate()))

    w.sub("Analysis options")
    opts = prog.getOptions("Program Information")
    try:
        for name in opts.getOptionNames():
            w.line("  %s = %s" % (name, safe_str(opts.getValueAsString(name))))
    except Exception as e:
        w.line("  (could not enumerate: " + str(e) + ")")

    # Metadata property map
    w.sub("User metadata (Program Information / Metadata)")
    try:
        md = prog.getMetadata()
        if md is not None:
            for k in md.keySet():
                w.line("  %s = %s" % (k, safe_str(md.get(k))))
    except Exception as e:
        w.line("  (unavailable: " + str(e) + ")")


def emit_02_executable_header(w, prog):
    w.section(2, "Executable / Container Header")
    fmt = safe_str(prog.getExecutableFormat())
    w.line("Format: " + fmt)

    # PE-specific header info via ProgramPropertyList -- Ghidra PE loader
    # populates "Program Information/PE Property" among others.
    plist_names = prog.getOptionsNames()
    for plname in plist_names:
        if "PE" in plname or "ELF" in plname or "Mach-O" in plname or "Header" in plname:
            w.sub(plname)
            try:
                opts = prog.getOptions(plname)
                for n in opts.getOptionNames():
                    w.line("  %s = %s" % (n, safe_str(opts.getValueAsString(n))))
            except Exception as e:
                w.line("  (unavailable: " + str(e) + ")")


def emit_03_memory_map(w, prog):
    w.section(3, "Memory Map")
    w.line("%-28s %-14s %-14s %-10s %-9s %-7s %-7s %s" %
           ("Name", "Start", "End", "Size", "Perms", "Init", "Type", "Comment"))
    w.line("-" * 120)
    mem = prog.getMemory()
    total = 0
    for block in mem.getBlocks():
        perms = ("r" if block.isRead() else "-") + \
                ("w" if block.isWrite() else "-") + \
                ("x" if block.isExecute() else "-")
        size = block.getSize()
        total += size
        comment = safe_str(block.getComment()) or ""
        if len(comment) > 40: comment = comment[:37] + "..."
        w.line("%-28s %-14s %-14s %-10d %-9s %-7s %-7s %s" % (
            safe_str(block.getName())[:28],
            fmt_addr(block.getStart()),
            fmt_addr(block.getEnd()),
            size,
            perms,
            "yes" if block.isInitialized() else "no",
            safe_str(block.getType()),
            comment,
        ))
    w.line("-" * 120)
    w.line("Total mapped: %d bytes across %d blocks" % (total, len(list(mem.getBlocks()))))


def emit_05_imports(w, prog):
    w.section(5, "Imports (External Symbols)")
    sym_mgr = prog.getSymbolTable()
    count = 0
    w.line("%-40s %-40s %-14s" % ("Library", "Function", "Bound-to"))
    w.line("-" * 100)
    # Iterate external library namespaces
    externals = sym_mgr.getExternalSymbols()
    while externals.hasNext():
        es = externals.next()
        lib = es.getParentNamespace().getName()
        name = es.getName()
        # Attempt to resolve where in the thunk/IAT this actually lives
        # by inspecting references TO the external location.
        addrs = []
        refs = sym_mgr.getReferencesTo(es.getAddress())
        for ref in refs:
            addrs.append(fmt_addr(ref.getFromAddress()))
        bound = ",".join(addrs[:3])
        if len(addrs) > 3: bound += ",…"
        w.line("%-40s %-40s %-14s" % (lib[:40], name[:40], bound))
        count += 1
    w.line("-" * 100)
    w.line("Total imports: %d" % count)


def emit_06_exports(w, prog):
    w.section(6, "Exports")
    sym_mgr = prog.getSymbolTable()
    it = sym_mgr.getAllSymbols(True)
    count = 0
    w.line("%-40s %-14s %-6s" % ("Name", "Address", "Kind"))
    w.line("-" * 80)
    for sym in it:
        if not sym.isExternalEntryPoint():
            continue
        w.line("%-40s %-14s %-6s" % (
            safe_str(sym.getName())[:40],
            fmt_addr(sym.getAddress()),
            safe_str(sym.getSymbolType()),
        ))
        count += 1
    w.line("-" * 80)
    w.line("Total exports / entry points: %d" % count)


def emit_07_symbols(w, prog):
    w.section(7, "Symbol Table (defined + external, minus default labels)")
    sym_mgr = prog.getSymbolTable()
    it = sym_mgr.getAllSymbols(True)
    count = 0
    w.line("%-50s %-14s %-10s %-10s %s" % ("Name", "Address", "Type", "Source", "Namespace"))
    w.line("-" * 120)
    for sym in it:
        if not VERBOSE_SYMBOLS and sym.getSource() == SourceType.DEFAULT:
            continue
        w.line("%-50s %-14s %-10s %-10s %s" % (
            safe_str(sym.getName())[:50],
            fmt_addr(sym.getAddress()),
            safe_str(sym.getSymbolType()),
            safe_str(sym.getSource()),
            safe_str(sym.getParentNamespace().getName(True)),
        ))
        count += 1
    w.line("-" * 120)
    w.line("Total non-default symbols: %d" % count)


def emit_08_strings(w, prog):
    w.section(8, "String Table (ASCII + Unicode)")
    listing = prog.getListing()
    data_it = listing.getDefinedData(True)
    count = 0
    w.line("%-14s %-6s %-6s  %s" % ("Address", "Len", "Type", "Value (escaped)"))
    w.line("-" * 110)
    for data in data_it:
        dt = data.getDataType()
        dt_name = dt.getName()
        if dt_name.lower().find("string") < 0 and dt_name.lower().find("unicode") < 0 \
           and dt_name.lower().find("char") < 0:
            continue
        val = data.getDefaultValueRepresentation()
        if val is None:
            continue
        # Clip very long strings to 200 chars for readability
        if len(val) > 200:
            val = val[:197] + "..."
        # Escape tabs / newlines so grep/less behave
        val_esc = val.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")
        w.line("%-14s %-6d %-6s  %s" % (
            fmt_addr(data.getAddress()),
            data.getLength(),
            dt_name[:6],
            val_esc,
        ))
        count += 1
    w.line("-" * 110)
    w.line("Total string-like data items: %d" % count)


def emit_09_data_types(w, prog):
    w.section(9, "Data Type Manager (structs, enums, typedefs, function sigs)")
    dtm = prog.getDataTypeManager()
    w.line("%-50s %-16s %s" % ("Name", "Category", "Kind"))
    w.line("-" * 100)
    count = 0
    it = dtm.getAllDataTypes()
    while it.hasNext():
        dt = it.next()
        kind = dt.getClass().getSimpleName()
        w.line("%-50s %-16s %s" % (
            safe_str(dt.getName())[:50],
            safe_str(dt.getCategoryPath().getPath())[:16],
            kind,
        ))
        count += 1
    w.line("-" * 100)
    w.line("Total data types: %d" % count)


def emit_10_relocations(w, prog):
    w.section(10, "Relocations")
    reloc_tbl = prog.getRelocationTable()
    it = reloc_tbl.getRelocations()
    count = 0
    w.line("%-14s %-10s %-20s %s" % ("Address", "Type", "Symbol", "Values"))
    w.line("-" * 100)
    while it.hasNext():
        r = it.next()
        sym = r.getSymbolName() if hasattr(r, 'getSymbolName') else ''
        vals = r.getValues() if hasattr(r, 'getValues') else None
        w.line("%-14s %-10d %-20s %s" % (
            fmt_addr(r.getAddress()),
            r.getType(),
            safe_str(sym)[:20],
            str(list(vals)) if vals else "",
        ))
        count += 1
    w.line("-" * 100)
    w.line("Total relocations: %d" % count)


def emit_11_function_inventory(w, prog):
    w.section(11, "Function Inventory")
    fm = prog.getFunctionManager()
    funcs = list(fm.getFunctions(True))
    w.line("%-40s %-14s %-10s %-8s %-10s %s" % (
        "Name", "Entry", "Size", "Params", "Call-Conv", "Namespace"))
    w.line("-" * 120)
    for f in funcs:
        try:
            sz = f.getBody().getNumAddresses()
        except Exception:
            sz = -1
        w.line("%-40s %-14s %-10d %-8d %-10s %s" % (
            safe_str(f.getName())[:40],
            fmt_addr(f.getEntryPoint()),
            sz,
            f.getParameterCount(),
            safe_str(f.getCallingConventionName())[:10],
            safe_str(f.getParentNamespace().getName(True)),
        ))
    w.line("-" * 120)
    w.line("Total functions: %d" % len(funcs))
    return funcs


def emit_12_disassembly(w, prog, funcs):
    w.section(12, "Function Disassembly")
    listing = prog.getListing()
    for f in funcs:
        if monitor.isCancelled():
            w.line("[cancelled]")
            break
        w.line("")
        w.line("### " + f.getName() + "  @ " + fmt_addr(f.getEntryPoint()))
        w.line("    Signature: " + safe_str(f.getPrototypeString(True, True)))
        w.line("    Body: " + fmt_addr(f.getBody().getMinAddress()) +
               " -- " + fmt_addr(f.getBody().getMaxAddress()) +
               "  (" + str(f.getBody().getNumAddresses()) + " bytes)")
        body = f.getBody()
        insn_iter = listing.getInstructions(body, True)
        count = 0
        for ins in insn_iter:
            if monitor.isCancelled(): break
            op = ins.toString()
            comment = listing.getComment(CodeUnit.EOL_COMMENT, ins.getAddress())
            if comment:
                w.line("    %-14s  %-40s  ; %s" % (fmt_addr(ins.getAddress()), op, comment))
            else:
                w.line("    %-14s  %s" % (fmt_addr(ins.getAddress()), op))
            count += 1
        w.line("    --- end function (%d instructions) ---" % count)


def emit_13_decompilation(w, prog, funcs):
    w.section(13, "Function Decompilation (C pseudocode from DecompInterface)")
    if SKIP_DECOMP:
        w.line("[skipped: ghidra.dump.skip_decomp=1]")
        return

    decomp = DecompInterface()
    opts = DecompileOptions()
    # Try to apply program-default options; fall back silently if unavailable
    try:
        from ghidra.framework.options import ToolOptions
        # Use defaults; the headless context won't carry a Tool.
    except Exception:
        pass
    decomp.setOptions(opts)
    decomp.openProgram(prog)

    total = len(funcs)
    done = 0
    skipped_big = 0
    skipped_err = 0
    for f in funcs:
        done += 1
        if monitor.isCancelled():
            w.line("[cancelled at function %d/%d]" % (done, total))
            break

        try:
            body_bytes = f.getBody().getNumAddresses()
        except Exception:
            body_bytes = 0

        w.line("")
        w.line("### " + f.getName() + "  @ " + fmt_addr(f.getEntryPoint()) +
               "  (" + str(body_bytes) + " bytes)")

        if body_bytes > MAX_FUNC_BYTES:
            w.line("    // skipped: body %d bytes exceeds MAX_FUNC_BYTES=%d" % (body_bytes, MAX_FUNC_BYTES))
            skipped_big += 1
            continue

        try:
            tm = ConsoleTaskMonitor()
            res = decomp.decompileFunction(f, DECOMP_TIMEOUT, tm)
            if res is None or not res.decompileCompleted():
                err = res.getErrorMessage() if res is not None else "no result"
                w.line("    // decompile failed: " + safe_str(err))
                skipped_err += 1
                continue
            c_code = res.getDecompiledFunction().getC()
            for line in c_code.split("\n"):
                w.line("    " + line)
        except Exception as e:
            w.line("    // decompile exception: " + str(e))
            skipped_err += 1

        if done % 50 == 0:
            monitor.setMessage("Decompiled %d / %d functions" % (done, total))

    decomp.dispose()
    w.line("")
    w.line("--- Decompilation complete: %d/%d, skipped %d (too big), %d (errors) ---" %
           (done - skipped_big - skipped_err, total, skipped_big, skipped_err))


def emit_14_call_graph(w, prog, funcs):
    w.section(14, "Call Graph (caller → callees)")
    for f in funcs:
        calls = f.getCalledFunctions(monitor)
        if not calls:
            continue
        w.line(f.getName() + " (" + fmt_addr(f.getEntryPoint()) + ") calls:")
        for callee in calls:
            w.line("    -> " + callee.getName() + " (" + fmt_addr(callee.getEntryPoint()) + ")")


def emit_15_xrefs(w, prog):
    w.section(15, "Cross-References (>=2 sources, top 500)")
    ref_mgr = prog.getReferenceManager()
    seen = {}
    iter_refs = ref_mgr.getReferenceIterator(prog.getImageBase())
    count = 0
    buckets = {}
    while iter_refs.hasNext():
        r = iter_refs.next()
        to = r.getToAddress()
        if to is None: continue
        key = fmt_addr(to)
        if key not in buckets:
            buckets[key] = []
        buckets[key].append(fmt_addr(r.getFromAddress()) + ":" + safe_str(r.getReferenceType()))
        count += 1
        if count > 200000:  # safety cap
            break

    # Sort descending by reference count, take top 500
    items = sorted(buckets.items(), key=lambda kv: len(kv[1]), reverse=True)[:500]
    w.line("%-14s %-6s  %s" % ("Target", "Count", "Sample-Sources"))
    w.line("-" * 120)
    for addr, sources in items:
        if len(sources) < 2:
            continue
        sample = ", ".join(sources[:5])
        if len(sources) > 5: sample += ", …"
        w.line("%-14s %-6d  %s" % (addr, len(sources), sample))


def emit_17_comments(w, prog):
    w.section(17, "Bookmarks and User Comments")
    bm_mgr = prog.getBookmarkManager()
    it = bm_mgr.getBookmarksIterator()
    w.sub("Bookmarks")
    bm_count = 0
    while it.hasNext():
        b = it.next()
        w.line("  [%s] %-10s %s : %s" % (
            fmt_addr(b.getAddress()),
            safe_str(b.getTypeString()),
            safe_str(b.getCategory()),
            safe_str(b.getComment()),
        ))
        bm_count += 1
    w.line("  (total: %d)" % bm_count)

    w.sub("Plate / Pre / Post / EOL / Repeatable comments")
    listing = prog.getListing()
    com_count = 0
    for addr in prog.getMemory().getAddressRanges():
        start = addr.getMinAddress()
        end = addr.getMaxAddress()
        it_cu = listing.getCodeUnits(start, True)
        while it_cu.hasNext():
            cu = it_cu.next()
            if cu.getAddress().compareTo(end) > 0:
                break
            for ct, label in [(CodeUnit.PLATE_COMMENT, "PLATE"),
                              (CodeUnit.PRE_COMMENT, "PRE"),
                              (CodeUnit.POST_COMMENT, "POST"),
                              (CodeUnit.EOL_COMMENT, "EOL"),
                              (CodeUnit.REPEATABLE_COMMENT, "REP")]:
                c = cu.getComment(ct)
                if c:
                    w.line("  [%s] %s : %s" % (fmt_addr(cu.getAddress()), label, c.replace("\n", " / ")))
                    com_count += 1
    w.line("  (total: %d)" % com_count)


def emit_18_analysis_trace(w, prog):
    w.section(18, "Analysis Trace (applied analyzers)")
    opts = prog.getOptions("Analyzers")
    try:
        for name in opts.getOptionNames():
            w.line("  %-60s = %s" % (name, safe_str(opts.getValueAsString(name))))
    except Exception as e:
        w.line("  (unavailable: " + str(e) + ")")


def emit_19_clr_metadata(w, prog):
    """If this is a .NET PE, dump what Ghidra can see of the CLR metadata.
    The Ghidra PE loader parses the CLR header into program properties and
    memory blocks (.text$mn, #Strings, #US, #GUID, #Blob, #~ tables).
    For deeper .NET analysis, pair this with ilspycmd/ildasm output."""
    w.section(19, "CLR / .NET Metadata (if PE contains managed code)")
    fmt = prog.getExecutableFormat()
    if "Portable Executable" not in fmt:
        w.line("  (not a PE file -- section not applicable)")
        return

    # Heuristic: a .NET PE has either the "CLR Runtime Header" memory label,
    # or a ".net" or "COR20" string in early bytes
    mem = prog.getMemory()
    has_clr = False
    clr_blocks = []
    for block in mem.getBlocks():
        name = block.getName()
        if name in (".net", "CLR Runtime Header") or "COR20" in name or \
           name in ("#Strings", "#US", "#GUID", "#Blob", "#~"):
            has_clr = True
            clr_blocks.append(block)

    if not has_clr:
        # Fallback: look at symbols for CLR_*  markers
        sym_table = prog.getSymbolTable()
        try:
            for s in sym_table.getDefinedSymbols():
                nm = s.getName()
                if nm and ("CLR" in nm or "_CorDllMain" in nm or "_CorExeMain" in nm):
                    has_clr = True
                    break
        except Exception:
            pass

    if not has_clr:
        w.line("  (no CLR metadata detected -- appears to be native PE)")
        return

    w.line("  CLR metadata detected.")
    w.line("")

    # List CLR memory blocks with sizes
    w.sub("CLR Memory Blocks")
    for b in clr_blocks:
        w.line("  %-30s  start=%s  size=%d  perms=%s%s%s" % (
            b.getName(),
            fmt_addr(b.getStart()),
            b.getSize(),
            "R" if b.isRead() else "-",
            "W" if b.isWrite() else "-",
            "X" if b.isExecute() else "-",
        ))

    # Find CorDllMain / CorExeMain entry points in imports
    w.sub("CLR Entry Points")
    found_entry = False
    try:
        sym_table = prog.getSymbolTable()
        for s in sym_table.getExternalSymbols():
            nm = s.getName()
            if nm and nm in ("_CorDllMain", "_CorExeMain", "CorDllMain", "CorExeMain"):
                w.line("  External: %s (from %s)" %
                       (nm, safe_str(s.getParentNamespace().getName())))
                found_entry = True
    except Exception:
        pass
    if not found_entry:
        w.line("  (none found via symbol table)")

    # Look for mscoree.dll import which confirms managed runtime binding
    w.sub("Runtime References")
    try:
        ext_mgr = prog.getExternalManager()
        for lib in ext_mgr.getExternalLibraryNames():
            if lib and "mscor" in lib.lower():
                w.line("  External library: %s" % lib)
    except Exception:
        pass

    w.line("")
    w.line("  Note: Ghidra's .NET support is limited. For full IL/C# analysis,")
    w.line("  run ilspycmd against the binary separately. The analyze-with-ghidra.sh")
    w.line("  driver does this automatically for .NET binaries when ilspycmd is installed.")


def emit_20_aux_tool_output(w, prog):
    """Section 20 is a placeholder for the analyze-driver to optionally
    append capa / ilspycmd output. The driver writes a marker file
    <dump>.aux-output.txt and appends its contents here if present."""
    w.section(20, "Auxiliary Tool Output (capa / ilspycmd)")
    # At Ghidra-script time this is always empty; the driver script concatenates
    # after. We emit the header so the offset is consistent.
    w.line("  (populated post-analysis by analyze-with-ghidra.sh if aux tools ran)")
    w.line("  See sibling files in the output directory:")
    w.line("    - <program>.capa.json       (capa capability detection, native PEs)")
    w.line("    - ilspy/*.cs                (ilspycmd C# decompilation, .NET PEs)")


# ======================================================================
#  Main
# ======================================================================
def _write_started_sentinel(out_path):
    """Write a `.started` sentinel alongside the eventual dump path so the
    driver can distinguish "script never executed" from "script ran but
    exploded mid-dump" even when .script.log is empty. Best-effort: if
    the directory isn't writable, we continue silently -- the sentinel
    is a diagnostic aid, not a correctness requirement.

    v1.3.0: pure-Python implementation (was java.io.FileOutputStream
    via JPype). See Writer class docstring for rationale."""
    try:
        marker = out_path + ".started"
        parent = os.path.dirname(marker)
        if parent and not os.path.isdir(parent):
            try:
                os.makedirs(parent)
            except Exception:
                pass
        with io.open(marker, 'w', encoding='utf-8') as fh:
            fh.write("GhidraDump.py v1.3.2 started at "
                     + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                     + "\n")
    except Exception as e:
        # Swallow; log via println for visibility in .script.log.
        try:
            println("GhidraDump: sentinel write failed: " + str(e))
        except Exception:
            pass


def main():
    # v1.3.1: diagnostic sentinel first, BEFORE any Ghidra global access,
    # so we know at minimum the function was reached.
    _trace("main-entered", "")

    # v1.3.0: emit a visible marker to the script log. If println exists
    # (it's a Ghidra-injected global), this lands in .script.log.
    try:
        println("GhidraDump.py v1.3.2: main() entered, parsing args...")
        _trace("println-works", "")
    except Exception as _pl_err:
        _trace("println-FAILED", str(_pl_err))

    try:
        out_path = resolve_output_path()
        _trace("out-path-resolved", out_path)
    except Exception as _op_err:
        _trace("resolve_output_path-FAILED", str(_op_err))
        raise

    try:
        println("GhidraDump: writing to " + out_path)
    except Exception:
        pass

    # Second marker: a filesystem sentinel. Independent of Ghidra's own
    # logging, so even a corrupt scriptlog can't hide the fact that we got
    # this far.
    _write_started_sentinel(out_path)

    try:
        w = Writer(out_path)
        _trace("writer-created", out_path)
    except Exception as _w_err:
        _trace("writer-create-FAILED", "path=%s err=%s" % (out_path, str(_w_err)))
        raise
    start = time.time()

    try:
        w.line("# Ghidra Comprehensive Analysis Dump")
        w.line("# Generated: " + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        w.line("# Program : " + currentProgram.getName())
        w.line("# Script  : GhidraDump.py v1.3.2")
        w.line("# Flags   : VERBOSE_SYMBOLS=%s  MAX_FUNC_BYTES=%d  DECOMP_TIMEOUT=%d  SKIP_DECOMP=%s" %
               (VERBOSE_SYMBOLS, MAX_FUNC_BYTES, DECOMP_TIMEOUT, SKIP_DECOMP))
        w.line("")
        w.line("Table of contents:")
        for i, t in [
            (1, "Program Metadata"),
            (2, "Executable Header"),
            (3, "Memory Map"),
            (5, "Imports"),
            (6, "Exports"),
            (7, "Symbols"),
            (8, "Strings"),
            (9, "Data Types"),
            (10, "Relocations"),
            (11, "Function Inventory"),
            (12, "Function Disassembly"),
            (13, "Function Decompilation"),
            (14, "Call Graph"),
            (15, "Cross-References"),
            (17, "Comments & Bookmarks"),
            (18, "Analysis Trace"),
            (19, "CLR / .NET Metadata"),
            (20, "Auxiliary Tool Output"),
        ]:
            w.line("  %02d. %s" % (i, t))

        # Each section is independently try-wrapped so a failure in one
        # section cannot block emission of the others. The funcs list
        # survives across section 11 -> 14.
        funcs = []

        try:
            emit_01_program_metadata(w, currentProgram)
        except Exception as e:
            w.line("[section 01 error: " + str(e) + "]")

        try:
            emit_02_executable_header(w, currentProgram)
        except Exception as e:
            w.line("[section 02 error: " + str(e) + "]")

        try:
            emit_03_memory_map(w, currentProgram)
        except Exception as e:
            w.line("[section 03 error: " + str(e) + "]")

        try:
            emit_05_imports(w, currentProgram)
        except Exception as e:
            w.line("[section 05 error: " + str(e) + "]")

        try:
            emit_06_exports(w, currentProgram)
        except Exception as e:
            w.line("[section 06 error: " + str(e) + "]")

        try:
            emit_07_symbols(w, currentProgram)
        except Exception as e:
            w.line("[section 07 error: " + str(e) + "]")

        try:
            emit_08_strings(w, currentProgram)
        except Exception as e:
            w.line("[section 08 error: " + str(e) + "]")

        try:
            emit_09_data_types(w, currentProgram)
        except Exception as e:
            w.line("[section 09 error: " + str(e) + "]")

        try:
            emit_10_relocations(w, currentProgram)
        except Exception as e:
            w.line("[section 10 error: " + str(e) + "]")

        try:
            funcs = emit_11_function_inventory(w, currentProgram)
            if funcs is None:
                funcs = []
        except Exception as e:
            w.line("[section 11 error: " + str(e) + "]")
            funcs = []

        try:
            emit_12_disassembly(w, currentProgram, funcs)
        except Exception as e:
            w.line("[section 12 error: " + str(e) + "]")

        try:
            emit_13_decompilation(w, currentProgram, funcs)
        except Exception as e:
            w.line("[section 13 error: " + str(e) + "]")

        try:
            emit_14_call_graph(w, currentProgram, funcs)
        except Exception as e:
            w.line("[section 14 error: " + str(e) + "]")

        try:
            emit_15_xrefs(w, currentProgram)
        except Exception as e:
            w.line("[section 15 error: " + str(e) + "]")

        try:
            emit_17_comments(w, currentProgram)
        except Exception as e:
            w.line("[section 17 error: " + str(e) + "]")

        try:
            emit_18_analysis_trace(w, currentProgram)
        except Exception as e:
            w.line("[section 18 error: " + str(e) + "]")

        try:
            emit_19_clr_metadata(w, currentProgram)
        except Exception as e:
            w.line("[section 19 error: " + str(e) + "]")

        try:
            emit_20_aux_tool_output(w, currentProgram)
        except Exception as e:
            w.line("[section 20 error: " + str(e) + "]")

        elapsed = time.time() - start
        w.line("")
        w.line("")
        w.line("# End of dump. Elapsed: %.1fs, bytes written: %d, output: %s" %
               (elapsed, w.bytes_written(), w.path()))

    finally:
        # ALWAYS close the writer, even if an unexpected exception escapes
        # the per-section try blocks. Without this, a surprise failure in
        # framework code (e.g. a Ghidra API change) could leak the output
        # file handle and leave a partially-written, locked dump.
        try:
            w.close()
            _trace("writer-closed", "bytes=%d" % w.bytes_written())
        except Exception as close_err:
            _trace("writer-close-FAILED", str(close_err))
            try:
                println("GhidraDump: warning - writer close raised: " + str(close_err))
            except Exception:
                pass

    try:
        println("GhidraDump: complete in %.1fs, wrote %d bytes to %s" %
                (time.time() - start, w.bytes_written(), w.path()))
    except Exception:
        pass
    _trace("script-complete", "bytes=%d path=%s" % (w.bytes_written(), w.path()))


try:
    main()
    _trace("main-returned", "ok")
except Exception as _top_err:
    import traceback as _tb
    _trace("main-raised", "%s\n%s" % (str(_top_err), _tb.format_exc()))
    raise
