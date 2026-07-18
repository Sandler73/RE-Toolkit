#!/usr/bin/env python3
# =============================================================================
# tools/check-headers.py
# =============================================================================
#
# Synopsis:
#     Verify that every code file carries a complete and correctly ordered
#     header block.
#
# Description:
#     RE-Toolkit requires each code file to document itself in a header block:
#     shell files use a leading comment block, Python files use a module
#     docstring. This check enforces that the required sections are present so
#     that documentation quality does not depend on review discipline alone.
#
#     Requirements differ by file class:
#
#         Stage files (stages/static/*.sh)
#             Synopsis, Description, Execution Parameters, Provides, Notes,
#             Version. Each must also define at least one stage function and
#             must not carry a stale "Part of RE-Toolkit vX.Y.Z" marker.
#
#         Library modules (lib/*.sh)
#             Synopsis, Description, Provides, Version.
#
#         Entry points and tools (*.sh, tools/*, *.py at any depth)
#             Synopsis, Description, Version.
#
#     The check also rejects per-release notes in a Version section. Version
#     carries a version and a date; release history belongs in CHANGELOG.md.
#
# Execution Parameters:
#     [root]     Optional path to scan. Defaults to the repository root.
#     --report   Emit a Markdown coverage table instead of pass/fail output.
#                Intended for a CI job summary.
#
# Examples:
#     python3 tools/check-headers.py
#     python3 tools/check-headers.py --report
#
# Exit Codes:
#     0    Every file satisfies its header requirements.
#     1    One or more files are non-compliant.
#
# Notes:
#     The required header format is documented in CONTRIBUTING.md.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================
"""Verify header-block completeness across the RE-Toolkit source tree."""

from __future__ import annotations

import re
import sys
from pathlib import Path

STAGE_SECTIONS = ["Synopsis", "Description", "Execution Parameters", "Provides",
                  "Notes", "Version"]
LIB_SECTIONS = ["Synopsis", "Description", "Provides", "Version"]
BASE_SECTIONS = ["Synopsis", "Description", "Version"]

# Release-note phrasing that must not appear inside a header Version section.
VERSION_NOISE = re.compile(
    r"^\s*[#]?\s*(-\s*)?(FIX|NEW|ADD|CHANGE|BREAKING)[: ]|"
    r"^\s*[#]?\s*\d+\.\d+\.\d+\s*[-]{1,2}\s*\d{4}-\d{2}-\d{2}",
    re.IGNORECASE,
)


def header_text(path: Path) -> str:
    """Return the file's header block: comment block or module docstring."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""

    if path.suffix == ".py":
        # A Python file may document itself in a leading comment block, in the
        # module docstring, or in both. Consider all of it.
        comment_lines = []
        for i, line in enumerate(text.splitlines()):
            if i == 0 and line.startswith("#!"):
                continue
            if line.startswith("#") or not line.strip():
                comment_lines.append(line)
            else:
                break
        docstring = ""
        m = re.search(r'^\s*(?:#[^\n]*\n|\s*\n)*\s*"""(.*?)"""', text, re.S)
        if m:
            docstring = m.group(1)
        return "\n".join(comment_lines) + "\n" + docstring

    lines = []
    for i, line in enumerate(text.splitlines()):
        if i == 0 and line.startswith("#!"):
            continue
        if line.startswith("#") or not line.strip():
            lines.append(line)
        else:
            break
    return "\n".join(lines)


def required_sections(rel: Path) -> list[str]:
    parts = rel.parts
    if len(parts) >= 2 and parts[0] == "stages" and rel.suffix == ".sh":
        return STAGE_SECTIONS
    if parts[0] == "lib" and rel.suffix == ".sh":
        return LIB_SECTIONS
    return BASE_SECTIONS


def check_file(root: Path, rel: Path) -> list[str]:
    """Return a list of problems for one file. Empty means compliant."""
    problems: list[str] = []
    head = header_text(root / rel)
    if not head.strip():
        return ["no header block found"]

    for section in required_sections(rel):
        if not re.search(rf"^[#\s]*{re.escape(section)}\s*:", head, re.M):
            problems.append(f"missing section: {section}")

    # Version must be a bare version and date, not a changelog.
    vm = re.search(r"^[#\s]*Version\s*:\s*$(.*?)(?=^[#\s]*[A-Z][A-Za-z ]+\s*:|\Z)",
                   head, re.M | re.S)
    if vm:
        body = vm.group(1)
        noisy = [ln for ln in body.splitlines() if VERSION_NOISE.match(ln)]
        if len(noisy) > 1:
            problems.append(
                f"Version section contains release notes ({len(noisy)} entries); "
                "move history to CHANGELOG.md")

    if re.search(r"Part of RE-Toolkit v\d+\.\d+\.\d+", head):
        problems.append("stale 'Part of RE-Toolkit vX.Y.Z' marker")

    if rel.parts[0] == "stages" and rel.suffix == ".sh":
        body = (root / rel).read_text(encoding="utf-8")
        if not re.search(r"^stage_[a-z0-9_]+\(\)", body, re.M):
            problems.append("no stage_* function defined")

    return problems


def collect(root: Path) -> list[Path]:
    out: list[Path] = []
    for pattern in ("*.sh", "*.py"):
        for p in root.rglob(pattern):
            rel = p.relative_to(root)
            if any(part in {".git", "__pycache__", "docs", "tasks"}
                   for part in rel.parts):
                continue
            out.append(rel)
    return sorted(out)


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    report = "--report" in argv[1:]
    root = Path(args[0]).resolve() if args else Path(__file__).resolve().parent.parent

    files = collect(root)
    results = {rel: check_file(root, rel) for rel in files}
    failing = {k: v for k, v in results.items() if v}

    if report:
        total = len(results)
        ok = total - len(failing)
        print("## Header audit\n")
        print(f"Compliant: **{ok} / {total}**\n")
        by_group: dict[str, list[Path]] = {}
        for rel in results:
            group = rel.parts[0] if len(rel.parts) > 1 else "(root)"
            by_group.setdefault(group, []).append(rel)
        print("| Group | Files | Compliant |")
        print("| --- | --- | --- |")
        for group in sorted(by_group):
            members = by_group[group]
            good = sum(1 for m in members if not results[m])
            print(f"| `{group}` | {len(members)} | {good} |")
        if failing:
            print("\n### Non-compliant\n")
            for rel, probs in sorted(failing.items()):
                print(f"- `{rel}`: {'; '.join(probs)}")
        return 1 if failing else 0

    for rel, probs in sorted(failing.items()):
        for p in probs:
            print(f"{rel}: {p}", file=sys.stderr)

    total = len(results)
    if failing:
        print(f"\nFAIL: {len(failing)} of {total} files non-compliant", file=sys.stderr)
        return 1
    print(f"OK: all {total} code files carry a compliant header block")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
