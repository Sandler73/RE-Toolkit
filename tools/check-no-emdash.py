#!/usr/bin/env python3
# =============================================================================
# tools/check-no-emdash.py
# =============================================================================
#
# Synopsis:
#     Repository-wide guard enforcing the project-wide prohibition on the
#     em-dash character (U+2014).
#
# Description:
#     RE-Toolkit forbids U+2014 in all source, comments, documentation, and
#     generated output. The approved substitutes are "--", "-", ":" and ",".
#     This check exists because an em-dash once broke an installer here-string
#     and killed a release under `set -e`, so the rule is enforced mechanically
#     rather than by review discipline.
#
#     The scan walks the repository, skipping binary files and any path matched
#     by the ignore list, and reports every offending file with line and column
#     so the fix is unambiguous. Exit status is non-zero when any occurrence is
#     found, which fails the CI job.
#
# Execution Parameters:
#     [root]    Optional path to scan. Defaults to the repository root
#               inferred from this file's location.
#     --quiet   Suppress the success message; report failures only.
#
# Examples:
#     python3 tools/check-no-emdash.py
#     python3 tools/check-no-emdash.py . --quiet
#
# Exit Codes:
#     0    No em-dash found.
#     1    One or more occurrences found.
#
# Notes:
#     Wired into CI as a required gate. See .github/workflows/lint.yml.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================
"""Fail if the em-dash character U+2014 appears anywhere in the repository."""

from __future__ import annotations

import sys
from pathlib import Path

EM_DASH = "\u2014"

IGNORE_DIRS = {
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules", ".venv", "venv", "out", "output",
}

IGNORE_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".xz",
    ".bz2", ".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".apk", ".dex",
    ".pyc", ".class", ".woff", ".woff2", ".ttf",
}


def scan(root: Path) -> list[tuple[Path, int, int, str]]:
    """Return (path, line_no, column, line_text) for each em-dash found."""
    findings: list[tuple[Path, int, int, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in IGNORE_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable: not our concern
        if EM_DASH not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            col = line.find(EM_DASH)
            while col != -1:
                findings.append((path.relative_to(root), lineno, col + 1, line.strip()))
                col = line.find(EM_DASH, col + 1)
    return findings


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    quiet = "--quiet" in argv[1:]
    root = Path(args[0]).resolve() if args else Path(__file__).resolve().parent.parent

    findings = scan(root)
    if not findings:
        if not quiet:
            print(f"OK: no em-dash (U+2014) found under {root}")
        return 0

    print(f"FAIL: {len(findings)} em-dash occurrence(s) found under {root}", file=sys.stderr)
    print("Replace U+2014 with '--', '-', ':' or ','.\n", file=sys.stderr)
    for rel, lineno, col, text in findings:
        excerpt = text if len(text) <= 100 else text[:97] + "..."
        print(f"  {rel}:{lineno}:{col}: {excerpt}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
