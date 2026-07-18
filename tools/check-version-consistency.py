#!/usr/bin/env python3
# =============================================================================
# tools/check-version-consistency.py
# =============================================================================
#
# Synopsis:
#     Verify that the project version is stated consistently everywhere it
#     appears.
#
# Description:
#     RE-Toolkit states its version in several places that must agree: the
#     RETOOLKIT_VERSION constant in the installer, the ANALYZER_VERSION
#     constant in the driver, the Version section of every code file's header
#     block, and the most recent release heading in CHANGELOG.md.
#
#     A version that drifts between these is a real defect, not a cosmetic one:
#     it makes a bug report ambiguous, because the version an operator reports
#     from --version may not be the version whose behavior they are describing.
#     This check makes that drift a build failure.
#
#     The authoritative version is RETOOLKIT_VERSION in install-retoolkit.sh.
#     Every other location is compared against it.
#
# Execution Parameters:
#     [root]      Optional path to scan. Defaults to the repository root.
#     --verbose   List every location checked, not only the mismatches.
#
# Examples:
#     python3 tools/check-version-consistency.py
#     python3 tools/check-version-consistency.py --verbose
#
# Exit Codes:
#     0    All version references agree.
#     1    A mismatch was found, or the authoritative version is missing.
#
# Notes:
#     Versioning follows Semantic Versioning 2.0.0. When cutting a release,
#     update the two constants, the header Version lines, and CHANGELOG.md
#     together.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================
"""Verify the project version is consistent across code and documentation."""

from __future__ import annotations

import re
import sys
from pathlib import Path

SEMVER = r"\d+\.\d+\.\d+"


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


def authoritative_version(root: Path) -> str | None:
    m = re.search(rf'RETOOLKIT_VERSION="({SEMVER})"', read(root / "install-retoolkit.sh"))
    return m.group(1) if m else None


def collect_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for pattern in ("*.sh", "*.py"):
        for p in root.rglob(pattern):
            rel = p.relative_to(root)
            if any(part in {".git", "__pycache__", "docs", "tasks", "tests"}
                   for part in rel.parts):
                continue
            out.append(rel)
    return sorted(out)


def header_version(root: Path, rel: Path) -> str | None:
    """Return the version stated in a file's header Version section."""
    text = read(root / rel)
    # Look only at the top of the file, where the header block lives.
    head = "\n".join(text.splitlines()[:120])
    m = re.search(rf"^[#\s]*Version\s*:\s*\n[#\s]*({SEMVER})", head, re.M)
    if m:
        return m.group(1)
    m = re.search(rf"^[#\s]*Version\s*:\s*({SEMVER})", head, re.M)
    return m.group(1) if m else None


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    verbose = "--verbose" in argv[1:]
    root = Path(args[0]).resolve() if args else Path(__file__).resolve().parent.parent

    expected = authoritative_version(root)
    if not expected:
        print("FAIL: RETOOLKIT_VERSION not found in install-retoolkit.sh", file=sys.stderr)
        return 1

    problems: list[str] = []
    checked = 0

    # Driver constant
    m = re.search(rf'ANALYZER_VERSION="({SEMVER})"', read(root / "analyze-binaries.sh"))
    if not m:
        problems.append("analyze-binaries.sh: ANALYZER_VERSION not found")
    else:
        checked += 1
        if m.group(1) != expected:
            problems.append(
                f"analyze-binaries.sh: ANALYZER_VERSION is {m.group(1)}, expected {expected}")
        elif verbose:
            print(f"  ok  analyze-binaries.sh ANALYZER_VERSION = {m.group(1)}")

    # Changelog most recent release
    changelog = read(root / "CHANGELOG.md")
    m = re.search(rf"^## \[({SEMVER})\]", changelog, re.M)
    if not m:
        problems.append("CHANGELOG.md: no release heading found")
    else:
        checked += 1
        if m.group(1) != expected:
            problems.append(
                f"CHANGELOG.md: latest release is {m.group(1)}, expected {expected}")
        elif verbose:
            print(f"  ok  CHANGELOG.md latest release = {m.group(1)}")

    # Header Version lines
    for rel in collect_files(root):
        v = header_version(root, rel)
        if v is None:
            continue  # header completeness is check-headers.py's job
        checked += 1
        if v != expected:
            problems.append(f"{rel}: header Version is {v}, expected {expected}")
        elif verbose:
            print(f"  ok  {rel} header Version = {v}")

    if problems:
        print(f"FAIL: version drift detected (authoritative version {expected})",
              file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print(f"OK: version {expected} is consistent across {checked} locations")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
