#!/usr/bin/env python3
# =============================================================================
# tools/check-no-disclosures.py
# =============================================================================
#
# Synopsis:
#     Fail if the repository discloses personal, host, credential, or
#     engagement information.
#
# Description:
#     RE-Toolkit is developed against real targets on a real workstation, so
#     operator paths, hostnames, and the names of analyzed samples reach source
#     comments and documentation naturally. They are invisible in review because
#     they read as ordinary technical detail: a worked example, a path in a
#     usage string, an attribution in a changelog entry.
#
#     Publishing them discloses who analyzed what, when, and from which machine.
#     For a dual-use analysis tool that is a meaningful leak, not a cosmetic one.
#     This check makes it a build failure instead of something a reader notices
#     after the fact.
#
#     Four categories are enforced:
#
#       Identity     Operator names, personal home paths, account names.
#       Host         Workstation hostnames.
#       Credentials  Private keys, cloud and service tokens, passwords,
#                    credentials embedded in URLs.
#       Engagement   Names of specific vendor products, sample binaries, and
#                    working directories used during development.
#
#     Generic and documented values are allowlisted deliberately: /opt, /root,
#     /home/user, example.com, and RFC 5737 documentation addresses are not
#     disclosures and flagging them would train reviewers to ignore this check.
#
#     Engagement terms are listed explicitly rather than inferred. A pattern
#     general enough to catch any product name would flag every legitimate
#     mention of a tool the project integrates.
#
# Execution Parameters:
#     [root]     Optional path to scan. Defaults to the repository root.
#     --quiet    Suppress the success message; report failures only.
#     --verbose  List each category checked, including those with no findings.
#
# Examples:
#     python3 tools/check-no-disclosures.py
#     python3 tools/check-no-disclosures.py . --verbose
#
# Exit Codes:
#     0    No disclosures detected.
#     1    One or more disclosures found.
#
# Notes:
#     When adding a worked example, use /path/to/..., sample.exe, or a name
#     under example.com. Wired into CI; see .github/workflows/ci.yml.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================
"""Fail if the repository discloses personal, host, or engagement information."""

from __future__ import annotations

import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".pytest_cache", ".ruff_cache"}
SKIP_SUFFIX = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".xz",
    ".pyc", ".woff", ".woff2", ".ttf",
}

# Two files necessarily contain the patterns this check searches for: the check
# itself, and its test, whose negative cases must carry a real-looking example
# of each category or they would prove nothing. Both are exempt by path.
#
# This is the only exemption mechanism, and it is deliberately a fixed list
# rather than a marker comment: an inline "allow" directive would let anyone
# silence the check on any line, which is precisely the failure mode it exists
# to prevent.
SELF_EXEMPT = {
    "tools/check-no-disclosures.py",
    "tests/python/test_repo_tools.py",
}

# Values that are generic, documented, or belong to the project itself.
ALLOW = [
    "/home/user", "/home/username", "/home/youruser", "/home/kali",
    "/home/alice", "/home/bob",        # documentation examples
    "/home/retdec",                    # path inside the RetDec container
    "/path/to",
    "example.com", "example.org", "example.net",
    "localhost", "127.0.0.1", "0.0.0.0", "255.255.255",
    "192.0.2.", "198.51.100.", "203.0.113.",   # RFC 5737 documentation ranges
    "noreply@microsoft.com", "support@microsoft.com", "security@microsoft.com",
    "@users.noreply.github.com",
]

CHECKS: dict[str, dict[str, str]] = {
    "identity": {
        "personal home path": r"/home/(?!user\b|username\b|youruser\b|kali\b|alice\b|bob\b|retdec\b)[a-z][a-z0-9._-]{1,32}",
        "personal home path (macOS)": r"/Users/(?!user\b|username\b|Shared\b)[A-Za-z][A-Za-z0-9._-]{1,32}",
        "operator name": r"\bRyan\b",
        "email address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    },
    "host": {
        "workstation hostname": r"\bklre\b",
    },
    "credentials": {
        "private key block": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY",
        "SSH public key": r"\bssh-(?:rsa|ed25519|dss)\s+AAAA[0-9A-Za-z+/]{20,}",
        "AWS access key id": r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b",
        "GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{16,}\b",
        "Slack token": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "Google API key": r"\bAIza[0-9A-Za-z_-]{35}\b",
        "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "credentials in URL": r"(?i)\b(?:mysql|postgres|postgresql|mongodb|redis|ftp|ssh|https?)://[^\s:@/]+:[^\s@/]+@",
        "password assignment": r"(?i)\b(?:password|passwd|passphrase)\b\s*[:=]\s*['\"][^'\"]{4,}['\"]",
        "api key assignment": r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"][A-Za-z0-9_\-.]{16,}['\"]",
        "private IPv4": r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b",
        "MAC address": r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b",
    },
    "authorship": {
        # Build-assistant and AI-tooling attribution. A published repository
        # should carry no trace of the environment it was assembled in: not a
        # sandbox path, not a model name, not a co-author trailer.
        #
        # Note what is deliberately absent: a generic "LLM" or "AI" pattern.
        # GhidraDump.py legitimately documents that its plain-text output is
        # designed to be fed to a language model, which is a product design
        # statement, not an attribution. Flagging it would be a false positive
        # that trains reviewers to ignore this check.
        "assistant attribution": r"\b(?:Claude|Anthropic|ChatGPT|OpenAI|Copilot|Codex)\b",
        "model name": r"\b(?:claude-[a-z0-9.-]+|gpt-[0-9][a-z0-9.-]*|sonnet-[0-9]|opus-[0-9]|haiku-[0-9])\b",
        "generated-by marker": r"(?i)\b(?:generated (?:by|with) (?:an? )?AI|AI-generated|written by (?:an? )?AI|co-authored-by:\s*\w+\s*<[^>]*noreply)",
        "build sandbox path": r"/home/claude\b|/mnt/user-data\b",
    },
    "engagement": {
        # Specific artifacts used during development. Listed explicitly: a
        # generic pattern would flag every tool this project integrates.
        "analyzed product": r"\bRedCheck\w*|\bCheck\.R\.Agent\b|\bredcheckx64\b|\brca64testrun\b",
        "private project name": r"\bre-unpacker\b|\bcuniculator\b|\bomniperitus\b",
    },
}


def allowed(line: str, hit: str) -> bool:
    """Allowlisting is scoped to the matched text, never the whole line.

    Line-scoped allowlisting is tempting and wrong: one benign token anywhere
    on a line would suppress every other pattern on it. A commit trailer such
    as `Co-authored-by: Bot <bot@users.noreply.github.com>` contains an
    allowlisted address, and under line scope that address silently excused the
    attribution marker sitting beside it.
    """
    return any(a in hit for a in ALLOW)


def scan(root: Path) -> list[tuple[str, str, str, int, str, str]]:
    findings = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(p in SKIP_DIRS for p in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIX:
            continue
        rel = str(path.relative_to(root))
        if rel in SELF_EXEMPT:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 4000:
                continue
            for category, patterns in CHECKS.items():
                for name, pat in patterns.items():
                    for m in re.finditer(pat, line):
                        hit = m.group(0)
                        if allowed(line, hit):
                            continue
                        findings.append(
                            (category, name, rel, lineno, hit, line.strip()[:150]))
    return findings


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    quiet = "--quiet" in argv[1:]
    verbose = "--verbose" in argv[1:]
    root = Path(args[0]).resolve() if args else Path(__file__).resolve().parent.parent

    findings = scan(root)

    if verbose:
        hit_names = {f[1] for f in findings}
        for category, patterns in CHECKS.items():
            for name in patterns:
                status = "FOUND" if name in hit_names else "none"
                print(f"  {category:<12} {name:<28} {status}")
        print()

    if not findings:
        if not quiet:
            total = sum(len(p) for p in CHECKS.values())
            print(f"OK: no disclosures detected ({total} patterns checked)")
        return 0

    print(f"FAIL: {len(findings)} disclosure(s) found under {root}", file=sys.stderr)
    print("Use /path/to/..., sample.exe, or example.com in worked examples.\n",
          file=sys.stderr)
    by_cat: dict[str, list] = {}
    for f in findings:
        by_cat.setdefault(f[0], []).append(f)
    for category in sorted(by_cat):
        print(f"  [{category}]", file=sys.stderr)
        for _, name, rel, lineno, hit, line in by_cat[category]:
            print(f"    {rel}:{lineno}: {name}: {hit}", file=sys.stderr)
            print(f"        {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
