# =============================================================================
# Makefile
# =============================================================================
#
# Synopsis:
#     Developer entry point for linting, testing, documentation checks, and
#     release preparation.
#
# Description:
#     Every target wraps the same command the corresponding CI job runs, so
#     `make check` locally and a green pipeline mean the same thing. Targets are
#     thin wrappers rather than reimplementations: when a rule is enforced by a
#     script in tools/, the target calls that script instead of duplicating its
#     logic, so there is no second source of truth to drift.
#
#     Optional tooling is detected rather than assumed. A contributor without
#     shfmt or bats installed gets a clear skip notice naming the install
#     command, not a confusing failure in an unrelated target.
#
#     Target groups:
#
#         Verification   check, verify, ci, release-check
#         Linting        lint, shellcheck, shellcheck-warnings, format, ruff
#         Testing        test, test-shell, test-python
#         Standards      emdash, headers, version, docs
#         Documentation  mermaid, wiki-check
#         Utility        help, tools, stats, clean, dist
#
# Execution Parameters:
#     make help      List every target with a one-line description.
#     make check     Run the full gate set, as CI does.
#     make V=1 ...   Echo the underlying commands instead of summaries.
#
# Examples:
#     make check                 Everything CI enforces
#     make test                  Both test suites
#     make lint                  Shell and Python linting
#     make release-check         Pre-tag validation
#     make V=1 test-shell        Verbose bats output
#
# Notes:
#     ShellCheck runs in two passes. The error-severity pass is blocking; the
#     warning-severity pass is advisory because of a documented backlog. See the
#     Development wiki page for why those sites need restructuring rather than a
#     flag.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ---- configuration ----------------------------------------------------------

PYTHON  ?= python3
VERSION := $(shell grep -oE 'RETOOLKIT_VERSION="[0-9]+\.[0-9]+\.[0-9]+"' \
                   install-retoolkit.sh 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

SH_FILES  := $(shell find . -name '*.sh' -not -path './.git/*' -not -path './node_modules/*')
PY_FILES  := $(shell find . -name '*.py' -not -path './.git/*' -not -path '*/__pycache__/*')
# The wiki is published to a separate repository, so only in-repo Markdown
# is validated. wiki/*.md is included when present, for local authoring.
MD_FILES  := README.md $(wildcard wiki/*.md)

# V=1 echoes the commands; otherwise targets print their own summaries.
ifeq ($(V),1)
  Q :=
else
  Q := @
endif

# Optional tooling. Each target checks its own dependency and skips clearly.
HAVE_SHELLCHECK := $(shell command -v shellcheck 2>/dev/null)
HAVE_SHFMT      := $(shell command -v shfmt 2>/dev/null)
HAVE_BATS       := $(shell command -v bats 2>/dev/null)
HAVE_RUFF       := $(shell command -v ruff 2>/dev/null)
HAVE_NODE       := $(shell command -v node 2>/dev/null)

BOLD := \033[1m
DIM  := \033[2m
OK   := \033[32m
WARN := \033[33m
ERR  := \033[31m
OFF  := \033[0m

.PHONY: help tools stats check verify ci syntax lint shellcheck \
        shellcheck-warnings format format-fix ruff test test-shell \
        test-python emdash disclosures headers version docs mermaid \
        wiki-check release-check dist clean

# ---- utility ----------------------------------------------------------------

help:
	@printf "$(BOLD)RE-Toolkit $(VERSION)$(OFF)  developer targets\n\n"
	@printf "$(BOLD)Verification$(OFF)\n"
	@printf "  %-22s %s\n" "check"                "Run every gate, as CI does"
	@printf "  %-22s %s\n" "verify"               "Fast gates only, no test suites"
	@printf "  %-22s %s\n" "release-check"        "Pre-tag validation"
	@printf "\n$(BOLD)Linting$(OFF)\n"
	@printf "  %-22s %s\n" "lint"                 "All linters"
	@printf "  %-22s %s\n" "shellcheck"           "ShellCheck, error severity (blocking)"
	@printf "  %-22s %s\n" "shellcheck-warnings"  "ShellCheck, warning severity (advisory)"
	@printf "  %-22s %s\n" "format"               "shfmt diff (advisory, not a gate)"
	@printf "  %-22s %s\n" "ruff"                 "Python linting"
	@printf "\n$(BOLD)Testing$(OFF)\n"
	@printf "  %-22s %s\n" "test"                 "Both test suites"
	@printf "  %-22s %s\n" "test-shell"           "bats suite"
	@printf "  %-22s %s\n" "test-python"          "pytest suite"
	@printf "\n$(BOLD)Standards$(OFF)\n"
	@printf "  %-22s %s\n" "emdash"               "Enforce the em-dash prohibition"
	@printf "  %-22s %s\n" "disclosures"          "Personal, host, and credential disclosure guard"
	@printf "  %-22s %s\n" "headers"              "Header-block completeness"
	@printf "  %-22s %s\n" "version"              "Version consistency"
	@printf "  %-22s %s\n" "docs"                 "Documentation consistency"
	@printf "\n$(BOLD)Documentation$(OFF)\n"
	@printf "  %-22s %s\n" "mermaid"              "Validate mermaid diagrams"
	@printf "  %-22s %s\n" "wiki-check"           "Required wiki pages present"
	@printf "\n$(BOLD)Utility$(OFF)\n"
	@printf "  %-22s %s\n" "tools"                "Report which optional tools are present"
	@printf "  %-22s %s\n" "stats"                "Repository statistics"
	@printf "  %-22s %s\n" "dist"                 "Build a distribution archive"
	@printf "  %-22s %s\n" "clean"                "Remove caches and build artifacts"
	@printf "\n$(DIM)Pass V=1 to echo underlying commands.$(OFF)\n"

tools:
	@printf "$(BOLD)==>$(OFF) Optional tooling\n"
	@printf "  %-12s %b\n" "shellcheck" "$(if $(HAVE_SHELLCHECK),$(OK)present$(OFF),$(WARN)missing  apt install shellcheck$(OFF))"
	@printf "  %-12s %b\n" "shfmt"      "$(if $(HAVE_SHFMT),$(OK)present$(OFF),$(WARN)missing  apt install shfmt$(OFF))"
	@printf "  %-12s %b\n" "bats"       "$(if $(HAVE_BATS),$(OK)present$(OFF),$(WARN)missing  apt install bats$(OFF))"
	@printf "  %-12s %b\n" "ruff"       "$(if $(HAVE_RUFF),$(OK)present$(OFF),$(WARN)missing  pip install ruff$(OFF))"
	@printf "  %-12s %b\n" "node"       "$(if $(HAVE_NODE),$(OK)present$(OFF),$(WARN)missing  needed for mermaid validation$(OFF))"

stats:
	@printf "$(BOLD)==>$(OFF) Repository statistics\n"
	@printf "  %-24s %s\n" "version"         "$(VERSION)"
	@printf "  %-24s %s\n" "analysis stages" "$$(ls stages/static/*.sh | wc -l)"
	@printf "  %-24s %s\n" "library modules" "$$(ls lib/*.sh | wc -l)"
	@printf "  %-24s %s\n" "shell files"     "$$(echo $(SH_FILES) | wc -w)"
	@printf "  %-24s %s\n" "python files"    "$$(echo $(PY_FILES) | wc -w)"
	@printf "  %-24s %s\n" "wiki pages"      "$$(ls wiki/*.md 2>/dev/null | wc -l)"
	@printf "  %-24s %s\n" "bats tests"      "$$(grep -h '^@test' tests/bats/*.bats | wc -l)"
	@printf "  %-24s %s\n" "shell LOC"       "$$(cat $(SH_FILES) | wc -l)"

# ---- verification -----------------------------------------------------------

check: verify test
	@printf "\n$(OK)$(BOLD)All gates passed.$(OFF)\n"

verify: syntax emdash disclosures headers version docs lint
	@printf "$(OK)  Fast gates passed.$(OFF)\n"

ci: check mermaid

syntax:
	@printf "$(BOLD)==>$(OFF) Syntax\n"
	$(Q)for f in $(SH_FILES); do \
	    bash -n "$$f" || { printf "$(ERR)  bash -n failed: %s$(OFF)\n" "$$f"; exit 1; }; \
	done
	$(Q)for f in $(PY_FILES); do \
	    $(PYTHON) -m py_compile "$$f" || { printf "$(ERR)  compile failed: %s$(OFF)\n" "$$f"; exit 1; }; \
	done
	@printf "$(OK)  ok$(OFF)    every shell and Python file parses\n"

# ---- linting ----------------------------------------------------------------

lint: shellcheck ruff

shellcheck:
	@printf "$(BOLD)==>$(OFF) ShellCheck (error severity, blocking)\n"
ifndef HAVE_SHELLCHECK
	@printf "$(WARN)  skip$(OFF)  shellcheck not installed. apt install shellcheck\n"
else
	$(Q)shellcheck -S error $(SH_FILES)
	@printf "$(OK)  ok$(OFF)    no error-severity findings\n"
endif

shellcheck-warnings:
	@printf "$(BOLD)==>$(OFF) ShellCheck (warning severity, advisory)\n"
ifndef HAVE_SHELLCHECK
	@printf "$(WARN)  skip$(OFF)  shellcheck not installed. apt install shellcheck\n"
else
	-$(Q)shellcheck -S warning $(SH_FILES)
	@printf "$(DIM)  Advisory only. A documented backlog exists; see the Development wiki.$(OFF)\n"
endif

# shfmt is available but is NOT part of `lint` or `check`, and is not a CI gate.
# This codebase predates shfmt and does not follow its default style: running it
# would rewrite roughly 26,000 lines of working shell to satisfy a formatter the
# project never adopted. The targets exist for anyone who wants the diff, not as
# a standard to meet.
format:
	@printf "$(BOLD)==>$(OFF) shfmt (check, advisory)\n"
ifndef HAVE_SHFMT
	@printf "$(WARN)  skip$(OFF)  shfmt not installed. apt install shfmt\n"
else
	-$(Q)shfmt -d -i 4 -ci $(SH_FILES)
	@printf "$(DIM)  Advisory only. shfmt is not a project standard.$(OFF)\n"
endif

format-fix:
	@printf "$(BOLD)==>$(OFF) shfmt (apply in place)\n"
ifndef HAVE_SHFMT
	@printf "$(WARN)  skip$(OFF)  shfmt not installed. apt install shfmt\n"
else
	$(Q)shfmt -w -i 4 -ci $(SH_FILES)
	@printf "$(OK)  ok$(OFF)    formatting applied\n"
endif

ruff:
	@printf "$(BOLD)==>$(OFF) ruff\n"
ifndef HAVE_RUFF
	@printf "$(WARN)  skip$(OFF)  ruff not installed. pip install ruff\n"
else
	$(Q)ruff check .
	@printf "$(OK)  ok$(OFF)    Python lint clean\n"
endif

# ---- standards --------------------------------------------------------------

emdash:
	@printf "$(BOLD)==>$(OFF) Em-dash guard\n"
	$(Q)$(PYTHON) tools/check-no-emdash.py

disclosures:
	@printf "$(BOLD)==>$(OFF) Disclosure guard\n"
	$(Q)$(PYTHON) tools/check-no-disclosures.py

headers:
	@printf "$(BOLD)==>$(OFF) Header compliance\n"
	$(Q)$(PYTHON) tools/check-headers.py

version:
	@printf "$(BOLD)==>$(OFF) Version consistency\n"
	$(Q)$(PYTHON) tools/check-version-consistency.py

docs:
	@printf "$(BOLD)==>$(OFF) Documentation consistency\n"
	$(Q)$(PYTHON) -m pytest tests/python/test_docs_consistency.py -q

# ---- documentation ----------------------------------------------------------

mermaid:
	@printf "$(BOLD)==>$(OFF) Mermaid diagram validation\n"
ifndef HAVE_NODE
	@printf "$(WARN)  skip$(OFF)  node not installed, required for mermaid validation\n"
else
	$(Q)npm install --no-save --no-fund --no-audit --silent mermaid@11 jsdom
	$(Q)node tools/validate-mermaid.mjs $(MD_FILES)
endif

# Local authoring aid only. NOT part of `check`, `verify`, or CI: the wiki is a
# separate GitHub repository, so wiki/ may legitimately be absent here.
wiki-check:
	@printf "$(BOLD)==>$(OFF) Wiki completeness (local authoring aid)\n"
	$(Q)if [ ! -d wiki ]; then \
	    printf "$(WARN)  skip$(OFF)  no wiki/ directory; pages live in the separate wiki repo\n"; \
	    exit 0; \
	fi; \
	missing=0; \
	for p in Home Installation Usage Architecture-and-Design Stage-Reference \
	         Configuration Output-and-Reports Dynamic-Analysis Security-Model \
	         Troubleshooting FAQ Development; do \
	    test -f "wiki/$$p.md" || { printf "$(WARN)  missing wiki/%s.md$(OFF)\n" "$$p"; missing=1; }; \
	done; \
	[ $$missing -eq 0 ] && printf "$(OK)  ok$(OFF)    all wiki pages present\n" || true

# ---- testing ----------------------------------------------------------------

test: test-shell test-python

test-shell:
	@printf "$(BOLD)==>$(OFF) bats\n"
ifndef HAVE_BATS
	@printf "$(WARN)  skip$(OFF)  bats not installed. apt install bats\n"
else
	$(Q)bats tests/bats
endif

test-python:
	@printf "$(BOLD)==>$(OFF) pytest\n"
	$(Q)$(PYTHON) -m pytest tests/python $(if $(V),-v,-q)

# ---- release ----------------------------------------------------------------

release-check: check
	@printf "$(BOLD)==>$(OFF) Release validation for $(VERSION)\n"
	$(Q)grep -q "^## \[$(VERSION)\]" CHANGELOG.md || { \
	    printf "$(ERR)  CHANGELOG.md has no entry for $(VERSION)$(OFF)\n"; exit 1; }
	$(Q)test -x install-retoolkit.sh || { \
	    printf "$(ERR)  install-retoolkit.sh is not executable$(OFF)\n"; exit 1; }
	$(Q)test -x analyze-binaries.sh || { \
	    printf "$(ERR)  analyze-binaries.sh is not executable$(OFF)\n"; exit 1; }
	@printf "$(OK)$(BOLD)  Ready to tag v$(VERSION).$(OFF)\n"

dist:
	@printf "$(BOLD)==>$(OFF) Building distribution archive\n"
	$(Q)rm -rf dist && mkdir -p dist/retoolkit-$(VERSION)
	$(Q)rsync -a --exclude '.git' --exclude '.github' --exclude 'dist' \
	    --exclude 'docs/legacy-html' --exclude 'tasks' --exclude '__pycache__' \
	    --exclude 'node_modules' ./ dist/retoolkit-$(VERSION)/
	$(Q)cd dist && tar -czf retoolkit-$(VERSION).tar.gz retoolkit-$(VERSION) \
	    && sha256sum retoolkit-$(VERSION).tar.gz > retoolkit-$(VERSION).sha256
	@printf "$(OK)  ok$(OFF)    dist/retoolkit-$(VERSION).tar.gz\n"

# ---- cleanup ----------------------------------------------------------------

clean:
	@printf "$(BOLD)==>$(OFF) Cleaning\n"
	$(Q)rm -rf .pytest_cache node_modules dist package-lock.json
	$(Q)find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	$(Q)find . -name '*.pyc' -delete 2>/dev/null || true
	@printf "$(OK)  ok$(OFF)    caches and build artifacts removed\n"
