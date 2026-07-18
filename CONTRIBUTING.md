# Contributing to RE-Toolkit

Thank you for considering a contribution. This document covers what the project
expects from a change so that review is quick and predictable.

## Table of contents

- [Ground rules](#ground-rules)
- [Getting set up](#getting-set-up)
- [Repository layout](#repository-layout)
- [Coding standards](#coding-standards)
- [Adding an analysis stage](#adding-an-analysis-stage)
- [Adding a tool to the installer](#adding-a-tool-to-the-installer)
- [Testing](#testing)
- [Definition of done](#definition-of-done)
- [Commit and pull request conventions](#commit-and-pull-request-conventions)
- [Reporting bugs](#reporting-bugs)

## Ground rules

**No em-dash.** The character U+2014 must not appear anywhere in the repository:
not in code, comments, documentation, or generated output. Use `--`, `-`, `:` or
`,` instead. This is enforced by `tools/check-no-emdash.py` and is a required CI
gate. The rule exists because an em-dash inside an installer here-string once
broke a release under `set -e`.

**The project is RE-Toolkit.** Write it that way in prose, headings, and
descriptions. The lowercase string survives deliberately as a literal, and those
occurrences must not be renamed:

| Literal | Role |
| --- | --- |
| `install-retoolkit.sh` | Filename |
| `/opt/retoolkit/`, `/var/log/retoolkit/` | Filesystem paths |
| `RETOOLKIT_VERSION`, `RETOOLKIT_LIB_DIR` | Shell variables |
| `retoolkit_setup_colors` | Function prefix |
| `retoolkit-dynamic` | Docker image tag |
| `retoolkit-3.7.3.tar.gz` | Release artifact |

A consistency check enforces the prose form while leaving every literal alone.

**Evidence over assertion.** Claims about a tool's behavior belong with the
evidence that supports them. If a flag is omitted because it is destructive, say
so at the call site. If a parser expects a specific output shape, state which
tool version produced that shape.

**Version history belongs in the changelog.** Source headers describe what a file
does now. Per-release notes, audit references, and feature-introduction markers
go in `CHANGELOG.md`, not scattered through the code.

**Never break the sandbox.** No stage may operate on the operator's original
file. Stages receive the sandboxed copy and must not reach outside their output
directory.

**No personal or engagement detail.** This project is developed against real
targets on a real workstation, and those references reach comments and
documentation naturally: a home path in a usage example, a hostname in a bug
note, the filename of an analyzed sample. They read as ordinary technical detail
in review, which is why `tools/check-no-disclosures.py` enforces it mechanically
and CI blocks on it.

In worked examples use `/path/to/...`, `sample.exe`, `Sample.Shared.dll`, or a
name under `example.com`. Attribute findings to "the operator" rather than by
name. Do not name a specific vendor product you analyzed.

The same check covers authorship: the repository carries no trace of the tools
or environment used to build it, meaning no assistant or vendor attribution, no
model names, no generated-by markers, no build-sandbox paths, and no co-author
trailers. Note that "LLM" is not flagged and should not be: `GhidraDump.py`
legitimately documents that its plain-text output is designed to be fed to a
language model, which is a product design statement rather than an attribution.

## Getting set up

```bash
git clone https://github.com/Sandler73/RE-Toolkit.git
cd RE-Toolkit

# Provision the toolchain on a Kali or Debian host or VM
sudo ./install-retoolkit.sh

# Development dependencies
sudo apt install shellcheck shfmt bats
python3 -m pip install --user pytest ruff
```

Development is best done in a disposable VM. The installer performs a system-wide
install by design and is not intended to run on a workstation you care about.

## Repository layout

| Path | Contents |
| --- | --- |
| `install-retoolkit.sh` | Layered provisioner for the analysis toolchain |
| `analyze-binaries.sh` | Run-time driver: argument parsing and orchestration |
| `GhidraDump.py` | Ghidra postscript producing the structured analysis dump |
| `lib/` | Shared modules sourced by the driver |
| `stages/static/` | One file per analysis stage, each defining one function |
| `tools/` | Development and diagnostic utilities |
| `tests/bats/` | Shell test suite |
| `tests/python/` | Python test suite |
| `wiki/` | Wiki source. Published separately; see below. |

`lib/` modules have distinct responsibilities and should stay that way:

| Module | Responsibility |
| --- | --- |
| `common.sh` | Logging, path handling, sandboxing, shared helpers |
| `tool-runner.sh` | Bounded tool execution, the run ledger, output validation |
| `detect-type.sh` | File type and runtime detection |
| `dispatch.sh` | Per-target pipeline orchestration |
| `aggregate.sh` | Cross-target aggregation and export generation |
| `ghidra-helper.sh` | Ghidra discovery and toolchain version recording |
| `viz-helper.sh` | Shared Python emitters for visualization |

## Documentation and the wiki

Repository documentation and wiki documentation have different lifecycles, and
conflating them causes build failures.

**In the repository:** `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`,
`SECURITY.md`, and `CODE_OF_CONDUCT.md`. These are versioned with the code and
are checked by CI.

**In the wiki:** everything under `wiki/`. GitHub serves a wiki from a separate
repository, `<repo>.wiki.git`, which is not a directory of the main repository.
The files under `wiki/` are authoring source for those pages.

Because the wiki is a separate repository, **nothing in CI or the test suite
gates on `wiki/`**. A check requiring those files would fail as soon as the
pages are published to the wiki and the directory is no longer needed here.
Mermaid validation and the required-documents check therefore cover in-repo
Markdown only.

To publish or update the wiki:

```bash
git clone https://github.com/Sandler73/RE-Toolkit.wiki.git
cp wiki/*.md RE-Toolkit.wiki/
cd RE-Toolkit.wiki && git add -A && git commit -m "Update wiki" && git push
```

Page names come from filenames, so `Architecture-and-Design.md` becomes the
"Architecture and Design" page. `Home.md` is the wiki landing page. Keep the
filenames as they are: the pages cross-link by name, and renaming one breaks
every link to it.

When behavior changes, update the wiki page in the same pull request as the code
so the two do not drift, then publish the wiki separately.

## Coding standards

### Shell

- Target `bash`, not POSIX `sh`. Scripts declare `#!/usr/bin/env bash`.
- Quote every expansion. `"$var"`, not `$var`.
- Prefer `[[ ]]` over `[ ]`.
- Declare function-local variables with `local`.
- Never invoke a tool without a timeout. Use `run_tool`, which enforces one and
  records the invocation in the run ledger.
- Never suppress stderr. Redirect it to the stage log so failures stay visible.
- A stage must not call `exit`. It returns, so the driver keeps control.

### Python

- Target Python 3.12 or later, except `GhidraDump.py`, which must remain
  compatible with both Jython 2.7 and CPython 3 because it runs inside Ghidra.
- Standard library only for repository tooling. Analysis code may use the
  packages the installer provisions into the virtual environment.
- Handle a missing optional dependency by skipping cleanly with a logged reason,
  never by raising into the driver.

### Header blocks

Every code file carries a header block. Shell files use comments; Python files
use a module docstring. The required sections:

```bash
#!/usr/bin/env bash
# =============================================================================
# stages/static/NN-name.sh
# =============================================================================
#
# Synopsis:
#     One sentence describing what this file does.
#
# Description:
#     What it does in detail, why it is built this way, and any behavior a
#     maintainer would otherwise have to rediscover by reading the code.
#
# Execution Parameters:
#     $1  target   Path to the sandboxed copy of the target binary.
#     $2  outdir   Path to this target's output directory.
#
# Provides:
#     stage_name()
#
# Output subtrees:
#     ${outdir}/NN-name/
#
# Skip controls:
#     SKIP_NAME
#
# Tools invoked (run_tool labels):
#     toolname
#
# Notes:
#     Anything a maintainer needs that does not fit above.
#
# Version:
#     3.7.3 - 2026-05-03
# =============================================================================
```

Keep `Version` as a bare version and date. Do not append release notes to it.

## Adding an analysis stage

1. **Choose a number.** Stage filenames are numbered by output-directory
   position, not execution order. Place a new stage where its output belongs in
   a directory listing. Numbering and execution order are decoupled on purpose;
   see the header of `lib/dispatch.sh`.

2. **Create the file** as `stages/static/NN-name.sh`, with the header block above
   and exactly one function named `stage_name`.

3. **Follow the stage contract.** A stage:
   - accepts `$1` target and `$2` outdir,
   - creates its own output subdirectory,
   - runs tools through `run_tool` so they are bounded and recorded,
   - honors its skip control,
   - skips cleanly with a logged reason when a tool is unavailable,
   - returns rather than exiting,
   - writes only inside its output subdirectory.

4. **Wire it into `lib/dispatch.sh`**, in the branches for the types it applies
   to, positioned correctly in the runtime order.

5. **Register the skip control** in `analyze-binaries.sh` argument parsing, as
   `--no-name` setting `SKIP_NAME=1`.

6. **Feed the summary.** If the stage produces findings that should influence the
   verdict, consume its output in `stages/static/85-summary.sh` and contribute
   weighted signals through `add_signal`.

7. **Document it** in the Stage Reference wiki page, and add a changelog entry.

A stage that produces no parsed output is not finished. If a tool runs and the
data never reaches `_summary.json`, the stage has not delivered anything an
analyst can use.

## Adding a tool to the installer

Prefer the distribution package. Fall back to a source or vendor install only
when the tool is genuinely not packaged.

- Add the package to the appropriate layer.
- Provide a source-build fallback where a package may be unavailable on a rolling
  distribution.
- Make the install idempotent: detect an existing install and skip it.
- Record the tool in the post-install verification table.
- For dual-use tooling, verify and record provenance. Note the upstream source
  and pin or verify what you fetch.
- Never fetch over plain HTTP.

## Testing

```bash
# Everything CI runs
make check

# Or individually
bats tests/bats
python3 -m pytest tests/python -v
make lint
python3 tools/check-no-emdash.py
python3 tools/check-headers.py
python3 tools/check-version-consistency.py
```

ShellCheck runs in two passes. The `error` pass is blocking and the repository is
clean at that level. The `warning` pass is advisory because of a known backlog,
described in the [Development wiki](https://github.com/Sandler73/RE-Toolkit/wiki/Development).
New code is expected to be warning-clean, so review your own additions with
`make shellcheck-warnings` before opening a pull request.

Python linting is configured in `ruff.toml`. The per-file ignores there are
justified by structural constraints rather than convenience, chiefly that
`GhidraDump.py` must run under both Jython 2.7 and CPython 3 and executes inside
a Ghidra script context that injects names at runtime. Do not add a suppression
without recording why it is structural.

`shfmt` is deliberately not a gate. This codebase predates it and does not follow
its default style; adopting it would rewrite roughly 26,000 lines of working
shell to satisfy a formatter the project never used. `make format` shows the diff
if you want it, but matching it is not required.

The scoring model has a dedicated golden-sample regression test at
`tests/python/test-scoring-model.py`. The scoring logic lives inside a bash
heredoc and cannot be imported, so the test deliberately mirrors it. If you change
a weight or a band threshold in `stages/static/85-summary.sh`, update the mirror
and the expected bands in the same commit.

## Definition of done

A change is not finished until all of the following hold:

- [ ] `bash -n` passes on every modified shell file
- [ ] `shellcheck` reports no new findings
- [ ] Both test suites pass
- [ ] `python3 tools/check-no-emdash.py` exits 0
- [ ] `python3 tools/check-no-disclosures.py` exits 0
- [ ] Header blocks on new or modified files are accurate and complete
- [ ] The `Version` line reflects the release the change ships in
- [ ] Documentation is updated: wiki pages for behavior, `CHANGELOG.md` for history
- [ ] Any new tool invocation is bounded by a timeout and recorded in the ledger
- [ ] The change was exercised against a real binary, not only a synthetic fixture

State clearly in the pull request what you verified and what you could not. A
change verified only in part is acceptable when the gap is declared; a change
claimed as verified when it was not is not.

## Commit and pull request conventions

Write commit subjects in the imperative mood, under 72 characters:

```
Add ROP gadget enumeration stage
Fix objdump relocation flag rejected by GNU binutils
Document the dynamic tier gating model
```

Explain the reasoning in the body. What changed is visible in the diff; why it
changed is not.

A pull request should describe the problem, the approach, the verification
performed, and any known limitation. The pull request template prompts for each.

## Reporting bugs

Open an issue using the bug report template. The single most useful thing you can
include is the exact command you ran, the relevant portion of the stage log from
the output directory, and the file type of the target. Redact anything sensitive.

For a vulnerability in RE-Toolkit itself, do not open a public issue. Follow
[SECURITY.md](SECURITY.md).
