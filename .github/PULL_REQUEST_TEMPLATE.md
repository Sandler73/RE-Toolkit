## Summary

<!-- What does this change do, and why? The diff shows what changed; explain why. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] New analysis stage
- [ ] New tool integration
- [ ] Breaking change (existing behavior or CLI changes)
- [ ] Documentation
- [ ] Testing or CI

## Related issues

<!-- For example: Closes #123 -->

## Approach

<!-- How does the change work? Note any alternative you rejected and why. -->

## Verification

<!--
State what you actually ran and what you observed. Be specific about what was
verified and what was not: a change verified in part is fine when the gap is
declared. Include the target type you tested against.
-->

- Command run:
- Target type:
- Observed result:
- Not verified:

## Checklist

- [ ] `bash -n` passes on every modified shell file
- [ ] `shellcheck` reports no new findings
- [ ] `bats tests/bats` passes
- [ ] `python3 -m pytest tests/python` passes
- [ ] `python3 tools/check-no-emdash.py` exits 0
- [ ] Header blocks on new or modified files are accurate and complete
- [ ] The `Version` line reflects the release this ships in
- [ ] `CHANGELOG.md` has an entry for this change
- [ ] Wiki pages are updated for any behavior change
- [ ] Exercised against a real binary, not only a synthetic fixture

## Stage changes only

<!-- Delete this section if no stage was added or modified. -->

- [ ] The stage honors its skip control
- [ ] Every tool runs through `run_tool` and is bounded by a timeout
- [ ] The stage skips cleanly with a logged reason when a tool is unavailable
- [ ] The stage returns rather than calling `exit`
- [ ] The stage writes only inside its own output subdirectory
- [ ] Findings reach `_summary.json` and are documented in the Stage Reference
- [ ] The stage is wired into `lib/dispatch.sh` in the correct runtime position

## Security considerations

<!--
Does this change how untrusted input is handled, how a tool is invoked, or what
the installer fetches or writes? If yes, describe the trust boundary involved.
If no, say so.
-->
