# Security Policy

## Supported versions

Security fixes are applied to the current release line. Older releases are not
backported.

| Version | Supported |
| --- | --- |
| 3.7.x | Yes |
| 3.0.x through 3.6.x | No |
| 2.x | No |

## Reporting a vulnerability

Do not open a public issue for a security report.

Report privately through GitHub Security Advisories, using the "Report a
vulnerability" button under the Security tab of this repository. That channel
keeps the report confidential until a fix is available.

Please include:

- A description of the issue and why it is a security concern
- The affected component: installer, driver, a specific stage, or a library module
- Steps to reproduce, including the exact command line
- What an attacker gains, and what access they need to start
- The RE-Toolkit version and host distribution
- A proof of concept, if you have one

What to expect:

| Stage | Target |
| --- | --- |
| Acknowledgement | Within 5 business days |
| Initial assessment | Within 10 business days |
| Fix or mitigation plan | Communicated after assessment |

Reporters are credited in the release notes unless they ask not to be.

## What counts as a vulnerability

RE-Toolkit runs as a privileged installer and processes hostile input, so its
threat model is specific.

### In scope

- **Sandbox escape.** Anything that lets a target file be modified in place, or
  lets a stage write outside its designated output directory.
- **Code execution from a crafted target during static analysis.** The static
  path must never execute the target. A malicious binary that achieves execution
  through a parsing stage is a serious finding.
- **Command injection.** A crafted filename, path, or tool output that breaks out
  of a shell invocation.
- **Privilege escalation through the installer.** Writable paths later executed
  with elevated privilege, unsafe permissions on installed artifacts, or an
  insecure fetch that allows substituted content.
- **Insecure download or verification.** Fetching a tool over plain HTTP, or
  failing to verify content whose integrity the install depends on.
- **Secret disclosure.** Credentials or tokens written into logs, reports, or the
  output tree.

### Out of scope

- **The tools RE-Toolkit installs.** A vulnerability in Ghidra, radare2, or any
  other third-party tool belongs to that project. Report it upstream. If
  RE-Toolkit invokes a tool in a way that makes an upstream issue exploitable when
  it otherwise would not be, that part is in scope here.
- **Intended dynamic execution.** Tiers 2 through 4 execute the target. That is
  their purpose, and it is gated behind an explicit flag. Reports that dynamic
  analysis runs the binary describe intended behavior. A failure of the isolation
  those tiers promise is in scope.
- **Requiring prior root access.** RE-Toolkit is installed with `sudo`. An attack
  that presumes the attacker already has root is not a privilege boundary.
- **Analysis quality issues.** A missed detection, a false positive, or an
  incorrect severity is a bug. Open a normal issue.

## Operational guidance

**Analyze in a disposable VM.** RE-Toolkit is built to process malicious files. Run
it in an isolated virtual machine with no network path to anything you value and
no credentials mounted. Snapshot before a run and revert after.

**Understand the dynamic tiers before enabling them.** Tier 1 emulates and does
not execute. Tiers 2 through 4 genuinely execute the target and require
`--allow-real-execution`. Sandbox isolation reduces risk; it does not eliminate
it. Malware that detects and escapes a sandbox exists.

**Treat the output tree as untrusted.** It contains strings, resources, and
extracted files that came from a hostile binary. Extracted content is still
malicious content. HTML reports are self-contained and fetch nothing, but the
data rendered in them originated from the target.

**The original is protected, and this is verified.** Each target is copied into a
per-run sandbox and every stage works on the copy. After a run, the original's
SHA-256 is re-checked to prove nothing modified it. If that verification ever
fails, treat it as a security bug and report it.

## Dual-use statement

RE-Toolkit is dual-use software. It installs and orchestrates tooling that can be
used to analyze, deobfuscate, and understand software, including software you did
not write.

It is intended for defensive security work: malware analysis, incident response,
vulnerability research, software assurance, and security assessment of systems you
own or are authorized to assess.

Do not use RE-Toolkit against binaries or systems you lack authorization to
analyze. Reverse engineering may be restricted by license terms or by law in your
jurisdiction. Determining what you are permitted to do is your responsibility.

Contributions that exist primarily to enable unauthorized access, evade defensive
controls, or weaponize output will not be accepted.
