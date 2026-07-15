# Security policy

oh-my-safety is a security tool, so vulnerabilities in it matter. This page
explains how to report one and the security properties we commit to.

## Reporting a vulnerability

Please **do not** open a public issue for a security vulnerability. Instead, use
GitHub's private vulnerability reporting on the repository
(**Security → Report a vulnerability**), or email the maintainer listed in the
repository profile. Include:

- what the issue is and its impact,
- steps or a proof of concept to reproduce it,
- the version (`oh-my-safety version`) and macOS version.

We aim to acknowledge reports promptly and to credit reporters (unless you
prefer to remain anonymous) once a fix ships.

## What's in scope

- Any way oh-my-safety could be made to **exfiltrate data** or make a network
  call from a security check (this must never happen — see below).
- **Privilege issues**: unintended use of `sudo`, or writing outside the user's
  own config/state directories.
- **False assurance**: a check reporting "pass" while the condition it claims to
  verify is actually unsafe, in a way a reasonable user would be misled by.
- Command injection or unsafe handling of attacker-influenced input (filenames,
  process arguments, plist contents) within the checks.

## Security properties we commit to

- **No network calls from security checks.** Enforced in CI by a `grep` gate over
  `lib/checks/security/`. The only network traffic comes from the clearly-labeled
  privacy checks (see [privacy.md](privacy.md)).
- **No telemetry, ever.** Nothing is uploaded from anywhere in the tool.
- **Least privilege.** The tool never requires `sudo`; state lives under the
  user's own `~/.local/state/oh-my-safety` (mode 700). Full Disk Access is
  optional and only used to read data the user explicitly wants audited.
- **No auto-downloaded code or rules.** Opt-in scanners (gitleaks/trufflehog/YARA)
  are only invoked if you install and enable them; YARA rules are never fetched.

## Known limitations (not vulnerabilities)

The [threat model](threat-model.md) documents what oh-my-safety fundamentally
cannot detect (kernel rootkits, root-level tampering, sub-scan-interval
processes, stolen-Developer-ID malware). These are inherent to a userspace,
poll-based tool and are documented rather than treated as bugs.
