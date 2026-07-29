# Roadmap and implementation status

The product direction is described in [Product vision](vision.md). This page
separates working implementation from research so an aspirational feature is
never mistaken for protection that already exists.

## Released compatibility surface

The v0.2 compatibility line provides:

- the Bash 3.2 CLI, macOS privacy and security checks, config, local baselines,
  allowlists, finding handling, launchd service, and SwiftBar;
- Homebrew stable installation and an immutable-source installer;
- versioned check and status contracts preserved by the portable-core work.

The v0.2 line remains installable for compatibility; v0.3.0 is the current
feature release.

## Released in v0.3.0

Runtime and visibility:

- per-check scheduling, one non-overlapping global scan, stale-lock recovery,
  safe config reload, and partial-scan reconciliation;
- per-item open/re-alert/resolve notification lifecycle and explicit collector
  failure findings;
- append-only local event history plus deterministic ingestion into a SQLite
  event journal and replayable current-finding projection;
- composable personal, strict, developer, managed, server, offline, and
  air-gapped profiles.

Endpoint protection:

- macOS and Linux posture, persistence, network, process, permission, privacy,
  wallet, and TCC checks where supported;
- bounded local secret detection with redacted output and per-install HMAC
  fingerprints;
- bounded manual executable triage with hashes, ownership metadata, and
  explainable signals rather than unsupported “malware” verdicts; the scanner
  contract is ready for a later file-event collector;
- existing opt-in gitleaks, trufflehog, and local YARA adapters;
- opt-in HIBP password k-anonymity and breached-account adapters with explicit
  disclosure contracts and offline denial.

Operations:

- native desktop notification plus explicit SendGrid, Telegram, WhatsApp,
  Discord, and generic webhook channels;
- Debian/Ubuntu and Fedora/RHEL-compatible deb/rpm/tar packaging and a systemd
  user service;
- a self-hosted organization-controller MVP with secure bootstrap, enrollment,
  grouped signed policies, redacted findings, role-based administration, and
  audit history;
- signed, bounded, declarative offline-intelligence bundles with pinned
  Ed25519 trust, expiry, schema compatibility, atomic installation, and
  rollback prevention;
- GitHub Actions gates for Bash/Go tests, race detection, vet, reachable Go
  vulnerability analysis, docs, macOS, Homebrew stable/HEAD, SwiftBar, Linux
  package installation, controller binaries, release checksums, and formula
  updates.

## Next hardening milestones

These require careful design and are not current guarantees:

1. Run long-duration daemon, suspend/resume, upgrade, and fault-injection tests
   across supported macOS and Linux versions.
2. Add file-event collectors for changed executables and persistence targets,
   while retaining a polling fallback and strict resource limits.
3. Add reversible remediation transactions: precondition, dry run, user/policy
   authorization, backup, action, verification, and rollback.
4. Add package-manager integrity and dependency inventory adapters, then
   evaluate signed vulnerability records locally.
5. Add backup freshness, snapshot-deletion detection, ransomware canaries, and
   bounded file-change burst correlation.
6. Add browser-extension inventory, trust-store changes, privileged-account
   drift, SSH/sudo/PAM changes, kernel modules, udev, containers, and stronger
   agent self-integrity checks.
7. Add controller HA/backup automation, SSO/OIDC, rate limiting, staged policy
   rollout and acknowledgement, expiring exceptions, mTLS or hardware-backed
   device identity, and externally sealed audit checkpoints.
8. Add more internet-side sources only as explicit read-only adapters:
   provider-native repository secret alerts, domain/DNS/RDAP and certificate
   transparency monitoring, and scoped cloud/identity posture.

## High-assurance research

Privileged prevention, kernel/system extensions, real-time blocking, automated
quarantine, and hardware-backed attestation can materially affect reliability
and privacy. They will not ship merely as aggressive profile toggles. Each
needs platform entitlements, an explicit threat model, performance budgets,
false-positive controls, recovery behavior, and adversarial testing.

Air-gapped deployments remain useful without any network dependency. Their
evolution path is signed offline content, reproducible builds, removable-media
import procedures, stronger tamper evidence, and offline audit export—not a
hidden cloud requirement.

## Compatibility policy

- The `oh-my-privacy` alias and legacy flags remain deprecated compatibility
  shims until a future major release.
- Checks declare `CHECK_CONTRACT`; a newer contract is skipped visibly instead
  of being executed incorrectly.
- Homebrew, `brew services`, SwiftBar, config paths, state migrations, and
  machine-readable status formats are release gates.

Have a detector idea? Start with the documented
[custom-check contract](extending.md) and the security requirements in
[Contributing](../CONTRIBUTING.md).
