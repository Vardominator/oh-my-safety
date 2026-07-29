# Product vision

oh-my-safety is evolving from a periodic monitor and tripwire into a
local-first safety agent for personal computers, developer workstations,
servers, air-gapped systems, and organization-managed fleets.

The operating loop is:

```text
observe -> correlate -> assess -> propose or pre-authorize
        -> remediate -> verify -> learn
```

“Learn” means reviewed baselines and signed detector, policy, vulnerability,
and threat-intelligence updates. It does not mean self-modifying code,
unreviewed generated checks, or arbitrary commands running with elevated
privileges.

## Product guarantees

- Observation, scanning, correlation, evidence storage, policy evaluation, and
  remediation happen on the endpoint.
- Internet intelligence is optional and enters through explicit adapters or
  signed offline bundles. It is never required for core protection.
- A standalone endpoint remains useful without an account, controller, or
  external provider.
- The optional organization controller is self-hosted. Endpoints initiate
  connections and continue protecting the machine while disconnected.
- Organization reports use a closed redacted contract; sensitive evidence
  remains local. Any future evidence-sharing workflow would require a separate
  explicit, audited contract and cannot be introduced through ordinary policy.
- Automatic remediation is limited to low-risk, reversible actions approved by
  the local user or a signed organization policy. Files are never deleted by
  default, and arbitrary remote shell access is not a product capability.
- Missing permissions, stale data, failed collectors, and partial scans are
  shown as coverage gaps rather than a clean bill of health.
- macOS Homebrew, `brew services`, SwiftBar, existing CLI commands, config,
  state, baselines, allowlists, and upgrade paths remain supported throughout
  the runtime migration.

## Protection areas

### Endpoint posture and integrity

Continuously verify operating-system updates, disk encryption, Secure Boot,
firewalls, privileged accounts, remote access, authentication changes,
security services, package sources, persistence mechanisms, browser
extensions, trust stores, backup health, and the health of the agent itself.

Linux coverage targets Debian/Ubuntu and Fedora/RHEL-compatible distributions
first, including systemd services and timers, cron, SSH, sudoers/PAM, kernel
modules, udev, package integrity, SELinux/AppArmor, LUKS, listeners, and
containers.

### Secrets and malware

Use bounded local scanners for Git history, configuration files, logs,
archives, downloads, newly created executables, and changed persistence
targets. Raw secrets must never enter logs, notifications, or the organization
controller. Findings retain only redacted metadata and per-install
fingerprints.

Pattern scanning, code provenance, package ownership, process ancestry,
persistence, and network metadata are complementary signals. The product does
not claim that any one engine or a valid signature proves a file is safe.

### Recovery and remediation

Track backup freshness, snapshot deletion, ransomware canaries, and suspicious
bursts of writes, renames, or deletes. Remediation is transactional:
precondition check, dry run, authorization, backup, action, verification, and
rollback. Quarantine preserves the original path, metadata, hash, and recovery
instructions.

### Internet exposure

Connected profiles may explicitly monitor approved emails, domains,
repositories, cloud accounts, and public assets using breach feeds, DNS/RDAP,
certificate transparency, provider-native secret alerts, and read-only cloud
or identity APIs. The adapter must disclose every endpoint, field sent,
credential scope, retention assumption, and offline behavior.

Internet-side leaks cannot be discovered without an internet-side observation
source. Air-gapped profiles consume signed offline intelligence instead.

### Organization management

The self-hosted controller provides per-device enrollment, signed policies,
endpoint groups, expiring exceptions, role-based administration, staged
rollouts, fleet health, redacted finding lifecycle, and an immutable admin
audit trail. It never becomes a general-purpose remote execution channel.

## Profiles

Profiles are composed from independent policy axes:

- workload: `workstation`, `developer`, or `server`
- protection: `balanced` or `strict`
- management: `standalone` or `managed`
- connectivity: `connected`, `offline`, or `airgapped`

The initial presets are Personal Balanced, Personal Strict, Developer, Managed
Workstation, Managed Server, and Air-Gapped High Assurance.

## Delivery order

1. Make releases, Homebrew, SwiftBar, documentation, CI, scan state, and
   notification lifecycle trustworthy.
2. Introduce the portable agent core while retaining the Bash check adapter and
   all public compatibility contracts.
3. Deliver Linux packages, systemd services, and Linux endpoint checks.
4. Add bounded secret, malware, dependency, backup, and exposure adapters.
5. Add the self-hosted organization controller.
6. Add privileged real-time collectors and strict-mode prevention only after
   their entitlement, kernel, privacy, performance, and false-positive risks
   are adequately tested.
7. Add high-assurance signed offline content, stronger tamper evidence, and
   hardware-backed identity.

Features are documented as shipped only after their installation,
configuration, migration, privacy, and failure behavior are covered by CI.
