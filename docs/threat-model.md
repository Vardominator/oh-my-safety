# Threat model — what oh-my-safety does and doesn't protect against

oh-my-safety is a local-first endpoint safety agent, not a complete antivirus or
EDR. This page is an honest account of what it can and cannot do.

## The threats it's built for

### macOS infostealers (Atomic Stealer / AMOS and family)
This is the dominant real-world macOS threat: malware distributed through fake
or cracked apps that, once run, tries to steal your Keychain, browser data, and
crypto wallets, and exfiltrate them. oh-my-safety watches the whole kill chain:

| Stage of the attack | Check that watches for it |
|---------------------|---------------------------|
| You're tricked into running a malicious/cracked app | **process-audit** flags unsigned/adhoc binaries running from drop zones (`/tmp`, `/var/folders`, `~/Downloads`) |
| It shows a fake "enter your macOS password" dialog | **process-audit** flags `osascript` processes prompting for a password (the AMOS signature) |
| It reads your crypto wallets / seed phrases | **wallet-guard** inventories desktop + browser-extension wallets and flags world-readable or cloud-synced wallet data; **secrets-exposure** flags seed/password notes in unprotected folders |
| It installs itself to survive reboots | **persistence-scan** flags new LaunchAgents/Daemons, login items, cron jobs, and config profiles |
| It opens a backdoor / beacons out | **network-exposure** flags new listening services (critical if the binary is unsigned) |
| It grants itself Full Disk Access / screen recording | **tcc-audit** flags new sensitive TCC grants |

### Privacy exposure
The **privacy** checks verify your VPN is actually protecting you: that traffic
routes through the tunnel and that your IP, DNS, and IPv6 aren't leaking.

### Drifting into an insecure state
**hardening-posture** catches the slow erosion of your defenses — SIP or
Gatekeeper turned off, FileVault disabled, the firewall off, remote login left
on, or XProtect definitions gone stale — and tells you how to fix each.

On Linux, **linux-hardening-posture** covers visible LUKS, Secure Boot,
firewall, SELinux/AppArmor, SSH, and automatic-update posture, while
**linux-persistence-scan** watches systemd units/timers, cron, desktop autostart,
shell startup files, and `/etc/ld.so.preload`.

### Credential and public exposure

The built-in portable scanner and opt-in gitleaks/trufflehog adapters find
high-confidence credential material locally while retaining only redacted
metadata and fingerprints. Optional HIBP adapters can check a password through
k-anonymity or an explicitly approved email address through an authenticated
breach lookup. These sources are incomplete and delayed; “not found” is not
proof that a credential is private.

`oh-my-safety triage-executable PATH` can also hash a specifically selected
local executable and report bounded ownership, mode, location, and
explainable-risk signals. This is manual triage, not a scheduled file-event
collector, signature database, or malware verdict.

## What it deliberately does NOT do

- **It is not a full antivirus and does no privileged real-time blocking.** It
  detects and alerts; it does not delete, quarantine, or kill by default. OS
  controls and a reputable AV/EDR remain enforcement layers.
- **It cannot see kernel-level rootkits** or anything hiding below userspace.
- **It cannot detect malware running as root** that tampers with its own state,
  baselines, or the binary itself. The state directory is user-writable by design.
- **It polls; it doesn't hook.** A process that starts and exits between scans
  can be missed. (The osascript-phishing detector works because such dialogs
  stay open, but there's no guarantee.)
- **Signature checks trust Apple's Developer ID PKI.** Malware signed with a
  stolen or rented Developer ID passes the signature check until Apple revokes it.
- **Content scanning is bounded.** The built-in scanner enforces limits and
  skips binaries, symlinks, devices, and oversized content. Optional external
  scanners and YARA coverage depend on the rules and paths you configure.
- **Internet-side observation is necessarily external.** A fully local process
  cannot discover a paste, breach corpus, public repository, certificate log,
  or cloud-account change it never observes. Connected adapters disclose their
  documented minimum fields; air-gapped profiles cannot use them.
- **Organization visibility is not omniscience.** The optional self-hosted
  controller receives only the versioned redacted report contract, can be
  unreachable, and cannot prove that a privileged attacker did not forge or
  suppress endpoint telemetry. It is a fleet visibility and policy service,
  not remote attestation, MDM, or an EDR command channel.
- **Heuristics have false positives.** A legitimate app you just installed will
  show up as "new persistence"; a dev server is a "new listener". That's why
  every finding can be `ignore`d or `accept`ed — see [handling findings](configuration.md#responding-to-findings).

## How to think about it

Treat oh-my-safety as an always-on **smoke detector and posture verifier**. It
can correlate more signals over time, verify a remediation, and keep a local
history, but it cannot establish that an endpoint is clean. Combine it with
updates, disk encryption, tested backups, phishing-resistant authentication,
least privilege, OS defenses, and—where the risk warrants it—AV/EDR and
central identity/security controls.
