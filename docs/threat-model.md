# Threat model — what oh-my-safety does and doesn't protect against

oh-my-safety is a **monitor and tripwire**, not an antivirus. This page is an
honest account of what it can and cannot do, so you can rely on it
appropriately.

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

## What it deliberately does NOT do

- **It is not antivirus and does no real-time blocking.** It detects and alerts;
  it does not quarantine or kill anything. macOS **Gatekeeper** and **XProtect**
  remain your enforcement layer — which is exactly why hardening-posture checks
  they're on and current.
- **It cannot see kernel-level rootkits** or anything hiding below userspace.
- **It cannot detect malware running as root** that tampers with its own state,
  baselines, or the binary itself. The state directory is user-writable by design.
- **It polls; it doesn't hook.** A process that starts and exits between scans
  can be missed. (The osascript-phishing detector works because such dialogs
  stay open, but there's no guarantee.)
- **Signature checks trust Apple's Developer ID PKI.** Malware signed with a
  stolen or rented Developer ID passes the signature check until Apple revokes it.
- **Content scanning is opt-in and shallow by default.** The core never reads
  the contents of your files — only filenames and permissions. Deep content
  scanning requires you to enable gitleaks/trufflehog.
- **Heuristics have false positives.** A legitimate app you just installed will
  show up as "new persistence"; a dev server is a "new listener". That's why
  every finding can be `ignore`d or `accept`ed — see [handling findings](configuration.md#responding-to-findings).

## How to think about it

Treat oh-my-safety as an always-on **smoke detector** for your Mac: it won't put
out a fire, but it will tell you — quickly and specifically — when something
changed that deserves your attention, and it keeps a local, private record of
what "normal" looks like for your machine. Combine it with the basics it can't
replace: keep macOS updated, keep Gatekeeper/FileVault/XProtect on, and don't run
untrusted apps.
