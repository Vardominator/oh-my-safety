# linux-persistence-scan

**Category:** security · **Default severity:** critical · **Platforms:** linux · **Runs every:** 600s

## What it protects you from

Linux malware and unauthorized administrators commonly persist through
systemd units, desktop autostart files, cron jobs, shell startup files, or the
dynamic linker preload mechanism. This check records the visible startup
surface and reports newly added or changed entries.

## How it works

The local snapshot includes:

- User and system systemd service/timer files and enabled units.
- Desktop autostart entries.
- The current user's crontab and system cron files.
- SHA-256 fingerprints for common shell startup files.
- Presence of `/etc/ld.so.preload`.

The first run creates a local baseline and tells the user to review it. Later
runs report additions, removals, and changed startup-file fingerprints. A
snapshot containing changes is staged as pending and is not trusted until it is
approved.

## Findings

- **Critical:** `/etc/ld.so.preload` appears after the baseline.
- **Warn:** a unit, cron entry, autostart file, or shell-startup fingerprint is
  added or changed.
- **Info:** a previously baselined item disappears.
- **Pass:** no new persistence is found.

Finding IDs contain the persistence type and stable path or unit identifier.
They never include file contents.

## Responding

Inspect the unit, cron entry, or startup file and remove it using the owning
package or service manager when it is unexpected. Then run:

```bash
oh-my-safety recheck linux-persistence-scan
```

If all pending changes are trusted:

```bash
oh-my-safety accept linux-persistence-scan
```

To accept only one item:

```bash
oh-my-safety ignore linux-persistence-scan '<finding-id>'
```

## Permissions and limitations

Normal users can inventory their own persistence and world-readable system
configuration. Root-only units and cron files may be invisible; that reduced
coverage should be considered when assessing a managed endpoint.

The first baseline can contain pre-existing compromise. Review it or deploy a
known-good signed organization baseline before relying on drift detection.
