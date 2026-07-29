# linux-hardening-posture

**Category:** security · **Default severity:** warn · **Platforms:** linux · **Runs every:** 3600s

## What it protects you from

This check identifies missing host protections that make credential theft,
persistence, remote access, and recovery from compromise easier. It examines
the protections exposed by the running distribution without changing them.

## How it works

The check evaluates:

- LUKS/dm-crypt backing for the root filesystem when the block-device graph is
  visible.
- UEFI Secure Boot through `mokutil` when the machine is booted through EFI.
- An active ufw, firewalld, or nftables input policy.
- Enforcing SELinux or enabled AppArmor.
- Active SSH service and direct-root-login policy.
- A supported automatic security-update systemd timer.

Containers and machines that do not expose firmware or block-device state are
reported with explicit coverage notes. The check makes no network requests.

## Findings

- **Critical:** SSH permits direct root login.
- **Warn:** root disk appears unencrypted, Secure Boot is disabled, no active
  firewall is found, SELinux/AppArmor is disabled, unapproved SSH is active, or
  no supported security-update timer is enabled.
- **Skip:** none of the posture sources can be inspected.
- **Pass:** all inspectable controls pass; any remaining limitations are shown
  as informational coverage notes.

Each finding has a stable `linux-hard:*` identifier and can be individually
ignored after the risk is reviewed.

## Permissions and limitations

The check is useful as a normal user, but nftables, block-device, SSH, and
system-service details can be restricted. Missing access is never treated as
proof that a control is enabled. Firmware checks do not apply to BIOS-only
systems, and container disk encryption is owned by the host.

The presence of a firewall or mandatory-access-control system does not prove
that its policy is complete. This is a posture check, not a full policy audit.

## Configuration

```yaml
checks:
  security:
    linux_hardening_posture:
      enabled: true
      allow_remote_login: false
```

If SSH is an intentional service, set `allow_remote_login` to `true` and manage
its detailed policy separately.

After changing a setting, run:

```bash
oh-my-safety recheck linux-hardening-posture
```
