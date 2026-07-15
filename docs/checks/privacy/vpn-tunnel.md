# vpn-tunnel

Checks whether a VPN tunnel network interface is currently up on your Mac, so you can tell at a glance whether your VPN is actually connected.

**Category:** privacy · **Default severity:** warn · **Platforms:** all · **Runs every:** 300s (full scan)

## What it protects you from

A VPN only protects you while it is connected. VPN apps drop silently more often than people realize — after your Mac wakes from sleep, when Wi-Fi switches networks, when a session token expires, or when the app just crashes. When that happens the menu-bar icon does not always tell the truth, and your traffic quietly falls back to your regular, un-tunneled connection. From that moment on, every site you visit sees your real ISP address and your real location, exactly as if the VPN were never there.

This check is the simple, direct answer to "is my VPN actually up right now?" It looks for the network interface a VPN creates while connected. If that interface exists, a tunnel is up; if it has vanished, your VPN is disconnected and you are browsing in the clear. Think of it as a dashboard light for your VPN, not a deep security scan.

## How it works

This is a **local** check — it inspects your Mac's own network interfaces and makes **no network calls**. It is marked `CHECK_REQUIRES_NETWORK=false`.

1. It calls `get_vpn_interfaces`, which on macOS runs:
   ```
   ifconfig 2>/dev/null | grep -E "^(utun|tun|ppp|ipsec|wg)" | cut -d: -f1
   ```
   This lists every active network interface whose name starts with `utun`, `tun`, `ppp`, `ipsec`, or `wg` — the interface types VPN clients create (modern IKEv2/WireGuard VPNs typically appear as `utun`, OpenVPN as `tun`, older setups as `ppp` or `ipsec`).

2. For each interface it finds, it looks up that interface's address with `get_interface_ip`:
   ```
   ifconfig "<iface>" 2>/dev/null | grep "inet " | awk '{print $2}'
   ```
   and prints a pass line naming the interface and its IP.

3. If at least one tunnel interface was found, the check passes. If none were found, it warns.

Because it never touches the network, this check runs identically whether or not you are online, and it does **not** self-skip under `scan --offline` (unlike the network-based privacy checks such as `dns-leak` and `ipv6-leak`, which do skip when offline).

## What it flags (and how serious)

The code has exactly two outcomes — there is no `critical` path:

- **Pass** — for each tunnel interface found it prints:
  `Tunnel interface <iface> up (<ip>)` (the `(<ip>)` part is omitted if the interface has no `inet` address, e.g. `Tunnel interface utun4 up (10.2.0.6)`). The overall finding summary is **"VPN tunnel active"**.
- **Warn** — if no tunnel interface exists at all, it prints:
  `No VPN tunnel interfaces found — VPN may be disconnected`
  with the finding summary **"No VPN tunnel interface"** at **warn** severity, which raises a warning-level notification (subject to your notification settings).

## What's baselined

Nothing. This check is completely stateless. It keeps no baseline, records nothing between runs, and simply reports which interfaces are up at the moment it runs. There is no first-run snapshot and no drift comparison.

## Permissions

None. Reading `ifconfig` output works as an ordinary user, so the check needs no Full Disk Access and no TCC (privacy) permission.

## Configuration

Config keys under `checks.privacy.vpn_tunnel` in `~/.config/oh-my-safety/config.yaml`:

- `checks.privacy.vpn_tunnel.enabled` — default `true`. Turns the check on or off.
- `checks.privacy.vpn_tunnel.interfaces` — default list `utun*`, `tun*`, `ppp*`, `ipsec*`, `wg*`.
  **Heads-up:** despite living under this check's key, this list is **not** read by the `vpn-tunnel` check. Its detection uses the fixed `^(utun|tun|ppp|ipsec|wg)` pattern baked into `get_vpn_interfaces`. The configurable list is consumed only by the shared `is_vpn_interface` helper, which powers the `routing` check. Editing `interfaces` changes that check, not the tunnel-presence test here.

Enable or disable the check with:

    oh-my-safety disable vpn-tunnel
    oh-my-safety enable  vpn-tunnel

## Handling findings

- **Silence the alert but keep seeing it in `status`:** run `oh-my-safety ignore vpn-tunnel` with **no finding-id**. This mutes the whole check. The scan runner honors an allowlist entry equal to the check's own name, so even though this check reports a single whole-check finding, the mute takes effect: the warn is downgraded to a muted entry and no notification fires, while the check still appears in `status`.
- **Stop it running entirely** (for example, you do not use a VPN and never want this alert): `oh-my-safety disable vpn-tunnel`.
- **After you reconnect your VPN**, confirm the tunnel is back up with:

      oh-my-safety recheck vpn-tunnel

- **Per-item `ignore` and `accept` do not apply here.** This check produces no per-item finding-ids, so `oh-my-safety ignore vpn-tunnel <finding-id>` has nothing specific to target — use the no-id whole-check form above instead. And because there is no baseline, `oh-my-safety accept vpn-tunnel` does nothing meaningful either.

## Limitations

- **Presence, not protection.** It only confirms a tunnel interface *exists* — not that your traffic is actually routed through it. A tunnel can be up while your default route still bypasses it (split tunnel, or a half-torn-down connection). Proving traffic is routed through the VPN is the job of the separate `routing` check.
- **False positives.** macOS and other software create tunnel interfaces for reasons unrelated to a privacy VPN — Handoff/Continuity, a corporate VPN, a self-hosted WireGuard link, virtualization or container networks, or a leftover interface. Any of these registers as "VPN tunnel active."
- **False negatives / name-based detection.** A VPN that uses an interface name outside the fixed `utun/tun/ppp/ipsec/wg` prefixes is not recognized, producing a false "disconnected" warning while it is actually running. Because this check ignores the configurable `interfaces` list, you cannot teach it new prefixes from config.
- **Point-in-time only.** It samples once per full scan (every 300s by default), so a brief disconnect-and-reconnect between scans can be missed.
- **Userspace only.** Like all oh-my-safety checks, it runs as your user and trusts what the OS reports. Root-level malware that tampers with `ifconfig` output could hide a disconnected VPN from this check.
