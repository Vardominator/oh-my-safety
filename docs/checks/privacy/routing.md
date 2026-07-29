# routing

Checks that the endpoint's default internet route goes out through a recognized
VPN tunnel rather than the ordinary physical interface.

**Category:** privacy · **Default severity:** warn · **Platforms:** all · **Runs every:** 300s (full scan)

## What it protects you from

Having a VPN app "connected" is not the same as having your traffic go through
it. macOS and Linux choose where packets leave using a routing table, and the
important entry is the *default route*. If that route points at ordinary
Wi-Fi or Ethernet instead of the VPN tunnel, traffic may bypass the VPN even
though its app still shows a reassuring "connected" badge.

This can happen when a VPN connects but fails to install itself as the default route, when a split-tunnel setting sends "everything" out the wrong interface, or when a tunnel drops and the OS falls back to your physical connection. This check is the "is my traffic really going through the VPN?" test that complements the `vpn-tunnel` check (which only confirms a tunnel *interface* exists).

## How it works

The check makes **no network calls**. It only reads your local routing table and interface names, so it works fully offline and is **not** skipped by `scan --offline` (only checks that require network access are skipped in offline mode).

On macOS it reads the current default route with:

    netstat -rn | grep "^default" | head -1 | awk '{print $NF}'

That returns the interface name the first default route uses (for example `en0` for Wi-Fi or `utun4` for a tunnel). It then asks `is_vpn_interface` whether that name looks like a VPN interface. That helper matches the name against the glob list `checks.privacy.vpn_tunnel.interfaces` (by default `utun*`, `tun*`, `ppp*`, `ipsec*`, `wg*`); if no list is configured it falls back to the built-in pattern `^(utun|tun|ppp|ipsec|wg)`.

On Linux it reads the first `ip route show default` entry and extracts its
`dev` interface. Linux currently recognizes fixed `tun`, `tap`, `wg`, and
`ppp` prefixes; the configurable macOS glob list does not alter Linux
detection.

For context, when it reports it also prints the full default-route line from `get_default_route`:

    netstat -rn | grep "^default" | head -1

Separately, the background agent runs a lightweight version of this logic on
its configured fast interval (15 seconds by default) to catch a sudden route
flip between full scans.

## What it flags (and how serious)

There is no "critical" outcome for this check — only pass and warn.

- **Pass** — the default route's interface is a VPN interface. It prints `Default route via VPN (<iface>)` followed by the full route line, with the summary `Default route via <iface> (VPN)`.
- **Warn** — the default route's interface is *not* recognized as a VPN. It prints `Default route via <iface> — traffic may not be VPN-protected` plus the route line, with the summary `Default route via <iface> (not VPN)`.
- **Warn** — no default route could be found at all. It prints `Could not determine the default route`, with the summary `No default route`.

When the background agent hits either warn condition it raises a warning-level notification, subject to your notification settings.

## What's baselined

Nothing. This check is stateless: every run is a fresh look at the current default route. It keeps no history and has nothing to drift from, so there is nothing to accept or compare against.

## Permissions

No elevated permission is needed. macOS uses `netstat -rn`; Linux uses
`ip route`. Both inspect routing state available to the user, and the check
never self-skips for a macOS privacy permission.

## Configuration

Config for this check lives under `checks.privacy.routing`, and its VPN detection reuses the shared interface list under `checks.privacy.vpn_tunnel`:

    checks:
      privacy:
        routing:
          enabled: true
        vpn_tunnel:
          interfaces:
            - utun*
            - tun*
            - ppp*
            - ipsec*
            - wg*

- `checks.privacy.routing.enabled` (default `true`) — turns this check on or off.
- `checks.privacy.vpn_tunnel.interfaces` (default the list above) — on macOS,
  the glob patterns that count as "VPN". This check has no interface list of
  its own. Linux currently uses fixed `tun|tap|wg|ppp` prefixes.

Turn the check on or off with:

    oh-my-safety disable routing
    oh-my-safety enable  routing

## Handling findings

- **Silence the alerts but keep seeing it in `status`:** run `oh-my-safety ignore routing` with **no** finding-id. This mutes the whole check — it still runs, but its warnings are suppressed. The runner honors an allowlist entry equal to the check name, so this works even though `routing` reports a single whole-check finding rather than a list of items.
- **Stop it running entirely** (for example, you don't use a VPN and never will): `oh-my-safety disable routing`.
- **After fixing your setup**, confirm it now passes with: `oh-my-safety recheck routing`.

Per-item and baseline commands do **not** apply here. `routing` produces no per-item finding-ids, so `oh-my-safety ignore routing <finding-id>` has nothing specific to target — use the no-id whole-check mute above instead. And `oh-my-safety accept routing` does nothing meaningful, because this is not a baseline/drift check.

## Limitations

- **Name-based detection, not proof of protection.** It only checks that the default route's *interface name* looks like a VPN. It does not verify that packets actually reach the VPN server, that your DNS isn't leaking, or that the tunnel is healthy — those are covered by the `dns-leak`, `ipv6-leak`, and `vpn-tunnel` checks.
- **False positives.** A VPN that uses an interface name outside the configured `utun/tun/ppp/ipsec/wg` patterns will be reported as "not VPN-protected" even while it is working. Add its pattern to `checks.privacy.vpn_tunnel.interfaces` to fix this.
- **False passes.** Any tunnel-named interface counts as "VPN" — including a corporate VPN, a self-hosted WireGuard link, or a virtualization/container network — so it may report "Default route via VPN" for a tunnel that isn't your privacy VPN.
- **Only the first default route.** It inspects one `netstat` entry on macOS or
  one `ip route` entry on Linux. Split-tunnel setups and more-specific routes
  are not analyzed.
- **Timing.** In the background agent the full check runs about every 300s. A brief route flip between scans could be missed, though the agent's separate fast route-flip watcher (~15s) is designed to catch sudden changes sooner.
- **Userspace only.** Like all oh-my-safety checks it runs as your user and trusts what the OS reports; privileged malware that tampers with the routing table's appearance could hide a bad route from this check.
