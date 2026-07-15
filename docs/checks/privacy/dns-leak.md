# dns-leak

Checks whether your DNS lookups are being answered from outside your VPN tunnel, which would quietly reveal every site you visit even while the VPN is on.

**Category:** privacy · **Default severity:** warn · **Platforms:** all · **Runs every:** 300s (full scan)

## What it protects you from

Every time you open a website, your Mac first asks a DNS resolver to translate the name (like `example.com`) into an IP address. That question contains the name of every site you visit. When you connect to a VPN, you expect those DNS questions to travel *inside* the encrypted tunnel so nobody outside can see them.

A **DNS leak** happens when your VPN carries your web traffic but your DNS questions slip out over your normal internet connection instead. The result: your browsing looks private, but your internet provider (or whoever runs the resolver you're leaking to — including café or airport Wi-Fi) still sees a running list of every domain you look up. That defeats a big part of why you turned the VPN on. This check gives you a quick, honest signal that your DNS is actually going where your VPN goes.

## How it works

Each full scan, the check compares two independently discovered public IP addresses and sees whether they agree:

1. **Your DNS resolver's exit IP.** It runs `nslookup -type=txt o-o.myaddr.l.google.com ns1.google.com`. This asks one of Google's name servers a special question that makes it reply with the public IP of whichever resolver actually forwarded the request — in other words, where your DNS queries emerge onto the internet.
2. **Your VPN's public IP.** It reuses the public IP already discovered this scan (`OMS_PUBLIC_IP`) if an earlier check looked it up; otherwise it fetches it fresh via `get_public_ip`, which tries each endpoint in `checks.privacy.ip_address.services` in order (by default `ifconfig.me`, then `api.ipify.org`, then `icanhazip.com`), each with a 10-second timeout.

If those two IPs match, your DNS is exiting through the same place as the rest of your traffic — no leak. If they differ, your DNS is likely taking a different path.

For context, every outcome also prints your locally configured DNS servers, read with `scutil --dns` (nameserver entries, de-duplicated, up to the first six). This is a local read, involves no network call, and is **not** part of the pass/fail decision.

This check requires network access. Under `oh-my-safety scan --offline` it is skipped automatically and reported as `skipped (offline mode)`.

## What it flags (and how serious)

This check has no critical path — the worst it reports is a warning.

- **pass** — the resolver exit IP equals your VPN's public IP:
  `DNS resolver matches VPN IP — no leak`
- **warn** — the resolver exit IP is known but differs from your VPN's public IP (or the VPN IP couldn't be determined):
  `DNS resolver IP (<dns-ip>) differs from VPN IP (<vpn-ip-or-"unknown">) — possible leak`
- **info (treated as a pass)** — the resolver exit IP couldn't be determined at all (for example the DNS lookup failed), so no comparison is possible:
  `Could not determine DNS resolver IP (inconclusive)`

## What's baselined

None. This check is stateless — it re-measures the two IPs on every run and compares them fresh. Nothing is remembered between scans, so there is no "first run records quietly, later change flags" behavior.

## Permissions

None needed. It uses ordinary command-line tools (`nslookup`, `curl`, `scutil`) that require no Full Disk Access or any other special grant.

## Configuration

Config keys live under `checks.privacy.dns_leak`:

- `checks.privacy.dns_leak.enabled` — `true` by default.

It also relies on the shared public-IP endpoint list used across the privacy checks:

- `checks.privacy.ip_address.services` — the ordered list of services queried to learn your public (VPN) IP. Defaults to `ifconfig.me`, `api.ipify.org`, `icanhazip.com`.

Turn the check off or back on with:

    oh-my-safety disable dns-leak
    oh-my-safety enable  dns-leak

## Handling findings

- **To silence this check's alerts but still see it in `status`:** run `oh-my-safety ignore dns-leak` with **no finding-id**. That mutes the whole check. The runner honors an allowlist entry equal to the check name, so muting works even though dns-leak reports a single whole-check finding rather than individual items.
- **To stop it running entirely** (for example, you don't use a VPN and don't want the noise): `oh-my-safety disable dns-leak`.
- **After changing your VPN or DNS setup,** confirm the result with `oh-my-safety recheck dns-leak`.
- **Per-item ignore and baseline do not apply here.** `oh-my-safety ignore dns-leak <finding-id>` and `oh-my-safety accept` are meaningless for this check — it produces no per-item finding-ids and keeps no baseline.

## Limitations

- **It's a heuristic, not proof.** The test is a plain equality of two IPs. Many perfectly safe VPNs route DNS to their own resolver whose *egress* IP is not identical to your VPN *exit* IP — so this check can warn ("possible leak") even when your DNS is tunneled correctly. Treat a warning as "worth checking," not "definitely leaking."
- **It can be inconclusive.** If Google's TXT lookup fails or returns nothing, the resolver IP is unknown and the check reports "inconclusive" and passes — it will not warn on a leak it couldn't measure.
- **It leans on one measurement path.** The resolver identity comes specifically from `o-o.myaddr.l.google.com` via `ns1.google.com`; if that query is blocked, filtered, or rate-limited, the check simply can't decide.
- **Single resolver, single sample.** It reflects whichever resolver answers at that instant. Systems that rotate between resolvers, or leak only some queries, may show a clean result on one run and a warning on the next. It lists your configured DNS servers for context but does not test each of them, and it can't see encryption (DoH/DoT) or per-application split-DNS behavior.
- **A missing VPN IP still just warns.** If your public IP can't be fetched, the comparison can't confirm a match, so it reports a possible leak against an "unknown" VPN IP rather than staying silent.
