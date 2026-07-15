# ipv6-leak

Checks whether your Mac has a globally reachable IPv6 address that would expose your real location even when your VPN only protects IPv4 traffic.

**Category:** privacy · **Default severity:** warn · **Platforms:** all · **Runs every:** 300s (full scan)

## What it protects you from

Most consumer VPNs tunnel your IPv4 traffic but do nothing about IPv6. If your internet connection also has IPv6 (many home and mobile networks do), your Mac can keep reaching the internet directly over IPv6 while everything else goes through the VPN. That is an **IPv6 leak**: a website, tracker, or anyone watching can read your real IPv6 address — which ties back to your ISP and rough physical location — even though the VPN made you look anonymous over IPv4.

The whole point of a VPN is to hide the address that identifies you. An IPv6 leak quietly punches a hole in that, and you would never notice from the VPN app itself: the "what is my IP" page shows the VPN's IPv4 while every page you load can still log your genuine IPv6 on the side. This check is a quick sanity test that your real IPv6 address is not escaping.

## How it works

The check asks the internet what address it sees you coming from, over IPv6 if possible:

1. **Your visible IPv6 address.** It calls `get_ipv6_address`, which on macOS runs `curl -s --max-time 5 https://api64.ipify.org`. That endpoint answers over whichever protocol your machine actually connects with: if your Mac has working, routable IPv6, curl connects over IPv6 and the service echoes back an IPv6 address (something with colons, like `2601:...`); if IPv6 is blocked or unavailable, the connection falls back to IPv4 or returns nothing.
2. **Your VPN's IPv4 exit address.** It reuses `OMS_PUBLIC_IP` if an earlier check in the same scan already looked it up; otherwise it calls `get_public_ip`, which fetches over HTTPS from the services in `checks.privacy.ip_address.services` (by default `ifconfig.me`, then `api.ipify.org`, then `icanhazip.com`).

It then compares the two and decides:

- No address came back → treats IPv6 as blocked/unavailable (pass).
- The address it got equals your IPv4 exit → the lookup fell back to IPv4, so there is no separate IPv6 path (pass).
- The address contains a colon (`:`) → it is a real, reachable IPv6 address that is not your VPN exit — flagged as a leak (warn).
- Anything else (a non-empty, colon-free value that differs from your exit) → treated as tunneled (pass).

This is a **privacy** check, so it does make network calls: one HTTPS request to `api64.ipify.org` and (unless the public IP was already cached this scan) one HTTPS request to an IP-echo service. It inspects no local files, system databases, or network interfaces. It self-skips under `scan --offline` and reports `skipped (offline mode)`.

## What it flags (and how serious)

This check has no `critical` path — the worst outcome is `warn`. The code implements four outcomes, in this order:

- **Pass** — `IPv6 appears blocked or unavailable — no leak`: nothing came back from `api64.ipify.org`.
- **Pass** — `IPv6 matches IPv4 exit — no leak`: the returned address equals your public IPv4 exit.
- **Warn** — `IPv6 leak detected: <address>`: the returned address contains a colon, meaning it is a real IPv6 address that differs from your IPv4 exit. It also prints `Your real IPv6 address may be exposed`. This is the one condition that raises an alert.
- **Pass** — `IPv6 traffic tunneled through VPN — no leak`: a non-empty, colon-free address that differs from your IPv4 exit; treated as tunneled traffic.

## What's baselined

Nothing. This check keeps no baseline and records no state between runs. Every scan is a fresh, stateless test of "is a public IPv6 address visible right now?" There is no first-run snapshot and no drift comparison.

## Permissions

None needed. It requires no Full Disk Access and no TCC (privacy) grant — only `curl` and working outbound network access to reach `api64.ipify.org` and the IP-echo service.

## Configuration

Read from `~/.config/oh-my-privacy/config.yaml`:

- `checks.privacy.ipv6_leak.enabled` — default `true`.
- `checks.privacy.ip_address.services` — the shared list of IP-echo endpoints used to learn the VPN's IPv4 exit when it isn't already cached for the scan. Defaults: `ifconfig.me`, `api.ipify.org`, `icanhazip.com`.

The IPv6 lookup endpoint (`api64.ipify.org`) is hard-coded in the platform layer and is not configurable.

Enable or disable it:

    oh-my-safety disable ipv6-leak
    oh-my-safety enable  ipv6-leak

## Handling findings

- **Silence the alert but keep it in `status`:** `oh-my-safety ignore ipv6-leak` (with **no** finding-id) mutes the whole check. The runner honors an allowlist entry equal to the check name, so this works even though the check reports a single whole-check finding — a muted result then shows up as `muted by user` instead of alerting.
- **Stop it running entirely** (for example, you don't use a VPN, so a visible IPv6 isn't a concern): `oh-my-safety disable ipv6-leak`.
- **After changing your setup** (enabling your VPN's IPv6 protection, or disabling IPv6 on your network), confirm with `oh-my-safety recheck ipv6-leak`.
- **Per-item `ignore` and `accept` do not apply.** This check emits one whole-check finding keyed on its name — it has no per-item finding-ids, so `oh-my-safety ignore ipv6-leak <finding-id>` has nothing to target, and it keeps no baseline, so `oh-my-safety accept ipv6-leak` does nothing.

To actually fix a real leak, the change lives in your VPN or network settings: turn on your VPN's "IPv6 leak protection" / kill switch, choose a VPN that tunnels IPv6, or disable IPv6 on the interface you use (e.g. `networksetup -setv6off Wi-Fi`). Then recheck.

## Limitations

- **It is not actually VPN-aware.** It flags *any* globally-visible IPv6 address as a "leak," whether or not you are running a VPN. If you use IPv6 normally without a VPN, or your VPN legitimately tunnels IPv6 (its own IPv6 exit still contains a colon), you will still get a warn even though nothing is wrong. Treat the finding as "a public IPv6 address is reachable," not as proof your VPN is broken.
- **It cannot distinguish tunneled IPv6 from leaked IPv6.** The verdict rests entirely on what `api64.ipify.org` reports; the check has no way to tell whether that IPv6 went through the VPN or around it.
- **The "matches IPv4 exit" pass is effectively unreachable for a real IPv6 address**, since an IPv6 string will never equal an IPv4 string — so any genuine IPv6 falls through to the warn branch.
- **Point-in-time only.** It tests once per full scan (every 300s by default). A leak that appears and disappears between scans can be missed.
- **Depends on reachability.** If `api64.ipify.org` is blocked or unreachable, the result comes back empty and is read as "IPv6 blocked" — so a real leak could be missed when that endpoint is down. The lookup operators also see your request, an inherent trade-off of any external IP-detection check.
- **Userspace check.** Like all of oh-my-safety, it runs as an ordinary user process and trusts the OS network stack; root-level malware could block, spoof, or reroute these lookups to hide a leak.
