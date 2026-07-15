# ip-address

Fetches and shows your current public IP address so you can confirm the world sees your VPN's server, not your real home connection.

**Category:** privacy · **Default severity:** warn · **Platforms:** all · **Runs every:** 300s (full scan)

## What it protects you from

Your public IP address is the number every website, app, and server you contact can see. Left unprotected, it maps back to your real internet connection: your ISP, your rough physical location (often your city or neighborhood), and a value that can tie your browsing back to you and your household over time. Using a VPN is supposed to hide this — outsiders should see the VPN server's IP instead of yours.

The problem is that VPNs fail quietly. The app may say "Connected" while the tunnel has actually dropped, or it may never have carried the traffic you assumed it did. When that happens, your real IP is exposed and there is no obvious sign. This check pulls the IP the outside world sees right now and puts it in front of you, so you can eyeball it and confirm it is your VPN's address and not your own.

It is a reporting check, not an alarm: it hands you the number and lets you judge it. The related `vpn-tunnel`, `routing`, `dns-leak`, and `ipv6-leak` checks are the ones that actively flag leaks.

## How it works

This is a privacy check, so it deliberately makes an **outbound network call** (it is marked `CHECK_REQUIRES_NETWORK=true`). Because it touches the network, it **self-skips** — reported as "skipped (offline mode)" — whenever you run a scan with `scan --offline`.

When it runs, `check_ip_address` calls the platform helper `get_public_ip`, which on macOS does the following:

1. It reads the list of IP-lookup services from your config key `checks.privacy.ip_address.services`. For each one, in order, it runs:
   ```
   curl -s --max-time 10 <service>
   ```
   The first service that returns a non-empty response wins — that text is used as your public IP and no further services are contacted. By default the list is:
   - `ifconfig.me`
   - `api.ipify.org`
   - `icanhazip.com`
2. If the config list has entries but every one of them fails or times out, the lookup gives up and returns nothing (it does not silently reach out to any other server).
3. Only if the configured list is completely empty does it fall back to a hard-coded chain of the same three endpoints: `ifconfig.me`, then `api.ipify.org`, then `icanhazip.com` (each with `curl -s --max-time 10`).

When a public IP comes back, the check also stores it in the `OMS_PUBLIC_IP` environment variable, which the `ipv6-leak` and `dns-leak` checks reuse during the same scan so they do not have to look it up again.

No files, system databases, or local network interfaces are inspected — the result is entirely whatever the external IP service reports. Whichever service answers does see the request, so it learns the IP it is reporting back to you (which, when the VPN is working, is the VPN server's address, not your real one).

## What it flags (and how serious)

There are only two outcomes, and there is no `critical` path:

- **Pass** — an IP was retrieved. It prints:
  ```
  Public IP: <your-ip>
    (this should be your VPN server's IP, not your real IP)
  ```
  and records the finding summary `Public IP <your-ip>`. The check does **not** judge whether the IP is "good" — passing simply means it successfully learned your public IP. Reading it and confirming it is the VPN's address is left to you.
- **Warn** — no IP could be retrieved. It prints:
  ```
  Could not retrieve public IP address
  ```
  with the finding summary `Public IP unavailable`, at **warn** severity. In practice this means a network or connectivity problem (you are offline, behind a captive portal, or every request timed out) rather than a detected leak.

## What's baselined

None. This check is stateless: it keeps no baseline and remembers nothing between runs. Every scan is a fresh, one-shot lookup of "what is my public IP right now?" It does not compare against a previously recorded IP or warn when your IP changes (a VPN IP changes often). There is no first-run snapshot and no drift comparison.

## Permissions

None needed. It requires no Full Disk Access and no TCC (privacy) permission — just `curl` and working outbound network access.

## Configuration

Config keys it reads (in `~/.config/oh-my-safety/config.yaml`):

- `checks.privacy.ip_address.enabled` — default `true`. Turns the check on or off.
- `checks.privacy.ip_address.services` — the ordered list of IP-lookup endpoints to try; the first one that answers wins. Defaults to `ifconfig.me`, `api.ipify.org`, `icanhazip.com`. This same shared list is also used by the `ipv6-leak` and `dns-leak` checks as their public-IP source.

It also honors the whole-category switch `categories.privacy.enabled` (default `true`).

Toggle the check with:

    oh-my-safety disable ip-address
    oh-my-safety enable  ip-address

## Handling findings

- **To silence this check's alerts while still seeing it in `status`:** run `oh-my-safety ignore ip-address` with **no finding-id**. This mutes the whole check. The scan runner honors an allowlist entry equal to the check's own name, so a warn from this check is re-labeled "muted by user" and stops alerting — muting works even though the check reports a single whole-check finding rather than per-item findings.
- **To stop it running entirely** (for example, you do not use a VPN and do not care to see your public IP): `oh-my-safety disable ip-address`.
- **After changing your setup** (reconnecting the VPN, switching servers, fixing connectivity): confirm the result with `oh-my-safety recheck ip-address`.
- **Per-item ignore and accept do not apply here.** `ignore ip-address <finding-id>` is unnecessary because this check produces no per-item finding-ids — it reports one whole-check finding keyed only by the check name. Likewise `accept` (baseline) does nothing, because this check keeps no baseline and no state to accept.

## Limitations

- **It does not verify anything.** The check only fetches and displays your public IP; it has no idea whether that IP belongs to your VPN or to your real connection. As long as *any* IP comes back, it passes — it will happily report your true home IP as a clean pass if the VPN is down. Rely on `vpn-tunnel`, `routing`, and the leak checks to actually catch leaks.
- **A warn is ambiguous.** "Could not retrieve public IP" can mean no internet, a captive portal (hotel or airport Wi-Fi login page), or all three echo services being down at once — none of which is itself a privacy breach.
- **It trusts whatever the service returns.** If an endpoint replies with a non-empty error string or HTML page instead of an address, the check treats that text as your IP and passes.
- **Plain-text lookups can be tampered with.** The default services are contacted by bare hostname, so `curl` uses plain HTTP. A network attacker positioned between you and the service could in principle alter the returned value, so treat the displayed IP as a helpful indicator, not cryptographic proof.
- **Third-party dependency.** The accuracy of the reported IP is only as good as the external echo service you point it at, and that operator sees your request.
- **Point-in-time only.** It checks once per full scan (every 300s by default). A VPN drop that happens and recovers between scans can go unseen.
- **Userspace check.** Like all of oh-my-safety, it runs as an ordinary user process and trusts the OS network stack; root-level malware could redirect or spoof these lookups to hide the truth.
