# Privacy promise

oh-my-safety is a safety tool, so it holds itself to the standard it checks for:
**it never sends your data anywhere.** No telemetry, no analytics, no crash
reporting, no "anonymous usage stats", no update pings.

## The only network calls it ever makes

Every outbound request comes from the **privacy** checks, whose entire job is to
compare your public-facing identity against your VPN. The **security** checks
make **zero** network calls.

| Endpoint | Used by | Why | Disable with |
|----------|---------|-----|--------------|
| `ifconfig.me`, `api.ipify.org`, `icanhazip.com` | ip-address | Look up your public IP | `oh-my-safety disable ip-address` |
| `api64.ipify.org` | ipv6-leak | Detect IPv6 escaping the tunnel | `oh-my-safety disable ipv6-leak` |
| `ns1.google.com` (TXT `o-o.myaddr.l.google.com`) | dns-leak | Identify your DNS resolver's egress IP | `oh-my-safety disable dns-leak` |

You can change the IP-lookup services in config (`checks.privacy.ip_address.services`),
or disable the whole category with `oh-my-safety disable privacy`.

There are **no other endpoints.** The GitHub / Homebrew URLs in the source are
for installation and documentation only — they are never contacted while the
tool runs.

## Verify it yourself

The no-phone-home guarantee for the security checks is falsifiable — this returns
nothing:

```bash
grep -rE 'curl|wget|/dev/tcp|nc ' lib/checks/security/
```

CI enforces the same grep on every commit, so a security check can never quietly
start talking to the network. You can also run a full scan with your network off:
the security checks behave identically; only the privacy checks degrade.

Notably, the **opt-in** deep scanners are configured to stay offline too:
`trufflehog` is always invoked with `--no-verification` (its default behavior
would send discovered credentials to their issuing services to test them), and
oh-my-safety never downloads YARA rules for you.

## Where your data lives (all local)

- **Config:** `~/.config/oh-my-safety/` (and `overrides.conf` for CLI toggles)
- **State, baselines, logs:** `~/.local/state/oh-my-safety/` (created mode `700`; baseline files `600`)
- **Agent logs:** Homebrew's `var/log/oh-my-safety.log`, or `~/Library/Logs/oh-my-safety/` for a manual agent

Nothing under these paths is ever transmitted. Uninstalling leaves them in place
so you can review them; delete them manually if you want a clean wipe.

## A note on Full Disk Access

Some checks read protected data (the TCC database, `~/Documents`) and therefore
need Full Disk Access. Granting it increases what a compromised copy of the tool
could read — which is why the state directory is locked to your user and the
no-network invariant is enforced in code and CI. See
[monitoring.md](monitoring.md#full-disk-access) for the trade-offs.
