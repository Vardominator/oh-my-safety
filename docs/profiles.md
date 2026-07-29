# Operating profiles

Profiles are included in v0.3.0 and are not part of the v0.2.3 compatibility
line.

Profiles make the intended protection posture explicit without hiding the
individual settings. Selecting a profile writes one atomic bundle to
`overrides.conf`; every resulting value remains visible through the ordinary
configuration system and can be refined with `oh-my-safety set`.

List profiles and show the active one:

```bash
oh-my-safety profile list
oh-my-safety profile show
```

Select one:

```bash
oh-my-safety profile set personal-strict
```

## Presets

| Preset | Intended use | Connectivity | Default behavior |
|--------|--------------|--------------|------------------|
| `personal-balanced` | Everyday personal laptop | connected | Five-minute cadence, local desktop alerts |
| `personal-strict` | Higher-risk personal laptop | connected | Two-minute cadence and the bounded built-in local secret scan |
| `developer` | Source-code workstation | connected | Built-in local secret scan plus gitleaks/trufflehog adapters when those tools are already installed |
| `managed-workstation` | Employee endpoint | connected | Strict posture and built-in local secret scan; explicit controller enrollment applies signed policy |
| `managed-server` | Linux application/server workload | connected | Strict server posture with laptop/VPN privacy checks disabled |
| `airgapped-high-assurance` | Isolated high-assurance endpoint | airgapped | One-minute local cadence, privacy-network checks and every external notification blocked |

The axes are independent:

- workload: `workstation`, `developer`, or `server`
- protection: `balanced` or `strict`
- management: `standalone` or `managed`
- connectivity: `connected`, `offline`, or `airgapped`

The portable agent core exposes the same axes in its versioned readiness
contract.

## Important safety behavior

`offline` and `airgapped` are enforcement gates, not labels. With either
connectivity mode selected, one-off scans automatically enter offline mode, the
monitor does not run its fast VPN route probe, checks declaring network
requirements are skipped, and external notification channels are blocked even
if a channel was enabled separately.

Selecting `strict` does not authorize automatic remediation. A profile can
increase frequency and coverage, but state-changing actions still require local
approval or a separately verified signed organization policy. No profile
enables arbitrary remote commands.

`managed-*` means that the endpoint expects organization policy. It does not
silently enroll the device or transmit data. Until
`oh-my-safety organization enroll` succeeds, `profile show` reports that no
controller is enrolled and all protection remains local. Once enrolled, the
monitor fetches pinned signed policy and sends only the redacted report
contract at its configured cadence; see [Organization controller](organization.md).

## Customize after selecting a profile

For example, choose strict personal protection but keep a five-minute cadence:

```bash
oh-my-safety profile set personal-strict
oh-my-safety set monitoring.interval 300
oh-my-safety profile show
```

Selecting another profile later replaces the profile-controlled values as one
bundle. Unrelated overrides are preserved.
