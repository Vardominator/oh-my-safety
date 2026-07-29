# Getting started

oh-my-safety supports macOS 12 or newer and initially targets Debian/Ubuntu and
Fedora/RHEL-compatible Linux distributions. This page covers macOS; Linux
package and systemd instructions are in [linux.md](linux.md). Homebrew is the
recommended macOS installation because it also manages upgrades and the
background service.

## Release status

v0.3.0 is the current release. It includes the cross-platform runtime,
profiles, history, notification channels, portable commands, and organization
features. Use `--HEAD`, `--head`, or a source checkout only when you
intentionally want newer development code.

## Install with Homebrew

This repository doubles as its own tap, so tap it by URL and install v0.3.0:

```bash
brew tap vardominator/oh-my-safety https://github.com/Vardominator/oh-my-safety
brew install vardominator/oh-my-safety/oh-my-safety
oh-my-safety version
```

If `HOMEBREW_REQUIRE_TAP_TRUST=1` is enabled, trust the tap before installing:

```bash
brew trust --tap vardominator/oh-my-safety
```

To test the latest unreleased `main` branch instead of the stable release:

```bash
brew services stop oh-my-safety 2>/dev/null || true
brew uninstall oh-my-safety 2>/dev/null || true
brew install --HEAD vardominator/oh-my-safety/oh-my-safety
```

`--HEAD` may contain unfinished changes. Return to the stable release with:

```bash
brew services stop oh-my-safety 2>/dev/null || true
brew uninstall oh-my-safety
brew install vardominator/oh-my-safety/oh-my-safety
```

## Other installation methods

The install script places the application under `~/.local`. By default it
resolves the latest immutable GitHub release, verifies the tag archive against
that release's `checksums.txt`, and, on supported Linux architectures, installs
the separately checksummed agent-core binary when available. Inspect
[`install.sh`](../install.sh) before piping it to a shell:

```bash
curl -fsSL https://raw.githubusercontent.com/Vardominator/oh-my-safety/main/install.sh | bash
```

Pin a release or explicitly choose the mutable development branch:

```bash
curl -fsSL https://raw.githubusercontent.com/Vardominator/oh-my-safety/main/install.sh |
  bash -s -- --version v0.3.0
curl -fsSL https://raw.githubusercontent.com/Vardominator/oh-my-safety/main/install.sh |
  bash -s -- --head
```

Install and start the manual launchd agent in one step:

```bash
curl -fsSL https://raw.githubusercontent.com/Vardominator/oh-my-safety/main/install.sh |
  bash -s -- --with-agent
```

Or install the current source checkout:

```bash
git clone https://github.com/Vardominator/oh-my-safety.git
cd oh-my-safety
make install PREFIX="$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
```

Go 1.26.5 or newer is optional for a source installation. When present,
`make install` builds `oh-my-safety-agent` and `oh-my-safety-intel`; without it,
the Bash compatibility runtime still installs, but commands that require the
portable core report that it is unavailable.

Homebrew and manual launchd agents must not run at the same time. Use Homebrew
service commands for a Homebrew installation and `install-agent` only for a
manual installation.

## First run and verification

Run a scan, inspect the saved posture, and check permissions:

```bash
oh-my-safety scan
oh-my-safety status
oh-my-safety doctor
```

On v0.3.0, also verify the configuration and journal interfaces:

```bash
oh-my-safety profile show
oh-my-safety history --limit 10
```

Finding exit statuses are intentional: `0` means no finding, `1` means a warning,
and `2` means a critical finding. Status `3` or greater indicates an execution
error.

The first scan quietly records the current state for drift-based checks such as
persistence, listening ports, and TCC grants. Review the machine before treating
that baseline as trusted. Absolute problems such as a disabled firewall or
unsafe SSH-key permissions are still reported immediately.

## Continuous monitoring

For a Homebrew installation:

```bash
brew services start oh-my-safety
brew services list
```

The service runs at login, scans on a schedule, sends native notifications, and
logs to `$(brew --prefix)/var/log/oh-my-safety.log`. Manage it with:

```bash
brew services restart oh-my-safety
brew services stop oh-my-safety
```

For a non-Homebrew installation:

```bash
oh-my-safety install-agent
oh-my-safety uninstall-agent
```

See [continuous monitoring](monitoring.md) for permissions and logging details.
See [profiles](profiles.md) before choosing strict, managed, server, or
air-gapped behavior.

## Optional SwiftBar menu

```bash
brew install --cask swiftbar
oh-my-safety menubar install
```

Open SwiftBar after installation. Remove only the plugin with:

```bash
oh-my-safety menubar uninstall
```

The plugin reads saved local status; it does not scan or make network requests.
See the [menu-bar guide](menu-bar.md) for configuration and troubleshooting.

## Upgrade or uninstall

Upgrade a Homebrew installation and restart the service:

```bash
brew update
brew upgrade oh-my-safety
brew services restart oh-my-safety
oh-my-safety version
oh-my-safety doctor
```

Uninstall Homebrew-managed components:

```bash
oh-my-safety menubar uninstall
brew services stop oh-my-safety
brew uninstall oh-my-safety
brew untap vardominator/oh-my-safety
```

For the install-script path:

```bash
curl -fsSL https://raw.githubusercontent.com/Vardominator/oh-my-safety/main/install.sh |
  bash -s -- uninstall
```

Uninstalling preserves configuration and state so an upgrade or reinstall does
not lose baselines and allowlists. To erase them deliberately, review and remove
`~/.config/oh-my-safety` and `~/.local/state/oh-my-safety`.

## Next steps

- Configure checks and alerts: [configuration.md](configuration.md)
- Configure notification channels: [notifications.md](notifications.md)
- Inspect the durable timeline: [history.md](history.md)
- Understand a finding: [checks catalog](checks/README.md)
- Understand the guarantees: [privacy.md](privacy.md) and
  [threat-model.md](threat-model.md)
- Troubleshoot an installation: [troubleshooting.md](troubleshooting.md)
