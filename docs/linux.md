# Linux installation and monitoring

Linux support initially targets Debian/Ubuntu and Fedora/RHEL-compatible
distributions with glibc and a systemd user manager. Release builds cover
`amd64` (`x86_64`) and `arm64` (`aarch64`/`arm64`). Endpoint scanning runs as
the employee or operator account, not as root.

## Release status

v0.3.0 is the first tagged release with Linux packages and portable Linux
commands. Its immutable
[GitHub release](https://github.com/Vardominator/oh-my-safety/releases/tag/v0.3.0)
publishes:

```text
checksums.txt
oh-my-safety_VERSION_amd64.deb
oh-my-safety_VERSION_arm64.deb
oh-my-safety-VERSION.amd64.rpm
oh-my-safety-VERSION.arm64.rpm
oh-my-safety_VERSION_amd64.tar.gz
oh-my-safety_VERSION_arm64.tar.gz
oh-my-safety_VERSION_amd64.snap
oh-my-safety_VERSION_arm64.snap
```

Do not substitute a branch archive or CI artifact for a tagged package on a
production endpoint. Use a [development source checkout](#development-source-checkout)
only when intentionally evaluating newer code.

The signed APT archive is published at
`https://Vardominator.github.io/oh-my-safety/apt` with fingerprint
`C409801C769AE605678AC763F667FC021600FE36`. There is no current Snap Store
listing; release-attached Snap packages require explicit sideloading and Store
approval may be denied.

## Choose an installation path

| Path | Install location | Root needed | Verification | Intended use |
|------|------------------|-------------|--------------|--------------|
| Signed APT repository | `/usr/bin`, `/usr/lib/oh-my-safety` | Package/repository setup | Out-of-band key fingerprint plus signed apt metadata | Recommended for Debian/Ubuntu after the archive is announced live |
| Native `.deb`/`.rpm` | `/usr/bin`, `/usr/lib/oh-my-safety` | Package installation only | Release `checksums.txt` plus package-manager install | Recommended for tagged production releases |
| Tagged installer | `~/.local` | No, after OS prerequisites | Verifies the tag source and matching portable archive against `checksums.txt` | Per-user install without a native package |
| Experimental Snap | Snap-managed | Snap installation only | Locally built/CI artifact; classic confinement | Evaluation only; no current Store listing |
| Source checkout | `~/.local` by default | No, after OS prerequisites | Mutable Git checkout; no release checksum | Development only |

The native package and tagged installer include `oh-my-safety-agent` and
`oh-my-safety-intel`; Go is not required on the endpoint. Source installs build
those commands only when Go 1.26.5 or newer is available.
The portable `.tar.gz` is the verified payload used by the tagged installer;
it does not contain the packaged systemd unit and should not be unpacked
directly over `/usr`.

Do not install the Snap alongside APT, a native `.deb`/`.rpm`, or a source
monitor. They use separate state and locking, so concurrent monitors can repeat
scans, establish different baselines, and deliver duplicate notifications.

## Signed APT repository

The APT path supports normal `apt-get install oh-my-safety` and future
`apt-get upgrade` behavior, with a dedicated archive key, deb822 `Signed-By`
policy, signed `InRelease`, expiry metadata, and content-addressed indexes.
The exact 40-hex fingerprint is published above, in the reviewed release notes,
and in the [signed APT repository guide](apt-repository.md).

The complete copy-paste install, fingerprint verification, removal, and
maintainer activation instructions are in the
[signed APT repository guide](apt-repository.md). The checksum-verified release
`.deb` below remains available when repository installation is not appropriate.

## Fresh machine: native package

This is the recommended direct-package path for v0.3.0.

### 1. Install download prerequisites

Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates coreutils curl gawk grep
```

Fedora, RHEL, or Rocky Linux:

```bash
sudo dnf install -y ca-certificates coreutils curl gawk grep
```

The package manager installs the runtime dependencies declared by the package:
Bash, curl, `iproute2`/`iproute`, and `procps`/`procps-ng`. The background
monitor additionally requires a working systemd user manager:

```bash
command -v systemctl
systemctl --user show-environment >/dev/null
```

Run `systemctl --user` and all `oh-my-safety` commands as the protected user,
not with `sudo`. If the user-manager check fails, establish a normal login
session or ask an administrator to enable lingering for that specific account
before enabling continuous monitoring.

### 2. Download and verify the exact release asset

The following blocks detect `amd64` versus `arm64`, download only the package
for that host, require an exact matching row in `checksums.txt`, verify
SHA-256, and install the verified local file. Set `release` to a tag actually
shown on the Releases page. `v0.3.0` is the first Linux-capable tag.

Debian or Ubuntu:

```bash
(
  set -eu
  release="v0.3.0"
  version="${release#v}"
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 2 ;;
  esac
  asset="oh-my-safety_${version}_${arch}.deb"
  base="https://github.com/Vardominator/oh-my-safety/releases/download/${release}"
  download_dir="$(mktemp -d)"
  trap 'rm -rf "$download_dir"' EXIT
  cd "$download_dir"

  curl -fsSLO "${base}/checksums.txt"
  curl -fsSLO "${base}/${asset}"
  expected="$(awk -v name="$asset" '$2 == name {print $1; exit}' checksums.txt)"
  printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$'
  printf '%s  %s\n' "$expected" "$asset" | sha256sum --check -
  sudo apt-get install -y "./${asset}"
)
```

Fedora, RHEL, or Rocky Linux:

```bash
(
  set -eu
  release="v0.3.0"
  version="${release#v}"
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 2 ;;
  esac
  asset="oh-my-safety-${version}.${arch}.rpm"
  base="https://github.com/Vardominator/oh-my-safety/releases/download/${release}"
  download_dir="$(mktemp -d)"
  trap 'rm -rf "$download_dir"' EXIT
  cd "$download_dir"

  curl -fsSLO "${base}/checksums.txt"
  curl -fsSLO "${base}/${asset}"
  expected="$(awk -v name="$asset" '$2 == name {print $1; exit}' checksums.txt)"
  printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$'
  printf '%s  %s\n' "$expected" "$asset" | sha256sum --check -
  sudo dnf install -y "./${asset}"
)
```

The release checksum proves that the downloaded package matches the file
published with that GitHub release. Until the separately documented APT
archive is announced live, the project does not publish a usable APT or RPM
repository, so also verify the repository, signed tag, immutable release page,
and checksum through your normal software-approval process.

A native package installs commands in `/usr/bin`; no `PATH` change is needed:

```bash
command -v oh-my-safety
command -v oh-my-safety-agent
command -v oh-my-safety-intel
```

### 3. Configure before establishing the first baseline

The packaged service uses these default per-user locations:

- Config: `$HOME/.config/oh-my-safety/config.yaml`
- State: `$HOME/.local/state/oh-my-safety`
- Local event history: `$HOME/.local/state/oh-my-safety/log/events.tsv`
- SQLite journal: `$HOME/.local/state/oh-my-safety/journal.db`

On a fresh installation, copy the packaged default without overwriting an
existing user configuration:

```bash
config_dir="$HOME/.config/oh-my-safety"
install -d -m 700 "$config_dir"
if [ ! -e "$config_dir/config.yaml" ]; then
  install -m 600 /usr/lib/oh-my-safety/config/default.yaml \
    "$config_dir/config.yaml"
fi
oh-my-safety profile list
oh-my-safety profile show
oh-my-safety checks
```

Keep `personal-balanced` for an ordinary workstation, or select another
documented [operating profile](profiles.md). Selecting `managed-server` or
`managed-workstation` does not enroll or transmit anything; controller
enrollment is a separate explicit operation. Use
[`configuration.md`](configuration.md) for the supported YAML subset and
override precedence.

For example, CLI configuration writes an atomic user override without editing
YAML:

```bash
oh-my-safety set monitoring.interval 300
# On a server where VPN/privacy checks do not apply:
# oh-my-safety profile set managed-server
oh-my-safety profile show
oh-my-safety checks
```

A running monitor reloads valid configuration between scheduling ticks.

The packaged unit is sandboxed for the default
`~/.config/oh-my-safety` and `~/.local/state/oh-my-safety` write locations.
The interactive CLI honors custom XDG locations, but the packaged service
needs a separately reviewed systemd override before it can write elsewhere.

### 4. Verify locally and review the first baseline

Run readiness checks and an offline initial scan before starting the service:

```bash
oh-my-safety version
oh-my-safety doctor
oh-my-safety scan --offline
oh-my-safety status
oh-my-safety history --limit 20
oh-my-safety baseline show linux-persistence-scan
```

`doctor` warning that the monitoring service is not loaded is expected at this
stage. Scan exit status `0` means no finding, `1` a warning, and `2` a critical
finding; only status `3` or greater is an execution failure. An offline scan
skips checks whose declared inputs require the network.

The first persistence scan records the visible systemd, cron, autostart,
shell-startup, and preload state as its baseline. Review the machine before
treating that baseline as trusted. Do not approve an unfamiliar service,
startup-file change, cron entry, or `/etc/ld.so.preload` entry merely to clear
a warning.

### 5. Start continuous monitoring

The native package installs `/usr/lib/systemd/user/oh-my-safety.service` but
does not silently enable it. Enable it for the current user after configuration
and baseline review:

```bash
systemctl --user daemon-reload
systemctl --user enable --now oh-my-safety.service
systemctl --user is-enabled oh-my-safety.service
systemctl --user is-active oh-my-safety.service
journalctl --user -u oh-my-safety.service -n 50 --no-pager
oh-my-safety status
```

Follow the service log:

```bash
journalctl --user -u oh-my-safety.service -f
```

User services normally stop after logout. On a dedicated endpoint that must
remain monitored, an administrator can enable lingering for only that user:

```bash
sudo loginctl enable-linger "$USER"
```

Linux desktop notifications use `notify-send` when available and otherwise
remain visible in local status/history and the service log. Optional SendGrid,
Telegram, WhatsApp, Discord, and webhook delivery is configured separately in
[`notifications.md`](notifications.md).

## Tagged per-user installer

The v0.3.0 tagged installer is the easiest non-package path.
It installs beneath `~/.local`, verifies both the immutable tag source and the
matching `oh-my-safety_VERSION_ARCH.tar.gz` against release
`checksums.txt`, and uses the prebuilt portable commands. Go is not required.

Install the same runtime prerequisites first:

```bash
# Debian/Ubuntu:
sudo apt-get update
sudo apt-get install -y \
  bash ca-certificates coreutils curl gawk grep tar iproute2 procps

# Fedora/RHEL-compatible (run this instead):
# sudo dnf install -y \
#   bash ca-certificates coreutils curl gawk grep tar iproute procps-ng
```

Download the installer from the same immutable tag, inspect it, then run it
with that tag pinned:

```bash
release="v0.3.0"
installer="$(mktemp)"
curl -fsSL \
  "https://raw.githubusercontent.com/Vardominator/oh-my-safety/${release}/install.sh" \
  -o "$installer"
awk '{print}' "$installer"
bash "$installer" --version "$release"
rm -f "$installer"
```

Add the user-local commands to the current session and future login shells:

```bash
export PATH="$HOME/.local/bin:$PATH"
path_line='export PATH="$HOME/.local/bin:$PATH"'
grep -qxF "$path_line" "$HOME/.profile" 2>/dev/null ||
  printf '%s\n' "$path_line" >> "$HOME/.profile"
oh-my-safety version
```

For this installation path, copy the default from
`~/.local/lib/oh-my-safety/config/default.yaml`, perform the same initial
offline scan and baseline review described above, then install the per-user
service:

```bash
config_dir="$HOME/.config/oh-my-safety"
install -d -m 700 "$config_dir"
if [ ! -e "$config_dir/config.yaml" ]; then
  install -m 600 "$HOME/.local/lib/oh-my-safety/config/default.yaml" \
    "$config_dir/config.yaml"
fi
oh-my-safety doctor
oh-my-safety scan --offline
oh-my-safety status
oh-my-safety install-agent
systemctl --user is-active oh-my-safety.service
```

`install-agent` writes
`~/.config/systemd/user/oh-my-safety.service` with the exact installed binary
path and enables it. It intentionally runs as the current user.

## Experimental Snap package

The Snapcraft recipe builds native `amd64` and `arm64` classic snaps and
includes a user-scoped monitoring service. It is not currently available from
the Snap Store. Because useful endpoint scanning needs hidden-file, process,
network, and host-configuration access, strict confinement would create
material blind spots; Canonical's current classic review policy may reject this
management-oriented package.

On a native Linux builder, build and sideload it explicitly:

```bash
sudo snap install snapcraft --classic
case "$(uname -m)" in
  x86_64|amd64) snap_platform=amd64 ;;
  aarch64|arm64) snap_platform=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac
snapcraft --platform "$snap_platform"
sudo snap install --dangerous --classic ./oh-my-safety_*.snap
oh-my-safety doctor
oh-my-safety scan --offline
oh-my-safety status
oh-my-safety baseline show linux-persistence-scan
snap start --enable --user oh-my-safety.monitor
```

`--dangerous` acknowledges the local unsigned artifact; `--classic`
acknowledges that Snap's normal sandbox is not applied. Review the first scan
before enabling the monitor so existing malicious persistence is not silently
treated as a trusted baseline. Configuration and state live under
`~/snap/oh-my-safety/common/`, separate from native XDG state. See the
[Snap packaging guide](../packaging/snap/README.md) for exact service, state,
migration, build, uninstall, and Store-review details.

## Development source checkout

`main` is mutable. Use this path only for development or evaluation, not as a
substitute for the signed/tagged package.

Install the same runtime prerequisites as above, plus Git and Make. Install Go
1.26.5 or newer from a source approved by your organization if the full
portable-core feature set is required:

```bash
# Debian/Ubuntu:
sudo apt-get update
sudo apt-get install -y \
  bash ca-certificates coreutils curl gawk git grep make tar iproute2 procps

# Fedora/RHEL-compatible (run this instead):
# sudo dnf install -y \
#   bash ca-certificates coreutils curl gawk git grep make tar iproute procps-ng

git clone https://github.com/Vardominator/oh-my-safety.git
cd oh-my-safety
make install PREFIX="$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
path_line='export PATH="$HOME/.local/bin:$PATH"'
grep -qxF "$path_line" "$HOME/.profile" 2>/dev/null ||
  printf '%s\n' "$path_line" >> "$HOME/.profile"
oh-my-safety version
```

Without Go, `make install` still installs the Bash compatibility runtime. If a
`go` command is present, it must satisfy the version in `go.mod`; an older Go
command causes the portable-command build and installation to fail. Commands
that require `oh-my-safety-agent` or `oh-my-safety-intel`—bounded secret
scanning, executable triage, internet exposure, the SQLite bridge,
organization enrollment, and signed offline intelligence—remain unavailable
without a successful Go build and report that coverage honestly.

Configure, scan, review the first baseline, and run
`oh-my-safety install-agent` exactly as in the tagged per-user path.

## Update

### Signed APT repository

After that repository is officially activated:

```bash
sudo apt-get update
sudo apt-get install --only-upgrade oh-my-safety
systemctl --user daemon-reload
systemctl --user restart oh-my-safety.service
oh-my-safety version
```

### Native package

Repeat the matching download-and-verification block with a newer published
release tag; that block installs the verified `.deb` or `.rpm` over the
existing package. Then reload and restart the user service:

```bash
systemctl --user daemon-reload
systemctl --user restart oh-my-safety.service
oh-my-safety version
oh-my-safety doctor
```

The package manager replaces `/usr` application files and preserves the user's
configuration, baselines, history, notification credentials, and managed
enrollment state.

### Tagged per-user installer

Stop the monitor, download `install.sh` from the newer tag, and run it with the
same new tag in `--version`. The installer replaces the application tree
beneath `~/.local` and preserves XDG config/state:

```bash
systemctl --user stop oh-my-safety.service
new_release="v0.3.1"
installer="$(mktemp)"
curl -fsSL \
  "https://raw.githubusercontent.com/Vardominator/oh-my-safety/${new_release}/install.sh" \
  -o "$installer"
awk '{print}' "$installer"
bash "$installer" --version "$new_release"
rm -f "$installer"
systemctl --user start oh-my-safety.service
oh-my-safety version
oh-my-safety doctor
```

Use only a tag that exists on the Releases page and adjust `new_release` to the
actual version; `v0.3.1` above is an example, not a claim that it is published.

## Uninstall

Native package:

```bash
systemctl --user disable --now oh-my-safety.service
sudo apt-get remove oh-my-safety       # Debian/Ubuntu
# or: sudo dnf remove oh-my-safety     # Fedora/RHEL-compatible
systemctl --user daemon-reload
```

Experimental Snap:

```bash
snap stop --user oh-my-safety.monitor 2>/dev/null || true
sudo snap remove --purge oh-my-safety
```

Default tagged-installer prefix:

```bash
oh-my-safety uninstall-agent
installed_release="$(oh-my-safety version | awk 'NR == 1 {print $2}')"
installer="$(mktemp)"
curl -fsSL \
  "https://raw.githubusercontent.com/Vardominator/oh-my-safety/${installed_release}/install.sh" \
  -o "$installer"
awk '{print}' "$installer"
bash "$installer" uninstall
rm -f "$installer"
```

Source checkout instead:

```bash
oh-my-safety uninstall-agent
cd /path/to/oh-my-safety
make uninstall PREFIX="$HOME/.local"
```

Uninstall preserves:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/oh-my-safety
${XDG_STATE_HOME:-$HOME/.local/state}/oh-my-safety
```

Those directories contain configuration, allowlists, baselines, history,
notification credentials, signed policy/enrollment state, and local
intelligence. Review or archive them before an intentional manual deletion.

## Respond to expected persistence changes

After a legitimate package, service, cron, or startup change:

```bash
oh-my-safety recheck linux-persistence-scan
oh-my-safety baseline show linux-persistence-scan
oh-my-safety ignore linux-persistence-scan '<finding-id>'
# Or approve the entire staged snapshot only after reviewing every entry:
oh-my-safety accept linux-persistence-scan
```

## Build packages locally

Package maintainers need Go 1.26.5 or newer and
[nFPM](https://nfpm.goreleaser.com/):

```bash
OMS_PACKAGE_ARCH=amd64 ./scripts/build-linux-packages.sh
OMS_PACKAGE_ARCH=arm64 ./scripts/build-linux-packages.sh
```

The script writes `.deb`, `.rpm`, portable `.tar.gz`,
`oh-my-safety-agent`, and `oh-my-safety-intel` files to `dist/`. Distribution
CI inspects both architectures and installs the `amd64` native packages in
clean Ubuntu 24.04 and Rocky Linux 9 containers before a release can publish
them.

## Current limitations

- Full real-time process/file telemetry and blocking are not available.
- The signed APT publisher exists but is not a public channel until the
  archive fingerprint and live status are announced. There is no dnf
  repository yet.
- The classic Snap is locally buildable, but there is no Store listing and
  Canonical's current review policy makes approval uncertain.
- Some system posture is inaccessible without elevated privileges and is
  reported as limited coverage.
- The systemd unit is user-scoped, not tamper-proof MDM. A privileged attacker
  or the account owner can stop or remove it.
- Package-manager vulnerability correlation and privileged policy enforcement
  are later phases.
- Alpine/OpenRC and Arch packaging are not initial release targets.
