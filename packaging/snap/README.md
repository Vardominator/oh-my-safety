# Snap package

> **Status: experimental local package; not currently available from the Snap
> Store.** The recipe is buildable and locally installable, but Store
> publication is pending name registration and classic-confinement review.
> Canonical's current
> [review policy](https://snapcraft.io/docs/reference/administration/reviewing-classic-confinement-snaps/)
> lists management snaps and arbitrary host file access as unsupported classic
> categories, so approval is uncertain and may be denied. Do not advertise
> `snap install oh-my-safety` as available until a Store listing has been
> independently verified.

The Snapcraft recipe builds native `amd64` and `arm64` packages on matching
architectures. It uses `core24` and requires snapd 2.66 or newer because the
monitor is a per-user daemon.

## Install

The Store command below is future-facing. It works only after the name is
registered, classic confinement is approved, and a release is visibly
available in the Store:

```bash
sudo snap install oh-my-safety --classic
oh-my-safety version
snap services oh-my-safety
```

The monitor is deliberately disabled at installation. Configure the package,
run an offline scan, and review the first persistence baseline before enabling
continuous monitoring:

```bash
oh-my-safety doctor
oh-my-safety scan --offline
oh-my-safety status
oh-my-safety baseline show linux-persistence-scan
snap start --enable --user oh-my-safety.monitor
```

Snap user-service enablement is global rather than a private per-user toggle,
so an administrator should install and initialize this package only on systems
where that behavior is intended. Manage the running service without root:

```bash
snap start --user oh-my-safety.monitor
snap restart --user oh-my-safety.monitor
snap stop --user oh-my-safety.monitor
snap logs oh-my-safety.monitor
```

For monitoring after logout, the system administrator can enable lingering for
the intended account:

```bash
sudo loginctl enable-linger "$USER"
```

Do not run the Snap and a `.deb`, `.rpm`, source, or foreground monitor at the
same time. They keep separate state and scan locks, so two monitors can repeat
work and deliver duplicate findings. The Snap launcher declines to start when
the native `oh-my-safety.service` user unit is already active, but it cannot
reliably identify an arbitrary foreground process. Before switching:

```bash
systemctl --user disable --now oh-my-safety.service 2>/dev/null || true
pkill -f '[o]h-my-safety.*monitor' 2>/dev/null || true
snap start --enable --user oh-my-safety.monitor
```

Configuration and state are private, local, and shared across snap revisions:

```text
~/snap/oh-my-safety/common/config/oh-my-safety/
~/snap/oh-my-safety/common/state/oh-my-safety/
```

The user's real `HOME` is intentionally unchanged so scans cover the actual
endpoint. The Snap-specific XDG directories above contain only oh-my-safety's
configuration, baselines, journal, schedules, and findings.

Native configuration and history are not imported automatically. This avoids
silently copying notification credentials and organization enrollment
material. To migrate, stop both monitors, review the source directories
`~/.config/oh-my-safety` and `~/.local/state/oh-my-safety`, and copy only the
files you intend to retain into the Snap paths while preserving their private
permissions.

## Why classic confinement

Strict confinement cannot honestly provide this application's intended
coverage. The scanner needs read access to hidden credential locations,
persistence mechanisms, host processes, routes, listeners, and system
configuration. The `home` interface excludes hidden files, while enumerating a
few paths through `personal-files` would still omit unknown attack surfaces.

Classic confinement does not provide Snap's usual application sandbox. The
Store therefore requires a manual approval before this package can be
published, and users must include `--classic` when installing it. The daemon is
still user-scoped: it is not a root service and cannot read data the user could
not ordinarily read.

## Build and test locally

Install Snapcraft and use a native builder for the target architecture:

```bash
sudo snap install snapcraft --classic
snapcraft --platform amd64
# On an arm64 builder:
snapcraft --platform arm64
```

Install a local, unsigned artifact with both required acknowledgements:

```bash
sudo snap install --dangerous --classic ./oh-my-safety_*.snap
oh-my-safety version
snap services oh-my-safety
sudo snap remove --purge oh-my-safety
```

The GitHub workflow builds and smoke-tests both architectures on native
`ubuntu-24.04` and `ubuntu-24.04-arm` runners. It uploads artifacts on ordinary
CI and tag runs but never publishes from a tag. Store publication requires an
explicit manual run, successful builds for both architectures, scoped
credentials, and the `snap-store` GitHub environment. Configure required
reviewers on that environment before publishing.

## Store setup and credential scope

Publishing is intentionally not self-bootstrapping:

1. Sign in with `snapcraft login`.
2. Register `oh-my-safety` (or update the recipe if that name is unavailable).
3. Request approval for classic confinement and explain the endpoint-scanning
   access described above. Treat rejection as the expected risk: current
   review policy explicitly identifies management snaps as unsupported.
4. Export short-lived, package- and channel-scoped credentials:

   ```bash
   expiry="$(date -u -d '+30 days' '+%Y-%m-%dT%H:%M:%SZ')"
   snapcraft export-login \
     --snaps=oh-my-safety \
     --channels=edge \
     --acls=package_access,package_push,package_update,package_release \
     --expires="$expiry" \
     snapcraft-login.txt
   ```

5. Create a protected GitHub environment named `snap-store`, require a release
   reviewer, and store the complete file contents in its
   `SNAPCRAFT_STORE_CREDENTIALS` secret. Then securely delete the local file.

The workflow is experimental publishing plumbing, not evidence of Store
availability. It never registers a Store name, fails closed when a requested
publication lacks credentials, accepts publication only from canonical
`main`, and can publish only to `edge`. Candidate/stable promotion is not
automated: it requires a separate reviewed release process that verifies the
immutable GitHub release and both Store architectures first.
