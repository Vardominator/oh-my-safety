# Getting started

## Install

**Homebrew (recommended):** this repo doubles as its own tap, so tap it by URL
(the tap isn't a separate `homebrew-*` repo), then install:
```bash
brew tap vardominator/oh-my-safety https://github.com/Vardominator/oh-my-safety
brew install vardominator/oh-my-safety/oh-my-safety
# to try the latest unreleased main:
brew install --HEAD vardominator/oh-my-safety/oh-my-safety
```
If you have third-party tap-trust enabled (Homebrew 6+ with
`HOMEBREW_REQUIRE_TAP_TRUST=1`), run `brew trust vardominator/oh-my-safety` first.

**Install script:**
```bash
curl -fsSL https://raw.githubusercontent.com/Vardominator/oh-my-safety/main/install.sh | bash
# add --with-agent to also install the background monitor:
curl -fsSL .../install.sh | bash -s -- --with-agent
```

**From source:**
```bash
git clone https://github.com/Vardominator/oh-my-safety.git
cd oh-my-safety && make install
```

## First run

```bash
oh-my-safety scan
```

The first scan **records baselines quietly** for the drift-based checks
(persistence, listening ports, TCC grants) — it snapshots what's currently on
your Mac and treats that as "normal". It won't alarm you about existing state;
it will only flag *changes* from here on. You'll immediately see any absolute
issues, though — a disabled firewall, world-readable SSH keys, etc.

Then check your posture any time:
```bash
oh-my-safety status
```

## Turn on continuous monitoring

```bash
brew services start oh-my-safety
```
This installs a launchd agent that runs at login, scans on a schedule, and sends
a native notification when something new and serious appears. Not a Homebrew
user? Run `oh-my-safety install-agent`. See [monitoring.md](monitoring.md).

## Check your setup

```bash
oh-my-safety doctor
```
`doctor` reports your bash/platform, whether the agent is loaded, whether Full
Disk Access is available (and how to grant it), which optional tools are
installed, and fires a test notification so you can confirm alerts reach you.

## Next steps

- Tune what runs: [configuration.md](configuration.md)
- Understand a finding: open its page in the [checks catalog](checks/README.md)
- Understand the guarantees: [privacy.md](privacy.md) and [threat-model.md](threat-model.md)
