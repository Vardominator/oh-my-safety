# Menu bar (optional)

oh-my-safety works fully from the terminal and via background notifications — a
menu-bar icon is optional. If you want an at-a-glance status icon, use the
included [SwiftBar](https://swiftbar.app) plugin.

## Install

```bash
brew install --cask swiftbar        # if you don't have SwiftBar
oh-my-safety menubar install        # copies the plugin into SwiftBar's plugin folder
```

Then open SwiftBar. Remove it with `oh-my-safety menubar uninstall`.

## What it shows

The plugin is a **thin renderer**: it makes no network calls and runs no checks.
It simply calls `oh-my-safety status --format swiftbar` (which reads the last
scan from local state) and displays:

| Icon | Meaning |
|------|---------|
| 🛡️ | All good |
| ⚠️ N | N warnings |
| 🚨 N | N critical findings |
| 🌀 | Scan is stale or the agent isn't running |

The dropdown lists per-check summaries and offers "Run deep scan", "Full status",
and "Refresh". Because the background agent owns scanning and notifications, the
plugin never double-notifies.

## Is SwiftBar the right choice?

For now, yes — it's actively maintained, brew-installable, and the plugin is a
tiny wrapper over the `status --json` contract. A native Swift menu-bar app is on
the [roadmap](roadmap.md) for later; it would consume the exact same contract, so
nothing here is wasted. (xbar also works — the plugin keeps xbar-compatible
metadata — but it's effectively dormant, so we document SwiftBar.)
