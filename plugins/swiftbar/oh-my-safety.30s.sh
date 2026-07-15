#!/bin/bash

# <bitbar.title>oh-my-safety</bitbar.title>
# <bitbar.author>Vardominator</bitbar.author>
# <bitbar.author.github>Vardominator</bitbar.author.github>
# <bitbar.desc>macOS safety & privacy monitor status in your menu bar</bitbar.desc>
# <bitbar.abouturl>https://github.com/Vardominator/oh-my-safety</bitbar.abouturl>
#
# <swiftbar.hideAbout>false</swiftbar.hideAbout>
# <swiftbar.hideRunInTerminal>false</swiftbar.hideRunInTerminal>
# <swiftbar.hideLastUpdated>false</swiftbar.hideLastUpdated>
#
# Thin renderer: this plugin makes NO network calls and runs NO checks. It just
# reads the last scan result via `oh-my-safety status --format swiftbar`. The
# background agent (brew services start oh-my-safety) does the actual scanning.

OMS_BIN=""
for candidate in \
    "$(command -v oh-my-safety 2>/dev/null)" \
    /opt/homebrew/bin/oh-my-safety \
    /usr/local/bin/oh-my-safety \
    "$HOME/.local/bin/oh-my-safety"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        OMS_BIN="$candidate"
        break
    fi
done

if [ -z "$OMS_BIN" ]; then
    echo "🛡️?"
    echo "---"
    echo "oh-my-safety not found"
    echo "Install | href=https://github.com/Vardominator/oh-my-safety"
    exit 0
fi

exec "$OMS_BIN" status --format swiftbar
