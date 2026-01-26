# Claude Code Instructions for oh-my-privacy

This file provides context for Claude Code when working on this project.

## Project Overview

oh-my-privacy is a cross-platform VPN privacy verification tool written in Bash. It checks for IP leaks, DNS leaks, IPv6 leaks, and routing issues to verify your VPN is actually protecting your privacy.

## Architecture

```
oh-my-privacy/
├── bin/oh-my-privacy      # Main CLI entry point
├── lib/
│   ├── core.sh            # Core utilities, config parsing, logging
│   ├── platform/          # Platform-specific implementations
│   │   ├── macos.sh       # macOS (notifications via osascript)
│   │   ├── linux.sh       # Linux (notify-send, zenity)
│   │   └── windows.sh     # Windows/WSL (PowerShell)
│   └── checks/            # Modular privacy checks
│       ├── ip-address.sh
│       ├── dns-leak.sh
│       ├── vpn-tunnel.sh
│       ├── routing.sh
│       └── ipv6-leak.sh
├── config/default.yaml    # Default configuration
└── plugins/swiftbar/      # SwiftBar menu bar plugin
```

## Key Design Principles

1. **Platform Abstraction**: All platform-specific code lives in `lib/platform/`. Each platform implements the same function signatures.

2. **Modular Checks**: Each check in `lib/checks/` is independent and follows this pattern:
   - Define `check_<name>()` function
   - Return 0 for pass, 1 for fail
   - Use `print_check_result "pass|warn|fail" "message"` for output

3. **No External Dependencies**: Pure Bash with standard Unix tools. YAML parsing is done without requiring yq.

4. **Config-Driven**: All behavior can be controlled via YAML config at `~/.config/oh-my-privacy/config.yaml`.

## Adding New Checks

1. Create `lib/checks/your-check.sh`
2. Implement `check_your_check()` function
3. Add config entry in `config/default.yaml`
4. The check will be automatically discovered and run

## Adding Platform Support

1. Create `lib/platform/newplatform.sh`
2. Implement required functions: `send_notification()`, `get_public_ip()`, `get_vpn_interfaces()`, etc.
3. Update `detect_platform()` in `lib/core.sh`

## Testing

```bash
# Run single check
./bin/oh-my-privacy --once

# Test specific check
./bin/oh-my-privacy --check dns-leak

# Verbose output
./bin/oh-my-privacy --verbose --once

# Run shellcheck
make lint
```

## Common Tasks

- **Version bump**: Update `OMP_VERSION` in `lib/core.sh`, `plugins/swiftbar/oh-my-privacy.10s.sh`, and `Formula/oh-my-privacy.rb`
- **Add notification**: Use `notify "title" "message" "subtitle"` from any check
- **Debug platform detection**: Run with `--verbose` flag
