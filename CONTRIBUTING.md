# Contributing to oh-my-privacy

Thank you for your interest in contributing to oh-my-privacy! This document provides guidelines for contributing.

## Ways to Contribute

- **Add new privacy checks** - DNS over HTTPS detection, WebRTC leak detection, etc.
- **Improve platform support** - Better Windows support, FreeBSD, etc.
- **Fix bugs** - Check the issues page for known bugs
- **Improve documentation** - Help others use the tool
- **Report issues** - Found a bug or have a feature request?

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Vardominator/oh-my-privacy.git
   cd oh-my-privacy
   ```

2. Run locally without installing:
   ```bash
   ./bin/oh-my-privacy --once
   ```

3. Run shellcheck for linting:
   ```bash
   make lint
   ```

## Project Structure

```
oh-my-privacy/
├── bin/
│   └── oh-my-privacy          # Main CLI entry point
├── lib/
│   ├── core.sh                # Core utilities, config, logging
│   ├── platform/
│   │   ├── detect.sh          # Platform detection utilities
│   │   ├── macos.sh           # macOS-specific functions
│   │   ├── linux.sh           # Linux-specific functions
│   │   └── windows.sh         # Windows/WSL functions
│   └── checks/
│       ├── ip-address.sh      # Public IP check
│       ├── dns-leak.sh        # DNS leak detection
│       ├── vpn-tunnel.sh      # VPN interface check
│       ├── routing.sh         # Traffic routing check
│       └── ipv6-leak.sh       # IPv6 leak detection
├── config/
│   └── default.yaml           # Default configuration
├── install.sh                 # Installer script
└── Makefile                   # Build/install automation
```

## Adding a New Check

1. **Create the check file** at `lib/checks/your-check.sh`:

   ```bash
   #!/bin/bash
   # oh-my-privacy - Your Check Name
   # Brief description of what this check does

   CHECK_NAME="your-check"
   CHECK_DESCRIPTION="Your Check Description"

   check_your_check() {
       echo ""
       echo "Step N: Your Check Name"
       echo "-------------------------------------------"

       # Your check logic here
       # Use platform-agnostic functions from platform/*.sh

       if [[ condition_passes ]]; then
           print_check_result "pass" "Check passed message"
           return 0
       else
           print_check_result "fail" "Check failed message"
           return 1
       fi
   }
   ```

2. **Add configuration** in `config/default.yaml`:

   ```yaml
   checks:
     your_check:
       enabled: true
       # Any check-specific options
   ```

3. **Document the check** in README.md

## Adding Platform Support

Platform modules live in `lib/platform/`. Each platform must implement these functions:

| Function | Purpose |
|----------|---------|
| `send_notification(title, message, subtitle)` | System notification |
| `send_alert(title, message)` | Blocking alert dialog |
| `get_public_ip()` | Get public IP address |
| `get_dns_resolver_ip()` | Get DNS resolver IP |
| `get_dns_servers()` | List configured DNS servers |
| `get_vpn_interfaces()` | List VPN tunnel interfaces |
| `get_interface_ip(iface)` | Get IP of an interface |
| `get_default_route_interface()` | Get default route interface |
| `get_default_route_gateway()` | Get default gateway |
| `get_default_route()` | Get full default route info |
| `is_vpn_interface(iface)` | Check if interface is VPN |
| `get_ipv6_address()` | Get public IPv6 address |

## Code Style

- Use `bash` (not sh) for bash-specific features
- Use `[[ ]]` for conditionals, not `[ ]`
- Quote all variable expansions: `"$var"` not `$var`
- Use `local` for function-scoped variables
- Add comments for non-obvious logic
- Keep lines under 100 characters
- Use 4-space indentation

## Testing

Before submitting a PR:

1. **Test on your platform:**
   ```bash
   ./bin/oh-my-privacy --once
   ```

2. **Run shellcheck:**
   ```bash
   make lint
   ```

3. **Test specific checks:**
   ```bash
   ./bin/oh-my-privacy --check your-check
   ```

4. **Test with VPN connected and disconnected**

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests and linting
5. Commit with clear messages
6. Push and create a Pull Request

### PR Checklist

- [ ] Code follows the style guide
- [ ] shellcheck passes
- [ ] Tested on at least one platform
- [ ] Documentation updated if needed
- [ ] Config updated if new options added

## Reporting Issues

When reporting bugs, please include:

- oh-my-privacy version (`oh-my-privacy --version`)
- Operating system and version
- VPN software being used
- Full output with `--verbose` flag
- Steps to reproduce

## Feature Requests

Feature requests are welcome! Please:

- Check existing issues first
- Describe the use case
- Explain why this would benefit users

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
