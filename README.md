# <img src="media/shield.png" alt="" width="32" height="32"> oh-my-privacy

A neutral, third-party VPN verification tool that continuously monitors your connection for privacy leaks.

## Why?

People love using VPNs and trust them to keep their internet usage private. But **how do you verify your VPN is actually working?**

oh-my-privacy is an open-source tool that acts as an independent verifier, checking for:

- **IP Address Leaks** - Is your real IP visible?
- **DNS Leaks** - Are your DNS queries going through the VPN?
- **IPv6 Leaks** - Is IPv6 traffic bypassing your VPN?
- **Routing Issues** - Is your traffic actually going through the VPN tunnel?

## Installation

### Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/Vardominator/oh-my-privacy/main/install.sh | bash
```

### Homebrew (macOS/Linux)

```bash
brew tap Vardominator/oh-my-privacy
brew install oh-my-privacy
```

### From Source

```bash
git clone https://github.com/Vardominator/oh-my-privacy.git
cd oh-my-privacy
make install
```

## Usage

### Single Check

Run a one-time privacy check:

```bash
oh-my-privacy --once
```

### Continuous Monitoring

Monitor your VPN connection and get alerts when issues are detected:

```bash
oh-my-privacy
```

This will:
- Run a full privacy check every 60 seconds
- Perform quick route checks every 5 seconds
- Send system notifications if your VPN disconnects or leaks are detected

### Run Specific Check

```bash
oh-my-privacy --check dns-leak
oh-my-privacy --check ip-address
oh-my-privacy --check routing
```

### List Available Checks

```bash
oh-my-privacy --list-checks
```

### Background Daemon

```bash
oh-my-privacy --daemon
```

## Configuration

oh-my-privacy uses a YAML configuration file. On first run, a default config is created at `~/.config/oh-my-privacy/config.yaml`.

```yaml
# oh-my-privacy configuration
version: 1

monitoring:
  check_interval: 60          # Full check interval (seconds)
  fast_check_interval: 5      # Quick route check interval
  quiet_mode: false

notifications:
  enabled: true
  sound: true

checks:
  ip_address:
    enabled: true
  dns_leak:
    enabled: true
  vpn_tunnel:
    enabled: true
  routing:
    enabled: true
  ipv6_leak:
    enabled: true
```

### Custom Config File

```bash
oh-my-privacy --config /path/to/custom-config.yaml
```

## Platform Support

| Platform | Status | Notifications |
|----------|--------|---------------|
| macOS | Full | Native (osascript) |
| Linux | Full | notify-send, zenity |
| Windows/WSL | Full | PowerShell toast |

## SwiftBar / BitBar Integration (macOS)

oh-my-privacy includes a menu bar plugin for [SwiftBar](https://swiftbar.app/) (or BitBar) that shows your VPN status at a glance.

![SwiftBar Screenshot](media/swiftbar.png)

### SwiftBar Installation

1. **Install SwiftBar** (if not already installed):
   ```bash
   brew install --cask swiftbar
   ```

2. **Install oh-my-privacy**:
   ```bash
   curl -sSL https://raw.githubusercontent.com/Vardominator/oh-my-privacy/main/install.sh | bash
   ```

3. **Install the SwiftBar plugin**:
   ```bash
   # Create SwiftBar plugins directory if it doesn't exist
   mkdir -p ~/Library/Application\ Support/SwiftBar/Plugins

   # Download the plugin
   curl -sSL https://raw.githubusercontent.com/Vardominator/oh-my-privacy/main/plugins/swiftbar/oh-my-privacy.10s.sh \
     -o ~/Library/Application\ Support/SwiftBar/Plugins/oh-my-privacy.10s.sh

   # Make it executable
   chmod +x ~/Library/Application\ Support/SwiftBar/Plugins/oh-my-privacy.10s.sh
   ```

4. **Open SwiftBar** and select your plugins folder when prompted.

### What the Menu Bar Shows

| Icon | Meaning |
|------|---------|
| 🛡️ | VPN is protecting your traffic |
| ⚠️ N | N privacy leaks detected |
| 🔌 | Network check failed |

Click the icon to see:

- Current protection status
- Active route interface
- Your public IP address
- DNS resolver IP
- Quick actions to run full checks

### Customizing Refresh Interval

The plugin filename determines how often it refreshes. Rename to change:

- `oh-my-privacy.10s.sh` - Every 10 seconds (default)
- `oh-my-privacy.30s.sh` - Every 30 seconds
- `oh-my-privacy.1m.sh` - Every minute

## What Gets Checked

### 1. Public IP Address
Retrieves your public IP from multiple services to verify it matches your VPN server's IP, not your real IP.

### 2. DNS Leak Test
Uses Google's DNS resolver identification service to check if your DNS queries are leaking outside the VPN tunnel.

### 3. VPN Tunnel Status
Verifies that VPN tunnel interfaces (utun, tun, wg, ppp) are active and have assigned IPs.

### 4. Traffic Routing
Checks that your default route goes through the VPN interface, not your regular network adapter.

### 5. IPv6 Leak Test
Detects if IPv6 traffic is bypassing your VPN, which could expose your real IP.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECK_INTERVAL` | 60 | Full check interval (seconds) |
| `FAST_CHECK_INTERVAL` | 5 | Quick route check interval |
| `OMP_CONFIG_FILE` | ~/.config/oh-my-privacy/config.yaml | Config file path |
| `OMP_VERBOSE` | false | Enable debug output |

## Uninstall

```bash
# If installed via curl
curl -sSL https://raw.githubusercontent.com/Vardominator/oh-my-privacy/main/install.sh | bash -s uninstall

# If installed via make
make uninstall

# If installed via Homebrew
brew uninstall oh-my-privacy
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding New Checks

1. Create a new file in `lib/checks/your-check.sh`
2. Implement a function named `check_your_check()`
3. Return 0 for pass, 1 for fail
4. Add configuration options in `config/default.yaml`

## License

MIT License - see [LICENSE](LICENSE)

## Links

- [Report Issues](https://github.com/Vardominator/oh-my-privacy/issues)
- [WebRTC Leak Test](https://browserleaks.com/webrtc)
- [Comprehensive IP Leak Test](https://ipleak.net)
