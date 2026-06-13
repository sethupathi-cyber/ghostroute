# GhostRoute — System-Wide Anonymity Platform

> **For authorized security research, privacy protection, and bug bounty operations only.**

GhostRoute is a modular, root-powered Linux anonymity tool that routes **all system traffic** through Tor, proxies, and obfuscation layers. Every feature is independently togglable via an interactive TUI or CLI commands.

---

## Features

| Module | Description |
|---|---|
| **System-Wide Tor Routing** | iptables redirect of all TCP/UDP → Tor (AnonSurf-style) |
| **Tor Circuit Manager** | Tor daemon control, circuit monitoring, NEWNYM rotation |
| **Proxy Chain Engine** | SOCKS4/5/HTTP chaining with built-in scraper + validator |
| **IP Rotation** | Per-request, time-based, or manual IP cycling |
| **obfs4 Transport** | Pluggable transport hiding Tor traffic |
| **meek-lite Transport** | CDN-front obfuscation (Azure/Cloudflare) |
| **Packet Padding** | Random byte padding to disrupt size analysis |
| **Protocol Mimicry** | Disguise traffic as HTTPS/WebSocket |
| **Timing Jitter** | Random delays to defeat timing correlation |
| **DNS Protection** | Tor DNS / dnscrypt / DoH — prevents DNS leaks |
| **IPv6 Block** | sysctl disable + ip6tables DROP of all IPv6 |
| **Kill Switch** | Hard iptables DROP if tunnel drops |
| **MAC Spoofing** | Random MAC per session |
| **Leak Audit** | Checks IP, DNS, IPv6, headers, Tor exit |

---

## Installation

```bash
# Clone or download to your system
git clone https://github.com/yourname/ghostroute.git
cd ghostroute

# Install all dependencies (Debian/Ubuntu/Kali)
sudo bash install.sh
```

The installer:
- Installs `tor`, `obfs4proxy`, `dnscrypt-proxy`, `macchanger`, `iptables`
- Creates Python virtualenv at `/opt/ghostroute/venv`
- Writes config to `/etc/ghostroute/config.yaml`
- Creates `/usr/local/bin/ghostroute` CLI shortcut
- Sets up systemd service (optional)

---

## Quick Start

```bash
# Launch interactive TUI (recommended)
sudo ghostroute tui

# Start with specific modules
sudo ghostroute start --modules tor_routing,dns_protect,ipv6_block,kill_switch

# Start everything
sudo ghostroute start

# Stop and restore system
sudo ghostroute stop

# Run leak audit
sudo ghostroute audit

# Rotate IP manually
sudo ghostroute rotate
```

---

## TUI Controls

| Key | Action |
|---|---|
| `1` | Toggle System-Wide Tor Routing |
| `2` | Toggle Tor Circuit Manager |
| `3` | Toggle Proxy Chain Engine |
| `4` | Toggle IP Rotation |
| `5a` | Toggle obfs4 |
| `5b` | Toggle meek-lite |
| `5c` | Toggle Packet Padding |
| `5d` | Toggle Protocol Mimicry |
| `5e` | Toggle Timing Jitter |
| `6` | Toggle DNS Protection |
| `7` | Toggle IPv6 Block |
| `8` | Toggle Kill Switch |
| `9` | Toggle MAC Spoofing |
| `A` | Rotate IP now |
| `L` | Run leak audit |
| `S` | Scrape + validate proxies |
| `P` | Add proxy manually |
| `R` | Set rotation interval |
| `O` | Set obfuscation priority |
| `Q` | Quit and restore system |

---

## CLI Reference

```bash
# Toggle specific module
sudo ghostroute toggle tor_routing
sudo ghostroute toggle kill_switch

# Config management (dot-notation)
sudo ghostroute config rotation.interval_seconds 60
sudo ghostroute config rotation.mode request
sudo ghostroute config obfuscation.timing.max_jitter_ms 500
sudo ghostroute config kill_switch.mode soft

# Proxy management
sudo ghostroute proxy add 1.2.3.4:1080:socks5
sudo ghostroute proxy add 5.6.7.8:8080:http:user:pass
sudo ghostroute proxy scrape          # Fetch from public sources
sudo ghostroute proxy list            # Show pool status

# View current status
sudo ghostroute status
```

---

## Adding Your Own Proxies

Add proxies to `/etc/ghostroute/proxies.txt`, one per line:

```
# Format: ip:port:type or ip:port:type:username:password
185.199.0.1:1080:socks5
10.0.0.1:8080:http
10.0.0.2:1080:socks5:myuser:mypass
```

Supported types: `socks4`, `socks5`, `http`

---

## Obfuscation Priority

When multiple obfuscation methods are enabled, they are applied in priority order.

**Default order**: `obfs4 → meek → timing_jitter → packet_padding → protocol_mimicry`

Change the priority order at runtime:
```bash
# Via CLI
sudo ghostroute config obfuscation.priority '["obfs4","timing_jitter","packet_padding"]'

# Via TUI: press O and enter comma-separated list
```

---

## IP Rotation Modes

| Mode | Description | Command |
|---|---|---|
| `time` | Rotate every N seconds | `ghostroute config rotation.mode time` |
| `request` | Rotate every N requests | `ghostroute config rotation.mode request` |
| `manual` | Only rotate when you press A or run `rotate` | `ghostroute config rotation.mode manual` |

```bash
# Set rotation to every 30 seconds
sudo ghostroute config rotation.interval_seconds 30
```

---

## Leak Protection

GhostRoute prevents all major leak vectors:

| Vector | Protection |
|---|---|
| DNS Leak | iptables port-53 redirect → Tor DNS / dnscrypt |
| IPv6 Leak | sysctl disable + ip6tables full DROP |
| WebRTC | Out-of-scope for system tool (use Firefox + disable WebRTC in about:config) |
| Timing Correlation | Timing jitter module |
| Packet Size Analysis | Packet padding module |
| Proxy Header Leak | Elite mode proxy selection |
| Tunnel Drop | Kill switch hard iptables rules |
| MAC Tracking | MAC randomization per session |

Run a full audit anytime:
```bash
sudo ghostroute audit
```

---

## Configuration File

Full config is at `/etc/ghostroute/config.yaml`. Key settings:

```yaml
rotation:
  interval_seconds: 120   # Change rotation frequency
  mode: time              # time | request | manual

obfuscation:
  timing:
    min_jitter_ms: 5
    max_jitter_ms: 200
  padding:
    max_bytes: 512

tor:
  exclude_exit_nodes: "{cn},{ru},{ir}"
  preferred_exit_nodes: "{us},{de},{nl}"
```

---

## Requirements

- **OS**: Debian / Ubuntu / Kali Linux (root access)
- **Python**: 3.10+
- **Tools**: `tor`, `iptables`, `obfs4proxy` (optional), `macchanger` (optional), `dnscrypt-proxy` (optional)

---

## Ethical Notice

> GhostRoute is designed for **authorized security operations only**:
> - Bug bounty hunting on programs you are enrolled in
> - Privacy research and threat intelligence
> - Authorized red-team and penetration testing engagements
>
> Do not use this tool for unauthorized access, illegal activities, or to interfere with systems you do not have permission to test.
