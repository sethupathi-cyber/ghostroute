#!/usr/bin/env bash
# GhostRoute — System-Wide Anonymity Platform
# Installer script for Debian/Ubuntu/Kali Linux
# Run as root: sudo bash install.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

# ── Detect distro ─────────────────────────────────────────────────────────────
if [[ -f /etc/debian_version ]]; then
    DISTRO="debian"
elif [[ -f /etc/arch-release ]]; then
    DISTRO="arch"
else
    warn "Unknown distro — attempting Debian-style install"
    DISTRO="debian"
fi

INSTALL_DIR="/opt/ghostroute"
CONFIG_DIR="/etc/ghostroute"
LOG_DIR="/var/log/ghostroute"

echo ""
echo -e "${CYAN}"
echo "  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██████╗  ██████╗ ██╗   ██╗████████╗███████╗"
echo " ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝"
echo " ██║  ███╗███████║██║   ██║███████╗   ██║   ██████╔╝██║   ██║██║   ██║   ██║   █████╗"
echo " ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝"
echo " ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗"
echo "  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝"
echo -e "${NC}"
echo -e "          ${YELLOW}System-Wide Anonymity Platform Installer${NC}"
echo ""

# ── Step 1: System packages ───────────────────────────────────────────────────
info "Updating package lists..."
if [[ "$DISTRO" == "debian" ]]; then
    apt-get update -qq

    info "Installing system dependencies..."
    apt-get install -y -qq \
        tor \
        obfs4proxy \
        dnscrypt-proxy \
        macchanger \
        iptables \
        iptables-persistent \
        iproute2 \
        net-tools \
        curl \
        wget \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        resolvconf \
        dnsutils \
        procps \
        lsof

elif [[ "$DISTRO" == "arch" ]]; then
    pacman -Sy --noconfirm \
        tor \
        obfs4proxy \
        dnscrypt-proxy \
        macchanger \
        iptables \
        iproute2 \
        net-tools \
        curl \
        wget \
        python \
        python-pip \
        base-devel
fi

ok "System packages installed."

# ── Step 2: Python virtual environment ───────────────────────────────────────
info "Setting up Python virtual environment..."
mkdir -p "$INSTALL_DIR"

python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

pip install --quiet --upgrade pip
pip install --quiet -r "$(dirname "$0")/requirements.txt"

ok "Python environment ready."

# ── Step 3: Copy project files ────────────────────────────────────────────────
info "Installing GhostRoute to $INSTALL_DIR..."
cp -r "$(dirname "$0")"/* "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/ghostroute.py"

# ── Step 4: Config directory ──────────────────────────────────────────────────
info "Setting up config directory at $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Copy default config if not already present
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    cp "$INSTALL_DIR/config/default.yaml" "$CONFIG_DIR/config.yaml"
    ok "Default config installed."
else
    warn "Existing config found — keeping $CONFIG_DIR/config.yaml"
fi

# Create empty proxies file
touch "$CONFIG_DIR/proxies.txt"
chmod 600 "$CONFIG_DIR/proxies.txt"

# ── Step 5: Tor configuration ─────────────────────────────────────────────────
info "Configuring Tor..."
TORRC_GHOST="/etc/tor/torrc.ghostroute"

cat > "$TORRC_GHOST" << 'EOF'
# GhostRoute Tor Configuration
# This file is managed by GhostRoute — do not edit manually

SocksPort 9050
ControlPort 9051
HashedControlPassword 16:8C423A41EF4A342C67C4DEDBAD57B0F5D1AAEF9A7B3E6F2B01B19

TransPort 9040
DNSPort 5353

AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit

# Stream isolation
IsolateClientAddr 1
IsolateSOCKSAuth 1
IsolateClientProtocol 1

# Security
StrictNodes 0
ExcludeExitNodes {cn},{ru},{ir},{kp}
ExitNodes {us},{de},{nl},{se},{ch}

# Data directory
DataDirectory /tmp/ghostroute-tor

# Circuit settings
MaxCircuitDirtiness 600
NewCircuitPeriod 30
EOF

ok "Tor config written to $TORRC_GHOST"

# ── Step 6: Systemd service (optional) ───────────────────────────────────────
info "Creating systemd service..."
cat > /etc/systemd/system/ghostroute.service << EOF
[Unit]
Description=GhostRoute System-Wide Anonymity Platform
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/ghostroute.py start
ExecStop=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/ghostroute.py stop
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "Systemd service created (use: systemctl start ghostroute)"

# ── Step 7: CLI symlink ───────────────────────────────────────────────────────
info "Creating /usr/local/bin/ghostroute symlink..."
cat > /usr/local/bin/ghostroute << EOF
#!/usr/bin/env bash
exec $INSTALL_DIR/venv/bin/python $INSTALL_DIR/ghostroute.py "\$@"
EOF
chmod +x /usr/local/bin/ghostroute
ok "You can now run: sudo ghostroute [command]"

# ── Step 8: Verify dependencies ───────────────────────────────────────────────
info "Verifying installations..."
MISSING=()

command -v tor          &>/dev/null || MISSING+=("tor")
command -v obfs4proxy   &>/dev/null || MISSING+=("obfs4proxy")
command -v macchanger   &>/dev/null || MISSING+=("macchanger")
command -v iptables     &>/dev/null || MISSING+=("iptables")
command -v dnscrypt-proxy &>/dev/null || warn "dnscrypt-proxy not found (optional, DoH mode still works)"

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing tools: ${MISSING[*]}"
    warn "Some modules may not function. Install missing tools manually."
else
    ok "All required tools present."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  GhostRoute installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Launch TUI     : ${CYAN}sudo ghostroute tui${NC}"
echo -e "  Start all      : ${CYAN}sudo ghostroute start${NC}"
echo -e "  Quick start    : ${CYAN}sudo ghostroute start --modules tor_routing,dns_protect,ipv6_block,kill_switch${NC}"
echo -e "  Leak audit     : ${CYAN}sudo ghostroute audit${NC}"
echo -e "  Add proxy      : ${CYAN}sudo ghostroute proxy add 1.2.3.4:1080:socks5${NC}"
echo -e "  Rotate IP      : ${CYAN}sudo ghostroute rotate${NC}"
echo -e "  Stop & restore : ${CYAN}sudo ghostroute stop${NC}"
echo ""
echo -e "  Config file    : ${YELLOW}$CONFIG_DIR/config.yaml${NC}"
echo -e "  Proxy list     : ${YELLOW}$CONFIG_DIR/proxies.txt${NC}"
echo -e "  Logs           : ${YELLOW}$LOG_DIR/${NC}"
echo ""
echo -e "${RED}  ⚠  Use only for authorized security research and privacy operations.${NC}"
echo ""
