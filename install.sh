#!/bin/bash

# ==========================================================
# ProxDnx - ProxMenux-driven *.local publisher for Proxmox VE
# ==========================================================
# Author       : macedot
# Repository   : https://github.com/macedot/ProxDnx
# License      : AGPL-3.0 (https://www.gnu.org/licenses/agpl-3.0)
# Version      : 1.0
# Last Updated : 10/11/2026
# ==========================================================
# Description:
# This script installs and configures ProxDns, a daemon that
# publishes every ProxMenux-monitored LXC app as
# https://<service>.local via Caddy (reverse proxy + internal
# TLS) and avahi (mDNS service files + A records).
#
# - Ensures the script is run with root privileges.
# - Detects the architecture (amd64 / arm64) and downloads the
#   matching GitHub release (or uses --binary for a local file).
# - Installs the binary to /usr/local/bin/proxdns.
# - Bootstraps the configuration at
#     • $HOME/.config/proxdnx/config.yaml (only if missing)
# - Installs the mDNS alias publisher:
#     • /usr/local/bin/proxdns-mdns-publish
#     • /etc/systemd/system/proxdns-mdns.service
# - Installs the daemon service:
#     • /etc/systemd/system/proxdns.service
#       (Requires= caddy.service + avahi-daemon.service)
# - Adds log rotation at /etc/logrotate.d/proxdns.
# - Enables and starts both services.
#
# Notes:
# - caddy and avahi-daemon must be installed and running;
#   the daemon refuses to start otherwise (systemd Requires=).
# - Re-running this script performs an in-place upgrade
#   (service is restarted, config is never overwritten).
#
# Usage:
#   install.sh [-y] [VERSION]        install/upgrade (default: latest release)
#   install.sh --binary PATH         install a local binary (dev builds)
#   PROXDNS_REPO=owner/repo          override the GitHub repository
# ==========================================================

# Configuration ============================================
REPO="${PROXDNS_REPO:-macedot/ProxDnx}"
BIN="/usr/local/bin/proxdns"
PUBLISHER_BIN="/usr/local/bin/proxdns-mdns-publish"
PUBLISHER_UNIT="/etc/systemd/system/proxdns-mdns.service"
SERVICE_FILE="/etc/systemd/system/proxdns.service"
CONF_DIR="${HOME:-/root}/.config/proxdnx"
CONF="${CONF_DIR}/config.yaml"
LOG_DIR="/var/log/proxdns"
BIN_SRC=""
VERSION="latest"
ASSUME_YES=0

# Colors ===================================================
YW="\033[33m"
YWB="\033[1;33m"
MG="\033[1;35m"
GN="\033[1;92m"
RD="\033[01;31m"
CL="\033[m"
BL="\033[36m"
CUS="\e[38;5;214m"
BOLD="\033[1m"
BFR="\r\033[K"
HOLD="-"
CM="${GN}✓ ${CL}"
TAB="    "

# Helpers ==================================================
msg_info() {
    echo -e "${TAB}${MG}${1}${CL}"
}

msg_ok() {
    echo -e "${TAB}${CM}${GN}${1}${CL}"
}

msg_warn() {
    echo -e "${TAB}${YWB}${1}${CL}"
}

msg_error() {
    echo -e "${TAB}${RD}[ERROR] ${1}${CL}"
}

type_text() {
    local text="$1"
    local delay=0.02
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo
}

confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    if [ ! -t 0 ]; then
        msg_warn "Non-interactive shell detected — proceeding automatically."
        return 0
    fi
    read -r -p "$(echo -e "${TAB}${YWB}${1} [y/N]: ${CL}")" answer
    case "$answer" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

# Argument parsing =========================================
while [ $# -gt 0 ]; do
    case "$1" in
        --binary)
            BIN_SRC="${2:?--binary needs a path}"
            VERSION="local"
            shift 2
            ;;
        -y|--yes)
            ASSUME_YES=1
            shift
            ;;
        -h|--help)
            echo "Usage: install.sh [--binary PATH] [-y] [VERSION]"
            echo "  VERSION      release tag (default: latest)"
            echo "  --binary P   install a local binary instead of a release"
            echo "  -y           assume yes, skip confirmation"
            echo "  env PROXDNS_REPO=owner/repo overrides the repository"
            exit 0
            ;;
        *)
            VERSION="$1"
            shift
            ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { msg_error "This script must be run as root."; exit 1; }

echo -e "${CUS}${BOLD}"
echo "    ____                   ____  _   _  ___  ____  "
echo "   |  _ \ __ _ _ __   ___ |  _ \| \ | |/ _ \/ ___| "
echo "   | |_) / _\` | '_ \ / _ \| | | |  \| | | | \___ \ "
echo "   |  __/ (_| | | | |  __/| |_| | |\  | |_| |___) |"
echo "   |_|   \__,_|_| |_|\___||____/|_| \_|\___/|____/ "
echo -e "${CL}"

echo -e "${TAB}${BOLD}ProxDns — ProxMenux-driven *.local publisher${CL}"
echo -e "${TAB}repo: ${BL}https://github.com/${REPO}${CL}"
echo

# Prerequisites ============================================
msg_info "Checking prerequisites..."
for svc in caddy avahi-daemon; do
    if systemctl is-active --quiet "$svc"; then
        msg_ok "$svc is running"
    else
        msg_warn "$svc is NOT running — proxdns.service Requires it and will not start"
    fi
done
if command -v avahi-publish >/dev/null 2>&1; then
    msg_ok "avahi-publish available"
else
    msg_warn "avahi-publish not found — *.local A records will not resolve"
fi
if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
    msg_ok "downloader available"
else
    msg_error "need curl or wget to download the release"
    exit 1
fi

# Binary acquisition =======================================
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ -n "$BIN_SRC" ]; then
    msg_info "Using local binary: $BIN_SRC"
    cp "$BIN_SRC" "$TMP/proxdns" || { msg_error "cannot copy $BIN_SRC"; exit 1; }
else
    case "$(uname -m)" in
        x86_64)          ARCH=amd64 ;;
        aarch64|arm64)   ARCH=arm64 ;;
        *) msg_error "unsupported arch: $(uname -m)"; exit 1 ;;
    esac
    msg_ok "architecture: $ARCH"
    if [ "$VERSION" = "latest" ]; then
        URL="https://github.com/${REPO}/releases/latest/download/proxdns-linux-${ARCH}.tar.gz"
    else
        URL="https://github.com/${REPO}/releases/download/${VERSION}/proxdns-linux-${ARCH}.tar.gz"
    fi
    msg_info "Downloading ${VERSION}..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$TMP/dl.tar.gz" "$URL" || { msg_error "download failed: $URL"; exit 1; }
    else
        wget -qO "$TMP/dl.tar.gz" "$URL" || { msg_error "download failed: $URL"; exit 1; }
    fi
    tar -xzf "$TMP/dl.tar.gz" -C "$TMP" || { msg_error "extract failed"; exit 1; }
    [ -f "$TMP/proxdns" ] || { msg_error "archive missing the proxdns binary"; exit 1; }
    msg_ok "release downloaded"
fi

# Confirmation =============================================
echo
if ! confirm "Install/upgrade ProxDns on this host?"; then
    msg_error "Installation cancelled."
    exit 1
fi

# Files ====================================================
msg_info "Installing binary..."
install -m 0755 "$TMP/proxdns" "$BIN"
msg_ok "$BIN"

msg_info "Preparing directories..."
install -d -m 0755 "$LOG_DIR" "$CONF_DIR" /etc/avahi/services
msg_ok "directories ready"

if [ ! -f "$CONF" ]; then
    msg_info "Bootstrapping config at $CONF..."
    cat > "$CONF" <<'EOF'
# proxdns configuration (flat YAML subset; read + rewritten by proxdns)
# precedence: CLI flags > environment (PROXMENUX_*) > this file > built-in defaults
url: http://127.0.0.1:8008
token: ""
user: ""
password: ""
totp: ""
bridge: vmbr0
network: ""
interval: 60s
caddy: true
avahi: true
scan: false
api_addr: 127.0.0.1:9973
log_file: /var/log/proxdns/proxdns.log
EOF
    chmod 600 "$CONF"
    msg_ok "config created (edit to taste; restart proxdns to apply)"
else
    msg_ok "config kept as-is: $CONF"
fi

msg_info "Installing mDNS alias publisher..."
cat > "$PUBLISHER_BIN" <<'EOF'
#!/bin/bash
# managed by proxdns (ProxDnx)
# publishes one A record per line of /etc/avahi/proxdns-aliases.conf via avahi-publish
ALIASES="/etc/avahi/proxdns-aliases.conf"
while read -r name ip; do
    [ -z "$name" ] && continue
    case "$name" in "#"*) continue ;; esac
    [ -z "$ip" ] && continue
    avahi-publish -a -R "$name" "$ip" &
done < "$ALIASES"
wait
EOF
chmod 0755 "$PUBLISHER_BIN"

cat > "$PUBLISHER_UNIT" <<'EOF'
[Unit]
Description=ProxDNS mDNS alias publisher (avahi-publish per *.local name)
After=avahi-daemon.service
Requires=avahi-daemon.service

[Service]
Type=simple
ExecStart=/usr/local/bin/proxdns-mdns-publish
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
msg_ok "publisher installed"

msg_info "Installing proxdns.service (Requires: caddy + avahi-daemon)..."
cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=ProxDNS - ProxMenux driven caddy/avahi *.local publisher
Wants=network-online.target
After=network-online.target caddy.service avahi-daemon.service proxdns-mdns.service
Requires=caddy.service avahi-daemon.service

[Service]
Type=simple
ExecStart=/usr/local/bin/proxdns --config /root/.config/proxdnx/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
msg_ok "$SERVICE_FILE"

msg_info "Configuring log rotation..."
cat > /etc/logrotate.d/proxdns <<'EOF'
/var/log/proxdns/proxdns.log {
    weekly
    rotate 8
    compress
    delaycompress
    copytruncate
    missingok
    notifempty
}
EOF
msg_ok "/etc/logrotate.d/proxdns"

# Services =================================================
msg_info "Enabling and starting services..."
systemctl daemon-reload
systemctl enable --now proxdns-mdns.service >/dev/null 2>&1 || true
systemctl enable proxdns.service >/dev/null 2>&1
systemctl restart proxdns.service
sleep 2
if systemctl is-active --quiet proxdns; then
    msg_ok "proxdns is running"
else
    msg_error "proxdns failed to start — check: journalctl -u proxdns -n 30"
    exit 1
fi

# Summary ==================================================
SERVER_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk 'NR==1{split($4,a,"/");print a[1]}')
echo
echo -e "${CUS}🌐  ProxDns activated${CL}: every published app is reachable at ${BL}https://<service>.local${CL}"
echo
echo -e "${TAB}${GN}✓ ${CL}binary : ${BL}${BIN}${CL}"
echo -e "${TAB}${GN}✓ ${CL}config : ${BL}${CONF}${CL}"
echo -e "${TAB}${GN}✓ ${CL}logs   : ${BL}${LOG_DIR}/proxdns.log${CL} ${YW}(journalctl -u proxdns)${CL}"
echo -e "${TAB}${GN}✓ ${CL}api    : ${BL}http://${SERVER_IP:-127.0.0.1}:9973/api/domains${CL}"
echo
type_text "To review or tweak what gets published, edit the config and restart proxdns."
echo
exit 0
