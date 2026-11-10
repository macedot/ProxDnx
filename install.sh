#!/usr/bin/env bash
# ProxDnx installer — designed for `curl | bash` from the raw repo URL:
#   curl -fsSL https://raw.githubusercontent.com/macedot/ProxDnx/main/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- v1.2.3          # specific release
#   curl -fsSL .../install.sh | PROXDNS_REPO=you/ProxDnx bash
# Local mode (no GitHub needed):  ./install.sh --binary ./proxdns
set -euo pipefail

REPO="${PROXDNS_REPO:-macedot/ProxDnx}"
VERSION="${1:-latest}"
BIN_SRC=""   # --binary mode
BIN=/usr/local/bin/proxdns
CONF_DIR="${HOME:-/root}/.config/proxdnx"
CONF="${CONF_DIR}/config.yaml"
LOG_DIR=/var/log/proxdns

if [ "${1:-}" = "--binary" ]; then
  BIN_SRC="${2:?--binary needs a path}"
  VERSION="local"
fi

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

case "$(uname -m)" in
  x86_64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

echo "==> proxdns install: version=$VERSION arch=$ARCH repo=$REPO"

# --- acquire binary ----------------------------------------------------------
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [ -n "$BIN_SRC" ]; then
  cp "$BIN_SRC" "$TMP/proxdns"
else
  if [ "$VERSION" = "latest" ]; then
    URL="https://github.com/${REPO}/releases/latest/download/proxdns-linux-${ARCH}.tar.gz"
  else
    URL="https://github.com/${REPO}/releases/download/${VERSION}/proxdns-linux-${ARCH}.tar.gz"
  fi
  echo "==> downloading $URL"
  curl -fsSL -o "$TMP/dl.tar.gz" "$URL"
  tar -xzf "$TMP/dl.tar.gz" -C "$TMP"
fi

# --- prerequisites -----------------------------------------------------------
for svc in caddy avahi-daemon; do
  if ! systemctl is-active --quiet "$svc"; then
    echo "WARNING: $svc is not running — proxdns.service Requires it and will not start" >&2
  fi
done
command -v avahi-publish >/dev/null || echo "WARNING: avahi-publish not found (needed for *.local A records)" >&2

# --- files -------------------------------------------------------------------
install -m 0755 "$TMP/proxdns" "$BIN"

install -d -m 0755 "$LOG_DIR" "$CONF_DIR" /etc/avahi/services
if [ ! -f "$CONF" ]; then
  echo "==> writing $CONF (edit to taste; flags/env override it)"
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
fi

# mDNS alias publisher (managed by the daemon at runtime too; install here so
# the unit exists before first start)
install -m 0755 /dev/null /usr/local/bin/proxdns-mdns-publish
cat > /usr/local/bin/proxdns-mdns-publish <<'EOF'
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
chmod 0755 /usr/local/bin/proxdns-mdns-publish

cat > /etc/systemd/system/proxdns-mdns.service <<'EOF'
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

cat > /etc/systemd/system/proxdns.service <<'EOF'
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

systemctl daemon-reload
systemctl enable --now proxdns-mdns.service
systemctl enable proxdns.service
systemctl restart proxdns.service   # restart (not just start) so upgrades take effect

echo "==> installed."
echo "    binary:     $BIN"
echo "    config:     $CONF"
echo "    log:        $LOG_DIR/proxdns.log (+ journalctl -u proxdns)"
echo "    api:        curl http://127.0.0.1:9973/api/domains"
echo "    status:     systemctl status proxdns"
