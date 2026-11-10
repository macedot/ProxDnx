#!/usr/bin/env bash
# ProxDnx uninstaller:
#   curl -fsSL https://raw.githubusercontent.com/macedot/ProxDnx/main/uninstall.sh | bash
set -euo pipefail

echo "==> stopping proxdns"
systemctl disable --now proxdns.service 2>/dev/null || true
systemctl disable --now proxdns-mdns.service 2>/dev/null || true

# proxdns-managed avahi service files (marker comment) + aliases
if [ -d /etc/avahi/services ]; then
  n=0
  for f in /etc/avahi/services/*.service; do
    [ -f "$f" ] || continue
    if grep -q "managed by proxdns" "$f" 2>/dev/null; then
      rm -f "$f"; n=$((n+1))
    fi
  done
  [ "$n" -gt 0 ] && systemctl reload avahi-daemon 2>/dev/null || true
  echo "==> removed $n proxdns avahi service files"
fi
rm -f /etc/avahi/proxdns-aliases.conf

rm -f /usr/local/bin/proxdns /usr/local/bin/proxdns-mdns-publish
rm -f /etc/systemd/system/proxdns.service /etc/systemd/system/proxdns-mdns.service
rm -f /etc/logrotate.d/proxdns
systemctl daemon-reload

echo "==> kept (manual cleanup if wanted):"
echo "    caddy + avahi-daemon are still installed/running"
echo "    /etc/caddy/Caddyfile (generated; *.pre-proxdns-* backups exist)"
echo "    config + logs: /root/.config/proxdnx/  /var/log/proxdns/"
echo "==> uninstalled."
