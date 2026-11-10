#!/bin/bash

# ==========================================================
# ProxDnx - uninstaller
# ==========================================================
# Author       : macedot
# Repository   : https://github.com/macedot/ProxDnx
# License      : AGPL-3.0
# Version      : 1.0
# Last Updated : 10/11/2026
# ==========================================================
# Description:
# Removes ProxDnx and everything it manages:
#   • proxdnx.service + proxdnx-mdns.service
#   • /usr/local/bin/proxdnx + proxdnx-mdns-publish
#   • proxdnx-marked files in /etc/avahi/services
#   • /etc/avahi/proxdnx-aliases.conf
#   • /etc/logrotate.d/proxdnx
#
# Kept on purpose (manual cleanup if wanted):
#   • caddy + avahi-daemon (independent services)
#   • /etc/caddy/Caddyfile (*.pre-proxdnx-* backups exist)
#   • ~/.config/proxdnx/config.yaml + /var/log/proxdnx/
#
# Usage:
#   uninstall.sh [-y]
# ==========================================================

# Colors ===================================================
YW="\033[33m"
YWB="\033[1;33m"
GN="\033[1;92m"
RD="\033[01;31m"
CL="\033[m"
BL="\033[36m"
CUS="\e[38;5;214m"
BOLD="\033[1m"
CM="${GN}✓ ${CL}"
TAB="    "

msg_info()  { echo -e "${TAB}${YW}${1}${CL}"; }
msg_ok()    { echo -e "${TAB}${CM}${GN}${1}${CL}"; }
msg_error() { echo -e "${TAB}${RD}[ERROR] ${1}${CL}"; }

confirm() {
    [ "${ASSUME_YES:-0}" -eq 1 ] && return 0
    if [ ! -t 0 ]; then
        echo -e "${TAB}${YW}Non-interactive shell detected — proceeding automatically.${CL}"
        return 0
    fi
    read -r -p "$(echo -e "${TAB}${YWB}${1} [y/N]: ${CL}")" answer
    case "$answer" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

ASSUME_YES=0
while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) echo "Usage: uninstall.sh [-y]"; exit 0 ;;
        *) shift ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { msg_error "This script must be run as root."; exit 1; }

echo -e "${CUS}${BOLD}ProxDnx uninstaller${CL}"
echo

if ! confirm "Remove ProxDnx from this host?"; then
    msg_error "Uninstall cancelled."
    exit 1
fi

msg_info "Stopping services..."
systemctl disable --now proxdnx.service 2>/dev/null || true
systemctl disable --now proxdnx-mdns.service 2>/dev/null || true
msg_ok "services stopped"

msg_info "Removing proxdnx-managed avahi service files..."
n=0
if [ -d /etc/avahi/services ]; then
    for f in /etc/avahi/services/*.service; do
        [ -f "$f" ] || continue
        if grep -qiE "managed by proxdn(s|x)" "$f" 2>/dev/null; then
            rm -f "$f"
            n=$((n+1))
        fi
    done
fi
if [ "$n" -gt 0 ]; then
    systemctl reload avahi-daemon 2>/dev/null || true
fi
msg_ok "removed $n files"

msg_info "Removing proxdnx files..."
rm -f /etc/avahi/proxdnx-aliases.conf
rm -f /usr/local/bin/proxdnx /usr/local/bin/proxdnx-mdns-publish
rm -f /etc/systemd/system/proxdnx.service /etc/systemd/system/proxdnx-mdns.service
rm -f /etc/logrotate.d/proxdnx
systemctl daemon-reload
msg_ok "files removed"

echo
echo -e "${CUS}🗑  ProxDnx uninstalled.${CL}"
echo -e "${TAB}${YW}Kept on purpose (clean up manually if wanted):${CL}"
echo -e "${TAB}  • caddy + avahi-daemon are still installed/running"
echo -e "${TAB}  • ${BL}/etc/caddy/Caddyfile${CL} ${YW}(*.pre-proxdnx-* backups exist)${CL}"
echo -e "${TAB}  • ${BL}~/.config/proxdnx/${CL} ${YW}(config)${CL} and ${BL}/var/log/proxdnx/${CL} ${YW}(logs)${CL}"
echo
exit 0
