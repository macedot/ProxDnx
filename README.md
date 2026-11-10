# ProxDnx

ProxMenux-driven `*.local` publisher for a Proxmox host: derives
`name/ip/port` records for every running LXC from the [ProxMenux](https://github.com/MacRostie/proxmenux)
monitor API, then renders and reloads **Caddy** (reverse proxy) and **avahi**
(mDNS service files + `*.local` A records) so every app is reachable as
`https://<service>.local` on the LAN.

Go stdlib only — zero external dependencies.

## What a cycle does (default every 60s)

1. Query ProxMenux `/api/vms` + per-guest app discovery.
2. Pick each guest's IPv4 on the host bridge subnet (like `adguard_proxmox_sync.py`).
3. Diff against the previous run and log **kept / added / removed / changed**.
4. When something changed:
   - render `/etc/caddy/Caddyfile` (`https://<slug>.local` → `reverse_proxy ip:port`,
     TLS via Caddy's internal CA — no public CA can issue for `.local`),
     `caddy validate`, then `systemctl reload caddy`;
   - write `/etc/avahi/services/<slug>.service` and the alias list
     `/etc/avahi/proxdns-aliases.conf`, reload avahi-daemon, restart
     `proxdns-mdns.service` (one `avahi-publish -a -R slug.local <host-ip>` per app,
     so `<slug>.local` resolves to the host and caddy routes by Host header).

## API

```
curl http://127.0.0.1:9973/api/domains   # every published domain: {domain, service, name, ip, port}
curl http://127.0.0.1:9973/api/status    # last cycle stats + settings
curl http://127.0.0.1:9973/healthz
```

## Install / uninstall (raw-URL friendly)

```
curl -fsSL https://raw.githubusercontent.com/macedot/ProxDnx/main/install.sh | bash
curl -fsSL https://raw.githubusercontent.com/macedot/ProxDnx/main/install.sh | bash -s -- v1.0.0
curl -fsSL https://raw.githubusercontent.com/macedot/ProxDnx/main/uninstall.sh | bash
```

Other repo: prefix with `PROXDNS_REPO=you/ProxDnx`. Releases contain
`proxdns-linux-{amd64,arm64}.tar.gz` (built by GitHub Actions on `v*` tags).

## Config

`~/.config/proxdnx/config.yaml` (bootstrapped on first run; flags/env override):

```yaml
url: http://127.0.0.1:8008   # ProxMenux monitor
bridge: vmbr0                # subnet guests are matched against
interval: 60s
caddy: true
avahi: true
api_addr: 127.0.0.1:9973
log_file: /var/log/proxdns/proxdns.log
# optional auth (env PROXMENUX_TOKEN / PROXMENUX_USER / PROXMENUX_PASS also work)
token: ""
```

Logs: `/var/log/proxdns/proxdns.log` + journald (`journalctl -u proxdns`).

## Manual run

```
go build -o proxdns .
./proxdns --once --caddy --avahi      # single cycle
./proxdns --interval 30s --network 10.4.2.0/24
```

## systemd

`proxdns.service` `Requires=` + `After=` `caddy.service` and `avahi-daemon.service`
(the daemons must be up; the daemon keeps converging every interval, no cron).
