<div align="center">

# ProxDnx

**ProxMenux-driven `*.local` publisher for Proxmox VE** — every app in your
homelab becomes reachable as `https://<service>.local`, with mDNS discovery
and automatic reverse proxying, zero manual DNS.

<br />

<a href="https://github.com/macedot/ProxDnx/releases/latest"><img src="https://img.shields.io/github/v/release/macedot/ProxDnx?display_name=tag&label=latest&color=2A3A5D&style=flat-square" alt="Latest release" /></a>
<a href="https://github.com/macedot/ProxDnx/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-2A3A5D?style=flat-square" alt="License" /></a>
<a href="https://github.com/macedot/ProxDnx/releases"><img src="https://img.shields.io/badge/arch-amd64%20%7C%20arm64-E64804?style=flat-square" alt="Architectures" /></a>
<a href="https://github.com/macedot/ProxDnx/issues"><img src="https://img.shields.io/github/issues/macedot/ProxDnx?color=2A3A5D&style=flat-square" alt="Open issues" /></a>

</div>

<br />

<p align="center">
  <strong>ProxDnx</strong> watches your <a href="https://github.com/MacRimi/ProxMenux"><strong>ProxMenux</strong></a>
  Monitor, learns every running LXC app (name, IP, port), and publishes it as
  a valid <strong>https://&lt;service&gt;.local</strong> domain through Caddy and avahi —
  converging automatically every 60 seconds. Go stdlib only, zero dependencies.
</p>

---

## 📌 Installation

Run the following command in your Proxmox server terminal:

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/macedot/ProxDnx/main/install.sh)"
```

or with curl:

```bash
curl -fsSL https://raw.githubusercontent.com/macedot/ProxDnx/main/install.sh | bash
```

Install a specific release instead of the latest:

```bash
curl -fsSL https://raw.githubusercontent.com/macedot/ProxDnx/main/install.sh | bash -s -- v1.0.0
```

> ⚠️ Be careful when copying scripts from the internet. Always remember to check the source!
>
> 📄 You can [review the install script](https://github.com/macedot/ProxDnx/blob/main/install.sh) before execution.
>
> 🛡️ Requirements: [ProxMenux](https://github.com/MacRimi/ProxMenux) Monitor running, plus the `caddy` and `avahi-daemon` packages.

---

## 📌 How to Use

Once installed, ProxDnx runs as a systemd daemon and needs no interaction.
Every 60 seconds it:

1. Asks ProxMenux for every running LXC and its discovered apps/ports
2. Picks each guest's IP on the host bridge subnet (e.g. `vmbr0`)
3. Diffs against the previous run and logs **kept / added / removed / changed**
4. Updates what changed — and only what changed:
   - `/etc/caddy/Caddyfile` → `https://<service>.local` reverse-proxied to the app (TLS from Caddy's internal CA, `caddy validate` before reload)
   - `/etc/avahi/services/<service>.service` → mDNS advertisement
   - `proxdnx-mdns.service` → publishes `<service>.local` A records via `avahi-publish`

It also serves a small **static infrastructure layer** (disable with
`static_redirects: false`):

- `https://<host>.local` → **Proxmox VE web UI** (`:8006`)
- `https://menux.local`, `https://proxmenux.local`, `https://menux.<host>.local` → **ProxMenux Monitor** (`:8008`)
- only `https://apps.<host>.local` serves the ProxDnx dashboard itself

Open any published app from any mDNS-capable device on your LAN:

```
https://immich.local        https://plex.local        https://adguard-home.local
```

> 🔐 The first time, import Caddy's local root CA on your clients
> (`/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt`)
> so browsers show a valid padlock — no public CA can issue certificates
> for `.local`.

---

## 🌐 API

The daemon exports a small HTTP API reporting every domain it published:

| Endpoint | Description |
|---|---|
| `GET /api/domains` | All published domains: `{"domain","service","name","ip","port"}` |
| `GET /api/static` | Static infrastructure redirects (`enabled`, routes with names + targets) |
| `GET /api/status` | Interval, enabled writers, last cycle stats (kept/added/removed/changed) |
| `GET /healthz` | Liveness |

```bash
curl http://<your-proxmox-ip>:9973/api/domains
```

---

## ⚙️ Configuration

`~/.config/proxdnx/config.yaml` — bootstrapped on first install, never overwritten on upgrade:

| Key | Default | Purpose |
|---|---|---|
| `url` | `http://127.0.0.1:8008` | ProxMenux Monitor API |
| `bridge` | `vmbr0` | Host bridge whose subnet guests are matched against |
| `network` | *(empty)* | Explicit CIDR override (e.g. `10.4.2.0/24`) |
| `interval` | `60s` | Cycle interval |
| `caddy` / `avahi` | `true` (installer) | Enable each writer |
| `http` | `true` | Serve plain `http://name.local` on :80 alongside HTTPS (no redirect) |
| `static_redirects` | `true` | Static infra redirects: `<host>.local` → Proxmox UI, `menux*.local` → ProxMenux; listed separately on the portal |
| `api_addr` | `127.0.0.1:9973` | API listen address |
| `log_file` | `/var/log/proxdnx/proxdnx.log` | Log file (also journald) |
| `token` / `user` / `password` | *(empty)* | Optional ProxMenux auth (`PROXMENUX_TOKEN` env works too) |

**Useful commands:**

```bash
# Check service status
systemctl status proxdnx

# View logs
tail -f /var/log/proxdnx/proxdnx.log
journalctl -u proxdnx -n 50

# Restart after a config change
systemctl restart proxdnx
```

---

## 🧩 Services

| Service | Purpose |
|---|---|
| `proxdnx.service` | The daemon — `Requires=` + `After=` caddy and avahi-daemon |
| `proxdnx-mdns.service` | Publishes `<service>.local` A records via `avahi-publish` |

---

## 🔄 Updating

Re-run the install command — it downloads the latest release, upgrades the
binary and restarts the service. Your config is never overwritten.

---

## 🗑️ Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/macedot/ProxDnx/main/uninstall.sh | bash
```

Removes the services, the binary and every proxdnx-managed avahi file.
Kept on purpose: `caddy`, `avahi-daemon`, the generated
`/etc/caddy/Caddyfile` (with `.pre-proxdnx-*` backups), your config and logs.

---

## 📜 License

[AGPL-3.0](LICENSE) — free to use, modify and share; network services built on it must share their source.
