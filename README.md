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
curl -fsSL https://raw.githubusercontent.com/macedot/ProxDnx/main/install.sh | bash -s -- v0.1.8
```

The installer downloads the release tarball and **sha256-verifies it against
the release `checksums.txt`** before installing. Re-running it performs an
in-place upgrade — your config is never overwritten.

> ⚠️ Be careful when copying scripts from the internet. Always remember to check the source!
>
> 📄 You can [review the install script](https://github.com/macedot/ProxDnx/blob/main/install.sh) before execution.
>
> 🛡️ Requirements: [ProxMenux](https://github.com/MacRimi/ProxMenux) Monitor running, plus the `caddy` and `avahi-daemon` packages.
>
> 🐳 Running ProxDnx in a container instead? See [Docker / compose](#docker--compose) — no caddy/avahi needed there.

---

## 📌 How to Use

Once installed, ProxDnx runs as a systemd daemon and needs no interaction.
Every 60 seconds it:

1. Asks ProxMenux for every running LXC and its discovered apps/ports
2. Picks each guest's IP on the host bridge subnet (e.g. `vmbr0`)
3. TCP-probes every candidate port and fetches the app's UI title for an
   identity check
4. Diffs against the previous run and logs **kept / added / removed / changed**
5. Updates what changed — and only what changed:
   - `/etc/caddy/Caddyfile` → `https://<service>.local` reverse-proxied to the app (TLS from Caddy's internal CA, `caddy validate` before reload)
   - `/etc/avahi/services/<service>.service` → mDNS advertisement
   - `proxdnx-mdns.service` → publishes `<service>.local` A records via `avahi-publish`

A guest whose port stopped answering is **not** deleted: it stays visible on
the portal tagged `⚠ stale — port closed` (dimmed, excluded from caddy/avahi
until it answers again). When the served page title disagrees with the
registered name, the card gets an amber `⚠ name mismatch` badge. With
`autofix: true` the daemon can go one step further and **self-heal** wrong
ProxMenux registrations (see [Configuration](#️-configuration)).

It also serves a small **static infrastructure layer** — reverse-proxied like
any app, so no redirect and no port in the URL (disable with `static: false`):

- `https://<host>.local` → **Proxmox VE web UI** (proxied to `:8006`)
- `https://menux.local`, `https://proxmenux.local`, `https://menux.<host>.local` → **ProxMenux Monitor** (proxied to the configured monitor URL)
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
| `GET /api/domains` | All published domains: `{"domain","service","name","ip","port","stale","title","mismatch"}` |
| `GET /api/static` | Static infrastructure entries (`enabled`, routes with names + targets) |
| `GET /api/status` | Interval, enabled writers, `auth` flag, release `version`, last cycle stats (kept/added/removed/changed) |
| `GET /healthz` | Liveness — always open, even with `api_token` set |

```bash
curl http://<your-proxmox-ip>:9973/api/domains

# with api_token configured:
curl -H "Authorization: Bearer $TOKEN" http://<your-proxmox-ip>:9973/api/domains
```

---

## ⚙️ Configuration

`~/.config/proxdnx/config.yaml` — bootstrapped on first install, never
overwritten on upgrade. A fully annotated copy lives in
[`examples/config.example.yaml`](examples/config.example.yaml).

| Key | Default | Purpose |
|---|---|---|
| `url` | `http://127.0.0.1:8008` | ProxMenux Monitor API |
| `bridge` | `vmbr0` | Host bridge whose subnet guests are matched against |
| `network` | *(empty)* | Explicit CIDR override (e.g. `10.4.2.0/24`) |
| `interval` | `60s` | Cycle interval |
| `caddy` / `avahi` | `true` (installer) | Enable each writer |
| `http` | `true` | Serve plain `http://name.local` on :80 alongside HTTPS (no redirect) |
| `static` | `true` | Static infra entries, proxied like apps (no port URLs): `<host>.local` → Proxmox UI, `menux*.local` → ProxMenux; listed separately on the portal |
| `force_https` | `false` | Portal always generates `https://` links, even when the dashboard itself is opened over plain http |
| `probe` | `true` | TCP-probe every candidate port each cycle; dead ports are tagged `stale` (kept visible on the portal, excluded from caddy/avahi) and the UI title is checked against the registered name |
| `autofix` | `false` | Opt-in self-healing: when `probe` tags a registration stale or mismatched, sweep well-known ports on the guest, identify the real app by its UI title, and correct the ProxMenux registration through its own API (`PUT /api/vms/<vmid>/apps/<id>`). Renames demote the registration to link-only. Max 2 attempts per registration. Requires `probe` |
| `api_token` | *(auto-generated on first start)* | API/portal auth is on by default — like the Proxmox UI. On first start a random token is generated, stored in the config, and logged; present it via `Authorization: Bearer`, the `X-API-Token` header, `?token=`, or just open the portal and paste it into the token form. `/healthz` stays open. Constant-time compare. Set `api_token: "none"` to run an open API (loopback deployments) |
| `api_addr` | `127.0.0.1:9973` | API listen address. Loopback by default; binding non-loopback logs a loud warning — pair it with `api_token` |
| `log_file` | `/var/log/proxdnx/proxdnx.log` | Log file (also journald) |
| `token` / `user` / `password` | *(empty)* | Optional ProxMenux auth (`PROXMENUX_TOKEN` env works too) |

### Environment variables

Every key also exists as a `PROXDNX_*` environment variable, so a deployment
can be driven entirely without a config file (docker compose, systemd
`Environment=`, …):

`PROXDNX_URL`, `PROXDNX_TOKEN`, `PROXDNX_USER`, `PROXDNX_PASSWORD`,
`PROXDNX_TOTP`, `PROXDNX_BRIDGE`, `PROXDNX_NETWORK`, `PROXDNX_INTERVAL`,
`PROXDNX_CADDY`, `PROXDNX_AVAHI`, `PROXDNX_HTTP`, `PROXDNX_STATIC`,
`PROXDNX_FORCE_HTTPS`, `PROXDNX_PROBE`, `PROXDNX_AUTOFIX`, `PROXDNX_SCAN`,
`PROXDNX_API_ADDR`, `PROXDNX_API_TOKEN`, `PROXDNX_LOG_FILE`

Precedence: CLI flags > `PROXDNX_*` env > legacy `PROXMENUX_*` env (aliases
for url/token/user/pass/totp) > config file > built-in defaults. Malformed
env values (bad bool/duration) refuse startup and name the offending
variable.

Handy CLI flags (same precedence top): `-version` (print release and exit),
`-once` (single cycle, cron-style), `-autofix=false` (temporarily disable),
`-scan` (force fresh discovery POSTs), `-api-addr`, `-api-token`, `-config`.

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

<a name="docker--compose"></a>

## 🐳 Docker / compose

A `Dockerfile` and a ready-made `docker-compose.yml` ship at the repo root
(multi-stage Go build, distroless static runtime with CA certificates). In a
container ProxDnx serves the API/portal only — caddy/avahi management is a
host feature, so both writers stay off and everything is driven by env vars:

```bash
git clone https://github.com/macedot/ProxDnx && cd ProxDnx
# edit PROXDNX_URL / PROXDNX_API_TOKEN in docker-compose.yml, then:
docker compose up -d
```

```yaml
services:
  proxdnx:
    build: .
    restart: unless-stopped
    environment:
      PROXDNX_URL: "http://192.168.1.10:8008"   # ProxMenux monitor
      PROXDNX_API_ADDR: "0.0.0.0:9973"
      PROXDNX_API_TOKEN: "change-me"            # required when binding non-loopback
      PROXDNX_CADDY: "false"
      PROXDNX_AVAHI: "false"
      PROXDNX_PROBE: "true"
    ports:
      - "9973:9973"
```

No config file needed: every key is a `PROXDNX_*` environment variable.
(distroless has no shell/curl; add a sidecar healthcheck against
`http://container:9973/healthz` if you need one.)

---

## 🧪 Development

```bash
go vet ./...
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1
```

CI (`.github/workflows/test.yml`) runs vet + race-enabled tests on every push
and PR. The renderers are byte-golden-tested (renders must stay timestamp-free
so live hosts never churn), hostile service names are injection-tested, and
the API handlers — including the token auth matrix and the redirect guard —
are exercised with `httptest`.

Security posture: renderer labels are slug-restricted (`[a-z0-9-]`), the
config is validated at startup (URL scheme, interface name, CIDR, listen
address, positive interval), the API server enforces read/header/idle
timeouts, `nosniff` / `no-store`, `X-Frame-Options: DENY` and a restrictive
CSP, optional constant-time token auth protects every route (`/healthz`
exempt), file writes are O_EXCL with pid-unique temp names (config included —
it holds the monitor token/password), the identity probes cap redirects and
refuse loopback/link-local targets (SSRF guard), the monitor client caps
response bodies at 8 MiB and re-authenticates once on stale-session 401s,
and the installer sha256-verifies downloads against the release
`checksums.txt`.

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
