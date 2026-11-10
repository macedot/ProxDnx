#!/usr/bin/env python3
"""List running LXC guests from the ProxMenux monitor API with name, hosts and ports.

Reads /api/vms for guest name/IPs/status, then merges ports from:
  - app_watches[].ports        (catalog-tracked apps, incl. OCI-managed)
  - /api/vms/<id>/apps/docker-discovery  (cached GET; POST with --scan)
  - /api/vms/<id>/apps/native-discovery  (cached GET; POST with --scan)

Host IP selection: for each guest, prefer the IPv4 that lives on the same
subnet as the given host bridge (default vmbr0), like adguard_proxmox_sync.py.
Override with --network CIDR.

Auth is optional: if the monitor has auth disabled, plain requests work.
  --token TOK                 Bearer token (env PROXMENUX_TOKEN)
  --user U --password P       login via /api/auth/login (env PROXMENUX_USER/PROXMENUX_PASS)
  --totp CODE                 optional 2FA code (env PROXMENUX_TOTP)
  --url URL                   monitor base URL (default http://127.0.0.1:8008)
  --bridge DEV                host bridge whose subnet guests are matched against (default vmbr0)
  --network CIDR              explicit subnet override (e.g. 10.4.2.0/24)
  --output FILE               write [{"name","service","ip","port"}, ...] JSON — name is the LXC
                              hostname, service is the ProxMenux Apps service name (falls back to
                              the hostname); guests without a matched IP or ports are omitted
  --caddy                     generate /etc/caddy/Caddyfile (<slug>.local -> reverse_proxy) and
                              reload caddy; caddy must be running
  --avahi                     generate /etc/avahi/services/<slug>.service per app and reload
                              avahi-daemon; avahi-daemon must be running
  --scan                      force fresh docker/native discovery scans (slower)
  --all                       include non-running guests
  --only 100,109              restrict to these VMIDs
  --json                      emit full JSON (vmid, ips, ports with sources) to stdout
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from xml.sax.saxutils import escape as xml_escape

UA = "proxmenux-lxc-ports/1.2"
MANAGED_BY = "managed by proxdns (proxmenux-lxc-ports.py)"
CADDYFILE = "/etc/caddy/Caddyfile"
AVAHI_SERVICES_DIR = "/etc/avahi/services"
AVAHI_ALIASES = "/etc/avahi/proxdns-aliases.conf"
AVAHI_PUBLISHER_UNIT = "/etc/systemd/system/proxdns-mdns.service"
AVAHI_PUBLISHER_BIN = "/usr/local/bin/proxdns-mdns-publish"
AVAHI_PUBLISHER_BIN_SRC = """#!/bin/bash
# {marker}
# publishes one A record per line of {aliases} via avahi-publish
ALIASES="{aliases}"
PIDS=()
while read -r name ip; do
    [ -z "$name" ] && continue
    case "$name" in "#"*) continue ;; esac
    [ -z "$ip" ] && continue
    avahi-publish -a -R "$name" "$ip" &
    PIDS+=("$!")
done < "$ALIASES"
wait
""".format(marker=MANAGED_BY, aliases=AVAHI_ALIASES)
AVAHI_PUBLISHER_UNIT_SRC = """[Unit]
Description=ProxDNS mDNS alias publisher (avahi-publish per *.local name)
After=avahi-daemon.service
Requires=avahi-daemon.service

[Service]
Type=simple
ExecStart={bin}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
""".format(bin=AVAHI_PUBLISHER_BIN)
CADDY_MARKER = "# " + MANAGED_BY
AVAHI_MARKER = MANAGED_BY  # used inside <!-- --> template comment; must not contain "-->"

AVAHI_TEMPLATE = """<?xml version="1.0" standalone='no'?>
<!-- {marker} generated {ts} -->
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">{name}</name>
  <service>
    <type>_http._tcp</type>
    <port>{port}</port>
  </service>
</service-group>
"""


def http_json(url, method="GET", payload=None, token=None, timeout=10):
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {}
        return e.code, body


def acquire_token(base, args):
    user = args.user or os.environ.get("PROXMENUX_USER")
    password = args.password or os.environ.get("PROXMENUX_PASS")
    if not (user and password):
        sys.exit("auth: --token or --user/--password (or env) required when auth is enabled")
    code, body = http_json(
        base + "/api/auth/login", "POST",
        payload={"username": user, "password": password, "totp_token": args.totp},
        timeout=15,
    )
    if code == 200 and body.get("success") and body.get("token"):
        return body["token"]
    if body.get("requires_totp") and not args.totp:
        sys.exit("auth: 2FA required — pass --totp CODE")
    sys.exit("auth: login failed (HTTP %s): %s" % (code, body.get("message", body)))


def get_host_subnet(bridge):
    """IPv4 network of the host bridge, same approach as adguard_proxmox_sync.py."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "dev", bridge], text=True, timeout=5)
        for line in out.splitlines():
            for p in line.split():
                if "/" in p and p.count(".") == 3:
                    iface = ipaddress.IPv4Interface(p)
                    if not iface.ip.is_loopback:
                        return iface.network
    except Exception as e:
        print("warning: could not determine subnet of %s: %s" % (bridge, e), file=sys.stderr)
    return None


def pick_ip_in_subnet(ips, subnet):
    """IPv4 inside subnet; None if the guest has no address in the wanted network."""
    v4 = [ip for ip in ips if ":" not in ip]
    if not v4:
        return None
    if subnet is None:
        return v4[0]
    for ip in v4:
        try:
            if ipaddress.IPv4Address(ip) in subnet:
                return ip
        except ValueError:
            continue
    return None


def slugify(name):
    """AdGuard Home -> adguard-home; valid as mDNS/Caddy label."""
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "app"


def require_active(unit):
    """The flag asserts the service must be running; refuse otherwise."""
    r = subprocess.run(["systemctl", "is-active", "--quiet", unit])
    if r.returncode != 0:
        sys.exit("%s: service is not running — start it (systemctl start %s) before using this flag" % (unit, unit))


def dedupe_sites(records):
    """One site per slug (slugified service name); first record wins."""
    sites = {}
    for r in records:
        base = slugify(r["service"])
        s, n = base, 2
        while s in sites:
            s = "%s-%d" % (base, n)
            n += 1
        sites[s] = r
    return sites


def write_caddy(records):
    sites = dedupe_sites(records)
    if not sites:
        print("caddy: no records — Caddyfile left untouched", file=sys.stderr)
        return
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    if os.path.exists(CADDYFILE):
        with open(CADDYFILE) as f:
            cur = f.read()
        if cur.strip() and CADDY_MARKER not in cur:
            bak = "%s.pre-proxdns-%s" % (CADDYFILE, time.strftime("%Y%m%d-%H%M%S"))
            shutil.copy2(CADDYFILE, bak)
            print("caddy: existing unmanaged Caddyfile backed up -> %s" % bak, file=sys.stderr)
    # internal CA for TLS: no public CA can issue for .local; trust caddy's root
    # on clients to get valid https. Site labels keep https:// (port 443, with
    # automatic http:80 -> https redirect)
    out = [CADDY_MARKER, "# generated %s from %d records" % (ts, len(sites)), "",
           "{", "    local_certs", "}"]
    for s in sorted(sites):
        r = sites[s]
        out += ["", "https://%s.local {" % s, "    reverse_proxy %s:%d" % (r["ip"], r["port"]), "}"]
    tmp = CADDYFILE + ".tmp-proxdns"
    with open(tmp, "w") as f:
        f.write("\n".join(out) + "\n")
    chk = subprocess.run(["caddy", "validate", "--config", tmp, "--adapter", "caddyfile"],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        os.unlink(tmp)
        sys.exit("caddy: generated config failed validation:\n%s" % (chk.stderr or chk.stdout)[-800:])
    os.replace(tmp, CADDYFILE)
    rel = subprocess.run(["systemctl", "reload", "caddy"], capture_output=True, text=True)
    if rel.returncode != 0:
        sys.exit("caddy: reload failed: %s" % rel.stderr.strip())
    print("caddy: wrote %s (%d sites) and reloaded" % (CADDYFILE, len(sites)))


def get_host_ip(bridge):
    """First non-loopback IPv4 of the host bridge (mDNS aliases point here, at caddy)."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "dev", bridge], text=True, timeout=5)
        for line in out.splitlines():
            for p in line.split():
                if "/" in p and p.count(".") == 3:
                    iface = ipaddress.IPv4Interface(p)
                    if not iface.ip.is_loopback:
                        return str(iface.ip)
    except Exception:
        pass
    return None


def write_avahi(records, bridge="vmbr0"):
    sites = dedupe_sites(records)
    if not sites:
        print("avahi: no records — nothing written", file=sys.stderr)
        return
    os.makedirs(AVAHI_SERVICES_DIR, exist_ok=True)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    want = set()
    for s, r in sorted(sites.items()):
        fname = "%s.service" % s
        want.add(fname)
        path = os.path.join(AVAHI_SERVICES_DIR, fname)
        content = AVAHI_TEMPLATE.format(marker=AVAHI_MARKER, ts=ts,
                                        name=xml_escape(r["service"]), port=r["port"])
        with open(path, "w") as f:
            f.write(content)
    removed = []
    for f in sorted(os.listdir(AVAHI_SERVICES_DIR)):
        if not f.endswith(".service") or f in want:
            continue
        path = os.path.join(AVAHI_SERVICES_DIR, f)
        with open(path) as fh:
            cur = fh.read()
        if AVAHI_MARKER in cur:
            os.unlink(path)
            removed.append(f)
        else:
            print("avahi: left unmanaged file %s" % f, file=sys.stderr)
    rel = subprocess.run(["systemctl", "reload", "avahi-daemon"], capture_output=True, text=True)
    if rel.returncode != 0:
        sys.exit("avahi-daemon: reload failed: %s" % rel.stderr.strip())
    msg = "avahi: wrote %d service files in %s and reloaded" % (len(want), AVAHI_SERVICES_DIR)
    if removed:
        msg += " (removed stale: %s)" % ", ".join(removed)
    print(msg)

    # *.local A records -> host IP (caddy routes by Host header); without this,
    # service files only make apps browsable, <slug>.local does not resolve.
    host_ip = get_host_ip(bridge)
    if not host_ip:
        sys.exit("avahi: could not determine host IPv4 on %s for alias publishing" % bridge)
    lines = ["# %s" % MANAGED_BY, "# generated %s" % ts,
             "# all aliases point at the host so caddy can route by Host header"]
    lines += ["%s.local %s" % (s, host_ip) for s in sorted(sites)]
    body = "\n".join(lines) + "\n"
    alias_changed = True
    if os.path.exists(AVAHI_ALIASES):
        with open(AVAHI_ALIASES) as f:
            alias_changed = f.read() != body
    if alias_changed:
        with open(AVAHI_ALIASES, "w") as f:
            f.write(body)
    unit_changed = True
    if os.path.exists(AVAHI_PUBLISHER_UNIT):
        with open(AVAHI_PUBLISHER_UNIT) as f:
            unit_changed = f.read() != AVAHI_PUBLISHER_UNIT_SRC
    if unit_changed:
        with open(AVAHI_PUBLISHER_UNIT, "w") as f:
            f.write(AVAHI_PUBLISHER_UNIT_SRC)
    bin_changed = True
    if os.path.exists(AVAHI_PUBLISHER_BIN):
        with open(AVAHI_PUBLISHER_BIN) as f:
            bin_changed = f.read() != AVAHI_PUBLISHER_BIN_SRC
    if bin_changed:
        with open(AVAHI_PUBLISHER_BIN, "w") as f:
            f.write(AVAHI_PUBLISHER_BIN_SRC)
        os.chmod(AVAHI_PUBLISHER_BIN, 0o755)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    subprocess.run(["systemctl", "enable", "--quiet", "proxdns-mdns"], capture_output=True)
    if alias_changed or unit_changed or bin_changed:
        rel2 = subprocess.run(["systemctl", "restart", "proxdns-mdns"], capture_output=True, text=True)
        if rel2.returncode != 0:
            sys.exit("proxdns-mdns: restart failed: %s" % rel2.stderr.strip())
        time.sleep(1)
        alive = subprocess.run(["systemctl", "is-active", "--quiet", "proxdns-mdns"])
        if alive.returncode != 0:
            sys.exit("proxdns-mdns: exited immediately — check journalctl -u proxdns-mdns "
                     "(avahi may refuse A-record publishing)")
        print("avahi: %d *.local aliases -> %s via proxdns-mdns (restarted)" % (len(sites), host_ip))
    else:
        st = subprocess.run(["systemctl", "is-active", "--quiet", "proxdns-mdns"])
        if st.returncode != 0:
            sys.exit("proxdns-mdns: unit not running despite no changes — check journalctl -u proxdns-mdns")
        print("avahi: %d *.local aliases -> %s unchanged (proxdns-mdns running)" % (len(sites), host_ip))


def collect_ports(base, token, vmid, scan):
    """Return list of {source, name, port} entries for one guest."""
    found = []
    seen = set()

    def add(source, name, port):
        key = (source, name, port)
        if port and key not in seen:
            seen.add(key)
            found.append({"source": source, "name": name, "port": int(port)})

    # cached scans are GET, forced scans are POST
    disc = [
        ("docker", "/api/vms/%d/apps/docker-discovery" % vmid),
        ("native", "/api/vms/%d/apps/native-discovery" % vmid),
    ]
    for source, path in disc:
        try:
            code, body = http_json(base + path, "POST" if scan else "GET", token=token,
                                   timeout=120 if scan else 10)
            if code != 200:
                add(source + ":http%s" % code, None, None)
                continue
            for c in body.get("candidates") or []:
                for p in c.get("default_ports") or []:
                    add(source, c.get("container_name"), p)
            for issue in body.get("issues") or []:
                add(source + ":issue", issue, None)
        except Exception as e:
            add(source + ":error", str(e)[:40], None)
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("PROXMENUX_URL", "http://127.0.0.1:8008"))
    ap.add_argument("--token", default=os.environ.get("PROXMENUX_TOKEN"))
    ap.add_argument("--user", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--totp", default=os.environ.get("PROXMENUX_TOTP"))
    ap.add_argument("--bridge", default="vmbr0", help="host bridge to match subnets against (default vmbr0)")
    ap.add_argument("--network", default=None, help="explicit CIDR override, e.g. 10.4.2.0/24")
    ap.add_argument("--output", default=None, help="write [{name,service,ip,port}] JSON to FILE")
    ap.add_argument("--caddy", action="store_true",
                    help="generate /etc/caddy/Caddyfile (https://<slug>.local via Caddy's internal "
                         "CA) and reload caddy")
    ap.add_argument("--avahi", action="store_true",
                    help="generate /etc/avahi/services/<slug>.service per app and reload avahi-daemon")
    ap.add_argument("--scan", action="store_true", help="force fresh discovery scans (POST)")
    ap.add_argument("--all", action="store_true", help="include non-running guests")
    ap.add_argument("--only", default="", help="comma-separated VMID filter")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    token = args.token
    if not token and (args.user or args.password or os.environ.get("PROXMENUX_USER")):
        token = acquire_token(base, args)
    if args.caddy:
        require_active("caddy")
    if args.avahi:
        require_active("avahi-daemon")

    if args.network:
        try:
            subnet = ipaddress.ip_network(args.network, strict=False)
        except ValueError as e:
            sys.exit("--network: %s" % e)
    else:
        subnet = get_host_subnet(args.bridge)
    print("subnet filter: %s" % (subnet or "none (first IPv4 wins)"), file=sys.stderr)

    code, guests = http_json(base + "/api/vms", token=token, timeout=15)
    if code != 200 or not isinstance(guests, list):
        sys.exit("monitor: /api/vms failed (HTTP %s): %s — if auth is enabled, pass credentials" % (code, guests))

    only = {int(x) for x in args.only.split(",") if x.strip().isdigit()} if args.only else None
    rows = []
    records = []
    for g in guests:
        if not args.all and g.get("status") != "running":
            continue
        if g.get("type") not in (None, "lxc"):
            continue
        if only and g.get("vmid") not in only:
            continue
        ports = collect_ports(base, token, g["vmid"], args.scan)
        watch_ports = []
        for w in g.get("app_watches") or []:
            for p in w.get("ports") or []:
                if p.get("port"):
                    watch_ports.append({"source": "app_watch", "name": w.get("name") or w.get("helper_slug"),
                                        "port": int(p["port"])})
        ips = g.get("ips") or ([g["ip"]] if g.get("ip") else [])
        ip = pick_ip_in_subnet(ips, subnet)
        all_ports = sorted(watch_ports + ports, key=lambda x: (x["source"], x["port"] or 0))
        rows.append({
            "vmid": g.get("vmid"), "name": g.get("name"), "status": g.get("status"),
            "ips": ips, "ip": ip, "ports": all_ports,
        })
        if ip:
            for p in all_ports:
                if p.get("port"):
                    records.append({
                        "name": g.get("name"),
                        "service": p.get("name") or g.get("name"),
                        "ip": ip,
                        "port": p["port"],
                    })
    rows.sort(key=lambda r: r["vmid"] or 0)
    records.sort(key=lambda r: (r["name"], r["port"]))

    # one record per (ip, port): discovery sources can overlap
    seen = set()
    dedup = []
    for r in records:
        k = (r["ip"], r["port"])
        if k not in seen:
            seen.add(k)
            dedup.append(r)
    records = dedup

    if args.caddy:
        write_caddy(records)
    if args.avahi:
        write_avahi(records, args.bridge)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(records, f, indent=2)
            f.write("\n")
        print("wrote %d records -> %s" % (len(records), args.output), file=sys.stderr)
    if args.as_json:
        print(json.dumps(rows, indent=2))
        return

    hdr = "%-6s %-16s %-8s %-28s %s" % ("VMID", "NAME", "STATE", "HOSTS (picked)", "PORTS")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        v4 = [ip for ip in r["ips"] if ":" not in ip]
        disp = r["ip"] or (",".join(v4) or (r["ips"][0] if r["ips"] else "-"))
        if r["ip"] and len(v4) > 1:
            disp += " *"
        allports = sorted({p["port"] for p in r["ports"] if p.get("port")})
        notes = sorted({p["name"] for p in r["ports"] if not p.get("port")})
        line = "%-6s %-16s %-8s %-28s %s" % (
            r["vmid"], r["name"], r["status"], disp,
            ",".join(map(str, allports)) if allports else "-")
        if notes:
            line += "  (%s)" % ",".join(notes)
        if not r["ip"] and v4:
            line += "  [no IP in subnet]"
        print(line)
    print("\n%d LXC guests, %d name/ip/port records" % (len(rows), len(records)))


if __name__ == "__main__":
    main()
