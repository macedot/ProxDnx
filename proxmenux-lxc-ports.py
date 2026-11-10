#!/usr/bin/env python3
"""List running LXC guests from the ProxMenux monitor API with name, hosts and ports.

Reads /api/vms for guest name/IPs/status, then merges ports from:
  - app_watches[].ports        (catalog-tracked apps, incl. OCI-managed)
  - /api/vms/<id>/apps/docker-discovery  (cached GET; POST with --scan)
  - /api/vms/<id>/apps/native-discovery  (cached GET; POST with --scan)

Auth is optional: if the monitor has auth disabled, plain requests work.
  --token TOK                 Bearer token (env PROXMENUX_TOKEN)
  --user U --password P       login via /api/auth/login (env PROXMENUX_USER/PROXMENUX_PASS)
  --totp CODE                 optional 2FA code (env PROXMENUX_TOTP)
  --url URL                   monitor base URL (default http://127.0.0.1:8008)
  --scan                      force fresh docker/native discovery scans (slower)
  --all                       include non-running guests
  --only 100,109              restrict to these VMIDs
  --json                      emit JSON instead of a table
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

UA = "proxmenux-lxc-ports/1.0"


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
    ap.add_argument("--scan", action="store_true", help="force fresh discovery scans (POST)")
    ap.add_argument("--all", action="store_true", help="include non-running guests")
    ap.add_argument("--only", default="", help="comma-separated VMID filter")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    token = args.token
    if not token and (args.user or args.password or os.environ.get("PROXMENUX_USER")):
        token = acquire_token(base, args)

    code, guests = http_json(base + "/api/vms", token=token, timeout=15)
    if code != 200 or not isinstance(guests, list):
        sys.exit("monitor: /api/vms failed (HTTP %s): %s — if auth is enabled, pass credentials" % (code, guests))

    only = {int(x) for x in args.only.split(",") if x.strip().isdigit()} if args.only else None
    rows = []
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
        rows.append({
            "vmid": g.get("vmid"), "name": g.get("name"), "status": g.get("status"),
            "ips": g.get("ips") or ([g["ip"]] if g.get("ip") else []),
            "ports": sorted(watch_ports + ports, key=lambda x: (x["source"], x["port"] or 0)),
        })
    rows.sort(key=lambda r: r["vmid"] or 0)

    if args.as_json:
        print(json.dumps(rows, indent=2))
        return

    hdr = "%-6s %-16s %-8s %-28s %s" % ("VMID", "NAME", "STATE", "HOSTS", "PORTS (source)")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        v4 = [ip for ip in r["ips"] if ":" not in ip]
        disp_ips = ",".join(v4) or (r["ips"][0] if r["ips"] else "-")
        allports = sorted({p["port"] for p in r["ports"] if p.get("port")})
        notes = sorted({p["name"] for p in r["ports"] if not p.get("port")})
        line = "%-6s %-16s %-8s %-28s %s" % (
            r["vmid"], r["name"], r["status"], disp_ips,
            ",".join(map(str, allports)) if allports else "-")
        if notes:
            line += "  (%s)" % ",".join(notes)
        print(line)
    print("\n%d LXC guests" % len(rows))


if __name__ == "__main__":
    main()
