package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const avahiTemplate = `<?xml version="1.0" standalone='no'?>
<!-- managed by proxdnx (ProxDnx) -->
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">%s</name>
  <service>
    <type>_http._tcp</type>
    <port>%d</port>
  </service>
</service-group>
`

const publisherBinSrc = `#!/bin/bash
# managed by proxdnx (ProxDnx)
# publishes one A record per line of /etc/avahi/proxdnx-aliases.conf via avahi-publish
ALIASES="/etc/avahi/proxdnx-aliases.conf"
while read -r name ip; do
    [ -z "$name" ] && continue
    case "$name" in "#"*) continue ;; esac
    [ -z "$ip" ] && continue
    # defense in depth: the aliases file is root-owned, but never hand
    # avahi-publish a name/IP that is not a plain label / dotted quad
    case "$name" in *[!a-z0-9.-]*) continue ;; esac
    case "$ip" in *[!0-9.]*) continue ;; esac
    avahi-publish -a -R "$name" "$ip" &
done < "$ALIASES"
wait
`

const publisherUnitSrc = `[Unit]
Description=ProxDnx mDNS alias publisher (avahi-publish per *.local name)
After=avahi-daemon.service
Requires=avahi-daemon.service

[Service]
Type=simple
ExecStart=/usr/local/bin/proxdnx-mdns-publish
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`

var xmlEsc = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")

// StaticRoute is a fixed infrastructure entry handled exactly like a normal
// app: caddy reverse-proxies the local names to a well-known LAN UI — no
// redirect, no port in the browser URL. Rendered into the Caddyfile,
// published via mDNS, listed on the portal and disable-able via config
// (static).
type StaticRoute struct {
	Label    string   `json:"label"`
	Desc     string   `json:"desc"`
	Names    []string `json:"names"`
	Upstream string   `json:"upstream"`
	Secure   bool     `json:"-"` // https upstream with a self-signed cert (skip verify)
}

// staticRoutes derives the fixed infrastructure entries from the hostname.
// The ProxMenux upstream is the configured monitor URL itself, so a relocated
// monitor is followed automatically. The bare <host>.local name is answered
// but never published by us: the OS avahi daemon already announces it, and
// re-announcing a host's own name with a different A record triggers an avahi
// conflict rename.
func staticRoutes(host, menuxUpstream string) []StaticRoute {
	return []StaticRoute{
		{
			Label:    "Proxmox VE",
			Desc:     "Proxmox web UI",
			Names:    []string{host + ".local"},
			Upstream: fmt.Sprintf("https://127.0.0.1:%d", defaultPVEPort),
			Secure:   true,
		},
		{
			Label:    "ProxMenux",
			Desc:     "ProxMenux Monitor home",
			Names:    []string{"menux.local", "proxmenux.local", "menux." + host + ".local"},
			Upstream: menuxUpstream,
		},
	}
}

// site is one Caddy site / avahi service / alias.
type site struct {
	Slug string
	Rec  Record
}

// dedupeSites: one site per slug (slugified service name); first record wins,
// colliding slugs get -2, -3... suffixes.
func dedupeSites(recs []Record) map[string]Record {
	sites := make(map[string]Record, len(recs))
	for _, r := range recs {
		base := slugify(r.Service)
		s, n := base, 2
		for {
			if _, taken := sites[s]; !taken {
				break
			}
			s = fmt.Sprintf("%s-%d", base, n)
			n++
		}
		sites[s] = r
	}
	return sites
}

// sanitizeHost reduces a hostname to a DNS-safe label: lower-case, first
// dot-label only, [a-z0-9-] kept, leading/trailing dashes trimmed, fallback
// "proxdnx" when nothing survives.
func sanitizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.Index(h, "."); i >= 0 {
		h = h[:i]
	}
	var b strings.Builder
	for _, r := range h {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	if s := strings.Trim(b.String(), "-"); s != "" {
		return s
	}
	return "proxdnx"
}

// hostLabel returns the sanitized short hostname used to derive the portal
// names <host>.local and apps.<host>.local.
func hostLabel() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "proxdnx"
	}
	return sanitizeHost(h)
}

// firstIPv4 extracts the first non-loopback dotted-quad address from
// `ip -4 -o addr show` output. ParseIP-strict: junk like 999.1.1.1 is
// rejected instead of published as an A record.
func firstIPv4(out string) string {
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			if strings.Contains(f, "/") && strings.Count(f, ".") == 3 {
				ip := strings.Split(f, "/")[0]
				if p := net.ParseIP(ip); p != nil && p.To4() != nil && !p.IsLoopback() {
					return ip
				}
			}
		}
	}
	return ""
}

func hostIP(bridge string) string {
	out, err := execCommand([]string{"ip", "-4", "-o", "addr", "show", "dev", bridge})
	if err != nil {
		return ""
	}
	return firstIPv4(out)
}

// writeIfChanged writes content only when it differs; returns whether it wrote.
// The temp file gets a pid-unique name and O_CREATE|O_EXCL: an existing file
// (or symlink planted at the predictable legacy name) can never be followed or
// clobbered — the write either creates a fresh file atomically or fails.
func writeIfChanged(path, content string, perm os.FileMode) (bool, error) {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		return false, nil
	}
	tmp := fmt.Sprintf("%s.tmp-proxdnx-%d", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return false, err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return false, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// hasManagedMarker reports whether content carries our management marker,
// case-insensitively: our files say "managed by ProxDnx" while the legacy
// python-era markers said "managed by proxdns" — a case-sensitive contains
// matched neither and re-backed-up the same managed file every cycle.
func hasManagedMarker(content string) bool {
	return strings.Contains(strings.ToLower(content), managedByPrefix)
}

// applyCaddy renders the Caddyfile and reloads caddy when it changed.
// TLS uses Caddy's internal CA (no public CA can issue for .local); every site
// label is https:// so caddy binds 443 and auto-redirects 80.
// Static entries (cfg.Static) handle <host>.local -> Proxmox UI and
// menux*.local -> ProxMenux exactly like normal apps: reverse-proxied, no
// redirect, no port in the URL. The portal itself is served ONLY on
// apps.<host>.local, proxying to this daemon's API.
func applyCaddy(logger *log.Logger, recs []Record, cfg Config) error {
	sites := dedupeSites(recs)
	if len(sites) == 0 && !cfg.Static {
		logger.Printf("caddy: no records and static entries disabled — Caddyfile left untouched")
		return nil
	}
	cur, _ := os.ReadFile(caddyfile)
	if len(strings.TrimSpace(string(cur))) > 0 && !hasManagedMarker(string(cur)) {
		bak := fmt.Sprintf("%s.pre-proxdnx-%s", caddyfile, time.Now().Format("20060102-150405"))
		if err := os.WriteFile(bak, cur, 0o644); err == nil {
			logger.Printf("caddy: existing unmanaged Caddyfile backed up -> %s", bak)
		}
	}
	content := renderCaddyfile(sites, cfg, hostLabel())
	if strings.TrimSpace(string(cur)) == strings.TrimSpace(content) {
		logger.Printf("caddy: unchanged (%d sites)", len(sites))
		return nil
	}
	tmp := fmt.Sprintf("%s.tmp-proxdnx-%d", caddyfile, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(content)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		if werr != nil {
			return werr
		}
		return cerr
	}
	if out, err := execCommand([]string{"caddy", "validate", "--config", tmp, "--adapter", "caddyfile"}); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("generated config failed validation: %s", trunc(out, 400))
	}
	if err := os.Rename(tmp, caddyfile); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := run("systemctl", "reload", "caddy"); err != nil {
		return fmt.Errorf("reload failed: %v", err)
	}
	logger.Printf("caddy: wrote %s (%d sites) and reloaded", caddyfile, len(sites))
	return nil
}

// renderCaddyfile is the pure byte-level renderer: header comment, local_certs
// global, one https (+ optional plain-http twin) block per app, the static
// infrastructure blocks, and the portal block on apps.<host>.local only.
// No timestamps — output must be byte-stable so cycles stay idempotent.
func renderCaddyfile(sites map[string]Record, cfg Config, host string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s (ProxDnx)\n", managedBy)
	// no timestamps in rendered output: keeps cycles idempotent (no rewrite churn)
	fmt.Fprintf(&b, "# %d apps + portal", len(sites))
	if cfg.Static {
		b.WriteString(" + static entries")
	}
	b.WriteString("\n\n")
	b.WriteString("{\n    local_certs\n}\n")
	slugs := make([]string, 0, len(sites))
	for s := range sites {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	for _, s := range slugs {
		r := sites[s]
		fmt.Fprintf(&b, "\nhttps://%s.local {\n    reverse_proxy %s:%d\n}\n", s, r.IP, r.Port)
		if cfg.HTTP {
			// plain http twin: serves content on :80 instead of redirecting
			fmt.Fprintf(&b, "\nhttp://%s.local {\n    reverse_proxy %s:%d\n}\n", s, r.IP, r.Port)
		}
	}
	// static infrastructure entries: <host>.local -> Proxmox UI, menux*.local
	// -> ProxMenux — reverse-proxied like any app, no redirect. <host>.local is
	// announced by the OS avahi daemon (the host's own name — never publish it
	// here: re-announcing it with a different A record triggers an avahi
	// conflict rename); menux*.local + apps.<host>.local are published by
	// proxdnx-mdns-publish via the alias list below.
	if cfg.Static {
		for _, r := range staticRoutes(host, cfg.BaseURL) {
			names := make([]string, 0, len(r.Names))
			for _, n := range r.Names {
				names = append(names, "https://"+n)
			}
			if r.Secure {
				// https upstream (self-signed pve cert): skip verify
				fmt.Fprintf(&b, "\n%s {\n    reverse_proxy %s {\n        transport http {\n            tls_insecure_skip_verify\n        }\n    }\n}\n", strings.Join(names, ", "), r.Upstream)
			} else {
				fmt.Fprintf(&b, "\n%s {\n    reverse_proxy %s\n}\n", strings.Join(names, ", "), r.Upstream)
			}
			if cfg.HTTP {
				plain := make([]string, 0, len(r.Names))
				for _, n := range r.Names {
					plain = append(plain, "http://"+n)
				}
				if r.Secure {
					fmt.Fprintf(&b, "\n%s {\n    reverse_proxy %s {\n        transport http {\n            tls_insecure_skip_verify\n        }\n    }\n}\n", strings.Join(plain, ", "), r.Upstream)
				} else {
					fmt.Fprintf(&b, "\n%s {\n    reverse_proxy %s\n}\n", strings.Join(plain, ", "), r.Upstream)
				}
			}
		}
	}
	// portal: apps dashboard served by this daemon's API server — only on
	// apps.<host>.local.
	fmt.Fprintf(&b, "\nhttps://apps.%s.local {\n    reverse_proxy %s\n}\n", host, cfg.APIAddr)
	if cfg.HTTP {
		fmt.Fprintf(&b, "\nhttp://apps.%s.local {\n    reverse_proxy %s\n}\n", host, cfg.APIAddr)
	}
	return b.String()
}

// renderAliases is the pure alias-list renderer: one "name IP" line per app
// slug, apps.<host>.local for the portal, plus the static entry names. The
// bare <host>.local name is skipped — the OS avahi daemon already announces
// the host's own name, and re-announcing it would conflict-rename.
func renderAliases(sites map[string]Record, cfg Config, hostIP, host string) string {
	var ab strings.Builder
	fmt.Fprintf(&ab, "# %s (ProxDnx)\n# all aliases point at the host so caddy can route by Host header\n", managedBy)
	slugs := make([]string, 0, len(sites))
	for s := range sites {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	for _, s := range slugs {
		fmt.Fprintf(&ab, "%s.local %s\n", s, hostIP)
	}
	fmt.Fprintf(&ab, "apps.%s.local %s\n", host, hostIP)
	if cfg.Static {
		for _, r := range staticRoutes(host, cfg.BaseURL) {
			for _, n := range r.Names {
				if n == host+".local" {
					continue
				}
				fmt.Fprintf(&ab, "%s %s\n", n, hostIP)
			}
		}
	}
	return ab.String()
}

// countAliases counts publishable "name ip" lines (comments/blanks excluded).
func countAliases(content string) int {
	n := 0
	for _, l := range strings.Split(content, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	return n
}

// applyAvahi writes one .service file per app, the alias list (plus the static
// entry aliases), and manages the proxdnx-mdns publisher that turns
// <name>.local into A records on the host IP.
func applyAvahi(logger *log.Logger, recs []Record, cfg Config) error {
	sites := dedupeSites(recs)
	if len(sites) == 0 && !cfg.Static {
		logger.Printf("avahi: no records and static entries disabled — nothing written")
		return nil
	}
	if err := os.MkdirAll(avahiServicesDir, 0o755); err != nil {
		return err
	}
	changed := 0
	want := map[string]bool{}
	slugs := make([]string, 0, len(sites))
	for s := range sites {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	for _, s := range slugs {
		r := sites[s]
		fname := s + ".service"
		want[fname] = true
		path := filepath.Join(avahiServicesDir, fname)
		content := fmt.Sprintf(avahiTemplate, xmlEsc.Replace(r.Service), r.Port)
		wrote, err := writeIfChanged(path, content, 0o644)
		if err != nil {
			return err
		}
		if wrote {
			changed++
		}
	}
	removed := []string{}
	entries, _ := os.ReadDir(avahiServicesDir)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".service") || want[name] {
			continue
		}
		path := filepath.Join(avahiServicesDir, name)
		cur, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if hasManagedMarker(string(cur)) {
			if err := os.Remove(path); err == nil {
				removed = append(removed, name)
			}
		} else {
			logger.Printf("avahi: left unmanaged file %s", name)
		}
	}
	if err := run("systemctl", "reload", "avahi-daemon"); err != nil {
		return fmt.Errorf("reload failed: %v", err)
	}
	msg := fmt.Sprintf("avahi: %d service files in %s (reloaded; %d rewritten)", len(sites), avahiServicesDir, changed)
	if len(removed) > 0 {
		msg += fmt.Sprintf(", removed stale: %s", strings.Join(removed, ", "))
	}
	logger.Printf("%s", msg)

	// *.local A records -> host IP (caddy routes by Host header); without these
	// service files only make apps browsable, <slug>.local does not resolve.
	host := hostIP(cfg.Bridge)
	if host == "" {
		return fmt.Errorf("could not determine host IPv4 on %s for alias publishing", cfg.Bridge)
	}
	// portal alias: apps dashboard, reachable as apps.<host>.local (caddy ->
	// daemon API); static entry aliases (menux*.local) appended by
	// renderAliases. <host>.local itself never gets a record — see
	// renderCaddyfile.
	aliases := renderAliases(sites, cfg, host, hostLabel())
	nAliases := countAliases(aliases)
	aliasesChanged, err := writeIfChanged(avahiAliases, aliases, 0o644)
	if err != nil {
		return err
	}
	unitChanged, err := writeIfChanged(publisherUnit, publisherUnitSrc, 0o644)
	if err != nil {
		return err
	}
	binChanged, err := writeIfChanged(publisherBin, publisherBinSrc, 0o755)
	if err != nil {
		return err
	}
	_ = run("systemctl", "daemon-reload")
	_ = run("systemctl", "enable", "--quiet", "proxdnx-mdns")
	if aliasesChanged || unitChanged || binChanged {
		if err := run("systemctl", "restart", "proxdnx-mdns"); err != nil {
			return fmt.Errorf("proxdnx-mdns restart failed: %v", err)
		}
		time.Sleep(time.Second)
		if err := run("systemctl", "is-active", "--quiet", "proxdnx-mdns"); err != nil {
			return fmt.Errorf("proxdnx-mdns exited immediately — check journalctl -u proxdnx-mdns")
		}
		logger.Printf("avahi: %d *.local aliases -> %s via proxdnx-mdns (restarted)", nAliases, host)
	} else {
		if err := run("systemctl", "is-active", "--quiet", "proxdnx-mdns"); err != nil {
			return fmt.Errorf("proxdnx-mdns not running despite no changes — check journalctl -u proxdnx-mdns")
		}
		logger.Printf("avahi: %d *.local aliases -> %s unchanged (proxdnx-mdns running)", nAliases, host)
	}
	return nil
}
