package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// StaticRoute is a fixed infrastructure entry: local names caddy answers with
// a 308 redirect to a well-known LAN UI (never proxied). Rendered into the
// Caddyfile, published via mDNS, listed on the portal and disable-able via
// config (static_redirects).
type StaticRoute struct {
	Label  string   `json:"label"`
	Desc   string   `json:"desc"`
	Names  []string `json:"names"`
	Target string   `json:"target"`
}

// menuxPortFromURL extracts the monitor UI port from the configured API URL so
// a relocated ProxMenux monitor is followed automatically.
func menuxPortFromURL(raw string) int {
	if u, err := url.Parse(raw); err == nil {
		if p := u.Port(); p != "" {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
				return n
			}
		}
	}
	return defaultMenuxPort
}

// staticRoutes derives the fixed infrastructure redirects from the hostname.
// The bare <host>.local name is answered but never published by us: the OS
// avahi daemon already announces it, and re-announcing a host's own name with
// a different A record triggers an avahi conflict rename.
func staticRoutes(host string, menuxPort int) []StaticRoute {
	return []StaticRoute{
		{
			Label:  "Proxmox VE",
			Desc:   "Proxmox web UI",
			Names:  []string{host + ".local"},
			Target: fmt.Sprintf("https://%s.local:%d", host, defaultPVEPort),
		},
		{
			Label:  "ProxMenux",
			Desc:   "ProxMenux Monitor home",
			Names:  []string{"menux.local", "proxmenux.local", "menux." + host + ".local"},
			Target: fmt.Sprintf("http://%s.local:%d", host, menuxPort),
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

func hostIP(bridge string) string {
	out, err := execCommand([]string{"ip", "-4", "-o", "addr", "show", "dev", bridge})
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			if strings.Contains(f, "/") && strings.Count(f, ".") == 3 {
				ip := strings.Split(f, "/")[0]
				if !strings.HasPrefix(ip, "127.") {
					return ip
				}
			}
		}
	}
	return ""
}

// writeIfChanged writes content only when it differs; returns whether it wrote.
func writeIfChanged(path, content string, perm os.FileMode) (bool, error) {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		return false, nil
	}
	tmp := path + ".tmp-proxdnx"
	if err := os.WriteFile(tmp, []byte(content), perm); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, err
	}
	if perm != 0 {
		_ = os.Chmod(path, perm)
	}
	return true, nil
}

// hostLabel returns the sanitized short hostname used to derive the portal
// names <host>.local and apps.<host>.local. Falls back to "proxdnx".
func hostLabel() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "proxdnx"
	}
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

// applyCaddy renders the Caddyfile and reloads caddy when it changed.
// TLS uses Caddy's internal CA (no public CA can issue for .local); every site
// label is https:// so caddy binds 443 and auto-redirects 80.
// Static redirects (cfg.StaticRedirects) answer <host>.local -> Proxmox UI and
// menux*.local -> ProxMenux with plain 308s. The portal itself is served ONLY
// on apps.<host>.local, proxying to this daemon's API.
func applyCaddy(logger *log.Logger, recs []Record, cfg Config) error {
	sites := dedupeSites(recs)
	if len(sites) == 0 && !cfg.StaticRedirects {
		logger.Printf("caddy: no records and static redirects disabled — Caddyfile left untouched")
		return nil
	}
	cur, _ := os.ReadFile(caddyfile)
	if len(strings.TrimSpace(string(cur))) > 0 && !strings.Contains(string(cur), managedByPrefix) {
		bak := fmt.Sprintf("%s.pre-proxdnx-%s", caddyfile, time.Now().Format("20060102-150405"))
		if err := os.WriteFile(bak, cur, 0o644); err == nil {
			logger.Printf("caddy: existing unmanaged Caddyfile backed up -> %s", bak)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s (ProxDnx)\n", managedBy)
	// no timestamps in rendered output: keeps cycles idempotent (no rewrite churn)
	fmt.Fprintf(&b, "# %d apps + portal", len(sites))
	if cfg.StaticRedirects {
		b.WriteString(" + static redirects")
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
	// static infrastructure redirects: <host>.local -> Proxmox UI, menux*.local
	// -> ProxMenux. Plain 308s — these names are never proxied. <host>.local is
	// announced by the OS avahi daemon (the host's own name — never publish it
	// here: re-announcing it with a different A record triggers an avahi
	// conflict rename); menux*.local + apps.<host>.local are published by
	// proxdnx-mdns-publish via the alias list below.
	h := hostLabel()
	if cfg.StaticRedirects {
		menuxPort := menuxPortFromURL(cfg.BaseURL)
		for _, r := range staticRoutes(h, menuxPort) {
			names := make([]string, 0, len(r.Names))
			for _, n := range r.Names {
				names = append(names, "https://"+n)
			}
			fmt.Fprintf(&b, "\n%s {\n    redir %s{uri} 308\n}\n", strings.Join(names, ", "), r.Target)
			if cfg.HTTP {
				plain := make([]string, 0, len(r.Names))
				for _, n := range r.Names {
					plain = append(plain, "http://"+n)
				}
				fmt.Fprintf(&b, "\n%s {\n    redir %s{uri} 308\n}\n", strings.Join(plain, ", "), r.Target)
			}
		}
	}
	// portal: apps dashboard served by this daemon's API server — only on
	// apps.<host>.local.
	fmt.Fprintf(&b, "\nhttps://apps.%s.local {\n    reverse_proxy %s\n}\n", h, cfg.APIAddr)
	if cfg.HTTP {
		fmt.Fprintf(&b, "\nhttp://apps.%s.local {\n    reverse_proxy %s\n}\n", h, cfg.APIAddr)
	}
	content := b.String()
	if strings.TrimSpace(string(cur)) == strings.TrimSpace(content) {
		logger.Printf("caddy: unchanged (%d sites)", len(sites))
		return nil
	}
	tmp := caddyfile + ".tmp-proxdnx"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	if out, err := execCommand([]string{"caddy", "validate", "--config", tmp, "--adapter", "caddyfile"}); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("generated config failed validation: %s", trunc(out, 400))
	}
	if err := os.Rename(tmp, caddyfile); err != nil {
		return err
	}
	if err := run("systemctl", "reload", "caddy"); err != nil {
		return fmt.Errorf("reload failed: %v", err)
	}
	logger.Printf("caddy: wrote %s (%d sites) and reloaded", caddyfile, len(sites))
	return nil
}

// applyAvahi writes one .service file per app, the alias list (plus the static
// redirect aliases), and manages the proxdnx-mdns publisher that turns
// <name>.local into A records on the host IP.
func applyAvahi(logger *log.Logger, recs []Record, cfg Config) error {
	sites := dedupeSites(recs)
	if len(sites) == 0 && !cfg.StaticRedirects {
		logger.Printf("avahi: no records and static redirects disabled — nothing written")
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
		if strings.Contains(string(cur), managedByPrefix) {
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
	var ab strings.Builder
	fmt.Fprintf(&ab, "# %s (ProxDnx)\n# all aliases point at the host so caddy can route by Host header\n", managedBy)
	for _, s := range slugs {
		fmt.Fprintf(&ab, "%s.local %s\n", s, host)
	}
	// portal alias: apps dashboard, reachable as apps.<host>.local (caddy ->
	// daemon API). <host>.local itself needs no record: the OS avahi daemon
	// already announces the host's own name on every link.
	h := hostLabel()
	fmt.Fprintf(&ab, "apps.%s.local %s\n", h, host)
	// static redirect aliases: menux*.local -> host (caddy 308s them to the
	// ProxMenux UI). The bare <host>.local name is skipped — see applyCaddy.
	nAliases := len(slugs) + 1
	if cfg.StaticRedirects {
		menuxPort := menuxPortFromURL(cfg.BaseURL)
		for _, r := range staticRoutes(h, menuxPort) {
			for _, n := range r.Names {
				if n == h+".local" {
					continue
				}
				fmt.Fprintf(&ab, "%s %s\n", n, host)
				nAliases++
			}
		}
	}
	aliasesChanged, err := writeIfChanged(avahiAliases, ab.String(), 0o644)
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
