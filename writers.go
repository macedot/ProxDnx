package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const avahiTemplate = `<?xml version="1.0" standalone='no'?>
<!-- managed by proxdns (ProxDnx) -->
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
`

const publisherUnitSrc = `[Unit]
Description=ProxDnx mDNS alias publisher (avahi-publish per *.local name)
After=avahi-daemon.service
Requires=avahi-daemon.service

[Service]
Type=simple
ExecStart=/usr/local/bin/proxdns-mdns-publish
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`

var xmlEsc = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")

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
	tmp := path + ".tmp-proxdns"
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

// applyCaddy renders the Caddyfile and reloads caddy when it changed.
// TLS uses Caddy's internal CA (no public CA can issue for .local); every site
// label is https:// so caddy binds 443 and auto-redirects 80.
// proxdnx.local is added as the portal: it proxies to this daemon's API, which
// serves the apps dashboard.
func applyCaddy(logger *log.Logger, recs []Record, apiAddr string, httpEnabled bool) error {
	sites := dedupeSites(recs)
	if len(sites) == 0 {
		logger.Printf("caddy: no records — Caddyfile left untouched")
		return nil
	}
	cur, _ := os.ReadFile(caddyfile)
	if len(strings.TrimSpace(string(cur))) > 0 && !strings.Contains(string(cur), managedBy) {
		bak := fmt.Sprintf("%s.pre-proxdns-%s", caddyfile, time.Now().Format("20060102-150405"))
		if err := os.WriteFile(bak, cur, 0o644); err == nil {
			logger.Printf("caddy: existing unmanaged Caddyfile backed up -> %s", bak)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s (ProxDnx)\n", managedBy)
	// no timestamps in rendered output: keeps cycles idempotent (no rewrite churn)
	fmt.Fprintf(&b, "# %d apps + portal\n\n", len(sites))
	b.WriteString("{\n    local_certs\n}\n")
	slugs := make([]string, 0, len(sites))
	for s := range sites {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	for _, s := range slugs {
		r := sites[s]
		fmt.Fprintf(&b, "\nhttps://%s.local {\n    reverse_proxy %s:%d\n}\n", s, r.IP, r.Port)
		if httpEnabled {
			// plain http twin: serves content on :80 instead of redirecting
			fmt.Fprintf(&b, "\nhttp://%s.local {\n    reverse_proxy %s:%d\n}\n", s, r.IP, r.Port)
		}
	}
	// portal: apps dashboard served by this daemon's API server
	fmt.Fprintf(&b, "\nhttps://proxdnx.local {\n    reverse_proxy %s\n}\n", apiAddr)
	if httpEnabled {
		fmt.Fprintf(&b, "\nhttp://proxdnx.local {\n    reverse_proxy %s\n}\n", apiAddr)
	}
	content := b.String()
	if strings.TrimSpace(string(cur)) == strings.TrimSpace(content) {
		logger.Printf("caddy: unchanged (%d sites)", len(sites))
		return nil
	}
	tmp := caddyfile + ".tmp-proxdns"
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

// applyAvahi writes one .service file per app, the alias list, and manages the
// proxdns-mdns publisher that turns <slug>.local into A records on the host IP.
func applyAvahi(logger *log.Logger, recs []Record, bridge string) error {
	sites := dedupeSites(recs)
	if len(sites) == 0 {
		logger.Printf("avahi: no records — nothing written")
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
		if strings.Contains(string(cur), managedBy) {
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
	host := hostIP(bridge)
	if host == "" {
		return fmt.Errorf("could not determine host IPv4 on %s for alias publishing", bridge)
	}
	var ab strings.Builder
	fmt.Fprintf(&ab, "# %s (ProxDnx)\n# all aliases point at the host so caddy can route by Host header\n", managedBy)
	for _, s := range slugs {
		fmt.Fprintf(&ab, "%s.local %s\n", s, host)
	}
	// portal alias: the dashboard itself (served by caddy -> daemon API)
	fmt.Fprintf(&ab, "proxdnx.local %s\n", host)
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
	_ = run("systemctl", "enable", "--quiet", "proxdns-mdns")
	if aliasesChanged || unitChanged || binChanged {
		if err := run("systemctl", "restart", "proxdns-mdns"); err != nil {
			return fmt.Errorf("proxdns-mdns restart failed: %v", err)
		}
		time.Sleep(time.Second)
		if err := run("systemctl", "is-active", "--quiet", "proxdns-mdns"); err != nil {
			return fmt.Errorf("proxdns-mdns exited immediately — check journalctl -u proxdns-mdns")
		}
		logger.Printf("avahi: %d *.local aliases -> %s via proxdns-mdns (restarted)", len(sites), host)
	} else {
		if err := run("systemctl", "is-active", "--quiet", "proxdns-mdns"); err != nil {
			return fmt.Errorf("proxdns-mdns not running despite no changes — check journalctl -u proxdns-mdns")
		}
		logger.Printf("avahi: %d *.local aliases -> %s unchanged (proxdns-mdns running)", len(sites), host)
	}
	return nil
}
