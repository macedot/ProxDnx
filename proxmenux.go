package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client talks to the ProxMenux monitor API.
type Client struct {
	base  string
	token string
	user  string
	pass  string
	totp  string
	http  *http.Client

	tokenFromLogin bool // token came from ensureToken's login (re-issuable)
	fixMu          sync.Mutex
	fixAttempts    map[fixKey]int // autofix attempts per registration (cap 2)
}

func NewClient(cfg Config) *Client {
	return &Client{
		base:        strings.TrimRight(cfg.BaseURL, "/"),
		token:       cfg.Token,
		user:        cfg.User,
		pass:        cfg.Password,
		totp:        cfg.TOTP,
		http:        &http.Client{Timeout: 150 * time.Second},
		fixAttempts: map[fixKey]int{},
	}
}

// Record is one published domain.
type Record struct {
	Domain   string `json:"domain"`
	Service  string `json:"service"` // ProxMenux Apps service name
	Name     string `json:"name"`    // LXC hostname
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Stale    bool   `json:"stale,omitempty"`    // TCP probe failed: port closed
	Title    string `json:"title,omitempty"`    // detected UI page title ("" unknown)
	Mismatch bool   `json:"mismatch,omitempty"` // detected UI title disagrees with Service

	vmid  int    `json:"-"` // ProxMenux sidecar identity for autofix (internal)
	appID string `json:"-"`
}

type Guest struct {
	VMID       int        `json:"vmid"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	Type       string     `json:"type"`
	IP         string     `json:"ip"`
	IPs        []string   `json:"ips"`
	AppWatches []AppWatch `json:"app_watches"`
}

type AppWatch struct {
	ID    string `json:"id"` // sidecar app id — autofix PUTs corrections here
	Name  string `json:"name"`
	Slug  string `json:"helper_slug"`
	Ports []struct {
		Port int `json:"port"`
	} `json:"ports"`
}

type Discovery struct {
	Status     string      `json:"status"`
	Candidates []Candidate `json:"candidates"`
	Issues     []string    `json:"issues"`
}

type Candidate struct {
	ContainerName string `json:"container_name"`
	DefaultPorts  []int  `json:"default_ports"`
}

type portEntry struct {
	source string
	name   string
	port   int
}

func (c *Client) do(method, path string, timeout time.Duration) ([]byte, int, error) {
	req, err := http.NewRequest(method, c.base+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

func (c *Client) ensureToken() error {
	if c.token != "" || c.user == "" || c.pass == "" {
		return nil
	}
	payload := fmt.Sprintf(`{"username":%q,"password":%q`, c.user, c.pass)
	if c.totp != "" {
		payload += fmt.Sprintf(`,"totp_token":%q`, c.totp)
	}
	payload += "}"
	req, err := http.NewRequest("POST", c.base+"/api/auth/login", strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Success      bool   `json:"success"`
		Token        string `json:"token"`
		RequiresTOTP bool   `json:"requires_totp"`
		Message      string `json:"message"`
	}
	_ = json.Unmarshal(b, &out)
	if resp.StatusCode == 200 && out.Success && out.Token != "" {
		c.token = out.Token
		c.tokenFromLogin = true
		return nil
	}
	if out.RequiresTOTP {
		return fmt.Errorf("2FA required: pass --totp")
	}
	return fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(out.Message))
}

func (c *Client) getJSON(path string, out any, timeout time.Duration) error {
	b, err := c.authorized("GET", path, nil, timeout)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: %v", path, err)
	}
	return nil
}

// authorized issues an authorized request, re-authenticating once when a
// login-issued token is rejected (the monitor invalidates sessions on
// restart — without the retry every cycle fails until the daemon restarts).
// Config-provided tokens are static: no point retrying those.
func (c *Client) authorized(method, path string, body []byte, timeout time.Duration) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		if err := c.ensureToken(); err != nil {
			return nil, err
		}
		b, code, err := c.doBody(method, path, body, timeout)
		if err != nil {
			return nil, err
		}
		if code != 401 || attempt > 0 || !c.tokenFromLogin {
			if code >= 300 {
				return nil, fmt.Errorf("%s: HTTP %d: %s", path, code, trunc(string(b), 200))
			}
			return b, nil
		}
		// stale session: drop the token, re-login, retry once
		c.token = ""
	}
}

func (c *Client) doBody(method, path string, body []byte, timeout time.Duration) ([]byte, int, error) {
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

// fetchRecords returns the deduplicated, domain-keyed records for all running
// LXCs whose picked IP lies in the configured subnet (or all guests when no
// subnet could be resolved).
func (c *Client) fetchRecords(cfg Config, notef func(string, ...any)) ([]Record, error) {
	if err := c.ensureToken(); err != nil {
		return nil, err
	}
	var guests []Guest
	if err := c.getJSON("/api/vms", &guests, 20*time.Second); err != nil {
		return nil, err
	}
	subnet, err := resolveSubnet(cfg.Network, cfg.Bridge, notef)
	if err != nil {
		return nil, err
	}

	recs := []Record{}
	seenIPPort := map[string]bool{}
	for _, g := range guests {
		if g.Status != "running" {
			continue
		}
		if g.Type != "" && g.Type != "lxc" {
			continue
		}
		ip := pickIP(g.IPs, subnet)
		if ip == "" {
			continue
		}
		ports := c.guestPorts(g, cfg.Scan)
		if len(ports) == 0 {
			notef("note: guest %s (%d) has no discoverable ports — not published", g.Name, g.VMID)
		}
		for _, e := range ports {
			if e.port == 0 {
				continue
			}
			key := ip + ":" + strconv.Itoa(e.port)
			if seenIPPort[key] {
				continue
			}
			seenIPPort[key] = true
			svc := e.name
			if svc == "" {
				svc = g.Name
			}
			appID := ""
			if e.source == "app_watch" && len(g.AppWatches) > 0 {
				for _, w := range g.AppWatches {
					if w.Name == e.name || (w.Name == "" && w.Slug == e.name) {
						appID = w.ID
						break
					}
				}
			}
			recs = append(recs, Record{
				Domain:  slugify(svc) + ".local",
				Service: svc,
				Name:    g.Name,
				IP:      ip,
				Port:    e.port,
				vmid:    g.VMID,
				appID:   appID,
			})
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Domain < recs[j].Domain })
	if cfg.Probe {
		recs = probeRecords(recs, probeTimeout, probeWorkers, notef)
	}
	if cfg.AutoFix {
		c.autoFix(notef, recs)
	}
	return recs, nil
}

const (
	probeTimeout    = 1200 * time.Millisecond
	probeWorkers    = 16
	identityTimeout = 2500 * time.Millisecond
)

// probeRecords tags every record with liveness: Stale when the TCP port
// refuses connections, plus a UI-title identity check (plain HTTP, redirects
// followed) whose disagreement with the registered name sets Mismatch.
// Records are NEVER dropped here — stale ones stay visible on the portal,
// tagged; cycle() excludes them from caddy/avahi instead.
func probeRecords(recs []Record, timeout time.Duration, workers int, logf func(string, ...any)) []Record {
	type result struct {
		idx   int
		stale bool
		title string
	}
	results := make(chan result, len(recs))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, r := range recs {
		wg.Add(1)
		go func(idx int, addr string, service string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				results <- result{idx: idx, stale: true}
				return
			}
			c.Close()
			title := titleIdentity(identifyTitle(addr))
			results <- result{idx: idx, title: title}
		}(i, net.JoinHostPort(r.IP, strconv.Itoa(r.Port)), r.Service)
	}
	wg.Wait()
	close(results)
	byIdx := make(map[int]result, len(recs))
	for res := range results {
		byIdx[res.idx] = res
	}
	out := make([]Record, 0, len(recs))
	for i, r := range recs {
		res := byIdx[i]
		if res.stale {
			logf("stale %s -> %s:%d (port closed, shown tagged on portal, not published)", r.Domain, r.IP, r.Port)
			r.Stale = true
		} else if identityMismatch(r.Service, res.title) {
			logf("mismatch %s -> %s:%d (registered %q, page title %q)", r.Domain, r.IP, r.Port, r.Service, res.title)
			r.Title = res.title
			r.Mismatch = true
		} else {
			r.Title = res.title
		}
		out = append(out, r)
	}
	return out
}

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)`)

// identityClient is shared by the identity probes; total timeout includes
// redirects. Purely informational: failures yield no title, never errors.
// Redirects are bounded (3) and may not target loopback/unspecified/
// link-local addresses: those pages belong to the PVE host itself (monitor
// API, pveproxy), and a rogue LAN guest must not be able to make the daemon
// fetch them by answering its identity probe with a 302 (SSRF).
var identityClient = &http.Client{
	Timeout: identityTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("stopped after %d redirects", len(via))
		}
		return refuseInternalRedirect(req.URL)
	},
}

// refuseInternalRedirect rejects redirect targets that address the daemon's
// own host (loopback, unspecified, link-local — includes cloud metadata
// 169.254.169.254). Non-IP hosts pass: identity fetches dial IP literals;
// a hostname redirect only risks fetching a public page, not internal ones.
func refuseInternalRedirect(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("redirect to non-http scheme %q blocked", u.Scheme)
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("redirect to internal address %s blocked", ip)
	}
	return nil
}

// identifyTitle fetches the service's UI page title over plain HTTP.
func identifyTitle(addr string) string {
	resp, err := identityClient.Get("http://" + addr + "/")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return ""
	}
	m := titleRe.FindSubmatch(b)
	if m == nil {
		return ""
	}
	t := strings.TrimSpace(string(m[1]))
	if len(t) > 100 {
		t = t[:100]
	}
	return t
}

// authTitleWords appear on auth-gated pages whose title still names the app
// ("Login - Sonarr"); noIdentityTitleWords are API-doc pages that name a
// different product entirely ("FastAPI - Swagger UI") and carry no identity.
var authTitleWords = []string{"login", "unauthorized", "forbidden", "sign in", "signin", "welcome"}
var noIdentityTitleWords = []string{"swagger"}

// titleIdentity strips auth-page words from a UI title ("Login - Sonarr" ->
// "Sonarr"); returns "" when the title carries no app identity at all
// (auth-only pages, API-doc pages).
func titleIdentity(title string) string {
	t := strings.TrimSpace(title)
	if t == "" {
		return ""
	}
	tl := strings.ToLower(t)
	if containsAny(tl, noIdentityTitleWords) {
		return ""
	}
	if !containsAny(tl, authTitleWords) {
		return t
	}
	var keep []string
	for _, f := range strings.Fields(t) {
		fl := strings.ToLower(strings.Trim(f, "-:|·"))
		if fl == "" || containsAny(fl, authTitleWords) {
			continue
		}
		keep = append(keep, f)
	}
	return strings.Join(keep, " ")
}

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// titleHasIdentity reports whether a UI title can confirm or contradict a
// registered name at all.
func titleHasIdentity(title string) bool {
	return titleIdentity(title) != ""
}

// identityMismatch reports a disagreement between the registered service name
// and the UI title the endpoint actually serves. Slug containment (either
// direction) counts as agreement — "qBittorrent Web UI" vs "qBittorrent" —
// as does token-prefix agreement — "Cloudflare Tunnel WebUI" vs
// "Cloudflared" (cloudflare/cloudflared share the prefix). The incident case
// (registered Bazarr, page says Sonarr) still flags.
func identityMismatch(service, title string) bool {
	if service == "" || title == "" {
		return false
	}
	if !titleHasIdentity(title) {
		return false
	}
	s, t := slugify(service), slugify(title)
	if s == "" || t == "" {
		return false
	}
	if strings.Contains(t, s) || strings.Contains(s, t) {
		return false
	}
	for _, st := range strings.Split(s, "-") {
		if len(st) < 5 {
			continue
		}
		for _, tt := range strings.Split(t, "-") {
			if len(tt) < 5 {
				continue
			}
			if strings.HasPrefix(st, tt) || strings.HasPrefix(tt, st) {
				return false
			}
		}
	}
	return true
}

// publishable reports whether a record is rendered into caddy/avahi: stale
// records stay visible on the portal (tagged) but are not published.
func publishable(r Record) bool {
	return !r.Stale
}

// guestPorts merges app_watch catalog ports with docker/native discovery.
func (c *Client) guestPorts(g Guest, forceScan bool) []portEntry {
	var out []portEntry
	seen := map[string]bool{}
	add := func(source, name string, port int) {
		if port == 0 {
			return
		}
		k := source + "|" + name + "|" + strconv.Itoa(port)
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, portEntry{source: source, name: name, port: port})
	}

	for _, w := range g.AppWatches {
		for _, p := range w.Ports {
			name := w.Name
			if name == "" {
				name = w.Slug
			}
			add("app_watch", name, p.Port)
		}
	}
	for _, d := range []struct{ name, path string }{
		{"docker", "/api/vms/%d/apps/docker-discovery"},
		{"native", "/api/vms/%d/apps/native-discovery"},
	} {
		method := "GET"
		if forceScan {
			method = "POST"
		}
		b, code, err := c.do(method, fmt.Sprintf(d.path, g.VMID), 130*time.Second)
		if err != nil {
			continue
		}
		if code != 200 {
			continue
		}
		var disc Discovery
		if json.Unmarshal(b, &disc) != nil {
			continue
		}
		for _, cand := range disc.Candidates {
			for _, p := range cand.DefaultPorts {
				add(d.name, cand.ContainerName, p)
			}
		}
	}
	return out
}

// resolveSubnet mirrors adguard_proxmox_sync.py: derive the bridge's IPv4
// network via `ip -4 -o addr`, or use an explicit --network CIDR.
func resolveSubnet(network, bridge string, notef func(string, ...any)) (*net.IPNet, error) {
	if network != "" {
		_, ipnet, err := net.ParseCIDR(network)
		if err != nil {
			return nil, fmt.Errorf("--network: %v", err)
		}
		return ipnet, nil
	}
	out, err := execCommand([]string{"ip", "-4", "-o", "addr", "show", "dev", bridge})
	if err != nil {
		notef("warning: could not determine subnet of %s: %v (first IPv4 wins)", bridge, err)
		return nil, nil
	}
	if subnet := parseBridgeSubnet(out); subnet != nil {
		return subnet, nil
	}
	notef("warning: no IPv4 on %s (first IPv4 wins)", bridge)
	return nil, nil
}

// parseBridgeSubnet returns the first non-loopback IPv4 CIDR found in
// `ip -4 -o addr show` output, or nil.
func parseBridgeSubnet(out string) *net.IPNet {
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			if strings.Contains(f, "/") && strings.Count(f, ".") == 3 {
				ip, ipnet, err := net.ParseCIDR(f)
				if err != nil || ip.IsLoopback() {
					continue
				}
				return ipnet
			}
		}
	}
	return nil
}

// pickIP returns the IPv4 inside subnet; "" when the guest has none in it.
// Guests with no subnet IP fall back to their first usable global IPv4 so
// guests hosted on other bridges (e.g. a gluetun-side 10.77.x address) are
// still published — caddy proxies from the host, which reaches them. Docker
// bridges, CGNAT (tailscale) and link-local ranges never qualify.
var fallbackExclude = []*net.IPNet{
	mustCIDR("100.64.0.0/10"),  // CGNAT / tailscale
	mustCIDR("172.16.0.0/12"),  // docker bridges
	mustCIDR("169.254.0.0/16"), // link-local
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("bad builtin CIDR " + s)
	}
	return n
}

func excludedIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil || p.IsLoopback() || !p.IsGlobalUnicast() {
		return true
	}
	for _, n := range fallbackExclude {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

func pickIP(ips []string, subnet *net.IPNet) string {
	v4 := []string{}
	for _, ip := range ips {
		if !strings.Contains(ip, ":") {
			v4 = append(v4, ip)
		}
	}
	if len(v4) == 0 {
		return ""
	}
	if subnet != nil {
		for _, ip := range v4 {
			p := net.ParseIP(ip)
			if p != nil && subnet.Contains(p) {
				return ip
			}
		}
	}
	for _, ip := range v4 {
		if !excludedIP(ip) {
			return ip
		}
	}
	return ""
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// slugify: "AdGuard Home" -> "adguard-home"; valid mDNS/Caddy label.
func slugify(name string) string {
	s := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if s == "" {
		return "app"
	}
	return s
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
