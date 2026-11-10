package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
}

func NewClient(cfg Config) *Client {
	return &Client{
		base:  strings.TrimRight(cfg.BaseURL, "/"),
		token: cfg.Token,
		user:  cfg.User,
		pass:  cfg.Password,
		totp:  cfg.TOTP,
		http:  &http.Client{Timeout: 150 * time.Second},
	}
}

// Record is one published domain.
type Record struct {
	Domain  string `json:"domain"`
	Service string `json:"service"` // ProxMenux Apps service name
	Name    string `json:"name"`    // LXC hostname
	IP      string `json:"ip"`
	Port    int    `json:"port"`
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
	resp, err := c.http.Do(req)
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
		return nil
	}
	if out.RequiresTOTP {
		return fmt.Errorf("2FA required: pass --totp")
	}
	return fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(out.Message))
}

func (c *Client) getJSON(path string, out any, timeout time.Duration) error {
	if err := c.ensureToken(); err != nil {
		return err
	}
	b, code, err := c.do("GET", path, timeout)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("%s: HTTP %d: %s", path, code, trunc(string(b), 200))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: %v", path, err)
	}
	return nil
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
		for _, e := range c.guestPorts(g, cfg.Scan) {
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
			recs = append(recs, Record{
				Domain:  slugify(svc) + ".local",
				Service: svc,
				Name:    g.Name,
				IP:      ip,
				Port:    e.port,
			})
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Domain < recs[j].Domain })
	return recs, nil
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
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			if strings.Contains(f, "/") && strings.Count(f, ".") == 3 {
				ip, ipnet, err := net.ParseCIDR(f)
				if err != nil || ip.IsLoopback() {
					continue
				}
				return ipnet, nil
			}
		}
	}
	notef("warning: no IPv4 on %s (first IPv4 wins)", bridge)
	return nil, nil
}

// pickIP returns the IPv4 inside subnet; "" when the guest has none in it.
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
	if subnet == nil {
		return v4[0]
	}
	for _, ip := range v4 {
		p := net.ParseIP(ip)
		if p != nil && subnet.Contains(p) {
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
