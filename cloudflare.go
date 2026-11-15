package main

// Cloudflare Tunnel sync: when cloudflare_token + cloudflare_zone are set,
// every published app gets a public route through the managed tunnel:
//
//	DNS:     CNAME <name>.<zone> -> <tunnel-id>.cfargotunnel.com (proxied)
//	ingress: hostname rule -> http://<hostIP>:80 (caddy plain-http twin;
//	         caddy learns the public hostnames when the sync is enabled)
//
// The portal gets apps.<host>.<zone>. Infrastructure names (<host>.local,
// menux*) are deliberately never published — making Proxmox or ProxMenux
// reachable from the internet is not a default anyone should get silently.
//
// Ownership rules (same spirit as the old AdGuard sync, kept for the
// Cloudflare provider):
//   - DNS records we manage carry the comment "managed by ProxDnx". A record
//     without the marker pointing at a different target is user-owned and is
//     never modified — it is reported as a conflict instead.
//   - Ingress rules are ours iff their service is exactly our origin URL;
//     anything else (including the catch-all) is preserved untouched and the
//     catch-all always stays last (cloudflared requires it).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// cfAPIBase is the Cloudflare v4 API root. Package var so tests can point it
// at a httptest fake.
var cfAPIBase = "https://api.cloudflare.com/client/v4"

// cfDNSMarker stamps records created by the sync.
const cfDNSMarker = "managed by ProxDnx"

// CloudflareStatus is the outcome of the latest tunnel-sync pass; served on
// /api/cloudflare and rendered as a status chip on the portal.
type CloudflareStatus struct {
	Enabled   bool      `json:"enabled"`
	Zone      string    `json:"zone,omitempty"`
	TunnelID  string    `json:"tunnel_id,omitempty"`
	Count     int       `json:"count"`
	Added     []string  `json:"added,omitempty"`
	Updated   []string  `json:"updated,omitempty"`
	Removed   []string  `json:"removed,omitempty"`
	Conflicts []string  `json:"conflicts,omitempty"`
	Skipped   string    `json:"skipped,omitempty"`
	Error     string    `json:"error,omitempty"`
	At        time.Time `json:"at"`
}

// cfEnabled reports whether the tunnel sync is configured.
func cfEnabled(cfg Config) bool {
	return cfg.CloudflareToken != "" && strings.Trim(strings.TrimRight(cfg.CloudflareZone, "."), ".") != ""
}

// cfPublicNames enumerates the public hostnames: <slug>.<zone> per app plus
// apps.<host>.<zone> for the portal.
func cfPublicNames(sites map[string]Record, cfg Config) []string {
	host := hostLabel()
	zone := strings.Trim(strings.TrimRight(cfg.CloudflareZone, "."), ".")
	set := map[string]bool{}
	for s := range sites {
		set[s+"."+zone] = true
	}
	set["apps."+host+"."+zone] = true
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// cfIngressTarget is the origin every managed public hostname routes to: the
// caddy plain-http twin on the host, which routes by Host header.
func cfIngressTarget(answer string) string {
	return "http://" + answer + ":80"
}

type cfClient struct {
	base  string
	token string
	http  *http.Client
}

func newCFClient(token string) *cfClient {
	return &cfClient{
		base:  strings.TrimRight(cfAPIBase, "/"),
		token: token,
		http:  &http.Client{Timeout: 20 * time.Second},
	}
}

type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *cfClient) do(method, path string, payload, out any) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env cfEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("%s %s: %v", method, path, err)
	}
	if !env.Success || resp.StatusCode >= 300 {
		msg := resp.Status
		if len(env.Errors) > 0 {
			msg = fmt.Sprintf("%d %s", env.Errors[0].Code, env.Errors[0].Message)
		}
		return fmt.Errorf("%s %s: %s", method, path, msg)
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

type cfZone struct {
	ID      string `json:"id"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
}

type cfTunnel struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	DeletedAt *string `json:"deleted_at"`
}

type cfIngressRule struct {
	Hostname  string `json:"hostname,omitempty"`
	Path      string `json:"path,omitempty"`
	Service   string `json:"service,omitempty"`
	OriginReq any    `json:"origin_request,omitempty"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

// cfSync makes the Cloudflare zone + tunnel agree with the published set:
// adds missing CNAMEs and ingress rules, fixes drift on managed entries,
// prunes stale managed ones, and reports (never touches) user-owned records
// that already claim a desired name with a different target.
func cfSync(publish []Record, answer string, cfg Config) (CloudflareStatus, error) {
	st := CloudflareStatus{Enabled: true, Zone: strings.Trim(strings.TrimRight(cfg.CloudflareZone, "."), ".")}
	c := newCFClient(cfg.CloudflareToken)

	var zones []cfZone
	if err := c.do(http.MethodGet, "/zones?name="+url.QueryEscape(st.Zone), nil, &zones); err != nil {
		return st, fmt.Errorf("lookup zone %s: %v", st.Zone, err)
	}
	if len(zones) == 0 {
		return st, fmt.Errorf("zone %s not found (token lacks Zone:Read or wrong zone)", st.Zone)
	}
	zid, acct := zones[0].ID, zones[0].Account.ID

	tunnelID := strings.TrimSpace(cfg.CloudflareTunnelID)
	if tunnelID == "" {
		var tunnels []cfTunnel
		if err := c.do(http.MethodGet, "/accounts/"+acct+"/cfd_tunnels?is_deleted=false&per_page=20", nil, &tunnels); err != nil {
			return st, fmt.Errorf("list tunnels: %v", err)
		}
		if len(tunnels) == 0 {
			return st, fmt.Errorf("no tunnels in account — create one or set cloudflare_tunnel_id")
		}
		tunnelID = tunnels[0].ID
	}
	st.TunnelID = tunnelID
	var tun cfTunnel
	if err := c.do(http.MethodGet, "/accounts/"+acct+"/cfd_tunnels/"+tunnelID, nil, &tun); err != nil {
		return st, fmt.Errorf("tunnel %s: %v", tunnelID, err)
	}
	if tun.DeletedAt != nil {
		return st, fmt.Errorf("tunnel %s is deleted", tunnelID)
	}

	target := cfIngressTarget(answer)
	names := cfPublicNames(dedupeSites(publish), cfg)
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	st.Count = len(names)
	cname := tunnelID + ".cfargotunnel.com"

	// --- ingress rules ---
	var cfgWrap struct {
		Config struct {
			Ingress []cfIngressRule `json:"ingress"`
		} `json:"config"`
	}
	if err := c.do(http.MethodGet, "/accounts/"+acct+"/cfd_tunnels/"+tunnelID+"/configurations", nil, &cfgWrap); err != nil {
		return st, fmt.Errorf("read tunnel config: %v", err)
	}
	ingress := cfgWrap.Config.Ingress
	var catchAll *cfIngressRule
	kept := make([]cfIngressRule, 0, len(ingress)+len(names))
	for i := range ingress {
		r := ingress[i]
		if r.Hostname == "" {
			catchAll = &cfIngressRule{Path: r.Path, Service: r.Service, OriginReq: r.OriginReq}
			continue
		}
		if r.Service == target && !want[r.Hostname] {
			st.Removed = append(st.Removed, r.Hostname) // stale managed rule
			continue
		}
		kept = append(kept, r)
	}
	for _, n := range names {
		replaced := false
		for i := range kept {
			if kept[i].Hostname == n {
				if kept[i].Service != target {
					kept[i].Service = target
					kept[i].Path = ""
					st.Updated = append(st.Updated, n)
				}
				replaced = true
				break
			}
		}
		if !replaced {
			kept = append(kept, cfIngressRule{Hostname: n, Service: target})
			st.Added = append(st.Added, n)
		}
	}
	if catchAll == nil {
		catchAll = &cfIngressRule{Service: "http_status:404"}
	}
	final := append(kept, *catchAll)

	// DNS records (paginate)
	var existing []cfDNSRecord
	for page := 1; page <= 20; page++ {
		var batch []cfDNSRecord
		path := fmt.Sprintf("/zones/%s/dns_records?type=CNAME&per_page=100&page=%d", zid, page)
		if err := c.do(http.MethodGet, path, nil, &batch); err != nil {
			return st, fmt.Errorf("list dns records: %v", err)
		}
		existing = append(existing, batch...)
		if len(batch) < 100 {
			break
		}
	}
	byName := map[string]cfDNSRecord{}
	for _, r := range existing {
		byName[r.Name] = r
	}

	newIngress := func() any {
		return map[string]any{"config": map[string]any{"ingress": final}}
	}
	changedIngress := fmt.Sprintf("%v", final) != fmt.Sprintf("%v", ingress)
	if changedIngress {
		if err := c.do(http.MethodPut, "/accounts/"+acct+"/cfd_tunnels/"+tunnelID+"/configurations", newIngress(), nil); err != nil {
			return st, fmt.Errorf("update tunnel config: %v", err)
		}
	}

	recordBody := func(name string) map[string]any {
		return map[string]any{
			"type": "CNAME", "name": name, "content": cname,
			"proxied": true, "comment": cfDNSMarker, "ttl": 1,
		}
	}
	for _, n := range names {
		cur, ok := byName[n]
		switch {
		case !ok:
			if err := c.do(http.MethodPost, "/zones/"+zid+"/dns_records", recordBody(n), nil); err != nil {
				return st, fmt.Errorf("create %s: %v", n, err)
			}
			st.Added = append(st.Added, n)
		case cur.Content == cname && cur.Proxied && cur.Comment == cfDNSMarker:
			// already correct
		case cur.Content == cname || cur.Comment == cfDNSMarker:
			// ours (right target but unmarked/unproxied, or marked but drifted)
			if err := c.do(http.MethodPut, "/zones/"+zid+"/dns_records/"+cur.ID, recordBody(n), nil); err != nil {
				return st, fmt.Errorf("update %s: %v", n, err)
			}
			st.Updated = append(st.Updated, n)
		default:
			// user-owned record claiming this name with a different target
			st.Conflicts = append(st.Conflicts, n)
		}
	}
	if cfg.CloudflarePrune {
		for _, r := range existing {
			if want[r.Name] || r.Comment != cfDNSMarker || r.Content != cname {
				continue
			}
			if err := c.do(http.MethodDelete, "/zones/"+zid+"/dns_records/"+r.ID, nil, nil); err != nil {
				return st, fmt.Errorf("delete %s: %v", r.Name, err)
			}
			st.Removed = append(st.Removed, r.Name)
		}
	}
	return st, nil
}
