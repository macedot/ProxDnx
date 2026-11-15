package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeCF is a minimal Cloudflare v4 API: zones, tunnels, tunnel config and
// CNAME records, with mutation counters.
type fakeCF struct {
	zones    map[string]string          // zone name -> zone id
	accounts map[string]string          // zone id -> account id
	tunnels  map[string][]cfTunnel      // account id -> tunnels
	configs  map[string][]cfIngressRule // tunnel id -> ingress rules
	dns      map[string][]cfDNSRecord   // zone id -> records
	seq      int
	posts    int
	puts     int
	deletes  int
}

func (f *fakeCF) ok(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
}

func (f *fakeCF) fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": code, "message": msg}}})
}

func (f *fakeCF) zoneID(name string) (string, bool) {
	for zn, zid := range f.zones {
		if zn == name {
			return zid, true
		}
	}
	return "", false
}

func (f *fakeCF) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/client/v4")
		switch {
		case p == "/zones" && r.Method == http.MethodGet:
			name := r.URL.Query().Get("name")
			zid, ok := f.zoneID(name)
			if !ok {
				f.ok(w, []any{})
				return
			}
			f.ok(w, []map[string]any{{"id": zid, "account": map[string]string{"id": f.accounts[zid]}}})
		case strings.HasPrefix(p, "/accounts/") && strings.HasSuffix(p, "/cfd_tunnels") && r.Method == http.MethodGet:
			acct := strings.Split(strings.TrimPrefix(p, "/accounts/"), "/")[0]
			f.ok(w, f.tunnels[acct])
		case strings.Contains(p, "/cfd_tunnels/") && !strings.HasSuffix(p, "/configurations") && r.Method == http.MethodGet:
			tid := p[strings.LastIndex(p, "/")+1:]
			for _, list := range f.tunnels {
				for _, t := range list {
					if t.ID == tid {
						f.ok(w, t)
						return
					}
				}
			}
			f.fail(w, 7003, "could not route to tunnel")
		case strings.Contains(p, "/cfd_tunnels/") && strings.HasSuffix(p, "/configurations"):
			tid := strings.Split(strings.TrimPrefix(p, "/accounts/"), "/")[2]
			switch r.Method {
			case http.MethodGet:
				f.ok(w, map[string]any{"config": map[string]any{"ingress": f.configs[tid]}})
			case http.MethodPut:
				var body struct {
					Config struct {
						Ingress []cfIngressRule `json:"ingress"`
					} `json:"config"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				f.configs[tid] = body.Config.Ingress
				f.puts++
				f.ok(w, body.Config)
			default:
				f.fail(w, 405, "method not allowed")
			}
		case strings.HasPrefix(p, "/zones/") && strings.HasSuffix(p, "/dns_records") && r.Method == http.MethodGet:
			zid := strings.Split(strings.TrimPrefix(p, "/zones/"), "/")[0]
			batch := f.dns[zid]
			f.ok(w, batch) // test data < 100 rows, single page
		case strings.HasPrefix(p, "/zones/") && strings.HasSuffix(p, "/dns_records") && r.Method == http.MethodPost:
			zid := strings.Split(strings.TrimPrefix(p, "/zones/"), "/")[0]
			var rec map[string]any
			_ = json.NewDecoder(r.Body).Decode(&rec)
			f.seq++
			f.dns[zid] = append(f.dns[zid], cfDNSRecord{
				ID:      fmt.Sprintf("rec-%d", f.seq),
				Type:    rec["type"].(string),
				Name:    rec["name"].(string),
				Content: rec["content"].(string),
				Proxied: true,
				Comment: rec["comment"].(string),
			})
			f.posts++
			f.ok(w, rec)
		case strings.Contains(p, "/dns_records/"):
			zid := strings.Split(strings.TrimPrefix(p, "/zones/"), "/")[0]
			rid := p[strings.LastIndex(p, "/")+1:]
			list := f.dns[zid]
			idx := -1
			for i := range list {
				if list[i].ID == rid {
					idx = i
				}
			}
			if idx < 0 {
				f.fail(w, 81044, "record not found")
				return
			}
			switch r.Method {
			case http.MethodPut:
				var rec map[string]any
				_ = json.NewDecoder(r.Body).Decode(&rec)
				list[idx].Content = rec["content"].(string)
				list[idx].Comment = rec["comment"].(string)
				list[idx].Proxied = true
				f.puts++
				f.ok(w, rec)
			case http.MethodDelete:
				f.dns[zid] = append(list[:idx], list[idx+1:]...)
				f.deletes++
				f.ok(w, map[string]string{"id": rid})
			default:
				f.fail(w, 405, "method not allowed")
			}
		default:
			f.fail(w, 7000, "no route for "+p)
		}
	})
}

// newFakeCF installs the fake API and returns it plus a restore func.
func newFakeCF(t *testing.T) *fakeCF {
	t.Helper()
	f := &fakeCF{
		zones:    map[string]string{"kraftek.cloud": "zone1"},
		accounts: map[string]string{"zone1": "acct1"},
		tunnels:  map[string][]cfTunnel{"acct1": {{ID: "tunnel-uuid-1", Name: "homelab", Status: "connected"}}},
		configs:  map[string][]cfIngressRule{"tunnel-uuid-1": {}},
		dns:      map[string][]cfDNSRecord{"zone1": {}},
	}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	old := cfAPIBase
	cfAPIBase = srv.URL + "/client/v4"
	t.Cleanup(func() { cfAPIBase = old })
	return f
}

func cfTestCfg() Config {
	return Config{CloudflareToken: "tok", CloudflareZone: "kraftek.cloud", CloudflarePrune: true}
}

func TestCloudflareSyncFresh(t *testing.T) {
	f := newFakeCF(t)
	st, err := cfSync(testPublish(), "10.4.2.99", cfTestCfg())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	host := hostLabel()
	want := []string{"apps." + host + ".kraftek.cloud", "immich.kraftek.cloud", "sonarr.kraftek.cloud"}
	if st.Count != len(want) || st.TunnelID != "tunnel-uuid-1" {
		t.Fatalf("count=%d tunnel=%s (%+v)", st.Count, st.TunnelID, st)
	}
	for _, n := range want {
		found := false
		for _, r := range f.dns["zone1"] {
			if r.Name == n && r.Content == "tunnel-uuid-1.cfargotunnel.com" && r.Proxied && r.Comment == cfDNSMarker {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing/incorrect CNAME for %s (%+v)", n, f.dns["zone1"])
		}
	}
	ing := f.configs["tunnel-uuid-1"]
	if len(ing) != len(want)+1 {
		t.Fatalf("ingress rules = %d, want %d (+catch-all)", len(ing), len(want))
	}
	if last := ing[len(ing)-1]; last.Hostname != "" || last.Service != "http_status:404" {
		t.Fatalf("catch-all must stay last: %+v", ing)
	}
	for i := 0; i < len(ing)-1; i++ {
		if ing[i].Service != "http://10.4.2.99:80" {
			t.Fatalf("rule %s routes to %s, want caddy origin", ing[i].Hostname, ing[i].Service)
		}
	}
}

func TestCloudflareSyncIdempotent(t *testing.T) {
	f := newFakeCF(t)
	cfg := cfTestCfg()
	if _, err := cfSync(testPublish(), "10.4.2.99", cfg); err != nil {
		t.Fatalf("sync 1: %v", err)
	}
	posts1, puts1, deletes1 := f.posts, f.puts, f.deletes // run 1 legitimately creates records + config
	if _, err := cfSync(testPublish(), "10.4.2.99", cfg); err != nil {
		t.Fatalf("sync 2: %v", err)
	}
	if f.posts != posts1 || f.puts != puts1 || f.deletes != deletes1 {
		t.Fatalf("second sync should be a no-op: Δposts=%d Δputs=%d Δdeletes=%d",
			f.posts-posts1, f.puts-puts1, f.deletes-deletes1)
	}
}

func TestCloudflareSyncPruneConflictPreserve(t *testing.T) {
	f := newFakeCF(t)
	host := hostLabel()
	gone := "removed-app." + host + ".kraftek.cloud"
	// stale managed record, user-owned record claiming a desired name, managed stale ingress, foreign ingress
	f.dns["zone1"] = []cfDNSRecord{
		{ID: "r1", Type: "CNAME", Name: gone, Content: "tunnel-uuid-1.cfargotunnel.com", Proxied: true, Comment: cfDNSMarker},
		{ID: "r2", Type: "CNAME", Name: "sonarr.kraftek.cloud", Content: "other-target.example", Proxied: true, Comment: "user record"},
	}
	f.configs["tunnel-uuid-1"] = []cfIngressRule{
		{Hostname: gone, Service: "http://10.4.2.99:80"},
		{Hostname: "git.example.com", Service: "http://10.4.2.158:3000"}, // foreign — must survive
		{Service: "http_status:404"},
	}
	st, err := cfSync(testPublish(), "10.4.2.99", cfTestCfg())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if f.deletes != 1 {
		t.Fatalf("expected 1 record prune, got %d", f.deletes)
	}
	foundUserRecord := false
	for _, r := range f.dns["zone1"] {
		if r.ID == "r2" {
			foundUserRecord = true
		}
	}
	if !foundUserRecord {
		t.Fatalf("user-owned record must be untouched")
	}
	var conflict bool
	for _, c := range st.Conflicts {
		if c == "sonarr.kraftek.cloud" {
			conflict = true
		}
	}
	if !conflict {
		t.Fatalf("conflict not reported: %+v", st.Conflicts)
	}
	ing := f.configs["tunnel-uuid-1"]
	if len(ing) != 5 { // 3 managed names + foreign + catch-all
		t.Fatalf("ingress rules = %d (%+v)", len(ing), ing)
	}
	if ing[len(ing)-1].Service != "http_status:404" {
		t.Fatalf("catch-all no longer last: %+v", ing)
	}
	foreign := false
	for _, r := range ing {
		if r.Hostname == "git.example.com" && r.Service == "http://10.4.2.158:3000" {
			foreign = true
		}
	}
	if !foreign {
		t.Fatalf("foreign ingress rule was dropped: %+v", ing)
	}
}

func TestCloudflareSyncDeletedTunnel(t *testing.T) {
	f := newFakeCF(t)
	now := "2026-01-01T00:00:00Z"
	f.tunnels["acct1"] = []cfTunnel{{ID: "tunnel-uuid-1", Name: "homelab", DeletedAt: &now}}
	cfg := cfTestCfg()
	_, err := cfSync(testPublish(), "10.4.2.99", cfg)
	if err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Fatalf("expected deleted-tunnel error, got %v", err)
	}
}

func TestCloudflarePublicNamesStable(t *testing.T) {
	zone := strings.Trim(strings.TrimRight("kraftek.cloud", "."), ".")
	if zone != "kraftek.cloud" {
		t.Fatalf("zone normalization broken: %q", zone)
	}
}

func TestAPICloudflareDisabled(t *testing.T) {
	resp, body := get(t, newTestApp(nil).routes(), "/api/cloudflare")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("body: %v (%s)", err, body)
	}
	if v, _ := out["enabled"].(bool); v {
		t.Fatalf("expected enabled=false, got %s", body)
	}
}

func TestAPICloudflareEnabled(t *testing.T) {
	app := newTestApp(testPublish())
	app.cfg.CloudflareToken = "tok"
	app.cfg.CloudflareZone = "kraftek.cloud"
	app.cf = CloudflareStatus{Enabled: true, Count: 3, TunnelID: "tunnel-uuid-1", At: time.Unix(1700000000, 0)}
	resp, body := get(t, app.routes(), "/api/cloudflare")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out struct {
		Enabled bool `json:"enabled"`
		Count   int  `json:"count"`
		Routes  []struct {
			Hostname string `json:"hostname"`
			URL      string `json:"url"`
		} `json:"routes"`
		LastSync CloudflareStatus `json:"last_sync"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("body: %v (%s)", err, body)
	}
	host := hostLabel()
	// slugs + portal only — bare <host>.<zone> and infra are never public
	if !out.Enabled || out.Count != 3 || len(out.Routes) != 3 {
		t.Fatalf("enabled=%v count=%d routes=%d (%s)", out.Enabled, out.Count, len(out.Routes), body)
	}
	seen := map[string]string{}
	for _, r := range out.Routes {
		seen[r.Hostname] = r.URL
	}
	for _, n := range []string{"sonarr.kraftek.cloud", "immich.kraftek.cloud", "apps." + host + ".kraftek.cloud"} {
		if seen[n] != "https://"+n {
			t.Fatalf("route %s = %q", n, seen[n])
		}
	}
	if out.LastSync.TunnelID != "tunnel-uuid-1" {
		t.Fatalf("last_sync = %+v", out.LastSync)
	}
}

func TestRenderCaddyfileCloudflare(t *testing.T) {
	sites := map[string]Record{
		"immich": {Domain: "immich.local", Service: "Immich", Name: "immich", IP: "10.0.0.5", Port: 2283},
	}
	base := Config{BaseURL: "http://127.0.0.1:8008", APIAddr: "127.0.0.1:9973", HTTP: true, Static: true}
	if renderCaddyfile(sites, base, "horus") != renderCaddyfile(sites, base, "horus") {
		t.Fatal("unreachable")
	}
	// CF off: zero-value cloudflare fields must not change output
	off := renderCaddyfile(sites, base, "horus")
	if strings.Contains(off, "kraftek.cloud") {
		t.Fatal("cloudflare hostnames leaked into output with sync disabled")
	}
	on := base
	on.CloudflareToken = "tok"
	on.CloudflareZone = "kraftek.cloud"
	got := renderCaddyfile(sites, on, "horus")
	if !strings.Contains(got, "http://immich.kraftek.cloud {\n    reverse_proxy 10.0.0.5:2283\n}") {
		t.Fatalf("public app twin missing:\n%s", got)
	}
	if !strings.Contains(got, "http://apps.horus.kraftek.cloud {\n    reverse_proxy 127.0.0.1:9973\n}") {
		t.Fatalf("public portal twin missing:\n%s", got)
	}
}
