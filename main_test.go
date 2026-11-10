package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestApp(domains []Record) *App {
	return &App{
		cfg: Config{
			BaseURL: "http://127.0.0.1:8008",
			Bridge:  "vmbr0",
			Static:  true,
			HTTP:    true,
			APIAddr: "127.0.0.1:9973",
			Path:    "/tmp/fake-config.yaml",
			Interval: time.Minute,
			Caddy:   true,
			Avahi:   true,
		},
		log:     log.New(io.Discard, "", 0),
		domains: domains,
		stats:   CycleStats{At: time.Unix(1700000000, 0), Kept: 1, Total: 1},
	}
}

func get(t *testing.T, h http.Handler, path string) (*http.Response, string) {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestRoutesHealthz(t *testing.T) {
	resp, body := get(t, newTestApp(nil).routes(), "/healthz")
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("healthz: %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff header missing")
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("cache-control header missing")
	}
}

func TestRoutesPortal(t *testing.T) {
	resp, body := get(t, newTestApp(nil).routes(), "/")
	if resp.StatusCode != 200 {
		t.Fatalf("portal: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "ProxDnx") {
		t.Error("portal HTML missing")
	}
	if resp.Header.Get("Content-Type") == "" || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("content-type: %q", resp.Header.Get("Content-Type"))
	}
}

func TestRoutesDomains(t *testing.T) {
	app := newTestApp([]Record{
		{Domain: "immich.local", Service: "Immich", Name: "immich", IP: "10.0.0.5", Port: 2283},
	})
	resp, body := get(t, app.routes(), "/api/domains")
	if resp.StatusCode != 200 {
		t.Fatalf("domains: %d", resp.StatusCode)
	}
	var out struct {
		Count      int      `json:"count"`
		UpdatedAt  string   `json:"updated_at"`
		DomainList []Record `json:"domains"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v (%q)", err, body)
	}
	if out.Count != 1 || len(out.DomainList) != 1 || out.DomainList[0].Domain != "immich.local" {
		t.Errorf("domains payload wrong: %q", body)
	}

	// empty app: zero count, still valid JSON
	resp2, body2 := get(t, newTestApp(nil).routes(), "/api/domains")
	if resp2.StatusCode != 200 {
		t.Fatalf("empty domains: %d", resp2.StatusCode)
	}
	var out2 struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal([]byte(body2), &out2)
	if out2.Count != 0 {
		t.Errorf("empty count: %d (%q)", out2.Count, body2)
	}
}

func TestRoutesStatic(t *testing.T) {
	resp, body := get(t, newTestApp(nil).routes(), "/api/static")
	if resp.StatusCode != 200 {
		t.Fatalf("static: %d", resp.StatusCode)
	}
	var out struct {
		Enabled bool          `json:"enabled"`
		Routes  []StaticRoute `json:"routes"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v (%q)", err, body)
	}
	if !out.Enabled {
		t.Error("static must be enabled")
	}
	if len(out.Routes) != 2 {
		t.Fatalf("routes: %d", len(out.Routes))
	}
	if out.Routes[0].Upstream != "https://127.0.0.1:8006" {
		t.Errorf("pve upstream: %q", out.Routes[0].Upstream)
	}
	found := false
	for _, n := range out.Routes[1].Names {
		if n == "menux.local" {
			found = true
		}
	}
	if !found {
		t.Errorf("menux names missing: %v", out.Routes[1].Names)
	}

	app := newTestApp(nil)
	app.cfg.Static = false
	_, body2 := get(t, app.routes(), "/api/static")
	if strings.Contains(body2, `"enabled":true`) {
		t.Errorf("disabled static must report enabled=false: %q", body2)
	}
}

func TestRoutesStatus(t *testing.T) {
	resp, body := get(t, newTestApp(nil).routes(), "/api/status")
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var out struct {
		IntervalSeconds float64 `json:"interval_seconds"`
		Caddy           bool    `json:"caddy"`
		Avahi           bool    `json:"avahi"`
		Config          string  `json:"config"`
		LastCycle       struct {
			At    time.Time `json:"at"`
			Total int       `json:"total"`
		} `json:"last_cycle"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v (%q)", err, body)
	}
	if out.IntervalSeconds != 60 || !out.Caddy || !out.Avahi || out.Config == "" || out.LastCycle.Total != 1 {
		t.Errorf("status payload wrong: %q", body)
	}
}

func TestRoutesMethodAnd404(t *testing.T) {
	h := newTestApp(nil).routes()
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, path := range []string{"/api/domains", "/api/static", "/api/status"} {
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: got %d, want 405", path, resp.StatusCode)
		}
	}
	resp, err := http.Get(srv.URL + "/api/bogus")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path: got %d, want 404", resp.StatusCode)
	}
}

func TestHasOnceFlag(t *testing.T) {
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = []string{"proxdnx", "--once"}
	if !hasOnceFlag() {
		t.Error("--once not detected")
	}
	os.Args = []string{"proxdnx", "-once"}
	if !hasOnceFlag() {
		t.Error("-once not detected")
	}
	os.Args = []string{"proxdnx", "--other"}
	if hasOnceFlag() {
		t.Error("false positive once flag")
	}
}

func TestSortStrings(t *testing.T) {
	s := []string{"c", "a", "b", "a"}
	sortStrings(s)
	if strings.Join(s, ",") != "a,a,b,c" {
		t.Errorf("sortStrings: %v", s)
	}
	sortStrings(nil) // must not panic
}

func TestSetStats(t *testing.T) {
	app := newTestApp(nil)
	app.setStats(CycleStats{Total: 7})
	if app.stats.Total != 7 {
		t.Errorf("setStats: %+v", app.stats)
	}
}

// TestLoadEffectiveConfig exercises the real precedence chain:
// defaults < config file < env < CLI flags, plus the fast-fail validation.
func TestLoadEffectiveConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "url: http://10.1.1.1:8008\ninterval: 5s\nstatic: false\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := os.Args
	defer func() { os.Args = old }()

	os.Args = []string{"proxdnx", "--config", path}
	c, err := loadEffectiveConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.BaseURL != "http://10.1.1.1:8008" || c.Interval != 5*time.Second || c.Static {
		t.Errorf("file values not applied: %+v", c)
	}
	if c.Path != path {
		t.Errorf("path not resolved: %q", c.Path)
	}

	// flag beats file
	os.Args = []string{"proxdnx", "--config", path, "-static", "-caddy"}
	c, err = loadEffectiveConfig()
	if err != nil {
		t.Fatalf("load with flags: %v", err)
	}
	if !c.Static || !c.Caddy {
		t.Errorf("flags must override file: static=%v caddy=%v", c.Static, c.Caddy)
	}

	// invalid file -> startup refused
	if err := os.WriteFile(path, []byte("bridge: bad;name\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"proxdnx", "--config", path}
	if _, err = loadEffectiveConfig(); err == nil {
		t.Error("invalid bridge must refuse startup")
	}
}

func TestRunExec(t *testing.T) {
	if err := run("true"); err != nil {
		t.Errorf("true: %v", err)
	}
	err := run("sh", "-c", "echo boom >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("failing command must carry stderr: %v", err)
	}
}

// TestCycleUpdatesState runs the real diff/state machinery against a stub
// monitor API with all writers disabled — no /etc writes, no caddy reload.
func TestCycleUpdatesState(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/vms", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"vmid":5,"name":"sonarr","status":"running","type":"lxc","ips":["10.4.2.150"],
			 "app_watches":[{"name":"Sonarr","ports":[{"port":8989}]}]}
		]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := Config{BaseURL: srv.URL, Network: "10.4.2.0/24"} // writers off
	app := &App{cfg: cfg, client: NewClient(cfg), log: log.New(io.Discard, "", 0)}
	ctx := context.Background()

	if err := app.cycle(ctx); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	if len(app.domains) != 1 || app.stats.Added != 1 || app.stats.Total != 1 {
		t.Fatalf("cycle 1 state: %+v %+v", app.domains, app.stats)
	}
	// identical second cycle: everything kept, nothing changed
	if err := app.cycle(ctx); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	if app.stats.Kept != 1 || app.stats.Added != 0 || app.stats.Changed != 0 {
		t.Errorf("cycle 2 diff wrong: %+v", app.stats)
	}

	// a dying monitor must not corrupt the last known good state
	srv.Close()
	if err := app.cycle(ctx); err == nil {
		t.Fatal("expected error after server close")
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if len(app.domains) != 1 {
		t.Errorf("failed cycle must keep last good state: %+v", app.domains)
	}
	if app.stats.Error == "" {
		t.Error("stats.Error must be set on failure")
	}
}

func TestSetupLogging(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "proxdnx.log")
	lg := setupLogging(path)
	lg.Printf("hello-log")
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "hello-log") {
		t.Errorf("log file not written: %v %q", err, data)
	}
	// unwritable path: must not panic, returns stdout-only logger
	if lg := setupLogging(filepath.Join(dir, "missing-dir", "x.log")); lg == nil {
		t.Error("setupLogging must always return a logger")
	}
	// empty path: stdout only
	if lg := setupLogging(""); lg == nil {
		t.Error("empty path must still return a logger")
	}
}

func TestRequireActiveRefusesUnknown(t *testing.T) {
	// whatever the platform does with an unknown unit, the answer must be an
	// error — never a silent pass
	if err := requireActive("proxdnx-no-such-unit-xyz"); err == nil {
		t.Error("unknown unit must fail requireActive")
	}
}

func TestDefaultConfigValidAndSane(t *testing.T) {
	c := defaultConfig()
	if err := c.validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	if !c.Static || !c.HTTP {
		t.Errorf("static/http must default on: %+v", c)
	}
	if c.Caddy || c.Avahi || c.Scan {
		t.Errorf("writer flags must default off (CLI contract): %+v", c)
	}
}
