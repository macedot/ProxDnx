package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"AdGuard Home":   "adguard-home",
		"  --x--  ":      "x",
		"ABC":            "abc",
		"":               "app",
		"!!!":            "app",
		"hällo":          "h-llo", // non-ascii becomes a dash, like any other symbol
		"a.b/c":          "a-b-c",
		"tab\tnewline\n": "tab-newline",
		"Plex Media S":   "plex-media-s",
		"already-slug9":  "already-slug9",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSlugifyAlwaysSafe(t *testing.T) {
	hostile := []string{"} {", "a\nb\nc", "\\", `"quotes"`, "%s%d", " } drop { "}
	for _, in := range hostile {
		got := slugify(in)
		if strings.ContainsAny(got, "{}\\\"\n%") {
			t.Errorf("slugify(%q) leaked hostile chars: %q", in, got)
		}
		if len(got) == 0 {
			t.Errorf("slugify(%q) empty", in)
		}
	}
}

func TestTrunc(t *testing.T) {
	if trunc("  hello  ", 3) != "hel" {
		t.Errorf("long: %q", trunc("  hello  ", 3))
	}
	if trunc("hi", 10) != "hi" {
		t.Errorf("short: %q", trunc("hi", 10))
	}
}

// TestResolveSubnetShellPath covers the `ip` output parsing end to end,
// including the warning notef callbacks.
func TestResolveSubnetShellPath(t *testing.T) {
	notes := []string{}
	sub, err := resolveSubnet("", "lo", func(f string, a ...any) { notes = append(notes, f) })
	if err != nil || sub != nil {
		t.Fatalf("loopback bridge: sub=%v err=%v", sub, err)
	}
	if len(notes) == 0 {
		t.Error("loopback-only bridge must emit a warning note")
	}

	sub, err = resolveSubnet("", "proxdnx-no-such-if", func(f string, a ...any) { notes = append(notes, f) })
	if err != nil || sub != nil {
		t.Fatalf("missing bridge: sub=%v err=%v", sub, err)
	}

	sub, err = resolveSubnet("10.4.2.0/24", "whatever", func(string, ...any) {})
	if err != nil || sub == nil || sub.String() != "10.4.2.0/24" {
		t.Fatalf("explicit CIDR: sub=%v err=%v", sub, err)
	}

	if _, err = resolveSubnet("not-a-cidr", "whatever", func(string, ...any) {}); err == nil {
		t.Error("bad explicit CIDR must error")
	}
}

func TestPickIP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.4.2.0/24")
	if got := pickIP([]string{"fd00::1", "10.4.2.5", "10.5.0.1"}, subnet); got != "10.4.2.5" {
		t.Errorf("subnet pick: %q", got)
	}
	if got := pickIP([]string{"fd00::1"}, subnet); got != "" {
		t.Errorf("v6 only must be skipped, got %q", got)
	}
	if got := pickIP([]string{"10.4.2.5", "10.4.2.7"}, nil); got != "10.4.2.5" {
		t.Errorf("nil subnet must take first v4, got %q", got)
	}
	if got := pickIP([]string{"garbage", "10.4.2.9"}, subnet); got != "10.4.2.9" {
		t.Errorf("unparseable entries must be ignored, got %q", got)
	}
	if got := pickIP(nil, subnet); got != "" {
		t.Errorf("nil list: %q", got)
	}
}

// TestPickIPFallback: guests with no IP on the host bridge subnet (e.g.
// byparr living only on the gluetun-side bridge) must still be published —
// caddy proxies from the host, which reaches them. Docker bridges, CGNAT
// (tailscale) and link-local ranges must never be picked as fallback.
func TestPickIPFallback(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.4.2.0/24")
	if got := pickIP([]string{"10.77.0.39"}, subnet); got != "10.77.0.39" {
		t.Errorf("other-bridge guest must fall back to its IP, got %q", got)
	}
	if got := pickIP([]string{"172.17.0.5"}, subnet); got != "" {
		t.Errorf("docker-bridge IP must never be picked, got %q", got)
	}
	if got := pickIP([]string{"100.86.231.25"}, subnet); got != "" {
		t.Errorf("CGNAT/tailscale IP must never be picked, got %q", got)
	}
	if got := pickIP([]string{"169.254.9.9"}, subnet); got != "" {
		t.Errorf("link-local must never be picked, got %q", got)
	}
	if got := pickIP([]string{"172.17.0.5", "10.77.1.12"}, subnet); got != "10.77.1.12" {
		t.Errorf("docker entry must be skipped in favor of usable fallback, got %q", got)
	}
	if got := pickIP([]string{"10.77.0.39", "10.4.2.42"}, subnet); got != "10.4.2.42" {
		t.Errorf("subnet match must still win over fallback, got %q", got)
	}
}

// TestProbeRecords: records behind closed ports must be dropped (they become
// dead .local cards), live listeners kept, and order preserved.
func TestProbeRecords(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	portN, _ := strconv.Atoi(port)

	recs := []Record{
		{Domain: "alive.local", IP: "127.0.0.1", Port: portN},
		{Domain: "dead.local", IP: "127.0.0.1", Port: 1}, // nothing listens on tcp/1
	}
	got := probeRecords(recs, 800*time.Millisecond, 8, func(string, ...any) {})
	if len(got) != 1 || got[0].Domain != "alive.local" {
		t.Fatalf("probe kept wrong records: %+v", got)
	}
}

// TestFetchRecordsDropsClosedPorts is the regression test for the stale
// app_watches incident: a catalog watch pointing at a dead port must not be
// published, while a live discovery-found port on the same guest survives.
func TestFetchRecordsDropsClosedPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, livePort, _ := net.SplitHostPort(ln.Addr().String())
	livePortN, _ := strconv.Atoi(livePort)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/vms", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"vmid":5,"name":"repurposed","status":"running","type":"lxc","ips":["127.0.0.1"],
			 "app_watches":[{"name":"StaleApp","ports":[{"port":1}]}]}
		]`))
	})
	// discovery finds the actually-listening service
	mux.HandleFunc("/api/vms/5/apps/docker-discovery", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","candidates":[{"container_name":"RealApp","default_ports":[` + livePort + `]}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// probe runs against 127.0.0.1 so the "live" discovery port is really
	// open and the stale catalog port (tcp/1) is really closed
	cfg := Config{BaseURL: srv.URL, Network: "127.0.0.0/8", Probe: true}
	recs, err := NewClient(cfg).fetchRecords(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("fetchRecords: %v", err)
	}
	if len(recs) != 1 || recs[0].Domain != "realapp.local" || recs[0].Port != livePortN {
		t.Fatalf("dead watch port must be dropped, live one kept: %+v", recs)
	}

	// probe disabled: nothing is dropped
	cfg2 := Config{BaseURL: srv.URL, Network: "127.0.0.0/8", Probe: false}
	recs2, err := NewClient(cfg2).fetchRecords(cfg2, func(string, ...any) {})
	if err != nil {
		t.Fatalf("fetchRecords: %v", err)
	}
	if len(recs2) != 2 {
		t.Fatalf("probe=false must keep both records: %+v", recs2)
	}
}

func TestParseBridgeSubnet(t *testing.T) {
	out := "1: lo    inet 127.0.0.1/8 scope host lo\\\n    valid_lft forever\n2: vmbr0    inet 10.4.2.99/24 scope global vmbr0\n"
	sub := parseBridgeSubnet(out)
	if sub == nil || sub.String() != "10.4.2.0/24" {
		t.Fatalf("parseBridgeSubnet = %v", sub)
	}
	if sub.Contains(net.ParseIP("10.4.2.150")) != true {
		t.Error("guest 10.4.2.150 must be inside")
	}
	if sub.Contains(net.ParseIP("192.168.7.7")) {
		t.Error("192.168.7.7 must be outside")
	}
	if parseBridgeSubnet("only loopback\n1: lo    inet 127.0.0.1/8") != nil {
		t.Error("loopback-only output must yield nil")
	}
	if parseBridgeSubnet("") != nil {
		t.Error("empty output must yield nil")
	}
}

func TestNewClientTrimsBase(t *testing.T) {
	c := NewClient(Config{BaseURL: "http://127.0.0.1:8008/"})
	if c.base != "http://127.0.0.1:8008" {
		t.Errorf("base not trimmed: %q", c.base)
	}
}

// TestFetchRecords exercises the whole pipeline against a stub monitor API:
// filtering (running + lxc only), subnet matching, port dedup, slug/name
// fallbacks and bearer auth.
func TestFetchRecords(t *testing.T) {
	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/vms", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"vmid":5,"name":"sonarr-lxc","status":"running","type":"lxc","ips":["fd00::1","10.4.2.150"],
			 "app_watches":[
			   {"name":"Sonarr","helper_slug":"sonarr","ports":[{"port":8989},{"port":0}]},
			   {"name":"","helper_slug":"prowlarr","ports":[{"port":9696}]},
			   {"name":"Sonarr Dup","ports":[{"port":8989}]}]},
			{"vmid":6,"name":"stopped","status":"stopped","type":"lxc","ips":["10.4.2.151"],
			 "app_watches":[{"name":"X","ports":[{"port":80}]}]},
			{"vmid":7,"name":"vm-thing","status":"running","type":"qemu","ips":["10.4.2.152"],
			 "app_watches":[{"name":"Nope","ports":[{"port":80}]}]},
			{"vmid":8,"name":"outside","status":"running","type":"lxc","ips":["192.168.7.7"],
			 "app_watches":[{"name":"Out","ports":[{"port":8080}]}]}
		]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// probe-off: exercises filtering (running + lxc + subnet preference),
	// dedup, slug/name fallback and bearer auth deterministically. Out of
	// subnet 192.168.7.7 now survives picking via the fallback (probe would
	// prune it if unreachable — covered in TestFetchRecordsProbePrunes).
	cfg := Config{BaseURL: srv.URL, Token: "tok", Network: "10.4.2.0/24", Probe: false}
	c := NewClient(cfg)
	recs, err := c.fetchRecords(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("fetchRecords: %v", err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth header: %q", gotAuth)
	}

	type key struct {
		domain, ip string
		port       int
	}
	want := map[key]bool{
		{"sonarr.local", "10.4.2.150", 8989}:   true,
		{"prowlarr.local", "10.4.2.150", 9696}: true,
		{"out.local", "192.168.7.7", 8080}:     true,
	}
	if len(recs) != len(want) {
		t.Fatalf("want %d records, got %d: %+v", len(want), len(recs), recs)
	}
	for _, r := range recs {
		if !want[key{r.Domain, r.IP, r.Port}] {
			t.Errorf("unexpected record %+v", r)
		}
		if r.Service == "" || r.Name == "" {
			t.Errorf("record missing metadata: %+v", r)
		}
	}
	if recs[0].Domain > recs[len(recs)-1].Domain {
		t.Error("records not sorted by domain")
	}
	// name "" must fall back to helper_slug
	for _, r := range recs {
		if r.Domain == "prowlarr.local" && r.Service != "prowlarr" {
			t.Errorf("empty watch name should fall back to slug: %+v", r)
		}
	}
}

// TestFetchRecordsProbePrunes: with probing on, the stale catalog port
// (tcp/1, always refused) is dropped while the actually-listening discovery
// port survives — on the same guest, deterministically via loopback.
func TestFetchRecordsProbePrunes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, livePort, _ := net.SplitHostPort(ln.Addr().String())

	mux := http.NewServeMux()
	mux.HandleFunc("/api/vms", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"vmid":5,"name":"guest","status":"running","type":"lxc","ips":["127.0.0.1"],
			 "app_watches":[{"name":"App","ports":[{"port":1},{"port":` + livePort + `}]}]}
		]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := Config{BaseURL: srv.URL, Network: "127.0.0.0/8", Probe: true}
	recs, err := NewClient(cfg).fetchRecords(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("fetchRecords: %v", err)
	}
	if len(recs) != 1 || recs[0].Domain != "app.local" || recs[0].Port != ln.Addr().(*net.TCPAddr).Port {
		t.Fatalf("only the live port must survive: %+v", recs)
	}
}

// TestFetchRecordsDiscoveryMerge: catalog ports merge with docker discovery.
func TestFetchRecordsDiscoveryMerge(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/vms", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"vmid":9,"name":"media","status":"running","type":"lxc","ips":["10.4.2.160"]}
		]`))
	})
	mux.HandleFunc("/api/vms/9/apps/docker-discovery", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("scan=false must GET, got %s", r.Method)
		}
		_, _ = w.Write([]byte(`{"status":"ok","candidates":[{"container_name":"plex","default_ports":[32400,32400]}]}`))
	})
	// /api/vms/9/apps/native-discovery intentionally 404s — must be skipped

	srv := httptest.NewServer(mux)
	defer srv.Close()
	cfg := Config{BaseURL: srv.URL, Network: "10.4.2.0/24"}
	recs, err := NewClient(cfg).fetchRecords(cfg, func(string, ...any) {})
	if err != nil {
		t.Fatalf("fetchRecords: %v", err)
	}
	if len(recs) != 1 || recs[0].Domain != "plex.local" || recs[0].Port != 32400 {
		t.Fatalf("discovery merge wrong: %+v", recs)
	}
}

func TestFetchRecordsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	cfg := Config{BaseURL: srv.URL}
	if _, err := NewClient(cfg).fetchRecords(cfg, func(string, ...any) {}); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("500 must surface as error: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer bad.Close()
	cfg2 := Config{BaseURL: bad.URL}
	if _, err := NewClient(cfg2).fetchRecords(cfg2, func(string, ...any) {}); err == nil {
		t.Error("bad JSON must error")
	}
}

func TestEnsureToken(t *testing.T) {
	// no credentials: no-op
	c := NewClient(Config{BaseURL: "http://127.0.0.1:1"})
	if err := c.ensureToken(); err != nil {
		t.Fatalf("no creds must be a no-op: %v", err)
	}
	// existing token: no-op
	c = NewClient(Config{BaseURL: "http://127.0.0.1:1", Token: "preset"})
	if err := c.ensureToken(); err != nil {
		t.Fatalf("preset token must be a no-op: %v", err)
	}

	newLoginSrv := func(handler http.HandlerFunc) *httptest.Server {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/auth/login", handler)
		return httptest.NewServer(mux)
	}

	// success (with totp)
	var payload map[string]any
	srv := newLoginSrv(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&payload)
		_, _ = w.Write([]byte(`{"success":true,"token":"T1"}`))
	})
	defer srv.Close()
	c = NewClient(Config{BaseURL: srv.URL, User: "u", Password: "p", TOTP: "000000"})
	if err := c.ensureToken(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if c.token != "T1" {
		t.Errorf("token not stored: %q", c.token)
	}
	if payload["username"] != "u" || payload["password"] != "p" || payload["totp_token"] != "000000" {
		t.Errorf("login payload wrong: %v", payload)
	}

	// requires totp
	srv2 := newLoginSrv(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"requires_totp":true}`))
	})
	defer srv2.Close()
	c = NewClient(Config{BaseURL: srv2.URL, User: "u", Password: "p"})
	err := c.ensureToken()
	if err == nil || !strings.Contains(err.Error(), "2FA") {
		t.Errorf("requires_totp must surface: %v", err)
	}

	// plain failure
	srv3 := newLoginSrv(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"message":"bad creds"}`))
	})
	defer srv3.Close()
	c = NewClient(Config{BaseURL: srv3.URL, User: "u", Password: "p"})
	err = c.ensureToken()
	if err == nil || !strings.Contains(err.Error(), "bad creds") {
		t.Errorf("login failure must surface message: %v", err)
	}
}

// TestDoLimitsBody ensures oversized responses cannot balloon memory.
func TestDoLimitsBody(t *testing.T) {
	big := make([]byte, 9<<20) // 9 MiB > the 8 MiB cap
	for i := range big {
		big[i] = 'a'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer srv.Close()
	c := NewClient(Config{BaseURL: srv.URL})
	b, code, err := c.do("GET", "/big", 5_000_000_000)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if code != 200 {
		t.Errorf("code %d", code)
	}
	if len(b) > 8<<20 {
		t.Errorf("body not capped: %d bytes", len(b))
	}
}
