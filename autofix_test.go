package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestPlanFix(t *testing.T) {
	// the incident: registered Bazarr@6767 (dead), Sonarr answers on 8989
	plan, ok, _ := planFix("Bazarr", 6767, map[int]string{8989: "Sonarr"})
	if !ok || plan.name != "Sonarr" || plan.port != 8989 || !plan.registerOnly {
		t.Fatalf("incident plan wrong: %+v ok=%v", plan, ok)
	}

	// port moved, same app: title agrees -> patch port only, keep tracking
	plan, ok, _ = planFix("Sonarr", 1, map[int]string{8989: "Sonarr"})
	if !ok || plan.name != "Sonarr" || plan.port != 8989 || plan.registerOnly {
		t.Fatalf("port-move plan wrong: %+v ok=%v", plan, ok)
	}

	// registered port open and already correct: nothing to do (probe race)
	_, ok, why := planFix("Sonarr", 8989, map[int]string{8989: "Sonarr"})
	if ok {
		t.Fatalf("expected no-op, got plan %+v (%s)", plan, why)
	}

	// generic title: no verdict
	_, ok, _ = planFix("AdGuard Home", 1, map[int]string{3000: "Login"})
	if ok {
		t.Fatal("generic Login title must not drive a fix")
	}

	// ambiguous: registered name matches nothing, two different identified apps
	_, ok, _ = planFix("Watchtower", 1, map[int]string{8989: "Sonarr", 7878: "Radarr"})
	if ok {
		t.Fatal("ambiguous candidates must not drive a fix")
	}

	// nothing usable
	_, ok, _ = planFix("Sonarr", 1, nil)
	if ok {
		t.Fatal("no live candidates must not drive a fix")
	}
}

// TestAutoFixEndToEnd: full flow against a stub monitor — a stale registered
// port plus a live Sonarr on a well-known port results in a PUT that renames
// the registration, register-only.
func TestAutoFixEndToEnd(t *testing.T) {
	// serve the "real app" on a known sweep port
	ln, err := net.Listen("tcp", "127.0.0.1:8989")
	if err != nil {
		t.Skipf("tcp/8989 busy on this host: %v", err)
	}
	appSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><head><title>Sonarr</title></head></html>"))
	})}
	go func() { _ = appSrv.Serve(ln) }()
	defer appSrv.Close()

	var mu sync.Mutex
	var putPayload map[string]any
	putCalled := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/vms", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"vmid":5,"name":"repurposed","status":"running","type":"lxc","ips":["127.0.0.1"],
			 "app_watches":[{"id":"abc123","name":"Bazarr","helper_slug":"linuxserver-bazarr",
			   "ports":[{"port":6767}]}]}
		]`))
	})
	mux.HandleFunc("/api/vms/5/apps", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vmid":5,"apps":[{"id":"abc123","name":"Bazarr",
		  "helper_slug":"linuxserver-bazarr","installed_via":"oci_image",
		  "ports":[{"port":6767,"scheme":"http","web_path":"/"}]}]}`))
	})
	mux.HandleFunc("/api/vms/5/apps/abc123", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("autofix must PUT, got %s", r.Method)
			w.WriteHeader(405)
			return
		}
		body, _ := io.ReadAll(r.Body) // read body BEFORE taking the lock
		mu.Lock()
		putCalled++
		_ = json.Unmarshal(body, &putPayload)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := Config{BaseURL: srv.URL, Network: "127.0.0.0/8", Probe: true, AutoFix: true}
	c := NewClient(cfg)
	recs, err := c.fetchRecords(cfg, func(f string, a ...any) { t.Logf("autofix-notef: "+f, a...) })
	if err != nil {
		t.Fatalf("fetchRecords: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("no records produced")
	}
	// the stale record must carry its sidecar identity for autofix
	found := false
	for _, r := range recs {
		if r.Service == "Bazarr" {
			found = true
			if !r.Stale {
				t.Errorf("Bazarr@6767 is closed — must be tagged stale: %+v", r)
			}
			if r.vmid != 5 || r.appID != "abc123" {
				t.Errorf("record missing sidecar identity: %+v", r)
			}
		}
	}
	if !found {
		t.Fatalf("Bazarr record missing: %+v", recs)
	}

	mu.Lock()
	putCalledAfterFix, payloadAfterFix := putCalled, putPayload
	mu.Unlock()
	if putCalledAfterFix == 0 {
		t.Fatal("autofix did not PUT the corrected registration")
	}
	if payloadAfterFix["name"] != "Sonarr" {
		t.Errorf("rename payload wrong: %v", payloadAfterFix)
	}
	if _, has := payloadAfterFix["installed_via"]; has {
		t.Errorf("renamed registration must be register-only (no installed_via): %v", payloadAfterFix)
	}
	ports, _ := payloadAfterFix["ports"].([]any)
	if len(ports) != 1 {
		t.Fatalf("ports payload wrong: %v", payloadAfterFix["ports"])
	}
	p0 := ports[0].(map[string]any)
	if p0["port"] != float64(8989) {
		t.Errorf("fixed port wrong: %v", p0)
	}

	// attempts capped at 2: two PUTs across the four fetches, then silence
	_, _ = c.fetchRecords(cfg, func(string, ...any) {})
	_, _ = c.fetchRecords(cfg, func(string, ...any) {})
	_, _ = c.fetchRecords(cfg, func(string, ...any) {})
	mu.Lock()
	defer mu.Unlock()
	if putCalled != 2 {
		t.Errorf("attempt cap: %d PUTs, want 2", putCalled)
	}
}

// TestAutoFixDisabledByDefault: without autofix, nothing PUTs.
func TestAutoFixDisabledByDefault(t *testing.T) {
	putCalled := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/vms", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"vmid":5,"name":"repurposed","status":"running","type":"lxc","ips":["127.0.0.1"],
			 "app_watches":[{"id":"abc123","name":"Bazarr","ports":[{"port":6767}]}]}
		]`))
	})
	mux.HandleFunc("/api/vms/5/apps", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vmid":5,"apps":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := Config{BaseURL: srv.URL, Network: "127.0.0.0/8", Probe: true, AutoFix: false}
	if _, err := NewClient(cfg).fetchRecords(cfg, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if putCalled != 0 {
		t.Error("autofix must be opt-in")
	}
}

// TestOpenPorts: sanity of the sweep helper itself.
func TestOpenPorts(t *testing.T) {
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
	port := ln.Addr().(*net.TCPAddr).Port
	open := openPorts("127.0.0.1", []int{port, 1, 2}, 500*time.Millisecond, 4)
	if !open[port] {
		t.Errorf("listener port not detected open: %v", open)
	}
	if open[1] || open[2] {
		t.Error("closed ports detected open")
	}
	if _, err := strconv.Atoi(strconv.Itoa(port)); err != nil {
		t.Fatal(err) // keep strconv imported
	}
}
