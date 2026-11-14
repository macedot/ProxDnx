package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakeAdguard is a minimal AdGuard Home: login-gated rewrite store.
type fakeAdguard struct {
	user, pass string
	rewrites   map[string]adguardRewrite
	order      []string
	adds       int
	updates    int
	deletes    int
}

func (f *fakeAdguard) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/control/login" {
			var req struct{ Username, Password string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Username != f.user || req.Password != f.pass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "AGH", Value: "session"})
			w.WriteHeader(http.StatusOK)
			return
		}
		ok := false
		for _, c := range r.Cookies() {
			if c.Name == "AGH" && c.Value == "session" {
				ok = true
			}
		}
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/control/rewrite":
			arr := make([]adguardRewrite, 0, len(f.rewrites))
			for _, k := range f.order {
				arr = append(arr, f.rewrites[k])
			}
			_ = json.NewEncoder(w).Encode(arr)
		case "/control/rewrite/add":
			var rw adguardRewrite
			_ = json.NewDecoder(r.Body).Decode(&rw)
			if _, exists := f.rewrites[rw.Domain]; exists {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, "rewrite already exists")
				return
			}
			rw.Enabled = true
			f.rewrites[rw.Domain] = rw
			f.order = append(f.order, rw.Domain)
			f.adds++
			w.WriteHeader(http.StatusOK)
		case "/control/rewrite/update":
			var req struct {
				Target adguardRewrite `json:"target"`
				Update adguardRewrite `json:"update"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if _, exists := f.rewrites[req.Target.Domain]; !exists {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			delete(f.rewrites, req.Target.Domain)
			req.Update.Enabled = true
			f.rewrites[req.Update.Domain] = req.Update
			for i, k := range f.order {
				if k == req.Target.Domain {
					f.order[i] = req.Update.Domain
				}
			}
			f.updates++
			w.WriteHeader(http.StatusOK)
		case "/control/rewrite/delete":
			var rw adguardRewrite
			_ = json.NewDecoder(r.Body).Decode(&rw)
			if _, exists := f.rewrites[rw.Domain]; !exists {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			delete(f.rewrites, rw.Domain)
			for i, k := range f.order {
				if k == rw.Domain {
					f.order = append(f.order[:i], f.order[i+1:]...)
				}
			}
			f.deletes++
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func newFakeAdguard(t *testing.T, user, pass string) (*fakeAdguard, *httptest.Server) {
	t.Helper()
	f := &fakeAdguard{user: user, pass: pass, rewrites: map[string]adguardRewrite{}}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return f, srv
}

func testPublish() []Record {
	return []Record{
		{Service: "Sonarr", Domain: "sonarr", IP: "10.4.2.150", Port: 8989},
		{Service: "Immich", Domain: "immich", IP: "10.4.2.119", Port: 2283},
	}
}

func keys(m map[string]adguardRewrite) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestAdguardSyncAddsPublishedNames(t *testing.T) {
	f, srv := newFakeAdguard(t, "admin", "secret")
	cfg := Config{AdguardURL: srv.URL, AdguardUser: "admin", AdguardPassword: "secret", Static: true, AdguardPrune: true}
	answer := "10.4.2.99"
	if _, err := applyAdguard(testPublish(), answer, cfg); err != nil {
		t.Fatalf("sync: %v", err)
	}
	host := hostLabel()
	want := []string{
		"apps." + host + ".local", host + ".local",
		"immich.local", "menux." + host + ".local", "menux.local",
		"proxmenux.local", "sonarr.local",
	}
	got := keys(f.rewrites)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rewrites = [%s], want [%s]", strings.Join(got, ","), strings.Join(want, ","))
	}
	for _, k := range want {
		if r := f.rewrites[k]; r.Answer != answer || !r.Enabled {
			t.Fatalf("rewrite %s = %+v, want answer %s enabled", k, r, answer)
		}
	}
}

func TestAdguardSyncSuffixVariants(t *testing.T) {
	f, srv := newFakeAdguard(t, "admin", "secret")
	cfg := Config{AdguardURL: srv.URL, AdguardUser: "admin", AdguardPassword: "secret", AdguardSuffix: "home"}
	if _, err := applyAdguard(testPublish(), "10.4.2.99", cfg); err != nil {
		t.Fatalf("sync: %v", err)
	}
	for _, d := range []string{"sonarr.home", "immich.home", "apps." + hostLabel() + ".home"} {
		if _, ok := f.rewrites[d]; !ok {
			t.Fatalf("missing suffix rewrite %s (have %v)", d, keys(f.rewrites))
		}
	}
}

func TestAdguardSyncIdempotent(t *testing.T) {
	f, srv := newFakeAdguard(t, "admin", "secret")
	cfg := Config{AdguardURL: srv.URL, AdguardUser: "admin", AdguardPassword: "secret", Static: true, AdguardPrune: true}
	for i := 0; i < 2; i++ {
		if _, err := applyAdguard(testPublish(), "10.4.2.99", cfg); err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
	}
	if f.adds != len(f.rewrites) {
		t.Fatalf("expected %d total adds, got %d", len(f.rewrites), f.adds)
	}
	if f.updates != 0 || f.deletes != 0 {
		t.Fatalf("second sync should be a no-op, got updates=%d deletes=%d", f.updates, f.deletes)
	}
}

func TestAdguardSyncFixesDriftedAnswer(t *testing.T) {
	f, srv := newFakeAdguard(t, "admin", "secret")
	f.rewrites["sonarr.local"] = adguardRewrite{Domain: "sonarr.local", Answer: "1.2.3.4", Enabled: true}
	f.order = append(f.order, "sonarr.local")
	cfg := Config{AdguardURL: srv.URL, AdguardUser: "admin", AdguardPassword: "secret", AdguardPrune: true}
	if _, err := applyAdguard(testPublish(), "10.4.2.99", cfg); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if r := f.rewrites["sonarr.local"]; r.Answer != "10.4.2.99" {
		t.Fatalf("drifted rewrite not fixed: %+v", r)
	}
	if f.updates != 1 {
		t.Fatalf("expected 1 update, got %d", f.updates)
	}
}

func TestAdguardSyncPrunesOnlyManaged(t *testing.T) {
	f, srv := newFakeAdguard(t, "admin", "secret")
	answer := "10.4.2.99"
	// stale managed rewrite (ours: .local + host answer) and a user-owned one
	f.rewrites["removed-app.local"] = adguardRewrite{Domain: "removed-app.local", Answer: answer, Enabled: true}
	f.rewrites["user-app.local"] = adguardRewrite{Domain: "user-app.local", Answer: "10.9.9.9", Enabled: true}
	f.order = []string{"removed-app.local", "user-app.local"}
	cfg := Config{AdguardURL: srv.URL, AdguardUser: "admin", AdguardPassword: "secret", AdguardPrune: true}
	if _, err := applyAdguard(testPublish(), answer, cfg); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, ok := f.rewrites["removed-app.local"]; ok {
		t.Fatalf("stale managed rewrite was not pruned")
	}
	if _, ok := f.rewrites["user-app.local"]; !ok {
		t.Fatalf("user-owned rewrite was deleted")
	}
	if f.deletes != 1 {
		t.Fatalf("expected 1 delete, got %d", f.deletes)
	}
}

func TestAdguardSyncPruneDisabled(t *testing.T) {
	f, srv := newFakeAdguard(t, "admin", "secret")
	f.rewrites["removed-app.local"] = adguardRewrite{Domain: "removed-app.local", Answer: "10.4.2.99", Enabled: true}
	f.order = append(f.order, "removed-app.local")
	cfg := Config{AdguardURL: srv.URL, AdguardUser: "admin", AdguardPassword: "secret", AdguardPrune: false}
	if _, err := applyAdguard(testPublish(), "10.4.2.99", cfg); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, ok := f.rewrites["removed-app.local"]; !ok {
		t.Fatalf("prune=false must not delete rewrites")
	}
}

func TestAdguardBadCredentials(t *testing.T) {
	f, srv := newFakeAdguard(t, "admin", "secret")
	cfg := Config{AdguardURL: srv.URL, AdguardUser: "admin", AdguardPassword: "wrong"}
	_, err := applyAdguard(testPublish(), "10.4.2.99", cfg)
	if err == nil || !strings.Contains(err.Error(), "bad credentials") {
		t.Fatalf("expected bad-credentials error, got %v", err)
	}
	if len(f.rewrites) != 0 {
		t.Fatalf("failed login must not touch rewrites")
	}
}

func TestAPIAdguardDisabled(t *testing.T) {
	resp, body := get(t, newTestApp(nil).routes(), "/api/adguard")
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

func TestAPIAdguardEnabled(t *testing.T) {
	app := newTestApp(testPublish())
	app.cfg.AdguardURL = "http://127.0.0.1:1" // configured; the endpoint never dials AdGuard
	app.cfg.AdguardUser = "u"
	app.cfg.AdguardPassword = "p"
	app.cfg.AdguardSuffix = "home"
	app.cfg.Static = false // keep the expected name set deterministic
	app.adguard = AdguardStatus{Enabled: true, Synced: 8, At: time.Unix(1700000000, 0)}
	resp, body := get(t, app.routes(), "/api/adguard")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out struct {
		Enabled  bool `json:"enabled"`
		Count    int  `json:"count"`
		Rewrites []struct {
			Domain string `json:"domain"`
			Answer string `json:"answer"`
		} `json:"rewrites"`
		Suffix   string        `json:"suffix"`
		LastSync AdguardStatus `json:"last_sync"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("body: %v (%s)", err, body)
	}
	if !out.Enabled || out.Count != 8 || len(out.Rewrites) != 8 {
		t.Fatalf("enabled=%v count=%d rewrites=%d (%s)", out.Enabled, out.Count, len(out.Rewrites), body)
	}
	if out.Suffix != "home" || out.LastSync.Synced != 8 {
		t.Fatalf("suffix=%q last_sync=%+v", out.Suffix, out.LastSync)
	}
	seen := map[string]bool{}
	for _, r := range out.Rewrites {
		seen[r.Domain] = true
	}
	host := hostLabel()
	for _, d := range []string{
		"sonarr.local", "immich.local",
		"apps." + host + ".local", host + ".local",
		"sonarr.home", "immich.home", "apps." + host + ".home", host + ".home",
	} {
		if !seen[d] {
			t.Fatalf("missing rewrite %s (have %v)", d, body)
		}
	}
}
