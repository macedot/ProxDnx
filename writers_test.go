package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDedupeSites(t *testing.T) {
	recs := []Record{
		{Domain: "a.local", Service: "App", IP: "10.0.0.1", Port: 80},
		{Domain: "b.local", Service: "App", IP: "10.0.0.2", Port: 81}, // slug collision -> app-2
		{Domain: "c.local", Service: "App", IP: "10.0.0.3", Port: 82}, // -> app-3
		{Domain: "d.local", Service: "Other", IP: "10.0.0.4", Port: 83},
	}
	sites := dedupeSites(recs)
	if len(sites) != 4 {
		t.Fatalf("want 4 sites, got %d: %v", len(sites), sites)
	}
	if sites["app"].IP != "10.0.0.1" {
		t.Errorf("first record must win the base slug: %v", sites["app"])
	}
	if sites["app-2"].IP != "10.0.0.2" || sites["app-3"].IP != "10.0.0.3" {
		t.Errorf("collision suffixes wrong: %v %v", sites["app-2"], sites["app-3"])
	}
	if sites["other"].Port != 83 {
		t.Errorf("plain slug missing: %v", sites["other"])
	}
}

func TestSanitizeHost(t *testing.T) {
	cases := map[string]string{
		"horus":             "horus",
		"horus.example.com": "horus", // first dot-label only
		"My-Host!":          "my-host",
		"  spaced  ":        "spaced",
		"--x--":             "x",
		"höst.local":     "hst", // dot-label cut first, non-ascii dropped
		"...":               "proxdnx",
		"":                  "proxdnx",
	}
	for in, want := range cases {
		if got := sanitizeHost(in); got != want {
			t.Errorf("sanitizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostLabelNeverEmpty(t *testing.T) {
	if hostLabel() == "" {
		t.Fatal("hostLabel must never be empty")
	}
}

func TestStaticRoutes(t *testing.T) {
	routes := staticRoutes("horus", "http://127.0.0.1:8008")
	if len(routes) != 2 {
		t.Fatalf("want 2 static routes, got %d", len(routes))
	}
	pve, menux := routes[0], routes[1]
	if pve.Label != "Proxmox VE" || len(pve.Names) != 1 || pve.Names[0] != "horus.local" {
		t.Errorf("pve route wrong: %+v", pve)
	}
	if pve.Upstream != "https://127.0.0.1:8006" || !pve.Secure {
		t.Errorf("pve upstream wrong: %+v", pve)
	}
	wantNames := []string{"menux.local", "proxmenux.local", "menux.horus.local"}
	if len(menux.Names) != 3 {
		t.Fatalf("menux names: %+v", menux)
	}
	for i, n := range wantNames {
		if menux.Names[i] != n {
			t.Errorf("menux name %d: got %q want %q", i, menux.Names[i], n)
		}
	}
	if menux.Upstream != "http://127.0.0.1:8008" || menux.Secure {
		t.Errorf("menux upstream wrong: %+v", menux)
	}
}

// TestRenderCaddyfileGolden pins the exact bytes. The renderer must stay
// byte-stable (no timestamps) so running hosts never churn their Caddyfile.
func TestRenderCaddyfileGolden(t *testing.T) {
	sites := map[string]Record{
		"immich": {Domain: "immich.local", Service: "Immich", Name: "immich", IP: "10.0.0.5", Port: 2283},
	}
	cfg := Config{BaseURL: "http://127.0.0.1:8008", APIAddr: "127.0.0.1:9973", HTTP: true, Static: true}
	want := `# managed by ProxDnx (ProxDnx)
# 1 apps + portal + static entries

{
    local_certs
}

https://immich.local {
    reverse_proxy 10.0.0.5:2283
}

http://immich.local {
    reverse_proxy 10.0.0.5:2283
}

https://horus.local {
    reverse_proxy https://127.0.0.1:8006 {
        transport http {
            tls_insecure_skip_verify
        }
    }
}

http://horus.local {
    reverse_proxy https://127.0.0.1:8006 {
        transport http {
            tls_insecure_skip_verify
        }
    }
}

https://menux.local, https://proxmenux.local, https://menux.horus.local {
    reverse_proxy http://127.0.0.1:8008
}

http://menux.local, http://proxmenux.local, http://menux.horus.local {
    reverse_proxy http://127.0.0.1:8008
}

https://apps.horus.local {
    reverse_proxy 127.0.0.1:9973
}

http://apps.horus.local {
    reverse_proxy 127.0.0.1:9973
}
`
	got := renderCaddyfile(sites, cfg, "horus")
	if got != want {
		t.Fatalf("render mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if renderCaddyfile(sites, cfg, "horus") != got {
		t.Error("renderer is not deterministic")
	}
}

func TestRenderCaddyfileVariants(t *testing.T) {
	sites := map[string]Record{
		"immich": {Domain: "immich.local", Service: "Immich", IP: "10.0.0.5", Port: 2283},
	}
	base := Config{BaseURL: "http://127.0.0.1:8008", APIAddr: "127.0.0.1:9973", HTTP: true, Static: true}

	noStatic := base
	noStatic.Static = false
	got := renderCaddyfile(sites, noStatic, "horus")
	if strings.Contains(got, "menux") || strings.Contains(got, "static") {
		t.Error("static disabled must drop every static block")
	}
	if strings.Contains(got, "https://horus.local") {
		t.Error("with static off, <host>.local must not be served at all")
	}
	if !strings.Contains(got, "https://apps.horus.local") {
		t.Error("portal must stay on apps.<host>.local")
	}
	if !strings.Contains(got, "# 1 apps + portal\n") {
		t.Errorf("header must not claim static entries: %q", strings.SplitN(got, "\n", 2)[0])
	}

	noHTTP := base
	noHTTP.HTTP = false
	got = renderCaddyfile(sites, noHTTP, "horus")
	if strings.Contains(got, "\nhttp://") {
		t.Error("http=false must render no plain-http twins")
	}
}

// TestRenderCaddyfileInjectionProof: app names come from ProxMenux (external
// data). Slugify must reduce anything hostile to a plain label so no Caddy
// directive can ever be smuggled through a service name.
func TestRenderCaddyfileInjectionProof(t *testing.T) {
	hostile := []string{
		`Evil } ; drop table`,
		"line1\nline2",
		`"} local /etc/passwd"`,
		"{{bad}}",
		"sp ace",
	}
	for _, name := range hostile {
		sites := map[string]Record{
			"x": {Domain: "x.local", Service: name, IP: "10.0.0.5", Port: 80},
		}
		got := renderCaddyfile(sites, Config{Static: false, APIAddr: "127.0.0.1:9973"}, "horus")
		if strings.Contains(got, name) {
			t.Errorf("hostile service name leaked into Caddyfile: %q", name)
		}
		if strings.Contains(got, "\n\n\n") {
			t.Errorf("name %q produced broken structure", name)
		}
		// every site label must be a clean <slug>.local
		for _, line := range strings.Split(got, "\n") {
			if strings.HasPrefix(line, "https://") && strings.HasSuffix(line, " {") {
				label := strings.TrimSuffix(strings.TrimPrefix(line, "https://"), " {")
				label = strings.TrimSuffix(label, ".local")
				for _, part := range strings.Split(label, ".") {
					if part == "" || strings.ContainsAny(part, "} {\";") {
						t.Errorf("unclean label from %q: %q", name, line)
					}
				}
			}
		}
	}
}

func TestRenderAliases(t *testing.T) {
	sites := map[string]Record{
		"plex":   {Domain: "plex.local", Service: "Plex", IP: "10.0.0.6", Port: 32400},
		"immich": {Domain: "immich.local", Service: "Immich", IP: "10.0.0.5", Port: 2283},
	}
	cfg := Config{BaseURL: "http://127.0.0.1:8008", Static: true}
	got := renderAliases(sites, cfg, "10.4.2.99", "horus")
	want := `# managed by ProxDnx (ProxDnx)
# all aliases point at the host so caddy can route by Host header
immich.local 10.4.2.99
plex.local 10.4.2.99
apps.horus.local 10.4.2.99
menux.local 10.4.2.99
proxmenux.local 10.4.2.99
menux.horus.local 10.4.2.99
`
	if got != want {
		t.Fatalf("aliases mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	for _, line := range strings.Split(got, "\n") {
		if line == "horus.local 10.4.2.99" {
			t.Error("bare <host>.local must never be published (avahi conflict rename)")
		}
	}
	if n := countAliases(got); n != 6 {
		t.Errorf("countAliases = %d, want 6", n)
	}

	off := renderAliases(sites, Config{Static: false}, "10.4.2.99", "horus")
	if strings.Contains(off, "menux") {
		t.Error("static off must drop static aliases")
	}
	if countAliases(off) != 3 {
		t.Errorf("static off: aliases = %d, want 3", countAliases(off))
	}
}

func TestFirstIPv4(t *testing.T) {
	out := "2: vmbr0    inet 10.4.2.99/24 scope global\n2: vmbr0    inet 10.4.2.99/24\n3: lo    inet 127.0.0.1/8 scope host\n4: vmbr0    inet6 fe80::1/64"
	if got := firstIPv4(out); got != "10.4.2.99" {
		t.Errorf("firstIPv4 = %q", got)
	}
	if got := firstIPv4("2: lo    inet 127.0.0.1/8\n"); got != "" {
		t.Errorf("loopback-only output must yield \"\", got %q", got)
	}
	// previously accepted junk addresses; must now be ParseIP-strict
	if got := firstIPv4("2: eth0    inet 999.1.1.1/24 scope global\n"); got != "" {
		t.Errorf("junk IPv4 must be rejected, got %q", got)
	}
	if got := firstIPv4("nothing here"); got != "" {
		t.Errorf("garbage must yield \"\", got %q", got)
	}
}

// TestHostIPLive exercises the real `ip` integration: loopback must never be
// published, missing interfaces must yield "".
func TestHostIPLive(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs the Linux `ip` command")
	}
	if got := hostIP("lo"); got != "" {
		t.Errorf("loopback must never be picked, got %q", got)
	}
	if got := hostIP("proxdnx-no-such-if"); got != "" {
		t.Errorf("missing iface must yield \"\", got %q", got)
	}
}

func TestWriteIfChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.conf")

	wrote, err := writeIfChanged(path, "one", 0o644)
	if err != nil || !wrote {
		t.Fatalf("first write: wrote=%v err=%v", wrote, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("perms: %v err=%v", fi.Mode().Perm(), err)
	}

	wrote, err = writeIfChanged(path, "one", 0o644)
	if err != nil || wrote {
		t.Fatalf("unchanged write must be skipped: wrote=%v err=%v", wrote, err)
	}

	wrote, err = writeIfChanged(path, "two", 0o600)
	if err != nil || !wrote {
		t.Fatalf("changed write: wrote=%v err=%v", wrote, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("perms not updated: %v", fi.Mode().Perm())
	}
	if body, _ := os.ReadFile(path); string(body) != "two" {
		t.Errorf("content: %q", body)
	}

	// no stray temp files left behind
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-proxdnx") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}

	// nested missing dir must fail cleanly, not create it
	if _, err := writeIfChanged(filepath.Join(dir, "no", "such", "f"), "x", 0o644); err == nil {
		t.Error("missing dir: expected error")
	}
}

func TestXMLesc(t *testing.T) {
	got := xmlEsc.Replace(`<a href="x">'&`)
	want := "&lt;a href=&quot;x&quot;&gt;&#39;&amp;"
	if got != want {
		t.Errorf("xmlEsc = %q, want %q", got, want)
	}
}

// TestPublisherScriptValidated guards the defense-in-depth filter that keeps
// avahi-publish away from names/IPs it should never see, even if the root-owned
// aliases file were tampered with.
func TestPublisherScriptValidated(t *testing.T) {
	for _, needle := range []string{`*[!a-z0-9.-]*`, `*[!0-9.]*`, `avahi-publish -a -R`} {
		if !strings.Contains(publisherBinSrc, needle) {
			t.Errorf("publisher script missing %q", needle)
		}
	}
}
