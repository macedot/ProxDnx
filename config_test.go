package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseFlatYAML(t *testing.T) {
	in := strings.Join([]string{
		"# full-line comment",
		"url: http://127.0.0.1:8008   # trailing comment",
		`token: "abc def"`,
		"user: 'quoted'",
		"password:",
		"interval: 90s",
		"caddy: false",
		"",
		"garbage line without colon",
	}, "\n")
	got := parseFlatYAML(in)
	cases := map[string]string{
		"url":      "http://127.0.0.1:8008",
		"token":    "abc def",
		"user":     "quoted",
		"password": "",
		"interval": "90s",
		"caddy":    "false",
	}
	for k, want := range cases {
		if got[k] != want {
			t.Errorf("key %q: got %q, want %q", k, got[k], want)
		}
	}
	if _, ok := got["garbage line without colon"]; ok {
		t.Error("colon-less line should be skipped")
	}
	if _, ok := got["# full-line comment"]; ok {
		t.Error("comment should be skipped")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if found, err := loadConfig(filepath.Join(dir, "missing.yaml"), &Config{}); found || err != nil {
		t.Fatalf("missing file: found=%v err=%v", found, err)
	}

	body := strings.Join([]string{
		"url: http://10.0.0.1:8008",
		"bridge: vmbr1",
		"network: 10.4.2.0/24",
		"interval: 90s",
		"caddy: false",
		"avahi: true",
		"http: false",
		"static: false",
		"force_https: true",
		"probe: true",
		"scan: true",
		"api_addr: 127.0.0.1:1234",
		"log_file: /tmp/x.log",
		"unknown_key: tolerated",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c := defaultConfig()
	found, err := loadConfig(path, &c)
	if err != nil || !found {
		t.Fatalf("loadConfig: found=%v err=%v", found, err)
	}
	if c.BaseURL != "http://10.0.0.1:8008" || c.Bridge != "vmbr1" || c.Network != "10.4.2.0/24" {
		t.Errorf("strings not merged: %+v", c)
	}
	if c.Interval != 90*time.Second {
		t.Errorf("interval: got %v", c.Interval)
	}
	if c.Caddy || !c.Avahi || c.HTTP || c.Static || !c.ForceHTTPS || !c.Probe || !c.Scan {
		t.Errorf("bools not merged: %+v", c)
	}
	if c.APIAddr != "127.0.0.1:1234" || c.LogFile != "/tmp/x.log" {
		t.Errorf("addrs not merged: %+v", c)
	}

	for _, bad := range []string{"interval: notaduration", "caddy: notabool"} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		c := defaultConfig()
		if _, err := loadConfig(path, &c); err == nil {
			t.Errorf("%q: expected error, got nil", bad)
		}
	}
}

func TestSaveConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	want := Config{
		BaseURL: "http://10.0.0.9:8008", Token: "tok", User: "u", Password: "p@ss #x",
		TOTP: "123", Bridge: "vmbr9", Network: "10.0.0.0/24", Interval: 90 * time.Second,
		Caddy: true, Avahi: false, HTTP: false, Static: false, ForceHTTPS: true, Probe: true, Scan: true,
		APIAddr: "127.0.0.1:1234", LogFile: "/tmp/log",
	}
	if err := saveConfig(path, &want); err != nil {
		t.Fatal(err)
	}
	// config holds credentials: must never be group/world readable
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config perms: %v (err=%v)", fi.Mode().Perm(), err)
	}
	var got Config
	found, err := loadConfig(path, &got)
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	got.Path = want.Path
	if got != want {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestApplyEnv(t *testing.T) {
	t.Setenv("PROXMENUX_URL", "http://env:8008")
	t.Setenv("PROXMENUX_TOKEN", "envtok")
	t.Setenv("PROXMENUX_USER", "envuser")
	t.Setenv("PROXMENUX_PASS", "envpass")
	t.Setenv("PROXMENUX_TOTP", "000000")
	t.Setenv("PROXDNX_NETWORK", "10.9.9.0/24")
	c := defaultConfig()
	applyEnv(&c)
	if c.BaseURL != "http://env:8008" || c.Token != "envtok" || c.User != "envuser" ||
		c.Password != "envpass" || c.TOTP != "000000" || c.Network != "10.9.9.0/24" {
		t.Errorf("env not applied: %+v", c)
	}
}

func TestConfigPath(t *testing.T) {
	if got, _ := configPath("/explicit.yaml"); got != "/explicit.yaml" {
		t.Errorf("explicit: %q", got)
	}
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if got, _ := configPath(""); got != filepath.Join("/xdg", "proxdnx", "config.yaml") {
		t.Errorf("xdg: %q", got)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/x")
	if got, _ := configPath(""); got != filepath.Join("/home/x", ".config", "proxdnx", "config.yaml") {
		t.Errorf("home: %q", got)
	}
}

func TestValidate(t *testing.T) {
	good := defaultConfig()
	if err := good.validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"url bad scheme", func(c *Config) { c.BaseURL = "ftp://x:8008" }},
		{"url no scheme", func(c *Config) { c.BaseURL = "127.0.0.1:8008" }},
		{"url no host", func(c *Config) { c.BaseURL = "http://" }},
		{"bridge empty", func(c *Config) { c.Bridge = "" }},
		{"bridge spaces", func(c *Config) { c.Bridge = "vmbr 0" }},
		{"bridge shell chars", func(c *Config) { c.Bridge = "vmbr0;reboot" }},
		{"bridge too long", func(c *Config) { c.Bridge = "abcdefghijklmnopqrst" }},
		{"network bad cidr", func(c *Config) { c.Network = "10.0.0.0/99" }},
		{"api_addr no port", func(c *Config) { c.APIAddr = "127.0.0.1" }},
	}
	for _, tc := range cases {
		c := defaultConfig()
		tc.mut(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
	// valid values that must pass
	ok := defaultConfig()
	ok.Network = "10.4.2.0/24"
	ok.Bridge = "vmbr0"
	ok.APIAddr = "127.0.0.1:9973"
	ok.ForceHTTPS = true
	if err := ok.validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestValidIface(t *testing.T) {
	for _, s := range []string{"vmbr0", "eth0.100", "enp3s0", "a", "bridge_1", "x-y.z"} {
		if !validIface(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"", "vmbr 0", "a;b", "abc$def", "sixteen-char-ok-no"} {
		if validIface(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}
