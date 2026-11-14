package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// configPath resolves the config file location: explicit --config wins, then
// $XDG_CONFIG_HOME, then ~/.config/proxdnx/config.yaml.
func configPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "proxdnx", "config.yaml"), nil
	}
	home := os.Getenv("HOME")
	if home == "" {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			home = u.HomeDir
		} else {
			return "", fmt.Errorf("cannot determine home directory (set HOME or --config)")
		}
	}
	return filepath.Join(home, ".config", "proxdnx", "config.yaml"), nil
}

// parseFlatYAML reads the flat "key: value" subset the app writes. Full-line
// comments and " # ... " trailing comments are ignored; quotes are stripped.
func parseFlatYAML(data string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			// quoted value: everything outside the quotes is decoration,
			// so inline comments inside quotes survive intact
			v = v[1 : len(v)-1]
		} else if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		m[k] = v
	}
	return m
}

func yamlValue(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " #:\"'") {
		return strconv.Quote(s)
	}
	return s
}

// loadConfig merges a config file into c; returns false if the file is absent.
func loadConfig(path string, c *Config) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	for k, v := range parseFlatYAML(string(data)) {
		switch k {
		case "url":
			c.BaseURL = v
		case "token":
			c.Token = v
		case "user":
			c.User = v
		case "password":
			c.Password = v
		case "totp":
			c.TOTP = v
		case "bridge":
			c.Bridge = v
		case "network":
			c.Network = v
		case "interval":
			d, err := time.ParseDuration(v)
			if err != nil {
				return true, fmt.Errorf("%s: bad duration %q: %v", k, v, err)
			}
			c.Interval = d
		case "caddy", "avahi", "http", "scan", "static", "force_https", "probe", "autofix":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return true, fmt.Errorf("%s: bad bool %q: %v", k, v, err)
			}
			switch k {
			case "caddy":
				c.Caddy = b
			case "avahi":
				c.Avahi = b
			case "http":
				c.HTTP = b
			case "static":
				c.Static = b
			case "force_https":
				c.ForceHTTPS = b
			case "probe":
				c.Probe = b
			case "autofix":
				c.AutoFix = b
			default:
				c.Scan = b
			}
		case "api_addr":
			c.APIAddr = v
		case "api_token":
			c.APIToken = v
		case "log_file":
			c.LogFile = v
		default:
			// unknown keys are tolerated so the file stays forward-compatible
		}
	}
	return true, nil
}

// saveConfig writes the effective config in a stable key order.
func saveConfig(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# proxdnx configuration (flat YAML subset; read+rewritten by proxdnx)\n")
	b.WriteString("# precedence: CLI flags > environment (PROXMENUX_*) > this file > built-in defaults\n")
	fmt.Fprintf(&b, "url: %s\n", yamlValue(c.BaseURL))
	fmt.Fprintf(&b, "token: %s\n", yamlValue(c.Token))
	fmt.Fprintf(&b, "user: %s\n", yamlValue(c.User))
	fmt.Fprintf(&b, "password: %s\n", yamlValue(c.Password))
	fmt.Fprintf(&b, "totp: %s\n", yamlValue(c.TOTP))
	fmt.Fprintf(&b, "bridge: %s\n", yamlValue(c.Bridge))
	fmt.Fprintf(&b, "network: %s\n", yamlValue(c.Network))
	fmt.Fprintf(&b, "interval: %s\n", c.Interval.String())
	fmt.Fprintf(&b, "caddy: %s\n", strconv.FormatBool(c.Caddy))
	fmt.Fprintf(&b, "avahi: %s\n", strconv.FormatBool(c.Avahi))
	fmt.Fprintf(&b, "http: %s\n", strconv.FormatBool(c.HTTP))
	fmt.Fprintf(&b, "static: %s\n", strconv.FormatBool(c.Static))
	fmt.Fprintf(&b, "force_https: %s\n", strconv.FormatBool(c.ForceHTTPS))
	fmt.Fprintf(&b, "probe: %s\n", strconv.FormatBool(c.Probe))
	fmt.Fprintf(&b, "autofix: %s\n", strconv.FormatBool(c.AutoFix))
	fmt.Fprintf(&b, "scan: %s\n", strconv.FormatBool(c.Scan))
	fmt.Fprintf(&b, "api_token: %s\n", yamlValue(c.APIToken))
	fmt.Fprintf(&b, "api_addr: %s\n", yamlValue(c.APIAddr))
	fmt.Fprintf(&b, "log_file: %s\n", yamlValue(c.LogFile))
	tmp := fmt.Sprintf("%s.tmp-proxdnx-%d", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// pid-unique O_EXCL temp + rename: this file holds the monitor token and
	// password — a symlink planted at the predictable legacy name must never
	// be followed (same hardening as writeIfChanged).
	return os.Rename(tmp, path)
}

// applyEnv overlays environment variables onto the config so a deployment
// can be fully driven without a config file (docker compose et al):
// PROXDNX_URL, PROXDNX_TOKEN, PROXDNX_USER, PROXDNX_PASSWORD, PROXDNX_TOTP,
// PROXDNX_BRIDGE, PROXDNX_NETWORK, PROXDNX_INTERVAL, PROXDNX_CADDY,
// PROXDNX_AVAHI, PROXDNX_HTTP, PROXDNX_STATIC, PROXDNX_FORCE_HTTPS,
// PROXDNX_PROBE, PROXDNX_AUTOFIX, PROXDNX_SCAN, PROXDNX_API_ADDR,
// PROXDNX_API_TOKEN, PROXDNX_LOG_FILE. The legacy PROXMENUX_* names stay as
// aliases (URL/TOKEN/USER/PASS/TOTP); PROXDNX_* wins when both are set.
// Malformed values fail startup instead of being silently ignored.
func applyEnv(c *Config) error {
	str := func(f func(*Config, string)) func(*Config, string) error {
		return func(c *Config, v string) error { f(c, v); return nil }
	}
	b := func(f func(*Config, bool)) func(*Config, string) error {
		return func(c *Config, v string) error {
			parsed, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("bad bool %q", v)
			}
			f(c, parsed)
			return nil
		}
	}
	bindings := []struct {
		key string
		set func(*Config, string) error
	}{
		{"PROXDNX_URL", str(func(c *Config, v string) { c.BaseURL = v })},
		{"PROXDNX_TOKEN", str(func(c *Config, v string) { c.Token = v })},
		{"PROXDNX_USER", str(func(c *Config, v string) { c.User = v })},
		{"PROXDNX_PASSWORD", str(func(c *Config, v string) { c.Password = v })},
		{"PROXDNX_TOTP", str(func(c *Config, v string) { c.TOTP = v })},
		{"PROXDNX_BRIDGE", str(func(c *Config, v string) { c.Bridge = v })},
		{"PROXDNX_NETWORK", str(func(c *Config, v string) { c.Network = v })},
		{"PROXDNX_INTERVAL", func(c *Config, v string) error {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return fmt.Errorf("bad duration %q", v)
			}
			c.Interval = d
			return nil
		}},
		{"PROXDNX_CADDY", b(func(c *Config, v bool) { c.Caddy = v })},
		{"PROXDNX_AVAHI", b(func(c *Config, v bool) { c.Avahi = v })},
		{"PROXDNX_HTTP", b(func(c *Config, v bool) { c.HTTP = v })},
		{"PROXDNX_STATIC", b(func(c *Config, v bool) { c.Static = v })},
		{"PROXDNX_FORCE_HTTPS", b(func(c *Config, v bool) { c.ForceHTTPS = v })},
		{"PROXDNX_PROBE", b(func(c *Config, v bool) { c.Probe = v })},
		{"PROXDNX_AUTOFIX", b(func(c *Config, v bool) { c.AutoFix = v })},
		{"PROXDNX_SCAN", b(func(c *Config, v bool) { c.Scan = v })},
		{"PROXDNX_API_ADDR", str(func(c *Config, v string) { c.APIAddr = v })},
		{"PROXDNX_API_TOKEN", str(func(c *Config, v string) { c.APIToken = v })},
		{"PROXDNX_LOG_FILE", str(func(c *Config, v string) { c.LogFile = v })},
	}
	// legacy aliases first: the PROXDNX_* bindings below override on conflict
	for k, set := range map[string]func(string){
		"PROXMENUX_URL":   func(v string) { c.BaseURL = v },
		"PROXMENUX_TOKEN": func(v string) { c.Token = v },
		"PROXMENUX_USER":  func(v string) { c.User = v },
		"PROXMENUX_PASS":  func(v string) { c.Password = v },
		"PROXMENUX_TOTP":  func(v string) { c.TOTP = v },
	} {
		if v := os.Getenv(k); v != "" {
			set(v)
		}
	}
	for _, bd := range bindings {
		if v := os.Getenv(bd.key); v != "" {
			if err := bd.set(c, v); err != nil {
				return fmt.Errorf("%s: %v", bd.key, err)
			}
		}
	}
	return nil
}
