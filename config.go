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
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
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
		case "caddy", "avahi", "scan":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return true, fmt.Errorf("%s: bad bool %q: %v", k, v, err)
			}
			if k == "caddy" {
				c.Caddy = b
			} else if k == "avahi" {
				c.Avahi = b
			} else {
				c.Scan = b
			}
		case "api_addr":
			c.APIAddr = v
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
	b.WriteString("# proxdns configuration (flat YAML subset; read+rewritten by proxdns)\n")
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
	fmt.Fprintf(&b, "scan: %s\n", strconv.FormatBool(c.Scan))
	fmt.Fprintf(&b, "api_addr: %s\n", yamlValue(c.APIAddr))
	fmt.Fprintf(&b, "log_file: %s\n", yamlValue(c.LogFile))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// applyEnv overlays PROXMENUX_* / PROXDNS_* environment variables.
func applyEnv(c *Config) {
	if v := os.Getenv("PROXMENUX_URL"); v != "" {
		c.BaseURL = v
	}
	if v := os.Getenv("PROXMENUX_TOKEN"); v != "" {
		c.Token = v
	}
	if v := os.Getenv("PROXMENUX_USER"); v != "" {
		c.User = v
	}
	if v := os.Getenv("PROXMENUX_PASS"); v != "" {
		c.Password = v
	}
	if v := os.Getenv("PROXMENUX_TOTP"); v != "" {
		c.TOTP = v
	}
	if v := os.Getenv("PROXDNS_NETWORK"); v != "" {
		c.Network = v
	}
}
