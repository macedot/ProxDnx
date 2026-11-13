// ProxDnx — ProxMenux-driven *.local publisher.
// Queries the ProxMenux monitor API for running LXC guests, derives
// name/ip/port records, renders the Caddyfile and avahi service files,
// publishes <slug>.local A records via avahi-publish, and exposes a small
// HTTP API reporting every domain published.
//
// Configuration lives in ~/.config/proxdnx/config.yaml (flat YAML subset,
// read + bootstrapped by the app). Precedence: CLI flags > environment
// (PROXMENUX_*) > config file > built-in defaults.
//
// Zero external dependencies: Go stdlib only.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultAPIAddr  = "127.0.0.1:9973"
	defaultLogFile  = "/var/log/proxdnx/proxdnx.log"
	defaultBaseURL  = "http://127.0.0.1:8008"
	defaultInterval = 60 * time.Second
	defaultPVEPort  = 8006 // Proxmox VE web UI (pveproxy), proxied at https://127.0.0.1:<port>
	managedBy       = "managed by ProxDnx"
	// detection prefix: matches legacy "managed by proxdns" markers too
	managedByPrefix  = "managed by proxdn"
	caddyfile        = "/etc/caddy/Caddyfile"
	avahiServicesDir = "/etc/avahi/services"
	avahiAliases     = "/etc/avahi/proxdnx-aliases.conf"
	publisherBin     = "/usr/local/bin/proxdnx-mdns-publish"
	publisherUnit    = "/etc/systemd/system/proxdnx-mdns.service"
)

type Config struct {
	BaseURL    string
	Token      string
	User       string
	Password   string
	TOTP       string
	Bridge     string
	Network    string
	Interval   time.Duration
	Caddy      bool
	Avahi      bool
	HTTP       bool // serve plain http:// alongside https:// (no redirect)
	Static     bool // static infra entries: <host>.local -> Proxmox UI, menux*.local -> ProxMenux (proxied)
	ForceHTTPS bool // portal always generates https:// links, regardless of access protocol
	Probe      bool // TCP-probe each candidate port; drop records whose port is closed
	Scan       bool
	APIAddr    string
	LogFile    string
	Path       string // resolved config file path

	created bool // config file was bootstrapped this run
}

func defaultConfig() Config {
	return Config{
		BaseURL:    defaultBaseURL,
		Bridge:     "vmbr0",
		Interval:   defaultInterval,
		HTTP:       true,
		Static:     true,
		ForceHTTPS: false,
		Probe:      true,
		APIAddr:    defaultAPIAddr,
		LogFile:    defaultLogFile,
	}
}

// CycleStats summarizes the last run.
type CycleStats struct {
	At         time.Time `json:"at"`
	Kept       int       `json:"kept"`
	Added      int       `json:"added"`
	Removed    int       `json:"removed"`
	Changed    int       `json:"changed"`
	Total      int       `json:"total"`
	DurationMS int64     `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
}

type App struct {
	cfg    Config
	client *Client
	log    *log.Logger

	mu      sync.Mutex
	domains []Record
	stats   CycleStats
}

// execCommand runs a command and returns combined output.
func execCommand(argv []string) (string, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// run returns an error carrying stderr when the command fails.
func run(argv ...string) error {
	out, err := execCommand(argv)
	if err != nil {
		if s := strings.TrimSpace(out); s != "" {
			return fmt.Errorf("%v: %s", err, s)
		}
		return err
	}
	return nil
}

func setupLogging(path string) *log.Logger {
	writers := []io.Writer{os.Stdout}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err == nil {
			if fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
				writers = append(writers, fh)
			} else {
				fmt.Fprintf(os.Stderr, "proxdnx: cannot open log file %s: %v (stdout only)\n", path, err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "proxdnx: cannot create log dir: %v (stdout only)\n", err)
		}
	}
	return log.New(io.MultiWriter(writers...), "", log.LstdFlags)
}

// validIface allows only sane Linux interface names (kernel limit: 15 bytes).
// The value ends up as an argv element of `ip ... show dev <name>`; exec does
// not invoke a shell, but rejecting garbage early keeps the command clean.
func validIface(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// validate fast-fails an effective config before anything is written or any
// cycle runs. Every field here is operator-controlled; bad values should
// refuse startup instead of producing broken renders mid-cycle.
func (c Config) validate() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url: must be an http(s) URL with a host (got %q)", c.BaseURL)
	}
	if !validIface(c.Bridge) {
		return fmt.Errorf("bridge: invalid interface name %q", c.Bridge)
	}
	if c.Network != "" {
		if _, _, err := net.ParseCIDR(c.Network); err != nil {
			return fmt.Errorf("network: %v", err)
		}
	}
	if _, _, err := net.SplitHostPort(c.APIAddr); err != nil {
		return fmt.Errorf("api_addr: %v", err)
	}
	return nil
}

func loadEffectiveConfig() (Config, error) {
	c := defaultConfig()

	var fConfig, fURL, fToken, fUser, fPass, fTOTP, fBridge, fNetwork, fInterval, fAPI, fLog string
	var fCaddy, fAvahi, fHTTP, fScan, fOnce, fStatic, fForceHTTPS, fProbe bool
	fs := flag.NewFlagSet("proxdnx", flag.ContinueOnError)
	fs.StringVar(&fConfig, "config", "", "config file path (default ~/.config/proxdnx/config.yaml)")
	fs.StringVar(&fURL, "url", "", "ProxMenux monitor base URL (env PROXMENUX_URL)")
	fs.StringVar(&fToken, "token", "", "Bearer token (env PROXMENUX_TOKEN)")
	fs.StringVar(&fUser, "user", "", "ProxMenux user (env PROXMENUX_USER)")
	fs.StringVar(&fPass, "password", "", "ProxMenux password (env PROXMENUX_PASS)")
	fs.StringVar(&fTOTP, "totp", "", "2FA code (env PROXMENUX_TOTP)")
	fs.StringVar(&fBridge, "bridge", "", "host bridge whose subnet guests are matched against (default vmbr0)")
	fs.StringVar(&fNetwork, "network", "", "explicit CIDR override, e.g. 10.4.2.0/24")
	fs.StringVar(&fInterval, "interval", "", "update interval (default 60s)")
	fs.BoolVar(&fCaddy, "caddy", false, "render and reload /etc/caddy/Caddyfile")
	fs.BoolVar(&fAvahi, "avahi", false, "render avahi service files + publish *.local A records")
	fs.BoolVar(&fHTTP, "http", false, "serve plain http:// alongside https:// (default: config/http, on)")
	fs.BoolVar(&fStatic, "static", false, "static infra entries: <host>.local -> Proxmox UI, menux*.local -> ProxMenux (proxied, no port in the URL) (default: config/static, on)")
	fs.BoolVar(&fForceHTTPS, "force-https", false, "portal always generates https:// links regardless of access protocol (default: config/force_https, off)")
	fs.BoolVar(&fProbe, "probe", false, "tcp-probe each candidate port and drop closed ones (default: config/probe, on)")
	fs.BoolVar(&fScan, "scan", false, "force fresh docker/native discovery scans (POST) each cycle")
	fs.StringVar(&fAPI, "api-addr", "", "HTTP API listen address (default 127.0.0.1:9973)")
	fs.StringVar(&fLog, "log-file", "", "log file (default /var/log/proxdnx/proxdnx.log)")
	fs.BoolVar(&fOnce, "once", false, "run a single cycle and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return c, err
	}

	path, err := configPath(fConfig)
	if err != nil {
		return c, err
	}
	c.Path = path
	found, err := loadConfig(path, &c)
	if err != nil {
		return c, fmt.Errorf("%s: %v", path, err)
	}
	applyEnv(&c)

	once := fOnce
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "url":
			c.BaseURL = fURL
		case "token":
			c.Token = fToken
		case "user":
			c.User = fUser
		case "password":
			c.Password = fPass
		case "totp":
			c.TOTP = fTOTP
		case "bridge":
			c.Bridge = fBridge
		case "network":
			c.Network = fNetwork
		case "interval":
			d, err := time.ParseDuration(fInterval)
			if err != nil || d <= 0 {
				err = fmt.Errorf("invalid --interval %q", fInterval)
			}
			_ = err
			if d > 0 {
				c.Interval = d
			}
		case "caddy":
			c.Caddy = fCaddy
		case "http":
			c.HTTP = fHTTP
		case "static":
			c.Static = fStatic
		case "force-https":
			c.ForceHTTPS = fForceHTTPS
		case "probe":
			c.Probe = fProbe
		case "avahi":
			c.Avahi = fAvahi
		case "scan":
			c.Scan = fScan
		case "api-addr":
			c.APIAddr = fAPI
		case "log-file":
			c.LogFile = fLog
		}
	})
	_ = once

	if err := c.validate(); err != nil {
		return c, err
	}

	if !found {
		// bootstrap the file with pure defaults so operators have a knob to edit
		def := defaultConfig()
		def.Path = path
		if err := saveConfig(path, &def); err != nil {
			return c, fmt.Errorf("cannot bootstrap config %s: %v", path, err)
		}
		c.created = true
	}
	return c, nil
}

// secureHeaders wraps every API/portal response: the API serves untrusted-ish
// JSON and an HTML dashboard on a LAN port, so forbid MIME sniffing and any
// caching of domain inventories.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// routes builds the API handler tree. Separated from serveAPI so tests can
// exercise it with httptest without binding a socket.
func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, portalHTML(a.cfg.ForceHTTPS))
	})
	mux.HandleFunc("GET /api/domains", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":      len(a.domains),
			"updated_at": a.stats.At,
			"domains":    a.domains,
		})
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"interval_seconds": a.cfg.Interval.Seconds(),
			"caddy":            a.cfg.Caddy,
			"avahi":            a.cfg.Avahi,
			"static":           a.cfg.Static,
			"force_https":      a.cfg.ForceHTTPS,
			"config":           a.cfg.Path,
			"last_cycle":       a.stats,
		})
	})
	mux.HandleFunc("GET /api/static", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		cfg := a.cfg
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled": cfg.Static,
			"routes":  staticRoutes(hostLabel(), cfg.BaseURL),
		})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	})
	a.log.Printf("api: listening on http://%s (GET /api/domains, /api/static, /api/status, /healthz)", a.cfg.APIAddr)
	return secureHeaders(mux)
}

// serveAPI runs the API server with explicit timeouts — a bare
// ListenAndServe has no ReadHeaderTimeout and is trivially slowloris-able.
func (a *App) serveAPI() error {
	srv := &http.Server{
		Addr:              a.cfg.APIAddr,
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	return srv.ListenAndServe()
}

// requireActive mirrors the CLI contract: the writer flags assert that the
// backing service must be running.
func requireActive(unit string) error {
	if err := run("systemctl", "is-active", "--quiet", unit); err != nil {
		return fmt.Errorf("%s: not running (systemctl start %s first)", unit, unit)
	}
	return nil
}

func (a *App) cycle(ctx context.Context) error {
	start := time.Now()
	recs, err := a.client.fetchRecords(a.cfg, a.log.Printf)
	if err != nil {
		a.setStats(CycleStats{At: start, Error: err.Error()})
		return err
	}

	cur := make(map[string]Record, len(recs))
	for _, r := range recs {
		cur[r.Domain] = r
	}
	a.mu.Lock()
	prev := make(map[string]Record, len(a.domains))
	for _, r := range a.domains {
		prev[r.Domain] = r
	}
	a.mu.Unlock()

	var kept, added, removed, changed []string
	for d, r := range cur {
		p, ok := prev[d]
		if !ok {
			added = append(added, d)
			continue
		}
		if p.IP == r.IP && p.Port == r.Port {
			kept = append(kept, d)
		} else {
			changed = append(changed, d)
		}
	}
	for d := range prev {
		if _, ok := cur[d]; !ok {
			removed = append(removed, d)
		}
	}

	// render + apply; a writer failure is logged, not fatal — the daemon and
	// API keep serving the last known good state. Stale records stay on the
	// portal (tagged) but are not published into caddy/avahi.
	publish := make([]Record, 0, len(recs))
	for _, r := range recs {
		if publishable(r) {
			publish = append(publish, r)
		}
	}
	if a.cfg.Caddy {
		if err := applyCaddy(a.log, publish, a.cfg); err != nil {
			a.log.Printf("caddy: apply failed: %v", err)
		}
	}
	if a.cfg.Avahi {
		if err := applyAvahi(a.log, publish, a.cfg); err != nil {
			a.log.Printf("avahi: apply failed: %v", err)
		}
	}

	stats := CycleStats{
		At: start, Kept: len(kept), Added: len(added),
		Removed: len(removed), Changed: len(changed), Total: len(cur),
		DurationMS: time.Since(start).Milliseconds(),
	}
	sortStrings(added)
	sortStrings(removed)
	sortStrings(changed)
	for _, d := range added {
		a.log.Printf("added %s -> %s:%d (%s)", d, cur[d].IP, cur[d].Port, cur[d].Service)
	}
	for _, d := range removed {
		a.log.Printf("removed %s (was %s:%d)", d, prev[d].IP, prev[d].Port)
	}
	for _, d := range changed {
		a.log.Printf("changed %s (%s:%d -> %s:%d)", d, prev[d].IP, prev[d].Port, cur[d].IP, cur[d].Port)
	}
	a.log.Printf("cycle done: kept=%d added=%d removed=%d changed=%d total=%d in %s",
		stats.Kept, stats.Added, stats.Removed, stats.Changed, stats.Total,
		time.Since(start).Round(time.Millisecond))

	a.mu.Lock()
	a.domains = recs
	a.stats = stats
	a.mu.Unlock()
	return nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func (a *App) setStats(s CycleStats) {
	a.mu.Lock()
	a.stats = s
	a.mu.Unlock()
}

func main() {
	cfg, err := loadEffectiveConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxdnx: %v\n", err)
		os.Exit(2)
	}
	logger := setupLogging(cfg.LogFile)
	if cfg.created {
		logger.Printf("config: bootstrapped %s with defaults (edit and restart to apply)", cfg.Path)
	}
	logger.Printf("proxdnx starting: config=%s url=%s bridge=%s network=%q interval=%s caddy=%v avahi=%v http=%v static=%v force_https=%v probe=%v",
		cfg.Path, cfg.BaseURL, cfg.Bridge, cfg.Network, cfg.Interval, cfg.Caddy, cfg.Avahi, cfg.HTTP, cfg.Static, cfg.ForceHTTPS, cfg.Probe)

	if cfg.Caddy {
		if err := requireActive("caddy"); err != nil {
			fatalf("%v", err)
		}
	}
	if cfg.Avahi {
		if err := requireActive("avahi-daemon"); err != nil {
			fatalf("%v", err)
		}
	}

	app := &App{cfg: cfg, client: NewClient(cfg), log: logger}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	apiErr := make(chan error, 1)
	go func() {
		if err := app.serveAPI(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			apiErr <- err
		}
	}()

	if err := app.cycle(ctx); err != nil {
		logger.Printf("initial cycle failed: %v", err)
	}
	if once := hasOnceFlag(); once {
		return
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Printf("shutting down")
			return
		case err := <-apiErr:
			logger.Printf("api server failed: %v", err)
			return
		case <-ticker.C:
			if err := app.cycle(ctx); err != nil {
				logger.Printf("cycle failed: %v", err)
			}
		}
	}
}

func hasOnceFlag() bool {
	for _, a := range os.Args[1:] {
		if a == "-once" || a == "--once" {
			return true
		}
	}
	return false
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "proxdnx: "+format+"\n", args...)
	os.Exit(2)
}
