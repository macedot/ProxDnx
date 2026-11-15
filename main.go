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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	AutoFix    bool // correct stale/mismatched ProxMenux registrations via its API
	Scan       bool
	APIToken   string // require this token on API/portal requests ("" = open)
	APIAddr    string

	CloudflareToken    string   // Cloudflare API token; "" = tunnel sync off
	CloudflareZone     string   // public zone (e.g. example.com)
	CloudflareTunnelID string   // tunnel UUID; "" = auto-discover the first non-deleted tunnel
	CloudflarePrune    bool     // prune managed DNS records/ingress that are no longer published
	CloudflareOnly     []string // allowlist: only these slugs get public routes (empty = every app)
	LogFile            string
	Path               string // resolved config file path

	created bool // config file was bootstrapped this run
	once    bool // -once: run a single cycle and exit
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
		AutoFix:    false,
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

	mu        sync.Mutex
	domains   []Record
	stats     CycleStats
	cf        CloudflareStatus
	names     map[string]string // slug -> renamed slug (user-edited URLs)
	namesPath string
	cycleBusy atomic.Bool

	sessions map[string]time.Time // cookie session id -> expiry
	sessMu   sync.Mutex
}

// nameRe is the charset a user-edited slug may use: a valid DNS label.
var nameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// loadNames reads the user-edited name overrides (names.json next to the
// config file). Missing or corrupt file = no overrides.
func loadNames(path string) map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	_ = json.Unmarshal(b, &m)
	out := map[string]string{}
	for k, v := range m {
		k = strings.ToLower(strings.TrimSpace(k))
		v = normalizeName(v)
		if k != "" && v != "" && nameRe.MatchString(v) && nameRe.MatchString(k) {
			out[k] = v
		}
	}
	return out
}

// saveNames persists the overrides atomically (writeIfChanged: skips when
// unchanged, pid-unique temp otherwise).
func saveNames(path string, names map[string]string) error {
	b, err := json.MarshalIndent(names, "", "  ")
	if err != nil {
		return err
	}
	_, err = writeIfChanged(path, string(b)+"\n", 0o600)
	return err
}

// normalizeName cleans a user-provided label: lower-case, whitespace and a
// trailing ".local" stripped, trimmed of separator chars.
func normalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".local")
	return strings.Trim(s, "-._ ")
}

// applyNameOverrides rewrites each record's published slug/domain according
// to the override map. The service name is never touched.
func applyNameOverrides(recs []Record, names map[string]string) {
	for i := range recs {
		r := &recs[i]
		if r.Slug == "" {
			r.Slug = slugify(r.Service)
		}
		r.effSlug = r.Slug
		if n, ok := names[r.Slug]; ok && n != "" {
			r.effSlug = n
		}
		r.Domain = r.effSlug + ".local"
	}
}

// validRename checks a rename against the current record set: the key must
// be a known slug, the new name a valid label, and it must not collide with
// another app's slug or a reserved static-infrastructure name (a colliding
// site would fail `caddy validate` and break publication for every app).
// Returns an HTTP status + message.
func validRename(recs []Record, names map[string]string, slug, name string, reserved map[string]bool) (int, string) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	name = normalizeName(name)
	if slug == "" {
		return http.StatusBadRequest, "missing slug"
	}
	if !nameRe.MatchString(name) {
		return http.StatusBadRequest, "invalid name: use letters, digits and dashes"
	}
	if reserved[name] {
		return http.StatusConflict, "name reserved for static infrastructure: " + name
	}
	known := false
	for _, r := range recs {
		if r.Slug == slug {
			known = true
			continue
		}
		if r.Slug == name || r.effSlug == name {
			return http.StatusConflict, "name already used by " + r.Domain
		}
	}
	if v, ok := names[slug]; ok && v == name {
		return http.StatusBadRequest, "no change"
	}
	for k, v := range names {
		if k != slug && v == name {
			return http.StatusConflict, "name already used by an override"
		}
	}
	if !known {
		return http.StatusNotFound, "unknown slug: " + slug
	}
	return 0, name
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

// setupLogging opens the log file root-only: the startup log carries the
// generated api_token, so a world-readable 0644 file would leak it to every
// local account (an existing wider-mode file is tightened too).
func setupLogging(path string) *log.Logger {
	writers := []io.Writer{os.Stdout}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err == nil {
			if fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
				_ = os.Chmod(path, 0o600)
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
	// time.NewTicker panics on non-positive intervals: a config typo like
	// "interval: 0s" must refuse startup instead of crash-looping.
	if c.Interval <= 0 {
		return fmt.Errorf("interval: must be positive (got %s)", c.Interval)
	}
	// Cloudflare tunnel sync publishes <name>.<zone>: a zone is required
	// when the provider is on.
	if c.CloudflareToken != "" && strings.Trim(strings.TrimRight(c.CloudflareZone, "."), ".") == "" {
		return fmt.Errorf("cloudflare_zone: required when cloudflare_token is set (apps publish <name>.<zone>)")
	}
	if c.CloudflareToken != "" {
		// the portal becomes apps.<host>.<zone> — publicly reachable, so an
		// open API must refuse to start rather than publish the inventory.
		if c.APIToken == apiTokenOff {
			return fmt.Errorf("api_token: %q refuses to start when cloudflare is enabled — apps.<host>.%s would be a public, open dashboard", apiTokenOff, c.CloudflareZone)
		}
		// tunnel ingress routes public names to caddy's plain-http twin
		// (cfIngressTarget hardcodes :80): without it every public route 404s.
		if !c.HTTP {
			return fmt.Errorf("http: must be true when cloudflare is set — public names route to caddy's plain-http twin on :80")
		}
		if c.CloudflareTunnelID != "" && !tunnelIDRe.MatchString(c.CloudflareTunnelID) {
			return fmt.Errorf("cloudflare_tunnel_id: not a tunnel UUID (%q)", c.CloudflareTunnelID)
		}
		for _, s := range c.CloudflareOnly {
			if !nameRe.MatchString(s) {
				return fmt.Errorf("cloudflare_only: invalid slug %q (letters, digits and dashes only)", s)
			}
		}
	}
	return nil
}

func loadEffectiveConfig() (Config, error) {
	c := defaultConfig()

	var fConfig, fURL, fToken, fUser, fPass, fTOTP, fBridge, fNetwork, fInterval, fAPI, fAPIToken, fLog string
	var fCaddy, fAvahi, fHTTP, fScan, fOnce, fVersion, fStatic, fForceHTTPS, fProbe, fAutoFix bool
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
	fs.BoolVar(&fAutoFix, "autofix", false, "correct stale/mismatched ProxMenux registrations via its API (default: config/autofix, off; requires probe)")
	fs.BoolVar(&fScan, "scan", false, "force fresh docker/native discovery scans (POST) each cycle")
	fs.StringVar(&fAPI, "api-addr", "", "HTTP API listen address (default 127.0.0.1:9973)")
	fs.StringVar(&fAPIToken, "api-token", "", "require this token on API/portal requests: browsers log in via the form (session cookie), API clients send Authorization: Bearer or X-API-Token (env PROXDNX_API_TOKEN)")
	fs.StringVar(&fLog, "log-file", "", "log file (default /var/log/proxdnx/proxdnx.log)")
	fs.BoolVar(&fOnce, "once", false, "run a single cycle and exit")
	fs.BoolVar(&fVersion, "version", false, "print version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return c, err
	}
	if fVersion {
		fmt.Println("proxdnx " + version)
		os.Exit(0)
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
	if err := applyEnv(&c); err != nil {
		return c, err
	}

	once := fOnce
	var flagErr error
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
				flagErr = fmt.Errorf("invalid --interval %q", fInterval)
				return
			}
			c.Interval = d
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
		case "autofix":
			c.AutoFix = fAutoFix
		case "avahi":
			c.Avahi = fAvahi
		case "scan":
			c.Scan = fScan
		case "api-addr":
			c.APIAddr = fAPI
		case "api-token":
			c.APIToken = fAPIToken
		case "log-file":
			c.LogFile = fLog
		}
	})
	c.once = once
	if flagErr != nil {
		return c, flagErr
	}

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
// caching of domain inventories, and pin the dashboard down (no framing, no
// external content).
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		// form-action 'self': the token login form POSTs to /api/login —
		// 'none' would block that submission in every CSP-enforcing browser
		// and leave users no way in except disabling auth.
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// sessionCookieName / sessionTTL: browser sessions issued by POST
// /api/login after a correct api_token. HttpOnly — the token itself never
// touches a URL, and JS can't read the cookie.
const (
	sessionCookieName = "pndx_session"
	sessionTTL        = 30 * 24 * time.Hour
)

// newSession issues a fresh session id and prunes expired ones.
func (a *App) newSession() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	if a.sessions == nil {
		a.sessions = map[string]time.Time{}
	}
	now := time.Now()
	for sid, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, sid)
		}
	}
	a.sessions[id] = now.Add(sessionTTL)
	return id, nil
}

// validSession reports whether a session id is live, sliding its expiry.
func (a *App) validSession(id string) bool {
	if id == "" {
		return false
	}
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	exp, ok := a.sessions[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(a.sessions, id)
		return false
	}
	a.sessions[id] = time.Now().Add(sessionTTL)
	return true
}

// requireToken enforces the optional api_token. Browsers log in once via
// the form (POST /api/login) and keep an HttpOnly session cookie — the
// token never travels in a URL. API clients present Authorization: Bearer
// or X-API-Token. /healthz and the login endpoint itself stay open.
// Compare is constant-time; an empty configured token disables auth.
func (a *App) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginPath := r.URL.Path == "/api/login" && r.Method == http.MethodPost
		if a.cfg.APIToken != "" && r.URL.Path != "/healthz" && !loginPath && !a.authorized(r) {
			if r.URL.Path == "/" && strings.Contains(r.Header.Get("Accept"), "text/html") {
				// browser: serve the token form instead of raw JSON
				form := authFormHTML
				if r.URL.Query().Get("failed") == "1" {
					form = strings.Replace(form, "__LOGIN_FAILED__", `<p class="err">wrong token — try again</p>`, 1)
				} else {
					form = strings.Replace(form, "__LOGIN_FAILED__", "", 1)
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, form)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"unauthorized: log in at / or present api_token via Authorization: Bearer or X-API-Token"}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tokenEqual compares two secrets without leaking their lengths: hashing
// both sides first makes the constant-time compare operate on fixed-size
// digests no matter what was submitted.
func tokenEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// authorized validates the session cookie, falling back to the header
// channels for API clients.
func (a *App) authorized(r *http.Request) bool {
	if c, err := r.Cookie(sessionCookieName); err == nil && a.validSession(c.Value) {
		return true
	}
	tok := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok = strings.TrimPrefix(h, "Bearer ")
	}
	if tok == "" {
		tok = r.Header.Get("X-API-Token")
	}
	return tokenEqual(tok, a.cfg.APIToken)
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
			"auth":             a.cfg.APIToken != "",
			"version":          version,
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
			"routes":  staticRoutes(hostLabel(), hostIP(cfg.Bridge), cfg),
		})
	})
	mux.HandleFunc("GET /api/cloudflare", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		st := a.cf
		domains := a.domains
		cfg := a.cfg
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !cfEnabled(cfg) {
			_ = json.NewEncoder(w).Encode(map[string]any{"enabled": false})
			return
		}
		type route struct {
			Hostname string `json:"hostname"`
			URL      string `json:"url"`
		}
		names := cfPublicNames(dedupeSites(domains), cfg)
		routes := make([]route, 0, len(names))
		for _, n := range names {
			routes = append(routes, route{Hostname: n, URL: "https://" + n})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled":   true,
			"zone":      strings.Trim(strings.TrimRight(cfg.CloudflareZone, "."), "."),
			"count":     len(routes),
			"routes":    routes,
			"last_sync": st,
		})
	})
	mux.HandleFunc("POST /api/names", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Slug string `json:"slug"`
			Name string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		if a.names == nil {
			a.names = map[string]string{}
		}
		status, msg := validRename(a.domains, a.names, in.Slug, in.Name, reservedNames(a.cfg))
		if status != 0 {
			a.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, msg)
			return
		}
		a.names[strings.ToLower(strings.TrimSpace(in.Slug))] = msg
		applyNameOverrides(a.domains, a.names)
		saveErr := saveNames(a.namesPath, a.names)
		a.mu.Unlock()
		if saveErr != nil {
			a.log.Printf("names: persist failed: %v (applied in-memory)", saveErr)
		} else {
			a.log.Printf("names: %s -> %s saved", in.Slug, msg)
		}
		a.triggerCycle()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("DELETE /api/names", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Slug string `json:"slug"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		slug := strings.ToLower(strings.TrimSpace(in.Slug))
		a.mu.Lock()
		if _, ok := a.names[slug]; !ok {
			a.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"no override for this slug"}`)
			return
		}
		delete(a.names, slug)
		applyNameOverrides(a.domains, a.names)
		saveErr := saveNames(a.namesPath, a.names)
		a.mu.Unlock()
		if saveErr != nil {
			a.log.Printf("names: persist failed: %v (applied in-memory)", saveErr)
		} else {
			a.log.Printf("names: override for %s removed (back to default)", slug)
		}
		a.triggerCycle()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.APIToken == "" {
			// auth disabled — nothing to log in to
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		tok := r.FormValue("token")
		if !tokenEqual(tok, a.cfg.APIToken) {
			time.Sleep(500 * time.Millisecond) // brute-force damping
			http.Redirect(w, r, "/?failed=1", http.StatusSeeOther)
			return
		}
		id, err := a.newSession()
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    id,
			Path:     "/",
			MaxAge:   int(sessionTTL.Seconds()),
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	})
	a.log.Printf("api: listening on http://%s (GET /api/domains, /api/static, /api/status, /api/cloudflare, /healthz)", a.cfg.APIAddr)
	if a.cfg.APIToken != "" {
		a.log.Printf("api: token auth ENABLED (healthz exempt)")
	}
	return secureHeaders(a.requireToken(mux))
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
	a.mu.Lock()
	applyNameOverrides(recs, a.names)
	a.mu.Unlock()

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
	if cfEnabled(a.cfg) {
		st := CloudflareStatus{Enabled: true, At: time.Now()}
		if answer := hostIP(a.cfg.Bridge); answer == "" {
			st.Skipped = "no host IPv4 on " + a.cfg.Bridge
			a.log.Printf("cloudflare: %s — sync skipped", st.Skipped)
		} else {
			s, err := cfSync(publish, answer, a.cfg)
			st.Zone = s.Zone
			st.TunnelID = s.TunnelID
			st.Count, st.Added, st.Updated, st.Removed, st.Conflicts = s.Count, s.Added, s.Updated, s.Removed, s.Conflicts
			if err != nil {
				st.Error = err.Error()
				a.log.Printf("cloudflare: sync failed: %v", err)
			} else {
				a.log.Printf("cloudflare: synced %d public names via tunnel %.8s… (added %d, updated %d, removed %d, conflicts %d)",
					st.Count, st.TunnelID, len(st.Added), len(st.Updated), len(st.Removed), len(st.Conflicts))
				if len(st.Conflicts) > 0 {
					a.log.Printf("cloudflare: conflicts (user-owned records left untouched): %s", strings.Join(st.Conflicts, ", "))
				}
			}
		}
		a.mu.Lock()
		a.cf = st
		a.mu.Unlock()
	}

	stats := CycleStats{
		At: start, Kept: len(kept), Added: len(added), Removed: len(removed),
		Changed: len(changed), Total: len(cur),
		DurationMS: time.Since(start).Milliseconds(),
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
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

func (a *App) setStats(s CycleStats) {
	a.mu.Lock()
	a.stats = s
	a.mu.Unlock()
}

// version is the release identifier baked in at build time:
//
//	go build -ldflags "-X main.version=v0.2.1" .
//
// Source builds show "dev". Surfaced on the portal footer, /api/status and
// the -version flag.
var version = "dev"

// apiTokenOff explicitly disables API auth; an empty api_token means
// "generate one on first start" (see ensureAPIToken).
const apiTokenOff = "none"

// generateToken returns a 256-bit URL-safe random token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ensureAPIToken resolves the effective API token. Like the Proxmox UI, the
// dashboard/API is authenticated BY DEFAULT: an empty api_token generates a
// random token on first start and persists it to the config file so it
// survives restarts; `none` opts out (open API, loopback deployments).
func ensureAPIToken(cfg *Config, logf func(string, ...any)) {
	switch cfg.APIToken {
	case apiTokenOff:
		cfg.APIToken = ""
		logf("api: auth disabled (api_token: none) — the API/portal is OPEN")
	case "":
		tok, err := generateToken()
		if err != nil {
			logf("api: token generation failed (%v) — continuing WITHOUT auth; set api_token explicitly", err)
			return
		}
		cfg.APIToken = tok
		if err := saveConfig(cfg.Path, cfg); err != nil {
			logf("api: generated api_token (in-memory only — could not write %s: %v): %s", cfg.Path, err, tok)
			return
		}
		logf("api: no api_token configured — generated one and stored it in %s: %s", cfg.Path, tok)
	}
}

func main() {
	cfg, err := loadEffectiveConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxdnx: %v\n", err)
		os.Exit(2)
	}
	logger := setupLogging(cfg.LogFile)
	ensureAPIToken(&cfg, logger.Printf)
	// belt and braces beyond validate(): the cloudflare sync publishes
	// apps.<host>.<zone> publicly, so no effective token (explicit "none" or
	// a failed generation) may ever pair with it.
	if cfEnabled(cfg) && cfg.APIToken == "" {
		fatalf("cloudflare sync is on but the API/portal has no token — refusing to expose apps.<host>.%s publicly; set api_token", strings.Trim(strings.TrimRight(cfg.CloudflareZone, "."), "."))
	}
	if host, _, splitErr := net.SplitHostPort(cfg.APIAddr); splitErr == nil && !loopbackHost(host) {
		if cfg.APIToken != "" {
			logger.Printf("api binds %s — token auth is enabled", cfg.APIAddr)
		} else {
			logger.Printf("warning: api binds %s UNAUTHENTICATED — set api_token in the config", cfg.APIAddr)
		}
	}
	if cfg.created {
		logger.Printf("config: bootstrapped %s with defaults (edit and restart to apply)", cfg.Path)
	}
	logger.Printf("proxdnx starting: config=%s url=%s bridge=%s network=%q interval=%s caddy=%v avahi=%v http=%v static=%v force_https=%v probe=%v autofix=%v cloudflare=%v api_auth=%v",
		cfg.Path, cfg.BaseURL, cfg.Bridge, cfg.Network, cfg.Interval, cfg.Caddy, cfg.Avahi, cfg.HTTP, cfg.Static, cfg.ForceHTTPS, cfg.Probe, cfg.AutoFix, cfEnabled(cfg), cfg.APIToken != "")

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
	if cfg.Path != "" {
		app.namesPath = filepath.Join(filepath.Dir(cfg.Path), "names.json")
		app.names = loadNames(app.namesPath)
		if len(app.names) > 0 {
			keys := make([]string, 0, len(app.names))
			for k := range app.names {
				keys = append(keys, k+"->"+app.names[k])
			}
			sort.Strings(keys)
			logger.Printf("names: %d override(s): %s", len(app.names), strings.Join(keys, ", "))
		}
	}

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
	if cfg.once {
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
			app.runCycle(ctx)
		}
	}
}

// runCycle runs one cycle guarded by cycleBusy: a cycle triggered from the
// rename API (out-of-band) can never overlap the ticker's cycle.
func (a *App) runCycle(ctx context.Context) {
	if !a.cycleBusy.CompareAndSwap(false, true) {
		a.log.Printf("cycle: one already running — skipped")
		return
	}
	defer a.cycleBusy.Store(false)
	if err := a.cycle(ctx); err != nil {
		a.log.Printf("cycle failed: %v", err)
	}
}

// triggerCycle fires a background cycle so a rename converges caddy/avahi
// immediately instead of waiting for the next tick. Apps without a monitor
// client (tests, API-only) skip it.
func (a *App) triggerCycle() {
	if a.client == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		a.runCycle(ctx)
	}()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "proxdnx: "+format+"\n", args...)
	os.Exit(2)
}

// loopbackHost reports whether the API bind host is loopback-only. Empty
// host = wildcard bind (all interfaces) — not loopback.
func loopbackHost(host string) bool {
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
