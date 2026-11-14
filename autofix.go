package main

// AutoFix — optional (config autofix, default off) self-healing of stale
// ProxMenux app registrations. When the probe tags a record stale or
// mismatched, the daemon sweeps well-known app ports on the guest, identifies
// what actually answers by its UI title, and corrects the registration
// through ProxMenux's own API (PUT /api/vms/<vmid>/apps/<app_id>), never by
// touching its files:
//
//   - port moved (title agrees with the registered name): patch the port,
//     keep every other registration field (update tracking preserved)
//   - different app lives there: rename to the identified title and demote
//     to register-only (name + port; the old registration's update state
//     belongs to an app that is no longer there)
//   - ambiguous or no identity: leave the record tagged, never guess
//
// Max 2 attempts per registration per daemon lifetime — if a fix does not
// heal, repeated attempts would just churn ProxMenux.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// knownAppPorts seeds the identity sweep: well-known default UI ports of
// common self-hosted apps. Candidate GENERATION only — the fix decision is
// always made from the measured UI title, never from this table.
var knownAppPorts = []int{
	8989, 7878, 6767, 8686, 9696, // *arr suite
	8096,       // Jellyfin/Emby
	32400,      // Plex
	2283,       // Immich
	3000, 3001, // AdGuard/Homepage/Uptime-Kuma/Grafana
	8080, 8112, 9091, 9117, // qBittorrent/Deluge/Transmission/Jackett
	8191,       // FlareSolverr
	9000, 9443, // Portainer
	81,         // Nginx Proxy Manager
	4321,       // Gitea Mirror
	9876,       // ddns-go
	8123, 5000, // Home Assistant/Synology
	443, 80, // generic TLS/plain UIs
}

type fixKey struct {
	vmid  int
	appID string
}

type fixPlan struct {
	name         string
	port         int
	registerOnly bool
	why          string
}

// planFix decides a fix from measured evidence: registered name, its (dead or
// mismatched) port, and the open candidate ports with their UI titles.
func planFix(registered string, regPort int, live map[int]string) (fixPlan, bool, string) {
	agree := 0
	titled := map[int]string{}
	for p, t := range live {
		if !titleHasIdentity(t) {
			continue // generic pages carry no identity
		}
		titled[p] = t
		if agree == 0 && !identityMismatch(registered, t) {
			agree = p
		}
	}
	if agree != 0 {
		if agree == regPort {
			return fixPlan{}, false, "registered port already serves the right app (probe race)"
		}
		return fixPlan{name: registered, port: agree, why: "title agrees with registration — port moved"}, true, ""
	}
	if len(titled) > 1 {
		return fixPlan{}, false, fmt.Sprintf("ambiguous: %d identified candidates", len(titled))
	}
	for p, t := range titled {
		return fixPlan{
			name: t, port: p, registerOnly: true,
			why: "single identified app — renamed; update tracking reset to register-only",
		}, true, ""
	}
	return fixPlan{}, false, "no usable identity found"
}

// openPorts TCP-probes ip on the given ports, returns the open ones.
func openPorts(ip string, ports []int, timeout time.Duration, workers int) map[int]bool {
	open := map[int]bool{}
	var mu sync.Mutex
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			open[port] = true
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return open
}

// identityTitles fetches UI-title identities for every open port in parallel
// (sequential fetches made the sweep take minutes on hosts with many open
// loopback services). Generic/unidentifiable titles collapse to "".
func identityTitles(ip string, open map[int]bool, timeout time.Duration, workers int) map[int]string {
	type result struct {
		port  int
		title string
	}
	results := make(chan result, len(open))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for p := range open {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results <- result{port, titleIdentity(identifyTitle(net.JoinHostPort(ip, strconv.Itoa(port))))}
		}(p)
	}
	wg.Wait()
	close(results)
	out := map[int]string{}
	for res := range results {
		out[res.port] = res.title
	}
	return out
}

// autoFix attempts to heal every discrepant record (stale or mismatched)
// that carries vmid + app id.
func (c *Client) autoFix(logf func(string, ...any), recs []Record) {
	type key struct {
		domain string
		vmid   int
		appID  string
	}
	groups := map[key]Record{}
	var order []key
	for _, r := range recs {
		if !(r.Stale || r.Mismatch) || r.appID == "" || r.vmid <= 0 {
			continue
		}
		k := key{r.Domain, r.vmid, r.appID}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = r
	}
	for _, k := range order {
		r := groups[k]
		fk := fixKey{vmid: r.vmid, appID: r.appID}
		c.fixMu.Lock()
		attempts := c.fixAttempts[fk]
		c.fixMu.Unlock()
		if attempts >= 2 {
			logf("autofix: %s (vmid %d): skipped, %d previous attempts", r.Domain, r.vmid, attempts)
			continue
		}
		ports := append([]int{r.Port}, knownAppPorts...)
		live := openPorts(r.IP, ports, probeTimeout, probeWorkers)
		liveTitles := identityTitles(r.IP, live, identityTimeout, probeWorkers)
		plan, ok, why := planFix(r.Service, r.Port, liveTitles)
		if !ok {
			logf("autofix: %s (vmid %d): %s — left tagged", r.Domain, r.vmid, why)
			continue
		}
		if c.applyFix(logf, r, plan) {
			c.fixMu.Lock()
			c.fixAttempts[fk] = attempts + 1
			c.fixMu.Unlock()
		}
	}
}

// applyFix reads the current sidecar registration via the monitor API and
// PUTs the corrected config back (ProxMenux validates + re-checks itself).
func (c *Client) applyFix(logf func(string, ...any), r Record, plan fixPlan) bool {
	var side struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := c.getJSON(fmt.Sprintf("/api/vms/%d/apps", r.vmid), &side, 10*time.Second); err != nil {
		logf("autofix: vmid %d: cannot read registrations: %v", r.vmid, err)
		return false
	}
	var cur map[string]any
	for _, a := range side.Apps {
		if fmt.Sprint(a["id"]) == r.appID {
			cur = a
			break
		}
	}
	if cur == nil {
		logf("autofix: app %s not found in vmid %d registrations", r.appID, r.vmid)
		return false
	}
	var payload map[string]any
	if plan.registerOnly {
		// identity changed: the old registration's update state belongs to an
		// app that is no longer here — demote to a link-only registration
		payload = map[string]any{
			"name":  plan.name,
			"ports": []map[string]any{{"port": plan.port, "scheme": "http", "web_path": "/"}},
		}
	} else {
		payload = map[string]any{}
		for k, v := range cur {
			switch k {
			case "id", "state", "created_at", "updated_at", "state_revision":
				continue // not part of the validate_config payload
			}
			payload[k] = v
		}
		payload["ports"] = []map[string]any{{"port": plan.port, "scheme": "http", "web_path": "/"}}
	}
	if err := c.putJSON(fmt.Sprintf("/api/vms/%d/apps/%s", r.vmid, r.appID), payload); err != nil {
		logf("autofix: vmid %d app %s: apply failed: %v", r.vmid, r.appID, err)
		return false
	}
	logf("autofix: vmid %d: registration %q@%d -> %q@%d (%s)",
		r.vmid, r.Service, r.Port, plan.name, plan.port, plan.why)
	return true
}

// putJSON issues an authorized JSON PUT against the monitor API.
func (c *Client) putJSON(path string, payload any) error {
	if err := c.ensureToken(); err != nil {
		return err
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("PUT", c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, trunc(string(body), 200))
	}
	return nil
}
