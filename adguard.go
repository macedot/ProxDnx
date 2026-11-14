package main

// AdGuard Home DNS-rewrite sync: replicate every published name — app slugs
// (<slug>.local), the portal (apps.<host>.local), static infra names and the
// bare <host>.local — as an AdGuard DNS rewrite pointing at the host IP, so
// any LAN client that uses AdGuard for DNS resolves the names without mDNS
// (Android apps, clients with mDNS disabled, cached-off devices).
//
// Enabled when adguard_url is set. Ownership rule for pruning: a rewrite is
// managed by ProxDnx iff its answer is the host IP; rewrites pointing
// elsewhere are user-created and are never touched.

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"sort"
	"strings"
	"time"
)

// adguardRewrite mirrors one AdGuard Home DNS-rewrite entry.
type adguardRewrite struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled bool   `json:"enabled"`
}

// adguardNames enumerates every published name, mirroring renderAliases (plus
// the bare <host>.local, which avahi deliberately does not announce but
// AdGuard can resolve) and adding <name>.<suffix> variants when a suffix is
// configured.
func adguardNames(sites map[string]Record, cfg Config) []string {
	host := hostLabel()
	set := map[string]bool{}
	for s := range sites {
		set[s+".local"] = true
	}
	set["apps."+host+".local"] = true
	set[host+".local"] = true
	if cfg.Static {
		for _, r := range staticRoutes(host, cfg.BaseURL) {
			for _, n := range r.Names {
				set[n] = true
			}
		}
	}
	suffix := strings.Trim(strings.TrimRight(cfg.AdguardSuffix, "."), ".")
	names := make([]string, 0, len(set)+len(set))
	for n := range set {
		names = append(names, n)
		if suffix != "" {
			names = append(names, strings.TrimSuffix(n, ".local")+"."+suffix)
		}
	}
	sort.Strings(names)
	return names
}

// isManagedAdguardDomain reports whether a rewrite domain looks like one this
// daemon would manage (.local, or the configured suffix). Used to bound
// pruning; rewrites outside these suffixes are never touched.
func isManagedAdguardDomain(domain, suffix string) bool {
	if strings.HasSuffix(domain, ".local") {
		return true
	}
	suffix = strings.Trim(strings.TrimRight(suffix, "."), ".")
	return suffix != "" && strings.HasSuffix(domain, "."+suffix)
}

// AdguardSync is the outcome of one rewrite-sync pass.
type AdguardSync struct {
	Names   int
	Added   []string
	Updated []string
	Removed []string
}

// applyAdguard makes AdGuard Home agree with the published name set: adds
// missing rewrites, fixes rewrites whose answer drifted, and (when pruning is
// enabled) removes managed rewrites that are no longer published. User-owned
// rewrites — any entry not pointing at the host IP — are never modified.
// Logging lives with the caller (the cycle); this stays side-effect free.
func applyAdguard(publish []Record, answer string, cfg Config) (AdguardSync, error) {
	var s AdguardSync
	if cfg.AdguardURL == "" {
		return s, nil
	}
	if cfg.AdguardUser == "" || cfg.AdguardPassword == "" {
		return s, fmt.Errorf("adguard_user/adguard_password missing")
	}
	base := strings.TrimRight(cfg.AdguardURL, "/")
	jar, err := cookiejar.New(nil)
	if err != nil {
		return s, err
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			// self-hosted AdGuard often serves a self-signed or internal cert
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	if err := adguardLogin(client, base, cfg.AdguardUser, cfg.AdguardPassword); err != nil {
		return s, err
	}
	existing, err := adguardListRewrites(client, base)
	if err != nil {
		return s, err
	}

	names := adguardNames(dedupeSites(publish), cfg)
	want := make(map[string]bool, len(names))
	byDomain := make(map[string]adguardRewrite, len(existing))
	for _, r := range existing {
		byDomain[r.Domain] = r
	}

	for _, d := range names {
		want[d] = true
		if cur, ok := byDomain[d]; ok {
			if cur.Answer != answer || !cur.Enabled {
				if err := adguardDo(client, http.MethodPut, base+"/control/rewrite/update",
					map[string]adguardRewrite{"target": cur, "update": {Domain: d, Answer: answer, Enabled: true}}); err != nil {
					return s, fmt.Errorf("update %s: %v", d, err)
				}
				s.Updated = append(s.Updated, d)
			}
			continue
		}
		if err := adguardDo(client, http.MethodPost, base+"/control/rewrite/add",
			adguardRewrite{Domain: d, Answer: answer, Enabled: true}); err != nil {
			return s, fmt.Errorf("add %s: %v", d, err)
		}
		s.Added = append(s.Added, d)
	}
	if cfg.AdguardPrune {
		for d, r := range byDomain {
			if want[d] || r.Answer != answer || !isManagedAdguardDomain(d, cfg.AdguardSuffix) {
				continue
			}
			if err := adguardDo(client, http.MethodDelete, base+"/control/rewrite/delete", r); err != nil {
				return s, fmt.Errorf("delete %s: %v", d, err)
			}
			s.Removed = append(s.Removed, d)
		}
	}
	s.Names = len(names)
	return s, nil
}

func adguardLogin(client *http.Client, base, user, password string) error {
	body, _ := json.Marshal(map[string]string{"username": user, "password": password})
	resp, err := client.Post(base+"/control/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("login: bad credentials")
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("login: %s", resp.Status)
	}
	return nil
}

func adguardListRewrites(client *http.Client, base string) ([]adguardRewrite, error) {
	resp, err := client.Get(base + "/control/rewrite")
	if err != nil {
		return nil, fmt.Errorf("list rewrites: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list rewrites: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var arr []adguardRewrite
	if err := json.Unmarshal(data, &arr); err != nil {
		// tolerate builds that wrap the array
		var wrapped struct {
			Rewrites []adguardRewrite `json:"rewrites"`
		}
		if err2 := json.Unmarshal(data, &wrapped); err2 != nil {
			return nil, fmt.Errorf("list rewrites: %v", err)
		}
		arr = wrapped.Rewrites
	}
	return arr, nil
}

func adguardDo(client *http.Client, method, url string, payload any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}
