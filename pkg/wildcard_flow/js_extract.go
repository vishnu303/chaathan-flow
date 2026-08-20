// Phase 3 — JavaScript Deep Analysis (unified Step 13)

// Replaces the old Step 14 (GoLinkFinder) and Step 18 (gf Secret Scan) with a
// single pass that fetches each JS file once and runs multiple analyzers:
//
//	14.1  Collect & rank JS URLs from crawler outputs
//	14.2  Unified concurrent fetch (in-memory, proxy-aware)
//	14.3  Analyzers: jsluice URLs/objects, secret patterns, source maps, subdomains
//	14.4  Secret validation (live checks against provider APIs)
//	14.5  Output routing to DB, files, and ROI
package wildcard_flow

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/utils"
)

// rankJSURLs scores and sorts JS URLs by priority so high-value files are
// fetched first. Returns a new sorted slice (does not mutate input).
func rankJSURLs(urls []string) []string {
	type scored struct {
		url   string
		score int
	}

	scoredURLs := make([]scored, 0, len(urls))
	for _, u := range urls {
		scoredURLs = append(scoredURLs, scored{url: u, score: scoreJSURL(u)})
	}

	sort.SliceStable(scoredURLs, func(i, j int) bool {
		return scoredURLs[i].score > scoredURLs[j].score
	})

	out := make([]string, len(scoredURLs))
	for i, s := range scoredURLs {
		out[i] = s.url
	}
	return out
}

func scoreJSURL(raw string) int {
	lower := strings.ToLower(raw)

	// Priority 1: First-party app bundles
	p1 := []string{"/app.js", "/main.js", "/bundle.js", "/application.js", "/_next/static/", "/static/js/app"}
	for _, p := range p1 {
		if strings.Contains(lower, p) {
			return 100
		}
	}

	// Priority 2: Chunk files with app paths
	p2 := []string{"/chunks/", "/assets/js/", "/build/", "/dist/", "/static/js/"}
	for _, p := range p2 {
		if strings.Contains(lower, p) {
			return 50
		}
	}

	// Priority 3: Recent wayback URLs (year >= current-2). Year tokens only
	// count as cache-dir-style path segments (/2026/...) — a year anywhere
	// in the string (ids, versions, prices) is not a freshness signal.
	currentYear := time.Now().Year()
	for y := currentYear; y >= currentYear-2; y-- {
		if strings.Contains(lower, fmt.Sprintf("/%d/", y)) {
			return 25
		}
	}

	return 0
}

// writeJSPartialOutput saves whatever was collected so far when the step is
// skipped or cancelled mid-execution. This ensures no findings are lost.
func writeJSPartialOutput(c *Ctx, endpoints []string, secrets []secretFinding, subdomains []string, filesFetched, mapsFetched int, totalBytes int64) {
	endpoints = utils.DedupeLines(endpoints)
	if len(endpoints) > 0 {
		if f, err := os.Create(c.F.JSEndpointsOut); err == nil {
			for _, ep := range endpoints {
				fmt.Fprintln(f, ep)
			}
			f.Close()
		}
	}
	if len(secrets) > 0 {
		if f, err := os.Create(c.F.JSSecretsOut); err == nil {
			for _, sf := range secrets {
				fmt.Fprintf(f, "[%s] [%s] [%s] %s\n", sf.URL, sf.Pattern, sf.Status, sf.Context)
			}
			f.Close()
		}
	}
	subdomains = filterJSSubdomainsToScope(c, utils.DedupeLines(subdomains))
	if len(subdomains) > 0 {
		if f, err := os.Create(c.F.JSSubdomainsOut); err == nil {
			for _, s := range subdomains {
				fmt.Fprintln(f, s)
			}
			f.Close()
		}
		// Append to consolidated subdomains so partial discoveries still
		// appear in the report (mirrors the full-path behavior).
		if utils.FileExists(c.F.ConsolidatedSubs) {
			if f, err := os.OpenFile(c.F.ConsolidatedSubs, os.O_APPEND|os.O_WRONLY, 0644); err == nil {
				for _, s := range subdomains {
					fmt.Fprintln(f, s)
				}
				f.Close()
			}
		}
	}
	meta := fmt.Sprintf("// JS Deep Analysis (PARTIAL) | Files: %d | Maps: %d | Size: %.2f MB | Endpoints: %d | Secrets: %d | Subdomains: %d\n",
		filesFetched, mapsFetched, float64(totalBytes)/(1024*1024), len(endpoints), len(secrets), len(subdomains))
	_ = os.WriteFile(c.F.JSMetadataOut, []byte(meta), 0644)
}

// ─────────────────────────────────────────────────────────────
// Fetch helpers
// ─────────────────────────────────────────────────────────────

// runJsluiceOnContent writes JS content to a temp file, runs jsluice urls,
// and returns extracted endpoints. Falls back to regex extraction on failure.
// fetchCtx (step timeout + skip signal) governs the jsluice execution.
func runJsluiceOnContent(c *Ctx, fetchCtx context.Context, body []byte, sourceURL string) []string {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("jsluice_%d_%d.js", os.Getpid(), rand.IntN(1000000)))
	if err := os.WriteFile(tmpFile, body, 0644); err != nil {
		return regexExtractEndpoints(string(body), sourceURL)
	}
	defer os.Remove(tmpFile)

	tmpOut := tmpFile + ".urls.json"
	defer os.Remove(tmpOut)

	if err := c.Tb.RunJsluiceURLs(fetchCtx, tmpFile, tmpOut); err != nil || !utils.FileExists(tmpOut) {
		// Fallback to regex extraction
		return regexExtractEndpoints(string(body), sourceURL)
	}

	return parseJsluiceOutput(tmpOut, sourceURL)
}

// jsluiceURLEntry represents one line of jsluice urls JSON output.
type jsluiceURLEntry struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	Type       string `json:"type"`
	Confidence string `json:"confidence"`
}

func parseJsluiceOutput(file, sourceURL string) []string {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()

	var endpoints []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry jsluiceURLEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.URL == "" || seen[entry.URL] {
			continue
		}
		seen[entry.URL] = true

		// Resolve relative URLs against the source
		resolved := entry.URL
		if !strings.HasPrefix(resolved, "http://") && !strings.HasPrefix(resolved, "https://") {
			if u, err := url.Parse(sourceURL); err == nil {
				resolved = u.Scheme + "://" + u.Host + resolved
			}
		}
		endpoints = append(endpoints, resolved)
	}
	return endpoints
}

// endpointPathRe matches quoted URL paths with at least two segments.
// Compiled once — regexExtractEndpoints runs once per fetched JS file.
var endpointPathRe = regexp.MustCompile(`["']((?:/[a-zA-Z0-9_\-./]+){2,})["']`)

// regexExtractEndpoints is the fallback when jsluice is unavailable or times out.
func regexExtractEndpoints(content, sourceURL string) []string {
	matches := endpointPathRe.FindAllStringSubmatch(content, -1)

	var endpoints []string
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		path := m[1]
		if seen[path] || len(path) < 3 {
			continue
		}
		seen[path] = true

		// Resolve against source
		if u, err := url.Parse(sourceURL); err == nil && u.Host != "" {
			endpoints = append(endpoints, u.Scheme+"://"+u.Host+path)
		} else {
			endpoints = append(endpoints, path)
		}
	}
	return endpoints
}

// ─────────────────────────────────────────────────────────────
// Secret scanning
// ─────────────────────────────────────────────────────────────

// extractEndpointsFromSourceMap pulls URL-like paths from source map sources array.
func extractEndpointsFromSourceMap(mapBody []byte) []string {
	var sm struct {
		Sources []string `json:"sources"`
	}
	if err := json.Unmarshal(mapBody, &sm); err != nil {
		return nil
	}

	var endpoints []string
	for _, s := range sm.Sources {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "/api/") || strings.Contains(lower, "/v1/") ||
			strings.Contains(lower, "/v2/") || strings.Contains(lower, "endpoint") ||
			strings.Contains(lower, "route") || strings.Contains(lower, "handler") {
			endpoints = append(endpoints, s)
		}
	}
	return endpoints
}

// ─────────────────────────────────────────────────────────────
// Secret validation
// ─────────────────────────────────────────────────────────────

// jsSubdomainReCache caches per-domain subdomain regexes — the pattern
// depends only on the scan domain, so compiling it once per file is waste.
var (
	jsSubdomainReCache   = make(map[string]*regexp.Regexp)
	jsSubdomainReCacheMu sync.Mutex
)

func jsSubdomainRegex(domain string) *regexp.Regexp {
	jsSubdomainReCacheMu.Lock()
	defer jsSubdomainReCacheMu.Unlock()
	if re, ok := jsSubdomainReCache[domain]; ok {
		return re
	}
	re := regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.` + regexp.QuoteMeta(domain))
	jsSubdomainReCache[domain] = re
	return re
}

func extractSubdomainsFromJS(content, domain string) []string {
	if domain == "" {
		return nil
	}

	// Match subdomains of the target domain
	matches := jsSubdomainRegex(domain).FindAllString(content, -1)

	staticExts := getStaticExtensions()
	seen := make(map[string]bool)
	var subs []string
	for _, m := range matches {
		m = strings.ToLower(strings.TrimSuffix(m, "."))
		if m == domain || seen[m] {
			continue
		}
		// Filter matches that are really static filenames (any known
		// static extension, not just .js/.css/.png).
		if idx := strings.LastIndex(m, "."); idx >= 0 && staticExts[m[idx:]] {
			continue
		}
		seen[m] = true
		subs = append(subs, m)
	}
	return subs
}

// ─────────────────────────────────────────────────────────────
// Shared helpers (moved from old content_discovery.go)
// ─────────────────────────────────────────────────────────────

// localUserAgents contains common browser User-Agent strings.
