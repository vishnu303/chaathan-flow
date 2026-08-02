// Phase 3 — JavaScript Deep Analysis (unified Step 13)
//
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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/notify"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// Secret patterns (strict-format, native Go)
// ─────────────────────────────────────────────────────────────

type secretPattern struct {
	Name  string
	Regex *regexp.Regexp
}

var jsSecretPatterns = []secretPattern{
	{"aws-keys", regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`)},
	{"google-api", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"stripe", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"github", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`)},
	{"slack-webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`)},
	{"jwt", regexp.MustCompile(`eyJhbGciOi[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
	{"private-key", regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`)},
	{"db-connection", regexp.MustCompile(`(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s"'<>]+`)},
	{"firebase", regexp.MustCompile(`[a-z0-9-]+\.firebaseio\.com`)},
	{"generic-secret", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password)\s*[=:]\s*["']([A-Za-z0-9+/=_\-]{16,})["']`)},
}

// ─────────────────────────────────────────────────────────────
// Priority ranking
// ─────────────────────────────────────────────────────────────

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

	// Priority 3: Recent wayback URLs (year >= current-2)
	currentYear := time.Now().Year()
	for y := currentYear; y >= currentYear-2; y-- {
		if strings.Contains(raw, fmt.Sprintf("%d", y)) {
			return 25
		}
	}

	return 0
}

// ─────────────────────────────────────────────────────────────
// Main step
// ─────────────────────────────────────────────────────────────

// stepJSDeepAnalysis is the unified JavaScript analysis step. It fetches JS
// files once and runs endpoint extraction (jsluice), secret scanning, source
// map harvesting, and subdomain extraction in a single pass.
// Returns true if the scan should be cancelled.
func stepJSDeepAnalysis(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("js_deep_analysis", "Step 13: JavaScript Deep Analysis"); skipped {
		return cancelled
	}

	if c.SkipJS {
		logger.StepHeader("Step 13: Skipping JavaScript Deep Analysis (--skip-js)")
		c.markStepCompleteIfNoFailure("js_deep_analysis")
		return c.cancelled()
	}

	writeEmptyFile(c.F.JSEndpointsOut)
	writeEmptyFile(c.F.JSSecretsOut)
	writeEmptyFile(c.F.JSSubdomainsOut)

	// ── 14.1 Collect JS URLs ──────────────────────────────────
	jsLimit := 5000
	if c.Cfg != nil && c.Cfg.General.JSAnalysis.JSLimit > 0 {
		jsLimit = c.Cfg.General.JSAnalysis.JSLimit
	}

	// Gather JS URLs from all crawler outputs
	var allJSURLs []string
	seen := make(map[string]bool)
	crawlerFiles := []string{
		c.F.WaybackOut,
		c.F.GauOut,
		c.F.KatanaOut,
		c.F.GospiderOut,
	}
	for _, file := range crawlerFiles {
		if !utils.FileExists(file) {
			continue
		}
		lines := loadLineSlice(file, 0)
		for _, line := range lines {
			u := extractPrimaryURL(line)
			if u == "" || seen[u] || !isUsefulJSURL(u) {
				continue
			}
			seen[u] = true
			allJSURLs = append(allJSURLs, u)
		}
	}

	// Also collect from live hosts (page-level script tags are already crawled)
	if len(allJSURLs) == 0 {
		// Fallback: try the live URL set if crawler outputs are empty
		if utils.FileExists(c.F.AllURLsLive) {
			collectJSURLsFromFile(c.F.AllURLsLive, c.F.JSURLsFile, jsLimit)
			allJSURLs = loadLineSlice(c.F.JSURLsFile, 0)
		}
	}

	if len(allJSURLs) == 0 {
		logger.Info("No JavaScript files found in crawled content")
		c.markStepCompleteIfNoFailure("js_deep_analysis")
		return c.cancelled()
	}

	// Rank and cap
	allJSURLs = rankJSURLs(allJSURLs)
	if len(allJSURLs) > jsLimit {
		allJSURLs = allJSURLs[:jsLimit]
	}

	// Write selected URLs to file for reference
	if f, err := os.Create(c.F.JSURLsFile); err == nil {
		for _, u := range allJSURLs {
			fmt.Fprintln(f, u)
		}
		f.Close()
	}

	logger.Info("Analyzing %d JavaScript files (priority-ranked)", len(allJSURLs))

	// ── 14.2–14.3 Unified Fetch + Analyze ─────────────────────
	cfg := c.jsAnalysisCfg()
	threads := cfg.Threads
	maxFileBytes := int64(cfg.MaxFileMB) * 1024 * 1024
	mapMaxBytes := int64(cfg.MapMaxMB) * 1024 * 1024

	transport := &http.Transport{
		TLSClientConfig:     utils.ModernBrowserTLSConfig(),
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}
	if c.Proxy != "" {
		if proxyURL, err := url.Parse(c.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}

	// Rate limiter
	var rateLimiter *time.Ticker
	if c.Tb.RateLimits != nil && c.Tb.RateLimits.GlobalRPS > 0 {
		interval := time.Second / time.Duration(c.Tb.RateLimits.GlobalRPS)
		rateLimiter = time.NewTicker(interval)
		defer rateLimiter.Stop()
	}

	jobs := make(chan string, len(allJSURLs))
	for _, u := range allJSURLs {
		jobs <- u
	}
	close(jobs)

	// Interactive skip: create a cancellable context that responds to both
	// parent cancellation, the 's' key skip signal, and the step timeout.
	drainSkipSignal(c)
	stepTimeout := time.Duration(cfg.MaxTimeout) * time.Minute
	fetchCtx, fetchCancel := context.WithTimeout(c.GoCtx, stepTimeout)
	defer fetchCancel()

	userSkipped := false
	go func() {
		select {
		case <-c.SkipChan:
			userSkipped = true
			fetchCancel()
		case <-fetchCtx.Done():
		}
	}()

	var wg sync.WaitGroup
	var mu sync.Mutex

	var endpoints []string
	var secretFindings []secretFinding
	var subdomains []string
	var totalBytes int64
	var filesFetched, mapsFetched int
	var processed int64 // atomic progress counter
	totalJobs := int64(len(allJSURLs))

	for range threads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jsURL := range jobs {
				select {
				case <-fetchCtx.Done():
					return
				default:
				}

				if rateLimiter != nil {
					select {
					case <-fetchCtx.Done():
						return
					case <-rateLimiter.C:
					}
				}

				body := fetchJSFile(c, client, jsURL, maxFileBytes)

				// Progress log every 200 files
				cur := atomic.AddInt64(&processed, 1)
				if cur%200 == 0 || cur == totalJobs {
					logger.Info("Progress: %d/%d JavaScript files analyzed", cur, totalJobs)
				}

				if body == nil {
					continue
				}

				mu.Lock()
				totalBytes += int64(len(body))
				filesFetched++
				mu.Unlock()

				// [A] jsluice endpoint extraction (via temp file)
				localEndpoints := runJsluiceOnContent(c, body, jsURL)

				// [C] Secret pattern scan
				localSecrets := scanSecrets(body, jsURL)

				// [D] Source map harvesting
				var mapSecrets []secretFinding
				var mapEndpoints []string
				mapBody := fetchSourceMap(c, client, jsURL, mapMaxBytes)
				if mapBody != nil {
					mu.Lock()
					mapsFetched++
					mu.Unlock()
					mapSecrets = scanSourceMapContent(mapBody, jsURL)
					mapEndpoints = extractEndpointsFromSourceMap(mapBody)
				}

				// [E] Subdomain extraction
				localSubs := extractSubdomainsFromJS(string(body), c.Domain)

				mu.Lock()
				endpoints = append(endpoints, localEndpoints...)
				endpoints = append(endpoints, mapEndpoints...)
				secretFindings = append(secretFindings, localSecrets...)
				secretFindings = append(secretFindings, mapSecrets...)
				subdomains = append(subdomains, localSubs...)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// On user skip or cancellation, save partial output and exit gracefully
	if userSkipped {
		logger.Skip("Skipped JS Deep Analysis — saving %d endpoints, %d secrets collected so far", len(endpoints), len(secretFindings))
		writeJSPartialOutput(c, endpoints, secretFindings, subdomains, filesFetched, mapsFetched, totalBytes)
		c.markStepCompleteIfNoFailure("js_deep_analysis")
		return c.cancelled()
	}
	if c.cancelled() {
		writeJSPartialOutput(c, endpoints, secretFindings, subdomains, filesFetched, mapsFetched, totalBytes)
		return true
	}

	// ── 14.4 Secret Validation ────────────────────────────────
	if !cfg.SkipValidation && len(secretFindings) > 0 {
		validateLimit := cfg.ValidateLimit
		if validateLimit > len(secretFindings) {
			validateLimit = len(secretFindings)
		}
		logger.ToolStart("Secret Validation")
		validateSecrets(c.GoCtx, client, secretFindings[:validateLimit])
	}

	// ── 14.5 Output Routing ───────────────────────────────────
	// Deduplicate and write endpoints
	endpoints = utils.DeduplicateSlice(endpoints)
	if len(endpoints) > 0 {
		if f, err := os.Create(c.F.JSEndpointsOut); err == nil {
			for _, ep := range endpoints {
				fmt.Fprintln(f, ep)
			}
			f.Close()
		}
	}

	// Write secrets
	if len(secretFindings) > 0 {
		if f, err := os.Create(c.F.JSSecretsOut); err == nil {
			for _, sf := range secretFindings {
				fmt.Fprintf(f, "[%s] [%s] [%s] %s\n", sf.URL, sf.Pattern, sf.Status, sf.Context)
			}
			f.Close()
		}
	}

	// Write subdomains (scope-filtered)
	subdomains = utils.DeduplicateSlice(subdomains)
	if c.ScopeFilter != nil {
		filtered := make([]string, 0, len(subdomains))
		for _, s := range subdomains {
			if c.ScopeFilter.IsInScope(s) && !c.ScopeFilter.IsOutOfScope(s) {
				filtered = append(filtered, s)
			}
		}
		subdomains = filtered
	}
	if len(subdomains) > 0 {
		if f, err := os.Create(c.F.JSSubdomainsOut); err == nil {
			for _, s := range subdomains {
				fmt.Fprintln(f, s)
			}
			f.Close()
		}
		// Append to consolidated subdomains so they appear in the report
		if utils.FileExists(c.F.ConsolidatedSubs) {
			if f, err := os.OpenFile(c.F.ConsolidatedSubs, os.O_APPEND|os.O_WRONLY, 0644); err == nil {
				for _, s := range subdomains {
					fmt.Fprintln(f, s)
				}
				f.Close()
			}
		}
	}

	// DB persistence
	if c.ScanID > 0 {
		if len(endpoints) > 0 {
			count, _ := ingest.ParseEndpointsFile(c.ScanID, c.F.JSEndpointsOut, "jsluice")
			logger.Result(count, "API endpoints extracted from JavaScript")
		}
		if len(secretFindings) > 0 {
			var parsed []database.GFMatch
			for _, sf := range secretFindings {
				parsed = append(parsed, database.GFMatch{
					URL:     sf.URL,
					Pattern: sf.Pattern,
					Status:  sf.Status,
				})
			}
			if err := database.InsertGFMatches(c.ScanID, parsed); err != nil {
				logger.Warning("Failed to persist secret findings: %v", err)
			}

			// ROI boost for hosts with secrets
			secretHosts := make(map[string]bool)
			for _, sf := range secretFindings {
				if u, err := url.Parse(sf.URL); err == nil && u.Hostname() != "" {
					secretHosts[u.Hostname()] = true
				}
			}
			if len(secretHosts) > 0 {
				hosts := make([]string, 0, len(secretHosts))
				for h := range secretHosts {
					hosts = append(hosts, h)
				}
				if err := database.MarkHostsJSSecrets(c.ScanID, hosts); err != nil {
					logger.Warning("Failed to flag JS-secret hosts: %v", err)
				} else {
					logger.Info("Prioritized %d hosts with exposed secrets", len(hosts))
				}
			}
		}
	}

	// Summary
	confirmedCount := 0
	for _, sf := range secretFindings {
		if sf.Status == "confirmed" {
			confirmedCount++
		}
	}
	if len(secretFindings) > 0 {
		if confirmedCount > 0 {
			logger.Result(len(secretFindings), "exposed secrets found (%d verified active)", confirmedCount)
		} else {
			logger.Result(len(secretFindings), "exposed secrets found (pending verification)")
		}
	}
	if len(subdomains) > 0 {
		logger.Result(len(subdomains), "subdomains discovered in JavaScript source")
	}

	// Notify confirmed secrets as high-severity findings
	if c.Notifier != nil && confirmedCount > 0 {
		for _, sf := range secretFindings {
			if sf.Status != "confirmed" {
				continue
			}
			_ = c.Notifier.SendFinding(notify.Finding{
				Target:      c.Domain,
				Type:        "js-secret",
				Name:        fmt.Sprintf("Confirmed %s secret in JS", sf.Pattern),
				Severity:    "high",
				Description: sf.Context,
				URL:         sf.URL,
				Timestamp:   time.Now(),
			})
		}
	}

	// Metadata
	meta := fmt.Sprintf("// JS Deep Analysis | Files: %d | Maps: %d | Size: %.4f GB | Endpoints: %d | Secrets: %d | Subdomains: %d\n",
		filesFetched, mapsFetched, float64(totalBytes)/(1024*1024*1024), len(endpoints), len(secretFindings), len(subdomains))
	_ = os.WriteFile(c.F.JSMetadataOut, []byte(meta), 0644)

	logger.Info("Processed %d JS files (%.2f MB) and %d source maps", filesFetched, float64(totalBytes)/(1024*1024), mapsFetched)

	c.markStepCompleteIfNoFailure("js_deep_analysis")
	return c.cancelled()
}

// writeJSPartialOutput saves whatever was collected so far when the step is
// skipped or cancelled mid-execution. This ensures no findings are lost.
func writeJSPartialOutput(c *Ctx, endpoints []string, secrets []secretFinding, subdomains []string, filesFetched, mapsFetched int, totalBytes int64) {
	endpoints = utils.DeduplicateSlice(endpoints)
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
	subdomains = utils.DeduplicateSlice(subdomains)
	if len(subdomains) > 0 {
		if f, err := os.Create(c.F.JSSubdomainsOut); err == nil {
			for _, s := range subdomains {
				fmt.Fprintln(f, s)
			}
			f.Close()
		}
	}
	meta := fmt.Sprintf("// JS Deep Analysis (PARTIAL) | Files: %d | Maps: %d | Size: %.2f MB | Endpoints: %d | Secrets: %d | Subdomains: %d\n",
		filesFetched, mapsFetched, float64(totalBytes)/(1024*1024), len(endpoints), len(secrets), len(subdomains))
	_ = os.WriteFile(c.F.JSMetadataOut, []byte(meta), 0644)
}

// ─────────────────────────────────────────────────────────────
// Fetch helpers
// ─────────────────────────────────────────────────────────────

func fetchJSFile(c *Ctx, client *http.Client, jsURL string, maxBytes int64) []byte {
	req, err := http.NewRequestWithContext(c.GoCtx, "GET", jsURL, nil)
	if err != nil {
		return nil
	}

	ua := localUserAgents[rand.N(len(localUserAgents))]
	if c.Tb.General != nil && c.Tb.General.UserAgent != "" {
		ua = c.Tb.General.UserAgent
	}
	req.Header.Set("User-Agent", ua)

	if c.Tb.CustomCookie != "" {
		req.Header.Set("Cookie", c.Tb.CustomCookie)
	}
	for _, h := range c.Tb.CustomHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil || len(body) == 0 {
		return nil
	}
	return body
}

// fetchSourceMap attempts to fetch the .map file for a given JS URL.
func fetchSourceMap(c *Ctx, client *http.Client, jsURL string, maxBytes int64) []byte {
	mapURL := jsURL + ".map"
	req, err := http.NewRequestWithContext(c.GoCtx, "GET", mapURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil || len(body) == 0 {
		return nil
	}

	// Validate it's actually JSON (source maps are JSON)
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	return body
}

// ─────────────────────────────────────────────────────────────
// jsluice integration
// ─────────────────────────────────────────────────────────────

// runJsluiceOnContent writes JS content to a temp file, runs jsluice urls,
// and returns extracted endpoints. Falls back to regex extraction on failure.
// The step-level timeout (2h) governs overall execution; no per-file timeout.
func runJsluiceOnContent(c *Ctx, body []byte, sourceURL string) []string {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("jsluice_%d_%d.js", os.Getpid(), rand.IntN(1000000)))
	if err := os.WriteFile(tmpFile, body, 0644); err != nil {
		return regexExtractEndpoints(string(body), sourceURL)
	}
	defer os.Remove(tmpFile)

	tmpOut := tmpFile + ".urls.json"
	defer os.Remove(tmpOut)

	if err := c.Tb.RunJsluiceURLs(c.GoCtx, tmpFile, tmpOut); err != nil || !utils.FileExists(tmpOut) {
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

// regexExtractEndpoints is the fallback when jsluice is unavailable or times out.
func regexExtractEndpoints(content, sourceURL string) []string {
	re := regexp.MustCompile(`["']((?:/[a-zA-Z0-9_\-./]+){2,})["']`)
	matches := re.FindAllStringSubmatch(content, -1)

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

type secretFinding struct {
	URL     string
	Pattern string
	Status  string // confirmed, invalid, unverified
	Context string
}

func scanSecrets(body []byte, sourceURL string) []secretFinding {
	var findings []secretFinding
	content := string(body)

	for _, sp := range jsSecretPatterns {
		matches := sp.Regex.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			val := m[0]
			if len(m) >= 2 && m[1] != "" {
				val = m[1]
			}

			if !isLikelySecret(sp.Name, val) {
				continue
			}

			ctx := extractSecretContext(content, sp.Regex, m[0])

			// Filter false positives based on context (e.g., Datadog RUM tokens).
			if isFalsePositiveContext(ctx) {
				continue
			}

			findings = append(findings, secretFinding{
				URL:     sourceURL,
				Pattern: sp.Name,
				Status:  "unverified",
				Context: ctx,
			})
		}
	}
	return findings
}

// falsePositiveContextPatterns matches context snippets that indicate a
// matched "secret" is actually a public-by-design value.
var falsePositiveContextPatterns = []*regexp.Regexp{
	// Datadog RUM/SDK client tokens (public, embedded in frontend code)
	regexp.MustCompile(`(?i)clientToken\s*[=:]`),
	regexp.MustCompile(`(?i)datadoghq\.com`),
	regexp.MustCompile(`(?i)datadogRum`),
	// React PropTypes internal constant
	regexp.MustCompile(`ReactPropTypesSecret`),
}

// isFalsePositiveContext returns true if the surrounding context indicates
// the matched secret is a known false positive.
func isFalsePositiveContext(ctx string) bool {
	for _, re := range falsePositiveContextPatterns {
		if re.MatchString(ctx) {
			return true
		}
	}
	return false
}

// scanSourceMapContent parses a source map JSON and scans sourcesContent for secrets.
func scanSourceMapContent(mapBody []byte, jsURL string) []secretFinding {
	var sm struct {
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
	}
	if err := json.Unmarshal(mapBody, &sm); err != nil {
		return nil
	}

	var findings []secretFinding
	for i, content := range sm.SourcesContent {
		if content == "" {
			continue
		}
		source := jsURL + ".map"
		if i < len(sm.Sources) {
			source = sm.Sources[i]
		}
		for _, sp := range jsSecretPatterns {
			matches := sp.Regex.FindAllStringSubmatch(content, -1)
			for _, m := range matches {
				val := m[0]
				if len(m) >= 2 && m[1] != "" {
					val = m[1]
				}
				if !isLikelySecret(sp.Name, val) {
					continue
				}
				ctx := extractSecretContext(content, sp.Regex, m[0])
				findings = append(findings, secretFinding{
					URL:     source,
					Pattern: sp.Name,
					Status:  "unverified",
					Context: "[sourcemap] " + ctx,
				})
			}
		}
	}
	return findings
}

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

func validateSecrets(ctx context.Context, client *http.Client, findings []secretFinding) {
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for i := range findings {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			sf := &findings[idx]
			switch sf.Pattern {
			case "aws-keys":
				sf.Status = validateAWSKey(ctx, client, sf.Context)
			case "github":
				sf.Status = validateGitHubToken(ctx, client, sf.Context)
			case "google-api":
				sf.Status = validateGoogleAPIKey(ctx, client, sf.Context)
			case "stripe":
				sf.Status = validateStripeKey(ctx, client, sf.Context)
			case "firebase":
				sf.Status = validateFirebase(ctx, client, sf.Context)
			case "slack-webhook":
				sf.Status = validateSlackWebhook(ctx, client, sf.Context)
			case "jwt":
				sf.Status = validateJWT(sf.Context)
			default:
				// No validation available — leave as unverified
			}
		}(i)
	}
	wg.Wait()
}

func extractTokenFromContext(pattern, ctx string) string {
	for _, sp := range jsSecretPatterns {
		if sp.Name == pattern {
			m := sp.Regex.FindStringSubmatch(ctx)
			if len(m) >= 1 {
				if len(m) >= 2 && m[1] != "" {
					return m[1]
				}
				return m[0]
			}
		}
	}
	return ""
}

func validateAWSKey(ctx context.Context, client *http.Client, context string) string {
	key := extractTokenFromContext("aws-keys", context)
	if key == "" || !strings.HasPrefix(key, "AKIA") {
		return "unverified"
	}
	// Lightweight check: attempt unsigned request to STS
	req, err := http.NewRequestWithContext(ctx, "GET", "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", nil)
	if err != nil {
		return "unverified"
	}
	req.Header.Set("X-Amz-Access-Key", key)
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	resp.Body.Close()
	// 403 with specific error means key exists but lacks permission = valid key
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusOK {
		return "confirmed"
	}
	return "invalid"
}

func validateGitHubToken(ctx context.Context, client *http.Client, context string) string {
	token := extractTokenFromContext("github", context)
	if token == "" {
		return "unverified"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return "unverified"
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "chaathan")
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return "confirmed"
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return "invalid"
	}
	return "unverified"
}

func validateGoogleAPIKey(ctx context.Context, client *http.Client, context string) string {
	key := extractTokenFromContext("google-api", context)
	if key == "" {
		return "unverified"
	}
	checkURL := "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + key
	req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
	if err != nil {
		return "unverified"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	resp.Body.Close()
	// 200 = valid token, 400 = invalid
	if resp.StatusCode == http.StatusOK {
		return "confirmed"
	}
	return "unverified"
}

func validateStripeKey(ctx context.Context, client *http.Client, context string) string {
	key := extractTokenFromContext("stripe", context)
	if key == "" {
		return "unverified"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.stripe.com/v1/account", nil)
	if err != nil {
		return "unverified"
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return "confirmed"
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return "invalid"
	}
	return "unverified"
}

func validateFirebase(ctx context.Context, client *http.Client, context string) string {
	// Extract firebase project URL
	re := regexp.MustCompile(`([a-z0-9-]+\.firebaseio\.com)`)
	m := re.FindString(context)
	if m == "" {
		return "unverified"
	}
	checkURL := "https://" + m + "/.json"
	req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
	if err != nil {
		return "unverified"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	resp.Body.Close()
	// 200 = world-readable (critical), 401/403 = secured
	if resp.StatusCode == http.StatusOK {
		return "confirmed"
	}
	return "unverified"
}

func validateSlackWebhook(ctx context.Context, client *http.Client, context string) string {
	re := regexp.MustCompile(`https://hooks\.slack\.com/services/[^\s"'<>]+`)
	webhookURL := re.FindString(context)
	if webhookURL == "" {
		return "unverified"
	}
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, strings.NewReader("{}"))
	if err != nil {
		return "unverified"
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	resp.Body.Close()
	// 404 = dead webhook, anything else = alive
	if resp.StatusCode == http.StatusNotFound {
		return "invalid"
	}
	return "confirmed"
}

func validateJWT(context string) string {
	re := regexp.MustCompile(`eyJhbGciOi[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	token := re.FindString(context)
	if token == "" {
		return "unverified"
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "unverified"
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "unverified"
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "unverified"
	}

	// Check expiry
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return "invalid" // expired
		}
		return "confirmed" // valid and not expired
	}
	return "unverified"
}

// ─────────────────────────────────────────────────────────────
// Subdomain extraction
// ─────────────────────────────────────────────────────────────

func extractSubdomainsFromJS(content, domain string) []string {
	if domain == "" {
		return nil
	}

	// Match subdomains of the target domain
	re := regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.` + regexp.QuoteMeta(domain))
	matches := re.FindAllString(content, -1)

	seen := make(map[string]bool)
	var subs []string
	for _, m := range matches {
		m = strings.ToLower(strings.TrimSuffix(m, "."))
		if m == domain || seen[m] {
			continue
		}
		// Filter obvious non-subdomains
		if strings.HasSuffix(m, ".js") || strings.HasSuffix(m, ".css") || strings.HasSuffix(m, ".png") {
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
var localUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
}

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range counts {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isLikelySecret checks if a matched value is likely a real secret.
func isLikelySecret(patternName, val string) bool {
	valLower := strings.ToLower(val)
	placeholders := []string{"placeholder", "undefined", "null", "false", "true", "your_token", "your_secret", "api_key_here", "example", "test", "dummy", "changeme", "xxxxx"}
	for _, ph := range placeholders {
		if valLower == ph || strings.Contains(valLower, ph) {
			return false
		}
	}

	// Filter known false-positive patterns.
	if isKnownFalsePositive(val) {
		return false
	}

	// Entropy check for generic patterns
	if patternName == "generic-secret" || patternName == "api-keys" {
		if len(val) < 8 {
			return false
		}
		if shannonEntropy(val) < 3.0 {
			return false
		}
	}

	// Filter repeating sequences
	if len(val) >= 10 {
		allSame := true
		for i := 1; i < len(val); i++ {
			if val[i] != val[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return false
		}
	}
	return true
}

// knownFalsePositivePatterns matches values that are commonly flagged as secrets
// but are public by design or well-known non-secrets.
var knownFalsePositivePatterns = []*regexp.Regexp{
	// Datadog RUM client tokens (public by design, prefixed with "pub")
	regexp.MustCompile(`^pub[0-9a-f]{32}$`),
	// React PropTypes secret (well-known non-secret constant)
	regexp.MustCompile(`(?i)SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED`),
	// Datadog application IDs (UUIDs, not secrets)
	regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
}

// isKnownFalsePositive returns true if the value matches a known false-positive pattern.
func isKnownFalsePositive(val string) bool {
	for _, re := range knownFalsePositivePatterns {
		if re.MatchString(val) {
			return true
		}
	}
	return false
}

// extractSecretContext returns surrounding context for a secret match.
func extractSecretContext(content string, re *regexp.Regexp, match string) string {
	idx := strings.Index(content, match)
	if idx < 0 {
		return match
	}
	ctxSize := 100
	start := idx - ctxSize
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + ctxSize
	if end > len(content) {
		end = len(content)
	}

	snippet := strings.TrimSpace(content[start:end])
	// Collapse whitespace for readability
	snippet = strings.Join(strings.Fields(snippet), " ")

	prefix := ""
	if start > 0 {
		prefix = "..."
	}
	suffix := ""
	if end < len(content) {
		suffix = "..."
	}
	return prefix + snippet + suffix
}

// jsAnalysisCfg returns the JS analysis config with safe defaults.
func (c *Ctx) jsAnalysisCfg() jsAnalysisDefaults {
	defaults := jsAnalysisDefaults{
		JSLimit:        5000,
		Threads:        15,
		MaxFileMB:      15,
		MapMaxMB:       20,
		ValidateLimit:  50,
		MaxTimeout:     120, // 2 hours
		SkipValidation: false,
	}
	if c.Cfg == nil {
		return defaults
	}
	cfg := c.Cfg.General.JSAnalysis
	if cfg.JSLimit > 0 {
		defaults.JSLimit = cfg.JSLimit
	}
	if cfg.Threads > 0 {
		defaults.Threads = cfg.Threads
	}
	if cfg.MaxFileMB > 0 {
		defaults.MaxFileMB = cfg.MaxFileMB
	}
	if cfg.MapMaxMB > 0 {
		defaults.MapMaxMB = cfg.MapMaxMB
	}
	if cfg.ValidateLimit > 0 {
		defaults.ValidateLimit = cfg.ValidateLimit
	}
	if cfg.MaxTimeout > 0 {
		defaults.MaxTimeout = cfg.MaxTimeout
	}
	defaults.SkipValidation = cfg.SkipValidation
	return defaults
}

type jsAnalysisDefaults struct {
	JSLimit        int
	Threads        int
	MaxFileMB      int
	MapMaxMB       int
	ValidateLimit  int
	MaxTimeout     int // entire step timeout in minutes
	SkipValidation bool
}
