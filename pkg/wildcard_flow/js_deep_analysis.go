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
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/flowkit"
	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/notify"
	"github.com/vishnu303/chaathan/utils"
)

// stepJSDeepAnalysis is the unified JavaScript analysis step. It fetches JS
// files once and runs endpoint extraction (jsluice), secret scanning, source
// map harvesting, and subdomain extraction in a single pass.
// Returns true if the scan should be cancelled.
func stepJSDeepAnalysis(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("js_deep_analysis", "Step 13: JavaScript Deep Analysis"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}

	if c.SkipJS {
		logger.StepHeader("Step 13: Skipping JavaScript Deep Analysis (--skip-js)")
		c.markStepCompleteIfNoFailure("js_deep_analysis")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	writeEmptyFile(c.F.JSEndpointsOut)
	writeEmptyFile(c.F.JSSecretsOut)
	writeEmptyFile(c.F.JSSubdomainsOut)

	// ── 14.1 Collect JS URLs ──────────────────────────────────
	jsLimit := jsURLLimit(c)
	allJSURLs := gatherJSURLs(c)

	if len(allJSURLs) == 0 {
		logger.Info("No JavaScript files found in crawled content")
		c.markStepCompleteIfNoFailure("js_deep_analysis")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	// Rank and cap
	allJSURLs = rankJSURLs(allJSURLs)
	if len(allJSURLs) > jsLimit {
		allJSURLs = allJSURLs[:jsLimit]
	}

	// Write selected URLs to file for reference
	writeStringLinesFile(c.F.JSURLsFile, allJSURLs)

	logger.Info("Analyzing %d JavaScript files (priority-ranked)", len(allJSURLs))

	// ── 14.2–14.3 Unified Fetch + Analyze ─────────────────────
	cfg := c.jsAnalysisCfg()
	threads := cfg.Threads
	maxFileBytes := int64(cfg.MaxFileMB) * 1024 * 1024
	mapMaxBytes := int64(cfg.MapMaxMB) * 1024 * 1024

	client := newJSHTTPClient(c)

	// Rate limiter
	rateLimiter := newJSRateLimiter(c)
	if rateLimiter != nil {
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

	userSkipped := &atomic.Bool{}
	go func() {
		select {
		case <-c.SkipChan:
			userSkipped.Store(true)
			fetchCancel()
		case <-fetchCtx.Done():
		}
	}()

	agg := &jsAnalysisAgg{}
	var wg sync.WaitGroup
	var processed int64 // atomic progress counter
	totalJobs := int64(len(allJSURLs))

	for range threads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.jsFetchWorker(jobs, client, fetchCtx, rateLimiter, maxFileBytes, mapMaxBytes, agg, &processed, totalJobs)
		}()
	}

	wg.Wait()

	// On user skip or cancellation, save partial output and exit gracefully
	if userSkipped.Load() {
		logger.Skip("Skipped JS Deep Analysis — saving %d endpoints, %d secrets collected so far", len(agg.endpoints), len(agg.secretFindings))
		writeJSPartialOutput(c, agg.endpoints, agg.secretFindings, agg.subdomains, agg.filesFetched, agg.mapsFetched, agg.totalBytes)
		persistJSPartialFindingsToDB(c, agg.secretFindings)
		c.markStepCompleteIfNoFailure("js_deep_analysis")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}
	if c.cancelled() {
		writeJSPartialOutput(c, agg.endpoints, agg.secretFindings, agg.subdomains, agg.filesFetched, agg.mapsFetched, agg.totalBytes)
		persistJSPartialFindingsToDB(c, agg.secretFindings)
		return flowkit.StepResult{Cancelled: true}
	}

	// ── 14.4 Secret Validation ────────────────────────────────
	validateJSSecrets(c, client, cfg, agg.secretFindings)

	// ── 14.5 Output Routing ───────────────────────────────────
	endpoints, subdomains := writeJSOutputFiles(c, agg.endpoints, agg.secretFindings, agg.subdomains)

	// DB persistence
	persistJSFindingsToDB(c, endpoints, agg.secretFindings)

	// Re-sync the DB against the consolidated file now that JS-discovered
	// subdomains were merged into it (the Step-6 purge predates this
	// discovery source).
	syncDBSubdomainsToConsolidated(c)

	// Summary
	confirmedCount := logJSSecretSummary(agg.secretFindings)
	if len(subdomains) > 0 {
		logger.Result(len(subdomains), "subdomains discovered in JavaScript source")
	}

	// Notify confirmed secrets as high-severity findings
	notifyConfirmedJSSecrets(c, agg.secretFindings, confirmedCount)

	// Metadata
	meta := fmt.Sprintf("// JS Deep Analysis | Files: %d | Maps: %d | Size: %.4f GB | Endpoints: %d | Secrets: %d | Subdomains: %d\n",
		agg.filesFetched, agg.mapsFetched, float64(agg.totalBytes)/(1024*1024*1024), len(endpoints), len(agg.secretFindings), len(subdomains))
	_ = os.WriteFile(c.F.JSMetadataOut, []byte(meta), 0644)

	logger.Info("Processed %d JS files (%.2f MB) and %d source maps", agg.filesFetched, float64(agg.totalBytes)/(1024*1024), agg.mapsFetched)

	c.markStepCompleteIfNoFailure("js_deep_analysis")
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// jsURLLimit returns the configured cap on JS URLs to analyze.
func jsURLLimit(c *Ctx) int {
	jsLimit := 5000
	if c.Cfg != nil && c.Cfg.General.JSAnalysis.JSLimit > 0 {
		jsLimit = c.Cfg.General.JSAnalysis.JSLimit
	}
	return jsLimit
}

// gatherJSURLs collects unique, useful JS URLs from all crawler outputs and
// ffuf discoveries. The consolidated live URL set is deliberately not used:
// url_consolidation (Step 16) has not run yet at this point in the flow.
// Files are streamed line-by-line so huge wayback/gau outputs never load
// fully into memory.
func gatherJSURLs(c *Ctx) []string {
	// Gather JS URLs from all crawler outputs
	var allJSURLs []string
	seen := make(map[string]bool)
	crawlerFiles := []string{
		c.F.WaybackOut,
		c.F.GauOut,
		c.F.KatanaOut,
		c.F.GospiderOut,
		c.F.FfufDiscoveredURLs,
	}
	for _, file := range crawlerFiles {
		if !utils.FileExists(file) {
			continue
		}
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			u := extractPrimaryURL(scanner.Text())
			if u == "" || seen[u] || !isUsefulJSURL(u) {
				continue
			}
			seen[u] = true
			allJSURLs = append(allJSURLs, u)
		}
		f.Close()
	}

	if len(allJSURLs) == 0 {
		logger.FileDebug("js_deep_analysis: no JS URLs in crawler/ffuf outputs (url_consolidation has not run yet)")
	}
	return allJSURLs
}

// writeStringLinesFile writes lines to path, ignoring create errors
// (best-effort output, matching the step's original semantics).
func writeStringLinesFile(path string, lines []string) {
	if f, err := os.Create(path); err == nil {
		for _, line := range lines {
			fmt.Fprintln(f, line)
		}
		f.Close()
	}
}

// newJSHTTPClient builds the proxy-aware HTTP client used to fetch JS files.
func newJSHTTPClient(c *Ctx) *http.Client {
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
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}
}

// newJSRateLimiter returns a ticker enforcing the global RPS limit, or nil
// when no rate limit is configured (or the toolbox is absent).
func newJSRateLimiter(c *Ctx) *time.Ticker {
	if c.Tb != nil && c.Tb.RateLimits != nil && c.Tb.RateLimits.GlobalRPS > 0 {
		interval := time.Second / time.Duration(c.Tb.RateLimits.GlobalRPS)
		return time.NewTicker(interval)
	}
	return nil
}

// jsAnalysisAgg accumulates findings from concurrent JS file analysis.
type jsAnalysisAgg struct {
	mu             sync.Mutex
	endpoints      []string
	secretFindings []secretFinding
	subdomains     []string
	totalBytes     int64
	filesFetched   int
	mapsFetched    int
}

// jsFetchWorker consumes JS URLs, fetches each file once, and runs all
// analyzers on the body.
func (c *Ctx) jsFetchWorker(jobs <-chan string, client *http.Client, fetchCtx context.Context, rateLimiter *time.Ticker, maxFileBytes, mapMaxBytes int64, agg *jsAnalysisAgg, processed *int64, totalJobs int64) {
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

		body := fetchJSFile(c, fetchCtx, client, jsURL, maxFileBytes)

		// Progress log every 200 files
		cur := atomic.AddInt64(processed, 1)
		if cur%200 == 0 || cur == totalJobs {
			logger.Info("Progress: %d/%d JavaScript files analyzed", cur, totalJobs)
		}

		if body == nil {
			continue
		}

		agg.mu.Lock()
		agg.totalBytes += int64(len(body))
		agg.filesFetched++
		agg.mu.Unlock()

		agg.analyzeJSFile(c, fetchCtx, client, jsURL, body, mapMaxBytes)
	}
}

// analyzeJSFile runs jsluice endpoint extraction, secret scanning, source
// map harvesting, and subdomain extraction on a single fetched JS body.
func (agg *jsAnalysisAgg) analyzeJSFile(c *Ctx, fetchCtx context.Context, client *http.Client, jsURL string, body []byte, mapMaxBytes int64) {
	// [A] jsluice endpoint extraction (via temp file)
	localEndpoints := runJsluiceOnContent(c, fetchCtx, body, jsURL)

	// [C] Secret pattern scan
	localSecrets := scanSecrets(body, jsURL)

	// [D] Source map harvesting
	var mapSecrets []secretFinding
	var mapEndpoints []string
	mapBody := fetchSourceMap(fetchCtx, client, jsURL, body, mapMaxBytes)
	if mapBody != nil {
		agg.mu.Lock()
		agg.mapsFetched++
		agg.mu.Unlock()
		mapSecrets = scanSourceMapContent(mapBody, jsURL)
		mapEndpoints = extractEndpointsFromSourceMap(mapBody)
	}

	// [E] Subdomain extraction
	localSubs := extractSubdomainsFromJS(string(body), c.Domain)

	agg.mu.Lock()
	agg.endpoints = append(agg.endpoints, localEndpoints...)
	agg.endpoints = append(agg.endpoints, mapEndpoints...)
	agg.secretFindings = append(agg.secretFindings, localSecrets...)
	agg.secretFindings = append(agg.secretFindings, mapSecrets...)
	agg.subdomains = append(agg.subdomains, localSubs...)
	agg.mu.Unlock()
}

// secretValidationPriority ranks patterns by live-validation value.
// Provider-checkable findings outrank generic/unvalidatable ones so the
// validation limit keeps the most actionable candidates.
var secretValidationPriority = map[string]int{
	"aws-keys":      0,
	"github":        1,
	"stripe":        2,
	"google-api":    3,
	"slack-webhook": 4,
	"firebase":      5,
	"jwt":           6,
}

// validateJSSecrets runs live validation against provider APIs for the top
// secret findings. Findings are sorted in place (validation mutates them)
// so confirmed statuses flow through to persistence and notifications.
func validateJSSecrets(c *Ctx, client *http.Client, cfg jsAnalysisDefaults, secretFindings []secretFinding) {
	if cfg.SkipValidation || len(secretFindings) == 0 {
		return
	}
	validateLimit := cfg.ValidateLimit
	if validateLimit > len(secretFindings) {
		validateLimit = len(secretFindings)
	}
	logger.ToolStart("Secret Validation")
	slices.SortStableFunc(secretFindings, func(a, b secretFinding) int {
		return cmp.Compare(secretValidationPriority[a.Pattern], secretValidationPriority[b.Pattern])
	})
	validateSecrets(c.GoCtx, client, secretFindings[:validateLimit])
}

// writeJSOutputFiles deduplicates and writes endpoints, secrets, and
// scope-filtered subdomains to their output files, returning the final
// endpoint and subdomain slices.
func writeJSOutputFiles(c *Ctx, endpoints []string, secretFindings []secretFinding, subdomains []string) ([]string, []string) {
	// Deduplicate and write endpoints
	endpoints = utils.DedupeLines(endpoints)
	if len(endpoints) > 0 {
		writeStringLinesFile(c.F.JSEndpointsOut, endpoints)
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
	subdomains = filterJSSubdomainsToScope(c, utils.DedupeLines(subdomains))
	if len(subdomains) > 0 {
		writeStringLinesFile(c.F.JSSubdomainsOut, subdomains)
		// Sync late-discovered subdomains into the subdomains table/report
		// (scope was already filtered above).
		if c.ScanID > 0 {
			if _, err := ingest.ParseSubdomainsFile(c.ScanID, c.F.JSSubdomainsOut, "js"); err != nil {
				logger.Warning("Failed to sync JS subdomains to database: %v", err)
			}
		}
		// Append to consolidated subdomains so they appear in the report
		appendSubsToConsolidated(c, subdomains)
	}
	return endpoints, subdomains
}

// filterJSSubdomainsToScope drops subdomains outside the configured scope.
func filterJSSubdomainsToScope(c *Ctx, subdomains []string) []string {
	if c.ScopeFilter == nil {
		return subdomains
	}
	filtered := make([]string, 0, len(subdomains))
	for _, s := range subdomains {
		if c.ScopeFilter.IsInScope(s) && !c.ScopeFilter.IsOutOfScope(s) {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// appendSubsToConsolidated appends subdomains to ConsolidatedSubs, skipping
// entries already present so the product file never accumulates duplicate
// lines across full runs and partial (skip/cancel) saves.
func appendSubsToConsolidated(c *Ctx, subdomains []string) {
	if len(subdomains) == 0 || !utils.FileExists(c.F.ConsolidatedSubs) {
		return
	}
	existing := make(map[string]bool)
	if f, err := os.Open(c.F.ConsolidatedSubs); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if line := strings.ToLower(strings.TrimSpace(scanner.Text())); line != "" {
				existing[line] = true
			}
		}
		f.Close()
	}
	var fresh []string
	for _, s := range subdomains {
		if !existing[strings.ToLower(strings.TrimSpace(s))] {
			fresh = append(fresh, s)
		}
	}
	if len(fresh) == 0 {
		return
	}
	if f, err := os.OpenFile(c.F.ConsolidatedSubs, os.O_APPEND|os.O_WRONLY, 0644); err == nil {
		for _, s := range fresh {
			fmt.Fprintln(f, s)
		}
		f.Close()
	}
}

// persistJSPartialFindingsToDB ingests partial (skip/cancel) JS output into
// the DB so collected findings are not lost on disk only. Mirrors the
// persistence of the full path (endpoints + secrets + subdomains).
func persistJSPartialFindingsToDB(c *Ctx, secretFindings []secretFinding) {
	if c.ScanID <= 0 {
		return
	}
	if utils.FileExists(c.F.JSEndpointsOut) {
		if count, _ := ingest.ParseEndpointsFile(c.ScanID, c.F.JSEndpointsOut, "jsluice"); count > 0 {
			logger.Result(count, "API endpoints extracted from JavaScript (partial)")
		}
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
			logger.Warning("Failed to persist partial secret findings: %v", err)
		}
		flagJSSecretHosts(c.ScanID, secretFindings)
	}
	if utils.FileExists(c.F.JSSubdomainsOut) {
		if _, err := ingest.ParseSubdomainsFile(c.ScanID, c.F.JSSubdomainsOut, "js"); err != nil {
			logger.Warning("Failed to sync partial JS subdomains to database: %v", err)
		}
	}
}

// persistJSFindingsToDB stores endpoints and secret matches, flagging
// secret-bearing hosts for ROI prioritization.
func persistJSFindingsToDB(c *Ctx, endpoints []string, secretFindings []secretFinding) {
	if c.ScanID <= 0 {
		return
	}
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
		flagJSSecretHosts(c.ScanID, secretFindings)
	}
}

// flagJSSecretHosts marks hosts with exposed JS secrets so they get
// prioritized by downstream scans.
func flagJSSecretHosts(scanID int64, secretFindings []secretFinding) {
	secretHosts := make(map[string]bool)
	for _, sf := range secretFindings {
		if u, err := url.Parse(sf.URL); err == nil && u.Hostname() != "" {
			secretHosts[u.Hostname()] = true
		}
	}
	if len(secretHosts) == 0 {
		return
	}
	hosts := make([]string, 0, len(secretHosts))
	for h := range secretHosts {
		hosts = append(hosts, h)
	}
	if err := database.MarkHostsJSSecrets(scanID, hosts); err != nil {
		logger.Warning("Failed to flag JS-secret hosts: %v", err)
	} else {
		logger.Info("Prioritized %d hosts with exposed secrets", len(hosts))
	}
}

// logJSSecretSummary logs the secret findings summary and returns the number
// of confirmed secrets.
func logJSSecretSummary(secretFindings []secretFinding) int {
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
	return confirmedCount
}

// notifyConfirmedJSSecrets sends high-severity notifications for verified
// secret findings.
func notifyConfirmedJSSecrets(c *Ctx, secretFindings []secretFinding, confirmedCount int) {
	if c.Notifier == nil || confirmedCount == 0 {
		return
	}
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

// writeJSPartialOutput saves whatever was collected so far when the step is
// skipped or cancelled mid-execution. This ensures no findings are lost.

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
