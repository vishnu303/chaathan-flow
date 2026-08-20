// Phase 3 — Content Discovery (Steps 11–16)
//
// Discovers URLs, endpoints, and directories from live hosts.
// Wayback/GAU run here (not in Phase 1) so URLs are collected
// only for validated live hosts.
//
//  12. Historical URL Discovery (Waybackurls + GAU) [Parallel]
//  13. Web Crawling (Katana + GoSpider) [Parallel, Optional]
//  14. JavaScript Deep Analysis (jsluice + secrets) — see js_deep_analysis.go
//  15. Directory Fuzzing (ffuf) [Optional — requires --wordlist]
//  16. HTTP Parameter Discovery (x8) [Optional]
//  17. URL Consolidation & Live Check (httpx) + ROI metadata
package wildcard_flow

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/flowkit"
	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/metadata"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 11 — Historical URL Discovery (Waybackurls + GAU)
// ─────────────────────────────────────────────────────────────

// stepURLDiscovery runs Waybackurls and GAU in parallel on the target domain.
// Returns true if the scan should be cancelled.
func stepURLDiscovery(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("url_discovery", "Step 11: Historical URL Discovery"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}
	writeEmptyFile(c.F.WaybackOut)
	writeEmptyFile(c.F.GauOut)

	// Track individual tool results so we can detect total failure.
	var waybackOK, gauOK bool
	var resultMu sync.Mutex

	var urlDiscoverySkipped bool
	err := runWithSkip(c, "url discovery", func(sCtx context.Context) error {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			logger.ToolStart("Waybackurls")
			logger.FileDebug("waybackurls input: domain=%s out=%s", c.Domain, c.F.WaybackOut)
			if err := c.Tb.RunWaybackurls(sCtx, c.Domain, c.F.WaybackOut); err != nil {
				if c.Verbose && sCtx.Err() == nil {
					logger.ToolFail("Waybackurls", err.Error())
				}
				logger.FileDebug("waybackurls failed: %v", err)
			} else {
				resultMu.Lock()
				waybackOK = true
				resultMu.Unlock()
				logger.ToolDone("Waybackurls")
			}
		}()

		go func() {
			defer wg.Done()
			logger.ToolStart("GAU")
			logger.FileDebug("gau input: domain=%s out=%s", c.Domain, c.F.GauOut)
			if err := c.Tb.RunGau(sCtx, c.Domain, c.F.GauOut); err != nil {
				if c.Verbose && sCtx.Err() == nil {
					logger.ToolFail("GAU", err.Error())
				}
				logger.FileDebug("gau failed: %v", err)
			} else {
				resultMu.Lock()
				gauOK = true
				resultMu.Unlock()
				logger.ToolDone("GAU")
			}
		}()

		wg.Wait()
		return nil
	})

	if err == ErrToolSkipped {
		urlDiscoverySkipped = true
	}

	if c.ScanID > 0 {
		if utils.FileExists(c.F.WaybackOut) {
			count, _ := ingestScopedURLsFile(c, c.F.WaybackOut, "waybackurls")
			label := ""
			if urlDiscoverySkipped {
				label = " (partial)"
			}
			logger.Result(count, "archived URLs via Wayback Machine%s", label)
		}
		if utils.FileExists(c.F.GauOut) {
			count, _ := ingestScopedURLsFile(c, c.F.GauOut, "gau")
			label := ""
			if urlDiscoverySkipped {
				label = " (partial)"
			}
			logger.Result(count, "archived URLs via GAU%s", label)
		}
	}

	waybackCount, _ := utils.CountFileLines(c.F.WaybackOut)
	gauCount, _ := utils.CountFileLines(c.F.GauOut)
	if urlDiscoverySkipped || waybackOK || gauOK || waybackCount > 0 || gauCount > 0 {
		c.markStepCompleteIfNoFailure("url_discovery")
	} else {
		c.markStepFailedSafe("url_discovery", fmt.Errorf("both Waybackurls and GAU failed"))
	}
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// ─────────────────────────────────────────────────────────────
// Step 12 — Web Crawling (Katana + GoSpider)
// ─────────────────────────────────────────────────────────────

// stepWebCrawling runs Katana and GoSpider in parallel.
// Returns true if the scan should be cancelled.
func stepWebCrawling(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("web_crawling", "Step 12: Web Crawling"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}

	if c.SkipCrawl {
		logger.StepHeader("Step 12: Skipping Web Crawling (--skip-crawl)")
		c.markStepCompleteIfNoFailure("web_crawling")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}
	writeEmptyFile(c.F.KatanaOut)
	writeEmptyFile(c.F.GospiderOut)
	var katanaOK, gospiderOK bool
	var crawlMu sync.Mutex

	liveHostCount, _ := utils.CountFileLines(c.F.HttpxLiveHosts)
	if liveHostCount == 0 {
		logger.Warning("No live hosts found — skipping web crawling")
		c.markStepCompleteIfNoFailure("web_crawling")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}
	logger.FileDebug("web_crawling input: %s (%d live hosts)", c.F.HttpxLiveHosts, liveHostCount)

	var crawlSkipped bool
	err := runWithSkip(c, "web crawling", func(sCtx context.Context) error {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			logger.ToolStart("Katana")
			logger.FileDebug("katana input: %s out=%s", c.F.HttpxLiveHosts, c.F.KatanaOut)
			if err := c.Tb.RunKatana(sCtx, c.F.HttpxLiveHosts, c.F.KatanaOut); err != nil {
				if sCtx.Err() == nil {
					logger.ToolFail("Katana", err.Error())
				}
			} else {
				crawlMu.Lock()
				katanaOK = true
				crawlMu.Unlock()
				logger.ToolDone("Katana")
			}
		}()

		go func() {
			defer wg.Done()
			logger.ToolStart("GoSpider")
			logger.FileDebug("gospider input: %s out=%s", c.F.HttpxLiveHosts, c.F.GospiderOut)
			if err := c.Tb.RunGoSpider(sCtx, c.F.HttpxLiveHosts, c.F.GospiderOut); err != nil {
				if sCtx.Err() == nil {
					logger.ToolFail("GoSpider", err.Error())
				}
			} else {
				crawlMu.Lock()
				gospiderOK = true
				crawlMu.Unlock()
				logger.ToolDone("GoSpider")
			}
		}()

		wg.Wait()
		return nil
	})

	if err == ErrToolSkipped {
		crawlSkipped = true
	}

	if c.ScanID > 0 {
		if utils.FileExists(c.F.KatanaOut) {
			count, _ := ingestScopedURLsFile(c, c.F.KatanaOut, "katana")
			label := ""
			if crawlSkipped {
				label = " (partial)"
			}
			logger.Result(count, "URLs crawled by Katana%s", label)
		}
		if utils.FileExists(c.F.GospiderOut) {
			count, _ := ingestScopedURLsFile(c, c.F.GospiderOut, "gospider")
			label := ""
			if crawlSkipped {
				label = " (partial)"
			}
			logger.Result(count, "URLs crawled by GoSpider%s", label)
		}
	}

	// Mark step based on outcome: complete if at least one crawler succeeded
	// or the step was skipped; failed only if both crawlers failed.
	katanaCount, _ := utils.CountFileLines(c.F.KatanaOut)
	gospiderCount, _ := utils.CountFileLines(c.F.GospiderOut)
	if crawlSkipped || katanaOK || gospiderOK || katanaCount > 0 || gospiderCount > 0 {
		c.markStepCompleteIfNoFailure("web_crawling")
	} else {
		c.markStepFailedSafe("web_crawling", fmt.Errorf("both Katana and GoSpider failed"))
	}
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// ─────────────────────────────────────────────────────────────
// Step 16 — HTTP Parameter Discovery (x8)
// ─────────────────────────────────────────────────────────────

// stepParamDiscovery discovers HTTP parameters with x8 (Step 16).
// After a successful run it converts discovered params into parameterized URLs
// (written to X8URLsOut) so they flow into Step 17 consolidation and
// downstream scanners (Nuclei/Dalfox).
// Returns true if the scan should be cancelled.
func stepParamDiscovery(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("param_discovery", "Step 15: HTTP Parameter Discovery (x8)"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}

	if c.SkipX8 {
		logger.StepHeader("Step 15: Skipping x8 (--skip-x8)")
		c.markStepCompleteIfNoFailure("param_discovery")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	writeEmptyFile(c.F.X8Out)
	writeEmptyFile(c.F.X8URLsOut)

	// Preflight check
	liveHostCount, _ := utils.CountFileLines(c.F.HttpxLiveHosts)
	if liveHostCount == 0 {
		logger.Warning("No live hosts found — skipping x8 parameter discovery")
		c.markStepCompleteIfNoFailure("param_discovery")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	// Merge FfufDiscoveredURLs and high-signal endpoints into a temporary input file
	x8InputFile := c.F.X8Input

	x8Targets := collectX8Targets(c)

	if len(x8Targets) == 0 {
		logger.Warning("No targets found for parameter discovery — skipping x8")
		c.markStepCompleteIfNoFailure("param_discovery")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	// Write targets to x8InputFile
	if err := writeX8Input(x8InputFile, x8Targets); err != nil {
		c.markStepFailedSafe("param_discovery", err)
		logger.Error("Failed to prepare x8 input: %v", err)
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	logger.ToolStart("x8")

	// Validate parameters wordlist if configured or available via SecLists.
	paramWordlist := resolveX8ParamWordlist(c)

	var x8Skipped bool
	if err := runWithSkip(c, "x8", func(sCtx context.Context) error {
		return c.Tb.RunX8WithWordlist(sCtx, x8InputFile, c.F.X8Out, paramWordlist)
	}); err != nil {
		if err == ErrToolSkipped {
			x8Skipped = true
		} else {
			c.markStepFailedSafe("param_discovery", err)
			logger.Warning("x8 failed: %v", err)
		}
	}

	if c.ScanID > 0 && utils.FileExists(c.F.X8Out) {
		count := convertX8ToURLs(c.F.X8Out, c.F.X8URLsOut)
		stored := storeX8ParamCounts(c.ScanID, c.F.X8Out)
		label := ""
		if x8Skipped {
			label = " (partial)"
		}
		logger.Result(count, "hidden parameters discovered%s", label)
		if stored > 0 {
			logger.Info("Stored x8 param counts for %d URLs%s", stored, label)
		}
	}

	c.markStepCompleteIfNoFailure("param_discovery")
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// ingestScopedURLsFile ingests a crawler URL file into the DB, applying the
// user scope filter when one is configured. The ingest layer only enforces
// domain-suffix scope, so with a narrow scope config in-domain but
// out-of-scope URLs would otherwise persist in the DB. The source file is
// left untouched — downstream readers apply their own filtering.
func ingestScopedURLsFile(c *Ctx, filePath, source string) (int, error) {
	if c.ScopeFilter == nil {
		return ingest.ParseURLsFile(c.ScanID, filePath, source)
	}
	tmp := filePath + ".scoped.tmp"
	if err := copyFile(filePath, tmp); err != nil {
		return ingest.ParseURLsFile(c.ScanID, filePath, source)
	}
	defer os.Remove(tmp)
	_ = utils.FilterFileLines(tmp, func(line string) bool {
		parsed, err := url.Parse(strings.TrimSpace(line))
		if err != nil || parsed.Hostname() == "" {
			return true // non-URL/noise lines pass through; the parser drops them
		}
		return c.ScopeFilter.IsInScope(parsed.Hostname()) && !c.ScopeFilter.IsOutOfScope(parsed.Hostname())
	})
	return ingest.ParseURLsFile(c.ScanID, tmp, source)
}

// collectX8Targets merges ffuf discoveries and high-signal crawler
// endpoints, deduplicates them, ranks them by ROI score, and caps the
// result at paramDiscoveryCap — the highest-value targets win instead of
// whichever 150 happened to be read first.
func collectX8Targets(c *Ctx) []string {
	var x8Targets []string

	// Add ffuf fuzzing results
	if utils.FileExists(c.F.FfufDiscoveredURLs) {
		if lines, err := utils.ReadNonEmptyLines(c.F.FfufDiscoveredURLs); err == nil {
			x8Targets = append(x8Targets, lines...)
		}
	}

	// Collect and add high-signal crawler endpoints (no limit to collect all possible targets)
	crawlerFiles := []string{
		c.F.WaybackOut,
		c.F.GauOut,
		c.F.KatanaOut,
		c.F.GospiderOut,
		c.F.JSEndpointsOut,
	}
	highSignal := collectHighSignalEndpoints(c, crawlerFiles)
	x8Targets = append(x8Targets, highSignal...)

	// Deduplicate, then rank by ROI score so the cap keeps the best targets.
	x8Targets = utils.DedupeLines(x8Targets)
	if len(x8Targets) > paramDiscoveryCap {
		type scoredTarget struct {
			url   string
			score int
		}
		scored := make([]scoredTarget, len(x8Targets))
		for i, t := range x8Targets {
			scored[i] = scoredTarget{url: t, score: urlROIScore(t)}
		}
		slices.SortStableFunc(scored, func(a, b scoredTarget) int {
			return cmp.Compare(b.score, a.score)
		})
		x8Targets = make([]string, 0, paramDiscoveryCap)
		for _, s := range scored[:paramDiscoveryCap] {
			x8Targets = append(x8Targets, s.url)
		}
	}
	return x8Targets
}

// writeX8Input writes the target list to x8's input file.
func writeX8Input(x8InputFile string, x8Targets []string) error {
	fIn, err := os.Create(x8InputFile)
	if err != nil {
		return err
	}
	for _, t := range x8Targets {
		_, _ = fIn.WriteString(t + "\n")
	}
	fIn.Close()
	return nil
}

// resolveX8ParamWordlist picks the x8 parameter wordlist: the configured
// wordlist when it exists, else SecLists auto-detect, else empty to fall
// back to x8's built-in parameter list.
func resolveX8ParamWordlist(c *Ctx) string {
	if c.Cfg != nil && c.Cfg.General.Wordlists.Parameters != "" && utils.FileExists(c.Cfg.General.Wordlists.Parameters) {
		return c.Cfg.General.Wordlists.Parameters
	}
	if autoWl := config.ResolveSecListFile("Discovery/Web-Content/burp-parameter-names.txt"); autoWl != "" {
		logger.Info("Auto-detected SecLists parameter wordlist for x8: %s", autoWl)
		return autoWl
	}
	if c.Cfg != nil && c.Cfg.General.Wordlists.Parameters != "" {
		logger.Warning("x8 parameters wordlist not found: %s", c.Cfg.General.Wordlists.Parameters)
	}
	logger.Info("SecLists parameter wordlist not found on device — falling back to x8's built-in parameter list")
	return ""
}

// collectHighSignalEndpoints reads raw URLs from crawler and discovery files,
// filters for in-scope high-signal parameters/endpoints (dynamic extensions,
// API paths, interesting keywords), deduplicates them by host+path, and
// returns a slice of URLs.
func collectHighSignalEndpoints(c *Ctx, files []string) []string {
	seen := make(map[string]bool)
	var endpoints []string

	// Dynamic extensions to look for
	extensions := []string{
		".php", ".aspx", ".asp", ".jsp", ".jspx", ".do", ".action", ".cfm", ".pl", ".py", ".rb", ".cgi",
	}

	// Interesting API and functional paths
	keywords := []string{
		"/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql/", "/json",
		"/login", "/register", "/auth", "/search", "/query", "/download", "/upload", "/file", "/admin", "/panel", "/debug", "/config",
	}

	for _, file := range files {
		if !utils.FileExists(file) {
			continue
		}

		f, err := os.Open(file)
		if err != nil {
			continue
		}

		c.scanHighSignalFile(f, seen, &endpoints, extensions, keywords)
		f.Close()
	}

	return endpoints
}

// scanHighSignalFile extracts deduplicated, in-scope high-signal URLs from one file.
func (c *Ctx) scanHighSignalFile(f *os.File, seen map[string]bool, endpoints *[]string, extensions, keywords []string) {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Clean line (strip GoSpider tags if present, or spaces)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		rawURL := fields[0]

		// Parse URL to validate and normalize
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
			continue
		}

		// Crawler output may reference third-party hosts — never feed those to x8.
		if !c.hostInScope(parsed.Hostname()) {
			continue
		}

		// Match criteria
		if isHighSignalURL(parsed, extensions, keywords) {
			// Normalize to host+path for deduplication (strip query params and fragment)
			dedupKey := parsed.Scheme + "://" + parsed.Host + parsed.Path
			if !seen[dedupKey] {
				seen[dedupKey] = true
				// Keep the original URL
				*endpoints = append(*endpoints, rawURL)
			}
		}
	}
}

// isHighSignalURL reports whether the parsed URL matches dynamic-extension,
// keyword-path, or query-parameter criteria.
func isHighSignalURL(parsed *url.URL, extensions, keywords []string) bool {
	// Clean/normalize path
	pathLower := strings.ToLower(parsed.Path)

	// 0. Static resources cannot host injection points — reject them even
	// when they carry query strings (e.g. /image.png?id=1).
	for ext := range getStaticExtensions() {
		if strings.HasSuffix(pathLower, ext) {
			return false
		}
	}

	// 1. Check extensions
	for _, ext := range extensions {
		if strings.HasSuffix(pathLower, ext) || strings.Contains(pathLower, ext+"/") {
			return true
		}
	}

	// 2. Check keywords in path
	for _, kw := range keywords {
		if strings.Contains(pathLower, kw) {
			return true
		}
	}

	// 3. Check if it already has query parameters (high signal for dynamic behavior)
	return parsed.RawQuery != ""
}

// ─────────────────────────────────────────────────────────────
// Step 15 — URL Consolidation & Live Check
// ─────────────────────────────────────────────────────────────

// stepURLConsolidation merges all URL sources, live-checks them with Httpx,
// and enriches ROI metadata for high-value targets.
// Returns true if the scan should be cancelled.
func stepURLConsolidation(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("url_consolidation", "Step 16: URL Consolidation & Live Check"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}
	writeEmptyFile(c.F.AllURLsRaw)
	_ = os.Remove(c.F.AllURLsLive)

	sources := c.urlSources()
	logger.SubStep("Merging URLs from %d sources...", len(sources))
	logger.FileDebug("url_consolidation sources: %v", sources)
	if err := utils.MergeAndDeduplicate(sources, c.F.AllURLsRaw); err != nil {
		c.markStepFailedSafe("url_consolidation", err)
		logger.Warning("URL merge failed: %v", err)
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	// Sanitize: unescape \uXXXX sequences, strip non-URL lines (GoSpider tags,
	// relative paths from GoLinkFinder), and re-deduplicate.
	// We also filter out any out-of-scope hostnames.
	isAllowedHost := func(host string) bool {
		host = strings.ToLower(strings.TrimSpace(host))
		if c.ScopeFilter != nil {
			return c.ScopeFilter.IsInScope(host) && !c.ScopeFilter.IsOutOfScope(host)
		}
		return host == c.Domain || strings.HasSuffix(host, "."+c.Domain)
	}
	if err := utils.SanitizeURLFile(c.F.AllURLsRaw, isAllowedHost); err != nil {
		logger.Warning("URL sanitization failed: %v", err)
	}
	rawCount, _ := utils.CountFileLines(c.F.AllURLsRaw)
	logger.Info("Consolidated %d unique URLs from all sources", rawCount)
	logger.FileDebug("url_consolidation merged %d raw URLs -> %s", rawCount, c.F.AllURLsRaw)

	// Live-check all URLs with httpx
	urlCheckSkipped, usedFallback := liveCheckConsolidatedURLs(c)

	// Persist live URLs into DB so GetScanStats / query commands reflect reality.
	// This is intentionally after the skip/fallback block so both paths populate the DB.
	persistLiveURLs(c, urlCheckSkipped, usedFallback)

	// ROI metadata enrichment (capped at per-host 5 and total metadataHostCap=250)
	enrichROIMetadata(c)

	c.markStepCompleteIfNoFailure("url_consolidation")
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// liveCheckConsolidatedURLs runs the httpx URL live-check, falling back to
// the raw URL set when no fresh output exists.
func liveCheckConsolidatedURLs(c *Ctx) (urlCheckSkipped, usedFallback bool) {
	logger.ToolStart("httpx")
	rawCount2, _ := utils.CountFileLines(c.F.AllURLsRaw)
	logger.FileDebug("httpx_url_check input: %s (%d URLs) out=%s", c.F.AllURLsRaw, rawCount2, c.F.AllURLsLive)
	if err := runWithSkip(c, "httpx (URL check)", func(sCtx context.Context) error {
		return c.Tb.RunHttpxURLCheck(sCtx, c.F.AllURLsRaw, c.F.AllURLsLive)
	}); err != nil {
		if err == ErrToolSkipped {
			urlCheckSkipped = true
		} else {
			c.markStepFailedSafe("url_consolidation", err)
			logger.Warning("URL live-check failed: %v", err)
		}
		// Fallback: use raw URLs if live-check fails/is skipped and no
		// fresh output exists from this scan session.
		if !utils.FileExists(c.F.AllURLsLive) || !fileModifiedAfter(c.F.AllURLsLive, c.StartTime) {
			usedFallback = true
			logger.Info("Live-check unavailable — using unverified URLs")
			if err := copyFile(c.F.AllURLsRaw, c.F.AllURLsLive); err != nil {
				logger.Warning("Failed to copy raw URLs as fallback: %v", err)
			}
		}
	} else {
		liveCount, _ := utils.CountFileLines(c.F.AllURLsLive)
		logger.Success("  %d live URLs confirmed", liveCount)
		logger.FileDebug("httpx_url_check output: %d live URLs -> %s", liveCount, c.F.AllURLsLive)
	}
	return urlCheckSkipped, usedFallback
}

// persistLiveURLs stores the live URL set into the DB and logs the
// consolidated count.
func persistLiveURLs(c *Ctx, urlCheckSkipped, usedFallback bool) {
	if c.ScanID <= 0 || !utils.FileExists(c.F.AllURLsLive) {
		return
	}
	if dbCount, err := ingest.ParseLiveURLsFile(c.ScanID, c.F.AllURLsLive, "httpx-url-check"); err != nil {
		logger.Warning("Failed to persist live URLs to DB: %v", err)
	} else {
		label := ""
		if usedFallback {
			label = " (from fallback)"
		} else if urlCheckSkipped {
			label = " (partial)"
		}
		logger.Result(dbCount, "verified live URLs consolidated%s", label)
	}
}

// enrichROIMetadata collects lightweight metadata for high-value URLs.
func enrichROIMetadata(c *Ctx) {
	if c.ScanID <= 0 || !utils.FileExists(c.F.AllURLsLive) {
		return
	}
	metaTargetCount := collectROIMetadataTargetsFromFile(c.F.AllURLsLive, c.F.ROIMetadataTargets, 5, metadataHostCap)
	if metaTargetCount <= 0 {
		return
	}
	logger.SubStep("Collecting lightweight metadata for %d high-value URLs...", metaTargetCount)
	metaTargets, _ := utils.ReadNonEmptyLines(c.F.ROIMetadataTargets)
	if len(metaTargets) > metadataHostCap {
		metaTargets = metaTargets[:metadataHostCap]
	}
	if count, err := metadata.CollectURLMetadata(c.GoCtx, c.ScanID, metaTargets, c.Proxy); err != nil {
		logger.Warning("URL metadata enrichment failed: %v", err)
	} else if count > 0 {
		logger.Result(count, "ROI candidate URLs enriched with metadata")
	}
}

// ─────────────────────────────────────────────────────────────
// Step 17 — Directory Fuzzing (ffuf)
// ─────────────────────────────────────────────────────────────

// ffufMaxTimeout returns the total time budget for the entire ffuf step
// (all hosts combined), not per-host.
func ffufMaxTimeout(c *Ctx) time.Duration {
	if c != nil && c.Cfg != nil && c.Cfg.Tools.Ffuf.MaxTimeout > 0 {
		return time.Duration(c.Cfg.Tools.Ffuf.MaxTimeout) * time.Minute
	}
	return time.Duration(config.DefaultConfig().Tools.Ffuf.MaxTimeout) * time.Minute
}

// stepDirFuzzing runs ffuf when a wordlist is provided via --wordlist.
// A single timeout (ffuf MaxTimeout) applies to the entire step, not per-host.
// Returns true if the scan should be cancelled.
func stepDirFuzzing(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("dir_fuzzing", "Step 14: Directory Fuzzing (ffuf)"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}

	if !resolveFfufWordlist(c) {
		c.markStepCompleteIfNoFailure("dir_fuzzing")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	writeEmptyFile(c.F.FfufOut)
	writeEmptyFile(c.F.FfufDiscoveredURLs)
	// Remove leftover ffuf temp files from aborted runs so stale results are
	// never parsed into the current scan.
	cleanupFfufTmpFiles(c.F.FfufOut)

	// Validate wordlist file exists before invoking ffuf.
	if !utils.FileExists(c.WordlistPath) {
		logger.Warning("ffuf wordlist not found: %s", c.WordlistPath)
		logger.Info("Install seclists (apt install seclists / pacman -S seclists) or provide a valid --wordlist path")
		logger.FileDebug("ffuf skipped: wordlist does not exist at %s", c.WordlistPath)
		c.markStepCompleteIfNoFailure("dir_fuzzing")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	liveHosts := ffufTargetHosts(c)

	var allResults []localFfufResult
	var resultsMu sync.Mutex

	logger.ToolStart("ffuf")

	var ffufSkipped bool
	if err := runWithSkip(c, "ffuf", func(sCtx context.Context) error {
		return fuzzAllHostsWithFfuf(c, sCtx, liveHosts, &allResults, &resultsMu)
	}); err != nil {
		if err == ErrToolSkipped {
			ffufSkipped = true
		} else {
			c.markStepFailedSafe("dir_fuzzing", err)
			logger.Warning("ffuf failed: %v", err)
		}
	} else {
		logger.ToolDone("ffuf")
	}

	writeFfufOutputs(c, allResults)

	if c.ScanID > 0 && utils.FileExists(c.F.FfufOut) {
		count, err := ingest.ParseFfufOutput(c.ScanID, c.F.FfufOut)
		if err != nil {
			logger.Warning("Failed to parse ffuf results: %v", err)
		} else {
			c.FfufTotalFindings = count
			label := ""
			if ffufSkipped {
				label = " (partial)"
			}
			logger.Result(count, "hidden paths discovered via fuzzing%s", label)
		}
	}

	c.markStepCompleteIfNoFailure("dir_fuzzing")
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// localFfufResult mirrors one hit in ffuf's JSON output.
type localFfufResult struct {
	Input  map[string]string `json:"input"`
	URL    string            `json:"url"`
	Status int               `json:"status"`
}

// resolveFfufWordlist fills c.WordlistPath from SecLists when unset and
// returns false when no wordlist is available (step should skip).
func resolveFfufWordlist(c *Ctx) bool {
	if c.WordlistPath != "" {
		return true
	}
	if autoWl := config.ResolveSecListFile("Discovery/Web-Content/common.txt"); autoWl != "" {
		c.WordlistPath = autoWl
		logger.Info("Auto-detected SecLists wordlist for ffuf: %s", autoWl)
		return true
	}
	logger.StepHeader("Step 14: Skipping Directory Fuzzing (no wordlist — run 'chaathan setup')")
	logger.Info("Provide --wordlist or run 'chaathan setup' to install SecLists")
	return false
}

// ffufTargetHosts returns the ROI-ranked, capped live-host list, falling
// back to the root domain when no live hosts exist. Ranking before the cap
// guarantees the highest-value hosts win the fuzzing budget instead of
// whichever hosts happen to sit first in the file (port variants of
// low-signal hosts would otherwise consume cap slots).
func ffufTargetHosts(c *Ctx) []string {
	liveHosts, _ := utils.ReadNonEmptyLines(c.F.HttpxLiveHosts)
	liveHosts = rankLiveHosts(c.ScanID, liveHosts)
	if len(liveHosts) > ffufHostCap {
		liveHosts = liveHosts[:ffufHostCap]
	}
	if len(liveHosts) == 0 {
		// Fallback to root domain
		liveHosts = []string{"https://" + c.Domain}
	}
	return liveHosts
}

// fuzzAllHostsWithFfuf runs ffuf across all hosts under a single step
// timeout, granting each host a fair per-host budget (total / host count,
// floor 2 min) so one slow host cannot consume the budget of the rest.
// Decoded results are appended under resultsMu.
func fuzzAllHostsWithFfuf(c *Ctx, sCtx context.Context, liveHosts []string, allResults *[]localFfufResult, resultsMu *sync.Mutex) error {
	// Apply a single timeout for the entire ffuf step (all hosts combined).
	totalBudget := ffufMaxTimeout(c)
	stepCtx, cancel := context.WithTimeout(sCtx, totalBudget)
	defer cancel()

	perHostBudget := totalBudget / time.Duration(len(liveHosts))
	if perHostBudget < 2*time.Minute {
		perHostBudget = 2 * time.Minute
	}

	for _, host := range liveHosts {
		select {
		case <-stepCtx.Done():
			return stepCtx.Err()
		default:
		}
		hostCtx, hostCancel := context.WithTimeout(stepCtx, perHostBudget)
		fuzzSingleHost(c, hostCtx, host, allResults, resultsMu)
		hostCancel()
	}
	return nil
}

// fuzzSingleHost fuzzes one host and appends decoded ffuf results.
func fuzzSingleHost(c *Ctx, stepCtx context.Context, host string, allResults *[]localFfufResult, resultsMu *sync.Mutex) {
	target := host
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	targetURL := target
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}
	targetURL += "FUZZ"

	// Unique per-host temp file: os.CreateTemp guarantees no collision
	// with stale files from aborted runs.
	tmpFfuf, tmpErr := os.CreateTemp(filepath.Dir(c.F.FfufOut), "ffuf_tmp_*.json")
	if tmpErr != nil {
		logger.Warning("ffuf: cannot create temp output file: %v", tmpErr)
		return
	}
	tmpFfufOut := tmpFfuf.Name()
	tmpFfuf.Close() // ffuf manages the file itself

	logger.FileDebug("ffuf input: target=%s wordlist=%s out=%s", targetURL, c.WordlistPath, tmpFfufOut)
	if err := c.Tb.RunFfufWithFUZZ(stepCtx, targetURL, c.WordlistPath, tmpFfufOut); err == nil && utils.FileExists(tmpFfufOut) {
		appendFfufResults(tmpFfufOut, allResults, resultsMu)
	} else if err != nil && stepCtx.Err() == nil {
		logger.Warning("ffuf failed on host %s: %v", targetURL, err)
	} else if err != nil && errors.Is(stepCtx.Err(), context.DeadlineExceeded) {
		logger.FileDebug("ffuf per-host budget exhausted on %s", targetURL)
	}
	os.Remove(tmpFfufOut)
}

// appendFfufResults decodes ffuf's JSON output and appends the hits.
func appendFfufResults(tmpFfufOut string, allResults *[]localFfufResult, resultsMu *sync.Mutex) {
	fIn, openErr := os.Open(tmpFfufOut)
	if openErr != nil {
		return
	}
	var payload struct {
		Results []localFfufResult `json:"results"`
	}
	if jsonErr := json.NewDecoder(fIn).Decode(&payload); jsonErr == nil {
		resultsMu.Lock()
		*allResults = append(*allResults, payload.Results...)
		resultsMu.Unlock()
	}
	fIn.Close()
}

// writeFfufOutputs writes the consolidated ffuf JSON and the discovered URL
// list.
func writeFfufOutputs(c *Ctx, allResults []localFfufResult) {
	// Write consolidated results to c.F.FfufOut
	consolidatedPayload := struct {
		Results []localFfufResult `json:"results"`
	}{Results: allResults}
	if jsData, err := json.Marshal(consolidatedPayload); err == nil {
		_ = os.WriteFile(c.F.FfufOut, jsData, 0644)
	}

	// Write extracted URLs to c.F.FfufDiscoveredURLs (deduplicated — the same
	// path can be discovered on multiple hosts).
	if len(allResults) > 0 {
		var urls []string
		for _, res := range allResults {
			if u := strings.TrimSpace(res.URL); u != "" {
				urls = append(urls, u)
			}
		}
		if urls = utils.DedupeLines(urls); len(urls) > 0 {
			writeStringLinesFile(c.F.FfufDiscoveredURLs, urls)
		}
	}
}

// cleanupFfufTmpFiles removes leftover ffuf temp files (ffuf_tmp_*.json) from
// aborted runs in the same directory as referenceFile.
func cleanupFfufTmpFiles(referenceFile string) {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(referenceFile), "ffuf_tmp_*.json"))
	if err != nil {
		return
	}
	for _, m := range matches {
		_ = os.Remove(m)
	}
}

// extractPrimaryURL strips auxiliary tokens (like httpx status codes) and
// returns the leading URL field from a scanner line.
func extractPrimaryURL(raw string) string {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// isUsefulJSURL checks if a URL is a JavaScript file and filters out common
// third-party libraries to maximize the value of the JS download limit.
func isUsefulJSURL(raw string) bool {
	if !isJavaScriptURL(raw) {
		return false
	}

	lower := strings.ToLower(raw)

	stopwords := []string{
		"jquery", "bootstrap", "react", "react-dom", "vue", "angular",
		"moment", "lodash", "underscore", "chart", "d3", "analytics",
		"gtm.js", "google-analytics", "ads.js", "tracking", "fontawesome",
		"recaptcha", "polyfill", "vendor.js", "node_modules", "swagger-ui",
	}

	for _, stopword := range stopwords {
		if strings.Contains(lower, stopword) {
			return false
		}
	}
	return true
}

// isJavaScriptURL returns true when the URL path ends in .js, ignoring query
// strings and fragments.
func isJavaScriptURL(raw string) bool {
	raw = extractPrimaryURL(raw)
	if raw == "" {
		return false
	}
	if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.HasSuffix(strings.ToLower(raw), ".js")
}

// ─────────────────────────────────────────────────────────────
// convertX8ToURLs — Step 16 helper
// ─────────────────────────────────────────────────────────────

// x8Result represents one entry in x8's -O json output.
type x8Result struct {
	Method      string             `json:"method"`
	URL         string             `json:"url"`
	FoundParams []x8FoundParameter `json:"found_params"`
}

type x8FoundParameter struct {
	Name string `json:"name"`
}

// parseX8Results tolerantly parses x8 JSON output. x8 normally emits one JSON
// object per line; retried, truncated, or noise-polluted runs can leave the
// file as multiple concatenated documents or a partial trailing line, which
// breaks whole-file unmarshalling. We try the whole file first, then fall back
// to per-line extraction, deduplicating by URL in both paths.
func parseX8Results(data []byte) []x8Result {
	var results []x8Result
	if err := json.Unmarshal(data, &results); err == nil {
		return dedupeX8Results(results)
	}

	var out []x8Result
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var single x8Result
		if err := json.Unmarshal([]byte(line), &single); err != nil {
			continue
		}
		if single.URL == "" || seen[single.URL] {
			continue
		}
		seen[single.URL] = true
		out = append(out, single)
	}
	return out
}

// dedupeX8Results removes duplicate entries (by URL) from parsed x8 results.
func dedupeX8Results(results []x8Result) []x8Result {
	seen := make(map[string]bool, len(results))
	out := results[:0]
	for _, r := range results {
		if r.URL == "" || seen[r.URL] {
			continue
		}
		seen[r.URL] = true
		out = append(out, r)
	}
	return out
}

// convertX8ToURLs parses x8's JSON output and writes parameterized URLs
// to outputFile.
func convertX8ToURLs(x8JSON, outputFile string) int {
	if !utils.FileExists(x8JSON) {
		return 0
	}

	data, err := os.ReadFile(x8JSON)
	if err != nil || len(data) == 0 {
		return 0
	}

	results := parseX8Results(data)

	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	count := 0
	for _, r := range results {
		if r.URL == "" || len(r.FoundParams) == 0 {
			continue
		}
		var paramPairs []string
		for _, p := range r.FoundParams {
			if p.Name != "" {
				paramPairs = append(paramPairs, url.QueryEscape(p.Name)+"=1")
			}
		}
		if len(paramPairs) == 0 {
			continue
		}
		qs := strings.Join(paramPairs, "&")
		// Insert discovered params before any #fragment — appending blindly
		// would bury them inside the fragment where servers never see them.
		base := r.URL
		if parsed, perr := url.Parse(r.URL); perr == nil {
			if parsed.RawQuery != "" {
				parsed.RawQuery += "&" + qs
			} else {
				parsed.RawQuery = qs
			}
			base = parsed.String()
		} else if strings.Contains(base, "?") {
			base += "&" + qs
		} else {
			base += "?" + qs
		}
		fmt.Fprintln(w, base)
		count++
	}
	w.Flush()
	return count
}

// storeX8ParamCounts parses x8's JSON output and stores the number of
// discovered parameters per URL in url_metadata for ROI scoring.
func storeX8ParamCounts(scanID int64, x8JSON string) int {
	if !utils.FileExists(x8JSON) {
		return 0
	}

	data, err := os.ReadFile(x8JSON)
	if err != nil || len(data) == 0 {
		return 0
	}

	results := parseX8Results(data)

	stored := 0
	for _, r := range results {
		if r.URL == "" || len(r.FoundParams) == 0 {
			continue
		}
		parsed, parseErr := url.Parse(strings.TrimSpace(r.URL))
		if parseErr != nil || parsed.Hostname() == "" {
			continue
		}
		err := database.UpsertURLMetadata(scanID, database.URLMetadata{
			URL:        r.URL,
			Host:       strings.ToLower(parsed.Hostname()),
			ParamCount: len(r.FoundParams),
		})
		if err != nil {
			logger.Warning("Failed to store x8 param count for %s: %v", r.URL, err)
		} else {
			stored++
		}
	}
	return stored
}
