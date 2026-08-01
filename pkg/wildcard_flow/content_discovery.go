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
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/database"
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
func stepURLDiscovery(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("url_discovery", "Step 11: Historical URL Discovery"); skipped {
		return cancelled
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
			count, _ := ingest.ParseURLsFile(c.ScanID, c.F.WaybackOut, "waybackurls")
			if count > 0 {
				label := ""
				if urlDiscoverySkipped {
					label = " (partial)"
				}
				logger.Result(count, "historical URLs (Waybackurls)%s", label)
			} else if !urlDiscoverySkipped {
				logger.Result(0, "historical URLs (Waybackurls)")
			}
		}
		if utils.FileExists(c.F.GauOut) {
			count, _ := ingest.ParseURLsFile(c.ScanID, c.F.GauOut, "gau")
			if count > 0 {
				label := ""
				if urlDiscoverySkipped {
					label = " (partial)"
				}
				logger.Result(count, "historical URLs (GAU)%s", label)
			} else if !urlDiscoverySkipped {
				logger.Result(0, "historical URLs (GAU)")
			}
		}
	}

	waybackCount, _ := utils.CountFileLines(c.F.WaybackOut)
	gauCount, _ := utils.CountFileLines(c.F.GauOut)
	if urlDiscoverySkipped || waybackOK || gauOK || waybackCount > 0 || gauCount > 0 {
		c.markStepCompleteIfNoFailure("url_discovery")
	} else {
		c.markStepFailedSafe("url_discovery", fmt.Errorf("both Waybackurls and GAU failed"))
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 12 — Web Crawling (Katana + GoSpider)
// ─────────────────────────────────────────────────────────────

// stepWebCrawling runs Katana and GoSpider in parallel.
// Returns true if the scan should be cancelled.
func stepWebCrawling(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("web_crawling", "Step 12: Web Crawling"); skipped {
		return cancelled
	}

	if c.SkipCrawl {
		logger.StepHeader("Step 12: Skipping Web Crawling (--skip-crawl)")
		c.markStepCompleteIfNoFailure("web_crawling")
		return c.cancelled()
	}
	writeEmptyFile(c.F.KatanaOut)
	writeEmptyFile(c.F.GospiderOut)
	var katanaOK, gospiderOK bool
	var crawlMu sync.Mutex

	liveHostCount, _ := utils.CountFileLines(c.F.HttpxLiveHosts)
	if liveHostCount == 0 {
		logger.Warning("No live hosts found — skipping web crawling")
		c.markStepCompleteIfNoFailure("web_crawling")
		return c.cancelled()
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
			count, _ := ingest.ParseURLsFile(c.ScanID, c.F.KatanaOut, "katana")
			if count > 0 {
				label := ""
				if crawlSkipped {
					label = " (partial)"
				}
				logger.Result(count, "crawled URLs (Katana)%s", label)
			} else if !crawlSkipped {
				logger.Result(0, "crawled URLs (Katana)")
			}
		}
		if utils.FileExists(c.F.GospiderOut) {
			count, _ := ingest.ParseURLsFile(c.ScanID, c.F.GospiderOut, "gospider")
			if count > 0 {
				label := ""
				if crawlSkipped {
					label = " (partial)"
				}
				logger.Result(count, "crawled URLs (GoSpider)%s", label)
			} else if !crawlSkipped {
				logger.Result(0, "crawled URLs (GoSpider)")
			}
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
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 16 — HTTP Parameter Discovery (x8)
// ─────────────────────────────────────────────────────────────

// stepParamDiscovery discovers HTTP parameters with x8 (Step 16).
// After a successful run it converts discovered params into parameterized URLs
// (written to X8URLsOut) so they flow into Step 17 consolidation and
// downstream scanners (Nuclei/Dalfox).
// Returns true if the scan should be cancelled.
func stepParamDiscovery(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("param_discovery", "Step 15: HTTP Parameter Discovery (x8)"); skipped {
		return cancelled
	}

	if c.SkipX8 {
		logger.StepHeader("Step 15: Skipping x8 (--skip-x8)")
		c.markStepCompleteIfNoFailure("param_discovery")
		return c.cancelled()
	}

	writeEmptyFile(c.F.X8Out)
	writeEmptyFile(c.F.X8URLsOut)

	// Preflight check
	liveHostCount, _ := utils.CountFileLines(c.F.HttpxLiveHosts)
	if liveHostCount == 0 {
		logger.Warning("No live hosts found — skipping x8 parameter discovery")
		c.markStepCompleteIfNoFailure("param_discovery")
		return c.cancelled()
	}

	// Merge FfufDiscoveredURLs and high-signal endpoints into a temporary input file
	x8InputFile := c.F.X8Input

	var x8Targets []string

	// Add ffuf fuzzing results
	if utils.FileExists(c.F.FfufDiscoveredURLs) {
		x8Targets = append(x8Targets, loadLineSlice(c.F.FfufDiscoveredURLs, 0)...)
	}

	// Collect and add high-signal crawler endpoints (no limit to collect all possible targets)
	crawlerFiles := []string{
		c.F.WaybackOut,
		c.F.GauOut,
		c.F.KatanaOut,
		c.F.GospiderOut,
		c.F.JSEndpointsOut,
	}
	highSignal := collectHighSignalEndpoints(crawlerFiles)
	x8Targets = append(x8Targets, highSignal...)

	// Deduplicate targets and cap at paramDiscoveryCap (150)
	x8Targets = utils.DeduplicateSlice(x8Targets)
	if len(x8Targets) > paramDiscoveryCap {
		x8Targets = x8Targets[:paramDiscoveryCap]
	}

	if len(x8Targets) == 0 {
		logger.Warning("No targets found for parameter discovery — skipping x8")
		c.markStepCompleteIfNoFailure("param_discovery")
		return c.cancelled()
	}

	// Write targets to x8InputFile
	if fIn, err := os.Create(x8InputFile); err == nil {
		for _, t := range x8Targets {
			_, _ = fIn.WriteString(t + "\n")
		}
		fIn.Close()
	} else {
		c.markStepFailedSafe("param_discovery", err)
		logger.Error("Failed to prepare x8 input: %v", err)
		return c.cancelled()
	}

	logger.ToolStart("x8")

	// Validate parameters wordlist if configured or available via SecLists.
	paramWordlist := ""
	if c.Cfg != nil && c.Cfg.General.Wordlists.Parameters != "" && utils.FileExists(c.Cfg.General.Wordlists.Parameters) {
		paramWordlist = c.Cfg.General.Wordlists.Parameters
	} else if autoWl := config.ResolveSecListFile("Discovery/Web-Content/burp-parameter-names.txt"); autoWl != "" {
		paramWordlist = autoWl
		logger.Info("Auto-detected SecLists parameter wordlist for x8: %s", autoWl)
	} else {
		if c.Cfg != nil && c.Cfg.General.Wordlists.Parameters != "" {
			logger.Warning("x8 parameters wordlist not found: %s", c.Cfg.General.Wordlists.Parameters)
		}
		logger.Info("  SecLists parameter wordlist not found on device — falling back to x8's built-in parameter list")
	}

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
		logger.Result(count, "parameterized URLs from x8%s", label)
		if stored > 0 {
			logger.Info("  Stored x8 param counts for %d URLs%s", stored, label)
		}
	}

	c.markStepCompleteIfNoFailure("param_discovery")
	return c.cancelled()
}

// collectHighSignalEndpoints reads raw URLs from crawler and discovery files,
// filters for high-signal parameters/endpoints (dynamic extensions, API paths, interesting keywords),
// deduplicates them by host+path, and returns a slice of URLs.
func collectHighSignalEndpoints(files []string) []string {
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

			// Clean/normalize path
			pathLower := strings.ToLower(parsed.Path)

			// Match criteria
			isDynamic := false

			// 1. Check extensions
			for _, ext := range extensions {
				if strings.HasSuffix(pathLower, ext) || strings.Contains(pathLower, ext+"/") {
					isDynamic = true
					break
				}
			}

			// 2. Check keywords in path
			if !isDynamic {
				for _, kw := range keywords {
					if strings.Contains(pathLower, kw) {
						isDynamic = true
						break
					}
				}
			}

			// 3. Check if it already has query parameters (high signal for dynamic behavior)
			if !isDynamic && parsed.RawQuery != "" {
				isDynamic = true
			}

			if isDynamic {
				// Normalize to host+path for deduplication (strip query params and fragment)
				dedupKey := parsed.Scheme + "://" + parsed.Host + parsed.Path
				if !seen[dedupKey] {
					seen[dedupKey] = true
					// Keep the original URL
					endpoints = append(endpoints, rawURL)
				}
			}
		}
		f.Close()
	}

	return endpoints
}

// ─────────────────────────────────────────────────────────────
// Step 15 — URL Consolidation & Live Check
// ─────────────────────────────────────────────────────────────

// stepURLConsolidation merges all URL sources, live-checks them with Httpx,
// and enriches ROI metadata for high-value targets.
// Returns true if the scan should be cancelled.
func stepURLConsolidation(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("url_consolidation", "Step 16: URL Consolidation & Live Check"); skipped {
		return cancelled
	}
	writeEmptyFile(c.F.AllURLsRaw)
	_ = os.Remove(c.F.AllURLsLive)

	sources := c.urlSources()
	logger.SubStep("Merging URLs from %d sources...", len(sources))
	logger.FileDebug("url_consolidation sources: %v", sources)
	if err := utils.MergeAndDeduplicate(sources, c.F.AllURLsRaw); err != nil {
		c.markStepFailedSafe("url_consolidation", err)
		logger.Warning("URL merge failed: %v", err)
		return c.cancelled()
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
	logger.Info("  Merged %d unique URLs", rawCount)
	logger.FileDebug("url_consolidation merged %d raw URLs -> %s", rawCount, c.F.AllURLsRaw)

	// Live-check all URLs with httpx
	logger.ToolStart("httpx")
	rawCount2, _ := utils.CountFileLines(c.F.AllURLsRaw)
	logger.FileDebug("httpx_url_check input: %s (%d URLs) out=%s", c.F.AllURLsRaw, rawCount2, c.F.AllURLsLive)
	var urlCheckSkipped bool
	var usedFallback bool
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
			logger.Info("  Using raw URLs as fallback")
			copyFile(c.F.AllURLsRaw, c.F.AllURLsLive)
		}
	} else {
		liveCount, _ := utils.CountFileLines(c.F.AllURLsLive)
		logger.Success("  %d live URLs confirmed", liveCount)
		logger.FileDebug("httpx_url_check output: %d live URLs -> %s", liveCount, c.F.AllURLsLive)
	}

	// Persist live URLs into DB so GetScanStats / query commands reflect reality.
	// This is intentionally after the skip/fallback block so both paths populate the DB.
	if c.ScanID > 0 && utils.FileExists(c.F.AllURLsLive) {
		if dbCount, err := ingest.ParseLiveURLsFile(c.ScanID, c.F.AllURLsLive, "httpx-url-check"); err != nil {
			logger.Warning("Failed to persist live URLs to DB: %v", err)
		} else {
			label := ""
			if usedFallback {
				label = " (from fallback)"
			} else if urlCheckSkipped {
				label = " (partial)"
			}
			logger.Result(dbCount, "live URLs consolidated%s", label)
		}
	}

	// ROI metadata enrichment (capped at per-host 5 and total metadataHostCap=250)
	if c.ScanID > 0 && utils.FileExists(c.F.AllURLsLive) {
		metaTargetCount := collectROIMetadataTargetsFromFile(c.F.AllURLsLive, c.F.ROIMetadataTargets, 5, metadataHostCap)
		if metaTargetCount > 0 {
			logger.SubStep("Collecting lightweight metadata for %d high-value URLs...", metaTargetCount)
			metaTargets := loadLineSlice(c.F.ROIMetadataTargets, metadataHostCap)
			if count, err := metadata.CollectURLMetadata(c.GoCtx, c.ScanID, metaTargets, c.Proxy); err != nil {
				logger.Warning("URL metadata enrichment failed: %v", err)
			} else if count > 0 {
				logger.Result(count, "ROI candidate URLs enriched with metadata")
			}
		}
	}

	c.markStepCompleteIfNoFailure("url_consolidation")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 17 — Directory Fuzzing (ffuf)
// ─────────────────────────────────────────────────────────────

// stepDirFuzzing runs ffuf when a wordlist is provided via --wordlist.
// Returns true if the scan should be cancelled.
func stepDirFuzzing(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("dir_fuzzing", "Step 14: Directory Fuzzing (ffuf)"); skipped {
		return cancelled
	}

	if c.WordlistPath == "" {
		if autoWl := config.ResolveSecListFile("Discovery/Web-Content/common.txt"); autoWl != "" {
			c.WordlistPath = autoWl
			logger.Info("Auto-detected SecLists wordlist for ffuf: %s", autoWl)
		} else {
			logger.StepHeader("Step 14: Skipping ffuf (no wordlist provided and SecLists not found on device)")
			logger.Info("Provide --wordlist or run 'chaathan setup' to install SecLists")
			c.markStepCompleteIfNoFailure("dir_fuzzing")
			return c.cancelled()
		}
	}

	writeEmptyFile(c.F.FfufOut)
	writeEmptyFile(c.F.FfufDiscoveredURLs)
	// Remove leftover ffuf temp files from aborted runs so stale results are
	// never parsed into the current scan.
	cleanupFfufTmpFiles(c.F.FfufOut)

	// Validate wordlist file exists before invoking ffuf.
	if !utils.FileExists(c.WordlistPath) {
		logger.Warning("ffuf wordlist not found: %s", c.WordlistPath)
		logger.Info("  Install seclists (apt install seclists / pacman -S seclists) or provide a valid --wordlist path")
		logger.FileDebug("ffuf skipped: wordlist does not exist at %s", c.WordlistPath)
		c.markStepCompleteIfNoFailure("dir_fuzzing")
		return c.cancelled()
	}

	liveHosts := loadLineSlice(c.F.HttpxLiveHosts, ffufHostCap)
	if len(liveHosts) == 0 {
		// Fallback to root domain
		liveHosts = []string{"https://" + c.Domain}
	}

	type localFfufResult struct {
		Input  map[string]string `json:"input"`
		URL    string            `json:"url"`
		Status int               `json:"status"`
	}

	var allResults []localFfufResult
	var resultsMu sync.Mutex

	logger.ToolStart("ffuf")

	var ffufSkipped bool
	if err := runWithSkip(c, "ffuf", func(sCtx context.Context) error {
		for _, host := range liveHosts {
			select {
			case <-sCtx.Done():
				return sCtx.Err()
			default:
			}

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
				continue
			}
			tmpFfufOut := tmpFfuf.Name()
			tmpFfuf.Close() // ffuf manages the file itself

			logger.FileDebug("ffuf input: target=%s wordlist=%s out=%s", targetURL, c.WordlistPath, tmpFfufOut)
			if err := c.Tb.RunFfufWithFUZZ(sCtx, targetURL, c.WordlistPath, tmpFfufOut); err == nil && utils.FileExists(tmpFfufOut) {
				if fIn, openErr := os.Open(tmpFfufOut); openErr == nil {
					var payload struct {
						Results []localFfufResult `json:"results"`
					}
					if jsonErr := json.NewDecoder(fIn).Decode(&payload); jsonErr == nil {
						resultsMu.Lock()
						allResults = append(allResults, payload.Results...)
						resultsMu.Unlock()
					}
					fIn.Close()
				}
			} else if err != nil && sCtx.Err() == nil {
				logger.Warning("ffuf failed on host %s: %v", targetURL, err)
			}
			os.Remove(tmpFfufOut)
		}
		return nil
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

	// Write consolidated results to c.F.FfufOut
	consolidatedPayload := struct {
		Results []localFfufResult `json:"results"`
	}{Results: allResults}
	if jsData, err := json.Marshal(consolidatedPayload); err == nil {
		_ = os.WriteFile(c.F.FfufOut, jsData, 0644)
	}

	// Write extracted URLs to c.F.FfufDiscoveredURLs
	if len(allResults) > 0 {
		if fUrls, err := os.Create(c.F.FfufDiscoveredURLs); err == nil {
			for _, res := range allResults {
				if strings.TrimSpace(res.URL) != "" {
					_, _ = fUrls.WriteString(res.URL + "\n")
				}
			}
			fUrls.Close()
		}
	}

	if c.ScanID > 0 && utils.FileExists(c.F.FfufOut) {
		count, err := ingest.ParseFfufOutput(c.ScanID, c.F.FfufOut)
		if err != nil {
			logger.Warning("Failed to parse ffuf results: %v", err)
		} else {
			if count > 0 {
				c.FfufTotalFindings = count
				label := ""
				if ffufSkipped {
					label = " (partial)"
				}
				logger.Result(count, "directory discoveries (ffuf)%s", label)
			} else if !ffufSkipped {
				logger.Result(0, "directory discoveries (ffuf)")
			}
		}
	}

	c.markStepCompleteIfNoFailure("dir_fuzzing")
	return c.cancelled()
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

// collectJSURLsFromFile filters live URLs for JavaScript files, deduplicates
// them, and writes up to limit entries into outputFile.
func collectJSURLsFromFile(inputFile, outputFile string, limit int) int {
	file, err := os.Open(inputFile)
	if err != nil {
		writeEmptyFile(outputFile)
		return 0
	}
	defer file.Close()

	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	seen := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := extractPrimaryURL(scanner.Text())
		if line == "" || seen[line] || !isUsefulJSURL(line) {
			continue
		}
		seen[line] = true
		fmt.Fprintln(f, line)
		count++
		if limit > 0 && count >= limit {
			break
		}
	}
	return count
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
		base := r.URL
		if strings.Contains(base, "?") {
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
