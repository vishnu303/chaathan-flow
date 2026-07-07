// Phase 3 — Content Discovery (Steps 12–18)
//
// Discovers URLs, endpoints, and directories from live hosts.
// Wayback/GAU run here (not in Phase 1) so URLs are collected
// only for validated live hosts.
//
//  12. Historical URL Discovery (Waybackurls + GAU) [Parallel]
//  13. Web Crawling (Katana + GoSpider) [Parallel, Optional]
//  14. JavaScript Analysis — Endpoint Discovery (GoLinkFinder)
//  15. Directory Fuzzing (ffuf) [Optional — requires --wordlist]
//  16. HTTP Parameter Discovery (Arjun) [Optional]
//  17. URL Consolidation & Live Check (httpx) + ROI metadata
//  18. JS Secret Scan (gf JS + Secrets)
package wildcard_flow

import (
	"bufio"
	"bytes"
	"context"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/pkg/database"
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
	if skipped, cancelled := c.resumeOrSkip("url_discovery", "Step 12: Historical URL Discovery"); skipped {
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
			logger.SubStep("[Start] Waybackurls")
			logger.FileDebug("waybackurls input: domain=%s out=%s", c.Domain, c.F.WaybackOut)
			if err := c.Tb.RunWaybackurls(sCtx, c.Domain, c.F.WaybackOut); err != nil {
				if c.Verbose && sCtx.Err() == nil {
					logger.Warning("Waybackurls failed: %v", err)
				}
				logger.FileDebug("waybackurls failed: %v", err)
			} else {
				resultMu.Lock()
				waybackOK = true
				resultMu.Unlock()
				logger.SubStep("[Done] Waybackurls")
			}
		}()

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] GAU")
			logger.FileDebug("gau input: domain=%s out=%s", c.Domain, c.F.GauOut)
			if err := c.Tb.RunGau(sCtx, c.Domain, c.F.GauOut); err != nil {
				if c.Verbose && sCtx.Err() == nil {
					logger.Warning("GAU failed: %v", err)
				}
				logger.FileDebug("gau failed: %v", err)
			} else {
				resultMu.Lock()
				gauOK = true
				resultMu.Unlock()
				logger.SubStep("[Done] GAU")
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
			count, _ := utils.ParseURLsFile(c.ScanID, c.F.WaybackOut, "waybackurls")
			if count > 0 {
				label := ""
				if urlDiscoverySkipped {
					label = " (partial)"
				}
				logger.Info("  Waybackurls found %d URLs%s", count, label)
			} else if urlDiscoverySkipped {
				logger.Info("  Waybackurls skipped — no URLs found")
			} else {
				logger.Info("  Waybackurls found 0 URLs")
			}
		}
		if utils.FileExists(c.F.GauOut) {
			count, _ := utils.ParseURLsFile(c.ScanID, c.F.GauOut, "gau")
			if count > 0 {
				label := ""
				if urlDiscoverySkipped {
					label = " (partial)"
				}
				logger.Info("  GAU found %d URLs%s", count, label)
			} else if urlDiscoverySkipped {
				logger.Info("  GAU skipped — no URLs found")
			} else {
				logger.Info("  GAU found 0 URLs")
			}
		}
	}

	waybackCount, _ := utils.CountFileLines(c.F.WaybackOut)
	gauCount, _ := utils.CountFileLines(c.F.GauOut)
	if urlDiscoverySkipped || waybackOK || gauOK || waybackCount > 0 || gauCount > 0 {
		c.markStepCompleteSafe("url_discovery")
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
	if skipped, cancelled := c.resumeOrSkip("web_crawling", "Step 13: Web Crawling"); skipped {
		return cancelled
	}

	if c.SkipCrawl {
		logger.StepHeader("Step 13: Skipping Web Crawling (--skip-crawl)")
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
			logger.SubStep("[Start] Katana")
			logger.FileDebug("katana input: %s out=%s", c.F.HttpxLiveHosts, c.F.KatanaOut)
			if err := c.Tb.RunKatana(sCtx, c.F.HttpxLiveHosts, c.F.KatanaOut); err != nil {
				if sCtx.Err() == nil {
					logger.Warning("Katana failed: %v", err)
				}
			} else {
				crawlMu.Lock()
				katanaOK = true
				crawlMu.Unlock()
				logger.SubStep("[Done] Katana")
			}
		}()

		go func() {
			defer wg.Done()
			logger.SubStep("[Start] GoSpider")
			logger.FileDebug("gospider input: %s out=%s", c.F.HttpxLiveHosts, c.F.GospiderOut)
			if err := c.Tb.RunGoSpider(sCtx, c.F.HttpxLiveHosts, c.F.GospiderOut); err != nil {
				if sCtx.Err() == nil {
					logger.Warning("GoSpider failed: %v", err)
				}
			} else {
				crawlMu.Lock()
				gospiderOK = true
				crawlMu.Unlock()
				logger.SubStep("[Done] GoSpider")
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
			count, _ := utils.ParseURLsFile(c.ScanID, c.F.KatanaOut, "katana")
			if count > 0 {
				label := ""
				if crawlSkipped {
					label = " (partial)"
				}
				logger.Info("  Katana found %d URLs%s", count, label)
			} else if crawlSkipped {
				logger.Info("  Katana skipped — no URLs found")
			} else {
				logger.Info("  Katana found 0 URLs")
			}
		}
		if utils.FileExists(c.F.GospiderOut) {
			count, _ := utils.ParseURLsFile(c.ScanID, c.F.GospiderOut, "gospider")
			if count > 0 {
				label := ""
				if crawlSkipped {
					label = " (partial)"
				}
				logger.Info("  GoSpider found %d URLs%s", count, label)
			} else if crawlSkipped {
				logger.Info("  GoSpider skipped — no URLs found")
			} else {
				logger.Info("  GoSpider found 0 URLs")
			}
		}
	}

	// Mark step based on outcome: complete if at least one crawler succeeded
	// or the step was skipped; failed only if both crawlers failed.
	katanaCount, _ := utils.CountFileLines(c.F.KatanaOut)
	gospiderCount, _ := utils.CountFileLines(c.F.GospiderOut)
	if crawlSkipped || katanaOK || gospiderOK || katanaCount > 0 || gospiderCount > 0 {
		c.markStepCompleteSafe("web_crawling")
	} else {
		c.markStepFailedSafe("web_crawling", fmt.Errorf("both Katana and GoSpider failed"))
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 13 — JavaScript Analysis (GoLinkFinder)
// ─────────────────────────────────────────────────────────────

// stepJSAnalysis extracts endpoints from JavaScript files with GoLinkFinder.
// Returns true if the scan should be cancelled.
// filterAndDeduplicateHosts filters live hosts to standard ports 80/443,
// maps bare host:port pairs to their proper scheme based on port,
// and deduplicates by hostname, preferring HTTPS (443) over HTTP (80).
func filterAndDeduplicateHosts(hosts []string) []string {
	type hostPref struct {
		target   string
		priority int // 2 for https (443), 1 for http (80)
	}
	bestUrls := make(map[string]hostPref)

	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}

		target := h
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			port := ""
			if idx := strings.LastIndex(target, ":"); idx != -1 {
				pPart := target[idx+1:]
				if _, err := strconv.Atoi(pPart); err == nil {
					port = pPart
				}
			}

			// Issue 2: map TLS ports to https://, others to http://
			if port == "443" || port == "8443" {
				target = "https://" + target
			} else if port != "" {
				target = "http://" + target
			} else {
				target = "https://" + target
			}
		}

		parsed, err := url.Parse(target)
		if err != nil {
			continue
		}

		hostname := strings.ToLower(parsed.Hostname())
		if hostname == "" {
			continue
		}

		if utils.ValidateDomain(hostname) != nil {
			continue
		}

		port := parsed.Port()
		scheme := strings.ToLower(parsed.Scheme)

		if port == "" {
			if scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}

		// Filter to standard ports 80/443 only (Issue 1)
		if port != "80" && port != "443" {
			continue
		}

		priority := 1
		if scheme == "https" && port == "443" {
			priority = 2
		}

		existing, exists := bestUrls[hostname]
		if !exists || priority > existing.priority {
			bestUrls[hostname] = hostPref{
				target:   target,
				priority: priority,
			}
		}
	}

	var result []string
	for _, pref := range bestUrls {
		result = append(result, pref.target)
	}
	slices.Sort(result) // Ensure deterministic order
	return result
}

// stepJSAnalysis extracts endpoints from JavaScript files with GoLinkFinder.
// Returns true if the scan should be cancelled.
func stepJSAnalysis(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("js_analysis", "Step 14: JavaScript Analysis"); skipped {
		return cancelled
	}
	writeEmptyFile(c.F.GoLinkFinderOut)
	logger.SubStep("Running GoLinkFinder...")

	var golinkfinderSkipped bool
	if err := runWithSkip(c, "GoLinkFinder", func(sCtx context.Context) error {
		liveHosts := loadLineSlice(c.F.HttpxLiveHosts, jsAnalysisHostCap)
		if len(liveHosts) == 0 {
			liveHosts = []string{"https://" + c.Domain}
		}

		// Filter standard ports 80/443 and deduplicate by hostname
		filteredHosts := filterAndDeduplicateHosts(liveHosts)
		if len(filteredHosts) == 0 {
			logger.Info("  No live hosts match standard ports 80/443. Skipping GoLinkFinder.")
			return nil
		}

		concurrency := 5
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		var writeMu sync.Mutex
		var loopErr error

		for _, host := range filteredHosts {
			select {
			case <-sCtx.Done():
				loopErr = sCtx.Err()
				// The outer loop checks loopErr and breaks.
			default:
			}
			if loopErr != nil {
				break
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(target string) {
				defer wg.Done()
				defer func() { <-sem }()

				// Issue 1: Add a per-host timeout of 15s (total, not just HTTP)
				hostCtx, hostCancel := context.WithTimeout(sCtx, 15*time.Second)
				defer hostCancel()

				tmpOut := filepath.Join(filepath.Dir(c.F.GoLinkFinderOut), fmt.Sprintf("golinkfinder_tmp_%d_%d.txt", os.Getpid(), rand.IntN(1000000)))
				// Issue 7: Clean up temp file immediately (replaces defer in outer loop)
				defer os.Remove(tmpOut)

				if err := c.Tb.RunGoLinkFinder(hostCtx, target, tmpOut); err == nil && utils.FileExists(tmpOut) {
					if data, readErr := os.ReadFile(tmpOut); readErr == nil && len(data) > 0 {
						writeMu.Lock()
						fOut, openErr := os.OpenFile(c.F.GoLinkFinderOut, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
						if openErr == nil {
							_, _ = fOut.Write(data)
							fOut.Close()
						}
						writeMu.Unlock()
					}
				}
			}(host)
		}

		wg.Wait()
		return loopErr
	}); err != nil {
		if err == ErrToolSkipped {
			golinkfinderSkipped = true
		} else {
			c.markStepFailedSafe("js_analysis", err)
			logger.Warning("GoLinkFinder failed: %v", err)
		}
	}

	if c.ScanID > 0 && utils.FileExists(c.F.GoLinkFinderOut) {
		count, _ := utils.ParseEndpointsFile(c.ScanID, c.F.GoLinkFinderOut, "golinkfinder")
		if count > 0 {
			label := ""
			if golinkfinderSkipped {
				label = " (partial)"
			}
			logger.Info("  Found %d endpoints%s", count, label)
		} else if golinkfinderSkipped {
			logger.Info("  GoLinkFinder skipped — endpoints unknown")
		} else {
			logger.Info("  Found 0 endpoints")
		}
	}

	c.markStepCompleteIfNoFailure("js_analysis")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 14 — HTTP Parameter Discovery (Arjun)
// ─────────────────────────────────────────────────────────────

// stepParamDiscovery discovers HTTP parameters with x8 (Step 16).
// After a successful run it converts discovered params into parameterized URLs
// (written to X8URLsOut) so they flow into Step 17 consolidation and
// downstream scanners (Nuclei/Dalfox).
// Returns true if the scan should be cancelled.
func stepParamDiscovery(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("param_discovery", "Step 16: HTTP Parameter Discovery (x8)"); skipped {
		return cancelled
	}

	if c.SkipX8 {
		logger.StepHeader("Step 16: Skipping x8 (--skip-x8)")
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
	x8InputFile := filepath.Join(filepath.Dir(c.F.HttpxLiveHosts), "x8_input.txt")
	
	var x8Targets []string

	// Add ffuf fuzzing results
	if utils.FileExists(c.F.FfufDiscoveredURLs) {
		x8Targets = append(x8Targets, loadLineSlice(c.F.FfufDiscoveredURLs, 0)...)
	}

	// Collect and add high-signal crawler endpoints (limit to 150 to keep it fast)
	crawlerFiles := []string{
		c.F.WaybackOut,
		c.F.GauOut,
		c.F.KatanaOut,
		c.F.GospiderOut,
		c.F.GoLinkFinderOut,
	}
	highSignal := collectHighSignalEndpoints(crawlerFiles, 150)
	x8Targets = append(x8Targets, highSignal...)

	// Deduplicate targets
	x8Targets = utils.DeduplicateSlice(x8Targets)

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

	logger.SubStep("Running x8 on %d targets...", len(x8Targets))

	// Validate parameters wordlist if configured.
	paramWordlist := ""
	if c.Cfg != nil && c.Cfg.General.Wordlists.Parameters != "" {
		if utils.FileExists(c.Cfg.General.Wordlists.Parameters) {
			paramWordlist = c.Cfg.General.Wordlists.Parameters
		} else {
			logger.Warning("x8 parameters wordlist not found: %s", c.Cfg.General.Wordlists.Parameters)
			logger.Info("  Install seclists (apt install seclists / pacman -S seclists) or set a valid wordlist in config.yaml")
			logger.Info("  Falling back to x8's built-in parameter list")
			logger.FileDebug("x8: configured wordlist does not exist at %s — using built-in default", c.Cfg.General.Wordlists.Parameters)
		}
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
		if count > 0 || stored > 0 {
			label := ""
			if x8Skipped {
				label = " (partial)"
			}
			logger.Info("  Generated %d parameterized URLs from x8 output%s", count, label)
			logger.Info("  Stored x8 param counts for %d URLs%s", stored, label)
		} else if x8Skipped {
			logger.Info("  x8 skipped — no parameters found")
		} else {
			logger.Info("  Generated 0 parameterized URLs from x8 output")
		}
	}

	c.markStepCompleteIfNoFailure("param_discovery")
	return c.cancelled()
}

// collectHighSignalEndpoints reads raw URLs from crawler and discovery files,
// filters for high-signal parameters/endpoints (dynamic extensions, API paths, interesting keywords),
// deduplicates them by host+path, and returns a capped slice of URLs.
func collectHighSignalEndpoints(files []string, limit int) []string {
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
					if limit > 0 && len(endpoints) >= limit {
						f.Close()
						return endpoints
					}
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
	if skipped, cancelled := c.resumeOrSkip("url_consolidation", "Step 17: URL Consolidation & Live Check"); skipped {
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
	if err := utils.SanitizeURLFile(c.F.AllURLsRaw); err != nil {
		logger.Warning("URL sanitization failed: %v", err)
	}
	rawCount, _ := utils.CountFileLines(c.F.AllURLsRaw)
	logger.Info("  Merged %d unique URLs", rawCount)
	logger.FileDebug("url_consolidation merged %d raw URLs -> %s", rawCount, c.F.AllURLsRaw)

	// Live-check all URLs with httpx
	logger.SubStep("Running httpx to live-check all URLs...")
	rawCount2, _ := utils.CountFileLines(c.F.AllURLsRaw)
	logger.FileDebug("httpx_url_check input: %s (%d URLs) out=%s", c.F.AllURLsRaw, rawCount2, c.F.AllURLsLive)
	var urlCheckSkipped bool
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
		if dbCount, err := utils.ParseLiveURLsFile(c.ScanID, c.F.AllURLsLive, "httpx-url-check"); err != nil {
			logger.Warning("Failed to persist live URLs to DB: %v", err)
		} else {
			label := ""
			if urlCheckSkipped {
				label = " (from fallback)"
			}
			logger.Info("  Stored %d live URLs in database%s", dbCount, label)
		}
	}

	// ROI metadata enrichment
	if c.ScanID > 0 && utils.FileExists(c.F.AllURLsLive) {
		metaTargetCount := collectROIMetadataTargetsFromFile(c.F.AllURLsLive, c.F.ROIMetadataTargets, 3, paramDiscoveryCap)
		if metaTargetCount > 0 {
			logger.SubStep("Collecting lightweight metadata for %d high-value URLs...", metaTargetCount)
			metaTargets := loadLineSlice(c.F.ROIMetadataTargets, paramDiscoveryCap)
			if count, err := metadata.CollectURLMetadata(c.ScanID, metaTargets, c.Proxy); err != nil {
				logger.Warning("URL metadata enrichment failed: %v", err)
			} else if count > 0 {
				logger.Info("  Stored path metadata for %d ROI candidate URLs", count)
			}
		}
	}

	c.markStepCompleteIfNoFailure("url_consolidation")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 16 — JS Secret Scan (gf JS + Secrets)
// ─────────────────────────────────────────────────────────────

// stepJSSecretScan downloads a capped set of JS files, scans their content
// with installed gf JS/secret patterns, and writes merged findings.
type gfPatternFile struct {
	Pattern  string   `json:"pattern"`
	Patterns []string `json:"patterns"`
	Flags    string   `json:"flags"`
}

// loadGFPatterns reads patterns from ~/.gf/ and compiles them to regular expressions.
func loadGFPatterns(allowlist map[string]bool) (map[string][]*regexp.Regexp, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	gfDir := filepath.Join(home, ".gf")
	entries, err := os.ReadDir(gfDir)
	if err != nil {
		return nil, err
	}

	compiledPatterns := make(map[string][]*regexp.Regexp)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		if allowlist != nil && !allowlist[name] {
			continue
		}

		filePath := filepath.Join(gfDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var pf gfPatternFile
		if err := json.Unmarshal(data, &pf); err != nil {
			continue
		}

		var rawPatterns []string
		if pf.Pattern != "" {
			rawPatterns = append(rawPatterns, pf.Pattern)
		}
		rawPatterns = append(rawPatterns, pf.Patterns...)

		// Determine Go regex flags
		prefix := ""
		caseInsensitive := strings.Contains(pf.Flags, "i")
		multiline := strings.Contains(pf.Flags, "m")
		if caseInsensitive || multiline {
			prefix = "(?"
			if caseInsensitive {
				prefix += "i"
			}
			if multiline {
				prefix += "m"
			}
			prefix += ")"
		}

		var regexes []*regexp.Regexp
		for _, raw := range rawPatterns {
			re, err := regexp.Compile(prefix + raw)
			if err != nil {
				continue
			}
			regexes = append(regexes, re)
		}
		if len(regexes) > 0 {
			compiledPatterns[name] = regexes
		}
	}
	return compiledPatterns, nil
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

// isLikelySecret checks if a string is likely to be a real secret.
func isLikelySecret(patternName, val string) bool {
	valLower := strings.ToLower(val)
	// Blacklist common placeholder patterns
	placeholders := []string{"placeholder", "undefined", "null", "false", "true", "your_token", "your_secret", "api_key_here"}
	for _, ph := range placeholders {
		if valLower == ph {
			return false
		}
	}
	// Basic entropy check for generic api-keys
	if patternName == "api-keys" {
		if len(val) < 8 {
			return false
		}
		entropy := shannonEntropy(val)
		if entropy < 3.0 {
			return false
		}
		// Filter out simple repeating sequences (e.g. "aaaaaaaaaa")
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
	}
	return true
}

// extractContext returns the matched text with a snippet of context before and after.
func extractContext(line string, start, end, contextSize int) string {
	lineLen := len(line)
	if start < 0 || end > lineLen || start > end {
		return ""
	}
	ctxStart := start - contextSize
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := end + contextSize
	if ctxEnd > lineLen {
		ctxEnd = lineLen
	}
	prefix := ""
	if ctxStart > 0 {
		prefix = "..."
	}
	suffix := ""
	if ctxEnd < lineLen {
		suffix = "..."
	}
	return fmt.Sprintf("%s%s%s", prefix, strings.TrimSpace(line[ctxStart:ctxEnd]), suffix)
}

// getFallbackGFPatterns returns hardcoded regexes for offline execution or when ~/.gf is empty.
func getFallbackGFPatterns(allowlist map[string]bool) map[string][]*regexp.Regexp {
	fallbacks := map[string]string{
		"aws-keys":      `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
		"api-keys":      `(?i)(?:api_key|apikey|secret|token|auth|password|key|credentials)[=:]["']([a-zA-Z0-9_\-\.\~]{10,80})["']`,
		"jwt":           `eyJhbGciOi`,
		"firebase":      `firebaseio\.com`,
		"github":        `(?i)github_token[=:]["']([a-zA-Z0-9]{35,40})["']`,
		"domxss":        `\.(innerHTML|outerHTML|location|href|write|writeln|src|location\.href)`,
		"js-sinks":      `(eval|setTimeout|setInterval|Function)\(`,
		"execs":         `exec\(`,
		"slack-webhook": `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
		"google-api":    `AIza[0-9A-Za-z-_]{35}`,
		"stripe-api":    `sk_live_[0-9a-zA-Z]{24}`,
		"db-connection": `(mongodb\+srv|postgres|mysql):\/\/[^\s"'` + "`" + `<>]+`,
		"private-key":   `-----BEGIN [A-Z ]+ PRIVATE KEY-----`,
	}

	compiled := make(map[string][]*regexp.Regexp)
	for name, pattern := range fallbacks {
		if allowlist != nil && !allowlist[name] {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiled[name] = []*regexp.Regexp{re}
		}
	}
	return compiled
}

// localUserAgents contains common, high-frequency browser User-Agent strings.
var localUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
}

// runInMemoryJSSecretScan concurrently downloads JS files and runs regex matches on them.
func runInMemoryJSSecretScan(ctx context.Context, c *Ctx, urls []string, jsPatterns, secretPatterns map[string][]*regexp.Regexp) (int, int, int64, []string, error) {
	threads := 10
	if c.Cfg != nil && c.Cfg.Tools.Httpx.Threads > 0 {
		threads = c.Cfg.Tools.Httpx.Threads / 5
		if threads < 5 {
			threads = 5
		}
		if threads > 15 {
			threads = 15
		}
	}

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
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	// Dynamic rate limiting setup (bound to GlobalRPS)
	var rateLimiter *time.Ticker
	if c.Tb.RateLimits != nil && c.Tb.RateLimits.GlobalRPS > 0 {
		interval := time.Second / time.Duration(c.Tb.RateLimits.GlobalRPS)
		rateLimiter = time.NewTicker(interval)
		defer rateLimiter.Stop()
	}

	jobs := make(chan string, len(urls))
	for _, u := range urls {
		jobs <- u
	}
	close(jobs)

	var wg sync.WaitGroup
	var mu sync.Mutex

	var jsMatches []string
	var secretMatches []string
	var totalBytes int64
	seenHostsWithSecrets := make(map[string]bool)

	for range threads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if rateLimiter != nil {
					select {
					case <-ctx.Done():
						return
					case <-rateLimiter.C:
					}
				}

				req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
				if err != nil {
					continue
				}

				// User agent setup
				ua := localUserAgents[rand.N(len(localUserAgents))]
				if c.Tb.General != nil && c.Tb.General.UserAgent != "" {
					ua = c.Tb.General.UserAgent
				}
				req.Header.Set("User-Agent", ua)

				// Inject Custom Cookies
				if c.Tb.CustomCookie != "" {
					req.Header.Set("Cookie", c.Tb.CustomCookie)
				}
				// Inject Custom Headers
				for _, h := range c.Tb.CustomHeaders {
					parts := strings.SplitN(h, ":", 2)
					if len(parts) == 2 {
						req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
					}
				}

				resp, err := client.Do(req)
				if err != nil {
					continue
				}

				// Max 10MB per file to protect memory
				body, err := io.ReadAll(io.LimitReader(resp.Body, jsFileMaxBytes))
				resp.Body.Close()
				if err != nil {
					continue
				}

				mu.Lock()
				totalBytes += int64(len(body))
				mu.Unlock()

				scanner := bufio.NewScanner(bytes.NewReader(body))
				buf := make([]byte, 0, 64*1024)
				scanner.Buffer(buf, jsFileMaxBytes)
				var localJSMatches []string
				var localSecretMatches []string
				foundSecret := false
				matchCount := 0
				maxMatches := jsSecretMaxMatches

				for scanner.Scan() {
					if matchCount >= maxMatches {
						break
					}
					lineTrimmed := strings.TrimSpace(scanner.Text())
					if lineTrimmed == "" {
						continue
					}

					// Scan JS patterns
					for name, regexes := range jsPatterns {
						if matchCount >= maxMatches {
							break
						}
						for _, re := range regexes {
							indices := re.FindAllStringSubmatchIndex(lineTrimmed, -1)
							for _, ind := range indices {
								if len(ind) < 2 {
									continue
								}
								start, end := ind[0], ind[1]
								secretVal := lineTrimmed[start:end]
								if len(ind) >= 4 {
									gStart, gEnd := ind[2], ind[3]
									if gStart >= 0 && gEnd >= 0 {
										secretVal = lineTrimmed[gStart:gEnd]
									}
								}

								if !isLikelySecret(name, secretVal) {
									continue
								}

								contextStr := extractContext(lineTrimmed, start, end, 100)
								matchLine := fmt.Sprintf("[%s] [%s] %s", target, name, contextStr)
								localJSMatches = append(localJSMatches, matchLine)
								matchCount++
								if matchCount >= maxMatches {
									break
								}
							}
						}
					}

					// Scan Secret patterns
					for name, regexes := range secretPatterns {
						if matchCount >= maxMatches {
							break
						}
						for _, re := range regexes {
							indices := re.FindAllStringSubmatchIndex(lineTrimmed, -1)
							for _, ind := range indices {
								if len(ind) < 2 {
									continue
								}
								start, end := ind[0], ind[1]
								secretVal := lineTrimmed[start:end]
								if len(ind) >= 4 {
									gStart, gEnd := ind[2], ind[3]
									if gStart >= 0 && gEnd >= 0 {
										secretVal = lineTrimmed[gStart:gEnd]
									}
								}

								if !isLikelySecret(name, secretVal) {
									continue
								}

								contextStr := extractContext(lineTrimmed, start, end, 100)
								matchLine := fmt.Sprintf("[%s] [%s] %s", target, name, contextStr)
								localSecretMatches = append(localSecretMatches, matchLine)
								foundSecret = true
								matchCount++
								if matchCount >= maxMatches {
									break
								}
							}
						}
					}
				}

				if len(localJSMatches) > 0 || len(localSecretMatches) > 0 {
					mu.Lock()
					jsMatches = append(jsMatches, localJSMatches...)
					secretMatches = append(secretMatches, localSecretMatches...)
					if foundSecret {
						if parsedURL, err := url.Parse(target); err == nil && parsedURL.Hostname() != "" {
							seenHostsWithSecrets[strings.ToLower(parsedURL.Hostname())] = true
						}
					}
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	if ctx.Err() != nil {
		return 0, 0, 0, nil, ctx.Err()
	}

	if len(jsMatches) > 0 {
		content := strings.Join(jsMatches, "\n") + "\n"
		_ = os.WriteFile(c.F.GFJSMatches, []byte(content), 0644)
		if c.ScanID > 0 {
			var parsed []database.GFMatch
			for _, match := range jsMatches {
				if !strings.HasPrefix(match, "[") {
					continue
				}
				firstClose := strings.Index(match, "]")
				if firstClose == -1 {
					continue
				}
				urlVal := match[1:firstClose]

				rest := match[firstClose+1:]
				firstOpen2 := strings.Index(rest, "[")
				if firstOpen2 == -1 {
					continue
				}
				secondClose := strings.Index(rest, "]")
				if secondClose == -1 || secondClose <= firstOpen2 {
					continue
				}
				patternVal := rest[firstOpen2+1 : secondClose]
				parsed = append(parsed, database.GFMatch{
					URL:     urlVal,
					Pattern: patternVal,
				})
			}
			if len(parsed) > 0 {
				if err := database.InsertGFMatches(c.ScanID, parsed); err != nil {
					logger.Warning("Failed to persist gf pattern matches: %v", err)
				}
			}
		}
	} else {
		writeEmptyFile(c.F.GFJSMatches)
	}

	if len(secretMatches) > 0 {
		content := strings.Join(secretMatches, "\n") + "\n"
		_ = os.WriteFile(c.F.GFSecretsMatches, []byte(content), 0644)
	} else {
		writeEmptyFile(c.F.GFSecretsMatches)
	}

	var secretHosts []string
	for host := range seenHostsWithSecrets {
		secretHosts = append(secretHosts, host)
	}

	return len(jsMatches), len(secretMatches), totalBytes, secretHosts, nil
}

func stepJSSecretScan(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("js_secret_scan", "Step 18: JS Secret Scan (gf JS + Secrets)"); skipped {
		return cancelled
	}

	writeEmptyFile(c.F.GFJSMatches)
	writeEmptyFile(c.F.GFSecretsMatches)
	writeEmptyFile(c.F.GFSecretsFinal)

	jsLimit := 0
	if c.Cfg != nil {
		jsLimit = c.Cfg.General.JSLimit
	}
	jsCount := collectJSURLsFromFile(c.F.AllURLsLive, c.F.JSURLsFile, jsLimit)
	if jsCount == 0 {
		logger.Info("  No JavaScript URLs found in live URL set")
		c.markStepCompleteIfNoFailure("js_secret_scan")
		return c.cancelled()
	}
	logger.Info("  Selected %d JavaScript URL(s) for fetching", jsCount)

	urls := loadLineSlice(c.F.JSURLsFile, 0)

	jsPatterns, err := loadGFPatterns(jsGFPatterns)
	if err != nil || len(jsPatterns) == 0 {
		jsPatterns = getFallbackGFPatterns(jsGFPatterns)
	}
	secretPatterns, err := loadGFPatterns(secretGFPatterns)
	if err != nil || len(secretPatterns) == 0 {
		secretPatterns = getFallbackGFPatterns(secretGFPatterns)
	}

	var jsMatchCount, secretMatchCount int
	var combinedBytes int64
	var secretHosts []string

	var scanSkipped bool
	logger.SubStep("Fetching & scanning JS files in-memory...")
	scanErr := runWithSkip(c, "JS In-Memory Secret Scan", func(sCtx context.Context) error {
		var err error
		jsMatchCount, secretMatchCount, combinedBytes, secretHosts, err = runInMemoryJSSecretScan(sCtx, c, urls, jsPatterns, secretPatterns)
		return err
	})

	if scanErr != nil {
		if scanErr == ErrToolSkipped {
			scanSkipped = true
			logger.Info("  JS scanning skipped by user")
		} else {
			c.markStepFailedSafe("js_secret_scan", scanErr)
			logger.Warning("JS scanning failed: %v", scanErr)
		}
	}

	if err := utils.MergeAndDeduplicate(existingFiles(c.F.GFJSMatches, c.F.GFSecretsMatches), c.F.GFSecretsFinal); err != nil {
		c.markStepFailedSafe("js_secret_scan", err)
		logger.Warning("Failed to merge JS secret findings: %v", err)
		writeEmptyFile(c.F.GFSecretsFinal)
	}

	totalFindings, _ := utils.CountFileLines(c.F.GFSecretsFinal)
	if totalFindings > 0 {
		label := ""
		if scanSkipped {
			label = " (partial)"
		}
		logger.Info("  Found %d JS/secret findings (%d JS matches, %d secret matches)%s", totalFindings, jsMatchCount, secretMatchCount, label)

		if c.ScanID > 0 && len(secretHosts) > 0 {
			if err := database.MarkHostsJSSecrets(c.ScanID, secretHosts); err != nil {
				logger.Warning("Failed to flag JS-secret hosts: %v", err)
			} else {
				logger.Info("  Flagged %d hosts with JS secrets for ROI boost", len(secretHosts))
			}
		}
	} else {
		if scanSkipped {
			logger.Info("  JS scanning skipped — no findings matched installed/fallback gf patterns")
		} else {
			logger.Info("  No JS or secret findings matched installed/fallback gf patterns")
		}
	}

	if totalFindings > 0 {
		metadataPath := filepath.Join(filepath.Dir(c.F.GFSecretsFinal), "gf_secrets_metadata.txt")
		header := fmt.Sprintf("// Scan Metadata | JS Combined File Size: %.4f GB\n", float64(combinedBytes)/(1024*1024*1024))
		_ = os.WriteFile(metadataPath, []byte(header), 0644)
	}

	c.markStepCompleteIfNoFailure("js_secret_scan")
	return c.cancelled()
}


// ─────────────────────────────────────────────────────────────
// Step 17 — Directory Fuzzing (ffuf)
// ─────────────────────────────────────────────────────────────

// stepDirFuzzing runs ffuf when a wordlist is provided via --wordlist.
// Returns true if the scan should be cancelled.
func stepDirFuzzing(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("dir_fuzzing", "Step 15: Directory Fuzzing (ffuf)"); skipped {
		return cancelled
	}

	if c.WordlistPath == "" {
		logger.StepHeader("Step 15: Skipping ffuf (no --wordlist provided)")
		logger.Info("Provide --wordlist to enable ffuf")
		c.markStepCompleteIfNoFailure("dir_fuzzing")
		return c.cancelled()
	}

	writeEmptyFile(c.F.FfufOut)
	writeEmptyFile(c.F.FfufDiscoveredURLs)

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

	logger.SubStep("Running ffuf with wordlist on %d live hosts...", len(liveHosts))

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

			tmpFfufOut := filepath.Join(filepath.Dir(c.F.FfufOut), fmt.Sprintf("ffuf_tmp_%d.json", rand.IntN(1000000)))

			logger.FileDebug("ffuf input: target=%s wordlist=%s out=%s", targetURL, c.WordlistPath, tmpFfufOut)
			if err := c.Tb.RunFfufWithFUZZ(sCtx, targetURL, c.WordlistPath, tmpFfufOut); err == nil && utils.FileExists(tmpFfufOut) {
				// Parse and add to allResults
				if data, readErr := os.ReadFile(tmpFfufOut); readErr == nil && len(data) > 0 {
					var payload struct {
						Results []localFfufResult `json:"results"`
					}
					if jsonErr := json.Unmarshal(data, &payload); jsonErr == nil {
						resultsMu.Lock()
						allResults = append(allResults, payload.Results...)
						resultsMu.Unlock()
					}
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
		logger.SubStep("[Done] ffuf - Merged results size: %d", len(allResults))
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
		count, err := utils.ParseFfufOutput(c.ScanID, c.F.FfufOut)
		if err != nil {
			logger.Warning("Failed to parse ffuf results: %v", err)
		} else {
			if count > 0 {
				c.FfufTotalFindings = count
				label := ""
				if ffufSkipped {
					label = " (partial)"
				}
				logger.Info("  Stored %d ffuf discoveries for ROI ranking%s", count, label)
			} else if ffufSkipped {
				logger.Info("  ffuf skipped — no discoveries found")
			} else {
				logger.Info("  Stored 0 ffuf discoveries for ROI ranking")
			}
		}
	}

	c.markStepCompleteIfNoFailure("dir_fuzzing")
	return c.cancelled()
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

	var results []x8Result
	if err := json.Unmarshal(data, &results); err != nil {
		logger.Warning("Failed to parse x8 JSON: %v", err)
		return 0
	}

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

	var results []x8Result
	if err := json.Unmarshal(data, &results); err != nil {
		return 0
	}

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
