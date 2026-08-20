// Phase 2 — Validation & Probing (Steps 6–10)
//
// Validates discovered assets through DNS resolution, HTTP probing,
// TLS analysis, and port scanning.
//
//  7. Consolidation & DNS Resolution (DNSx)
//  8. DNS Brute-force (ShuffleDNS) [Optional]
//  9. Port Scanning (Naabu) [Optional]
//  10. Live Web Server Probing (Httpx)
//  11. TLS Certificate Analysis (tlsx) + host metadata enrichment [Optional]
package wildcard_flow

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"io"
	neturl "net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/flowkit"
	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/metadata"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 7 — Consolidation & DNS Resolution
// ─────────────────────────────────────────────────────────────

// stepDNSConsolidation merges all passive sources and resolves them with DNSx.
// Returns true if the scan should be cancelled.
func stepDNSConsolidation(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("dns_resolution", "Step 6: Subdomain Consolidation & DNS Validation"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}
	writeEmptyFile(c.F.DnsxOut)

	passiveSources := existingFiles(
		c.F.SubfinderOut,
		c.F.AssetfinderOut,
		c.F.Sublist3rOut,
		c.F.AmassOut,
		c.F.GithubSubsOut,
		c.F.UncoverHostsOut, // hostnames extracted from uncover.json in Step 5
	)
	var sourceNames []string
	for _, p := range passiveSources {
		sourceNames = append(sourceNames, filepath.Base(p))
	}
	logger.FileDebug("dns_consolidation: %d passive source files available (%s)", len(passiveSources), strings.Join(sourceNames, ", "))
	if err := utils.MergeAndDeduplicate(passiveSources, c.F.ConsolidatedSubs); err != nil {
		c.markStepFailedSafe("dns_resolution", err)
		logger.Error("Failed to consolidate: %v", err)
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	// Canonicalize casing first: tool outputs mix upper/lowercase and
	// MergeAndDeduplicate is case-sensitive, so "A.example.com" and
	// "a.example.com" would otherwise survive as distinct subdomains.
	if err := utils.MapFileLines(c.F.ConsolidatedSubs, strings.ToLower); err != nil {
		c.markStepFailedSafe("dns_resolution", err)
		logger.Error("Failed to normalize subdomain casing: %v", err)
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	// Filter out invalid domains and ensure they belong to the target domain
	_ = utils.FilterFileLines(c.F.ConsolidatedSubs, func(line string) bool {
		line = strings.ToLower(strings.TrimSpace(line))
		if utils.ValidateDomain(line) != nil {
			return false
		}
		return line == c.Domain || strings.HasSuffix(line, "."+c.Domain)
	})

	subCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
	logger.Result(subCount, "unique subdomains consolidated")
	logger.FileDebug("consolidated subs total: %d -> %s", subCount, c.F.ConsolidatedSubs)

	// Apply scope filtering (removes out-of-scope subdomains before DNS resolution)
	if c.ScopeFilter != nil {
		if err := utils.FilterFileLines(c.F.ConsolidatedSubs, func(line string) bool {
			return c.ScopeFilter.IsInScope(line) && !c.ScopeFilter.IsOutOfScope(line)
		}); err == nil {
			afterCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
			if filtered := subCount - afterCount; filtered > 0 {
				logger.Info("Scope filter: removed %d out-of-scope subdomains", filtered)
				logger.FileDebug("scope filter: %d -> %d subdomains", subCount, afterCount)
			}
		}
	}

	// Purge out-of-scope / unconsolidated subdomains from the DB
	syncDBSubdomainsToConsolidated(c)

	subCount, _ = utils.CountFileLines(c.F.ConsolidatedSubs)
	if subCount == 0 {
		logger.Warning("No valid in-scope subdomains found for target %s — skipping dependent steps", c.Domain)
		c.markStepCompleteIfNoFailure("dns_resolution")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	// Sync consolidated subdomains to DB
	if c.ScanID > 0 {
		if count, err := ingest.ParseSubdomainsFile(c.ScanID, c.F.ConsolidatedSubs, "consolidated"); err != nil {
			c.markStepFailedSafe("dns_resolution", err)
			logger.Warning("Failed to sync consolidated subdomains to database: %v", err)
		} else {
			logger.FileDebug("synced %d consolidated subdomains to database", count)
		}
	}

	logger.ToolStart("dnsx")
	logger.FileDebug("dnsx input: %s (%d lines) out=%s", c.F.ConsolidatedSubs, subCount, c.F.DnsxOut)

	var dnsxSkipped bool
	if err := runWithSkip(c, "dnsx", func(sCtx context.Context) error {
		return c.Tb.RunDnsx(sCtx, c.F.ConsolidatedSubs, c.F.DnsxOut, c.ResolversPath)
	}); err != nil {
		if err == ErrToolSkipped {
			dnsxSkipped = true
		} else {
			c.markStepFailedSafe("dns_resolution", err)
			logger.ToolFail("dnsx", err.Error())
		}
	}

	if utils.FileExists(c.F.DnsxOut) {
		uniqueHosts, _ := utils.CountUniqueDNSxHosts(c.F.DnsxOut)
		resolvedCount, _ := utils.CountFileLines(c.F.DnsxOut)
		label := ""
		if dnsxSkipped {
			label = " (partial)"
		}
		logger.Result(uniqueHosts, "hosts resolved (%d DNS records)%s", resolvedCount, label)
		logger.FileDebug("dnsx output: %d hosts (%d resolved records) -> %s", uniqueHosts, resolvedCount, c.F.DnsxOut)
	}

	c.markStepCompleteIfNoFailure("dns_resolution")
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// ─────────────────────────────────────────────────────────────
// Step 8 — DNS Brute-force (ShuffleDNS)
// ─────────────────────────────────────────────────────────────

// stepDNSBruteforce runs ShuffleDNS when a dns-wordlist is provided.
// Returns true if the scan should be cancelled.
func stepDNSBruteforce(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("dns_bruteforce", "Step 7: DNS Brute-force (ShuffleDNS)"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}

	if c.SkipShuffleDNS {
		logger.StepHeader("Step 7: Skipping ShuffleDNS (--skip-shuffledns)")
		logger.FileDebug("shuffledns skipped via --skip-shuffledns flag")
		c.markStepCompleteIfNoFailure("dns_bruteforce")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	if c.DNSWordlistPath == "" {
		if autoWl := config.ResolveSecListFile("Discovery/DNS/subdomains-top1million-5000.txt"); autoWl != "" {
			c.DNSWordlistPath = autoWl
			logger.Info("Auto-detected SecLists DNS wordlist for ShuffleDNS: %s", autoWl)
		} else {
			logger.StepHeader("Step 7: Skipping DNS Brute-Force (no wordlist — run 'chaathan setup')")
			logger.Info("Use --dns-wordlist or run 'chaathan setup' to install SecLists")
			logger.FileDebug("shuffledns skipped: no --dns-wordlist provided and SecLists not found on device")
			c.markStepCompleteIfNoFailure("dns_bruteforce")
			return flowkit.StepResult{Cancelled: c.cancelled()}
		}
	}

	writeEmptyFile(c.F.ShufflednsOut)

	// Validate DNS wordlist exists (may be a default config path like seclists)
	if !utils.FileExists(c.DNSWordlistPath) {
		logger.Warning("DNS wordlist not found: %s", c.DNSWordlistPath)
		logger.Info("Install seclists (apt install seclists / pacman -S seclists) or provide a valid --dns-wordlist path")
		logger.FileDebug("shuffledns skipped: wordlist does not exist at %s", c.DNSWordlistPath)
		c.markStepCompleteIfNoFailure("dns_bruteforce")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	if c.ResolversPath != "" && !utils.FileExists(c.ResolversPath) {
		// Resolvers file was explicitly provided but doesn't exist
		logger.Warning("Resolvers file not found: %s", c.ResolversPath)
		logger.Info("Provide a valid --resolvers file path")
		logger.FileDebug("shuffledns skipped: resolvers file does not exist at %s", c.ResolversPath)
		c.markStepCompleteIfNoFailure("dns_bruteforce")
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	logger.ToolStart("ShuffleDNS")
	logger.FileDebug("shuffledns input: domain=%s wordlist=%s resolvers=%s out=%s",
		c.Domain, c.DNSWordlistPath, c.ResolversPath, c.F.ShufflednsOut)

	var shufflednsSkipped bool
	var beforeMerge int
	var newCount int
	if err := runWithSkip(c, "shuffledns", func(sCtx context.Context) error {
		return c.Tb.RunShuffleDNS(sCtx, c.Domain, c.DNSWordlistPath, c.ResolversPath, c.F.ShufflednsOut)
	}); err != nil {
		if err == ErrToolSkipped {
			shufflednsSkipped = true
		} else {
			c.markStepFailedSafe("dns_bruteforce", err)
			logger.ToolFail("ShuffleDNS", err.Error())
		}
	} else {
		// Scope-filter the raw brute-force output before merge AND before DB
		// ingest below — the ingest layer only enforces domain-suffix scope,
		// so with a narrow user scope out-of-scope subs would otherwise be
		// persisted to the DB and never purged (the Step-6 purge already ran).
		c.filterSubsToScope(c.F.ShufflednsOut)
		beforeMerge, _ = utils.CountFileLines(c.F.ConsolidatedSubs)
		// Merge brute-forced subs back into the consolidated list
		if err := utils.MergeAndDeduplicate(
			[]string{c.F.ConsolidatedSubs, c.F.ShufflednsOut},
			c.F.ConsolidatedSubs,
		); err != nil {
			logger.Warning("Failed to merge brute-force results: %v", err)
		}
		// Filter out invalid domains and ensure they belong to the target domain
		_ = utils.FilterFileLines(c.F.ConsolidatedSubs, func(line string) bool {
			line = strings.ToLower(strings.TrimSpace(line))
			if utils.ValidateDomain(line) != nil {
				return false
			}
			return line == c.Domain || strings.HasSuffix(line, "."+c.Domain)
		})
		c.filterSubsToScope(c.F.ConsolidatedSubs)
		afterMerge, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
		newCount = afterMerge - beforeMerge
		if newCount < 0 {
			newCount = 0
		}
		if afterMerge > 0 {
			logger.FileDebug("consolidated subs after shuffledns merge: %d", afterMerge)
		}
	}

	if c.ScanID > 0 && utils.FileExists(c.F.ShufflednsOut) {
		count, _ := ingest.ParseSubdomainsFile(c.ScanID, c.F.ShufflednsOut, "shuffledns")
		label := ""
		if shufflednsSkipped {
			label = " (partial)"
		}
		logger.Result(count, "subdomains via DNS brute-force (%d new)%s", newCount, label)
		logger.FileDebug("shuffledns output: %d subdomains -> %s", count, c.F.ShufflednsOut)
	}

	c.markStepCompleteIfNoFailure("dns_bruteforce")
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// ─────────────────────────────────────────────────────────────
// Step 10 — Live Web Server Probing (Httpx)
// ─────────────────────────────────────────────────────────────

// stepHTTPProbing probes all consolidated subdomains with Httpx.
// Returns true if the scan should be cancelled.
func stepHTTPProbing(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("http_probing", "Step 9: HTTP Probing & Liveness Check"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}
	writeEmptyFile(c.F.HttpxOut)
	writeEmptyFile(c.F.HttpxLiveHosts)

	// Merge ConsolidatedSubs and NaabuOut into HttpxInput
	sources := []string{c.F.ConsolidatedSubs}
	if utils.FileExists(c.F.NaabuOut) {
		sources = append(sources, c.F.NaabuOut)
	}
	if err := utils.MergeAndDeduplicate(sources, c.F.HttpxInput); err != nil {
		c.markStepFailedSafe("http_probing", err)
		logger.Error("Failed to prepare Httpx input: %v", err)
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	logger.ToolStart("httpx")
	hostInputCount, _ := utils.CountFileLines(c.F.HttpxInput)
	logger.FileDebug("httpx input: %s (%d hosts) out=%s", c.F.HttpxInput, hostInputCount, c.F.HttpxOut)

	var httpxSkipped bool
	if err := runWithSkip(c, "httpx", func(sCtx context.Context) error {
		return c.Tb.RunHttpx(sCtx, c.F.HttpxInput, c.F.HttpxOut)
	}); err != nil {
		if err == ErrToolSkipped {
			httpxSkipped = true
		} else {
			c.markStepFailedSafe("http_probing", err)
			logger.ToolFail("httpx", err.Error())
		}
	}

	if utils.FileExists(c.F.HttpxOut) {
		collectLiveHostTargetsFromHttpx(c, c.F.HttpxOut, c.F.HttpxLiveHosts)
	}

	if c.ScanID > 0 && utils.FileExists(c.F.HttpxOut) {
		count, _ := ingest.ParseHttpxOutput(c.ScanID, c.F.HttpxOut)
		label := ""
		if httpxSkipped {
			label = " (partial)"
		}
		logger.Result(count, "live web servers confirmed%s", label)
		logger.FileDebug("httpx output: %d live hosts -> %s", count, c.F.HttpxOut)
	}

	c.markStepCompleteIfNoFailure("http_probing")
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// ─────────────────────────────────────────────────────────────
// Step 11 — TLS Certificate Analysis (tlsx) + host metadata
// ─────────────────────────────────────────────────────────────

// stepTLSAnalysis examines TLS certificates and enriches host metadata.
// Returns true if the scan should be cancelled.
func stepTLSAnalysis(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("tls_analysis", "Step 10: TLS Certificate Analysis (tlsx)"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}

	if c.SkipTlsx {
		logger.StepHeader("Step 10: Skipping tlsx (--skip-tlsx)")
		c.markStepCompleteIfNoFailure("tls_analysis")
	} else {
		runTLSAnalysisTool(c)
	}

	// Host metadata enrichment (always attempted after step 9)
	enrichHostMetadata(c)

	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// runTLSAnalysisTool executes tlsx, parses its output, and re-probes any new
// subdomains discovered via certificate SANs.
func runTLSAnalysisTool(c *Ctx) {
	writeEmptyFile(c.F.TlsxOut)
	logger.ToolStart("tlsx")
	inputCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
	logger.FileDebug("tlsx input: %s (%d hosts) out=%s", c.F.ConsolidatedSubs, inputCount, c.F.TlsxOut)

	var tlsxSkipped bool
	if err := runWithSkip(c, "tlsx", func(sCtx context.Context) error {
		return c.Tb.RunTlsx(sCtx, c.F.ConsolidatedSubs, c.F.TlsxOut)
	}); err != nil {
		if err == ErrToolSkipped {
			tlsxSkipped = true
		} else {
			c.markStepFailedSafe("tls_analysis", err)
			logger.ToolFail("tlsx", err.Error())
		}
	}

	if c.ScanID > 0 && utils.FileExists(c.F.TlsxOut) {
		newSubs, certVulns, _ := ingest.ParseTlsxOutput(c.ScanID, c.F.TlsxOut, c.Domain)
		label := ""
		if tlsxSkipped {
			label = " (partial)"
		}
		logger.Result(newSubs, "new subdomains from certificate SANs%s", label)
		if newSubs > 0 {
			// Re-merge SANs back to ConsolidatedSubs and re-probe
			newSANs := extractNewTlsxSANs(c)
			if len(newSANs) > 0 {
				reprobeSANSubdomains(c, newSANs)
			}
		}
		logger.Result(certVulns, "certificate issues (expired/self-signed/mismatch)%s", label)
	}

	// Re-sync the DB against the consolidated file: TLS-SAN subdomains were
	// ingested above filtered only by domain suffix, so any in-domain but
	// user-out-of-scope SANs must be purged now (the Step-6 purge predates
	// this discovery source).
	syncDBSubdomainsToConsolidated(c)

	c.markStepCompleteIfNoFailure("tls_analysis")
}

// extractNewTlsxSANs reads tlsx output and returns unique, in-scope SANs that
// are not already part of ConsolidatedSubs.
func extractNewTlsxSANs(c *Ctx) []string {
	// 1. Read existing ConsolidatedSubs
	existingSubs := make(map[string]bool)
	if fExisting, err := os.Open(c.F.ConsolidatedSubs); err == nil {
		scanner := bufio.NewScanner(fExisting)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				existingSubs[strings.ToLower(line)] = true
			}
		}
		fExisting.Close()
	}

	// 2. Read tlsx output and find unique new SANs
	var newSANs []string
	if f, err := os.Open(c.F.TlsxOut); err == nil {
		defer f.Close()
		type tlsxJSON struct {
			SANs      []string `json:"san"`
			SubjectAN []string `json:"subject_an"`
		}
		scanner := bufio.NewScanner(f)
		seen := make(map[string]bool)
		for scanner.Scan() {
			var res tlsxJSON
			if err := json.Unmarshal(scanner.Bytes(), &res); err == nil {
				sans := res.SANs
				if len(sans) == 0 {
					sans = res.SubjectAN
				}
				for _, san := range sans {
					san = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(san, "*.")))
					if san == "" || seen[san] {
						continue
					}
					seen[san] = true
					if utils.ValidateDomain(san) == nil {
						if (san == c.Domain || strings.HasSuffix(san, "."+c.Domain)) && !existingSubs[san] {
							if c.ScopeFilter == nil || (c.ScopeFilter.IsInScope(san) && !c.ScopeFilter.IsOutOfScope(san)) {
								newSANs = append(newSANs, san)
							}
						}
					}
				}
			}
		}
	}
	return newSANs
}

// reprobeSANSubdomains runs httpx on new SAN-discovered subdomains and merges
// the results back into the consolidated outputs.
func reprobeSANSubdomains(c *Ctx, newSANs []string) {
	logger.SubStep("Re-probing %d new SAN-discovered subdomains...", len(newSANs))
	sanSubsInputFile := c.F.TlsSanNewSubs
	sanHttpxOutFile := c.F.TlsSanHttpxOut
	sanHttpxLiveFile := c.F.TlsSanHttpxLive

	fSan, err := os.Create(sanSubsInputFile)
	if err != nil {
		return
	}
	for _, san := range newSANs {
		_, _ = fSan.WriteString(san + "\n")
	}
	fSan.Close()

	// Run httpx on the new SAN subs. Wrapped in runWithSkip so
	// the user can interrupt a slow SAN re-probe with the 's' key.
	reprobeSkipped := false
	if err := runWithSkip(c, "httpx (SAN re-probe)", func(sCtx context.Context) error {
		return c.Tb.RunHttpx(sCtx, sanSubsInputFile, sanHttpxOutFile)
	}); err == ErrToolSkipped {
		reprobeSkipped = true
	}

	// Process whatever output httpx produced — partial output may
	// exist even when the run was skipped before completion.
	if utils.FileExists(sanHttpxOutFile) {
		if c.ScanID > 0 {
			if _, err := ingest.ParseHttpxOutput(c.ScanID, sanHttpxOutFile); err != nil {
				logger.Warning("Failed to parse SAN httpx output: %v", err)
			}
		}

		// Extract live hosts
		sanLiveCount := collectLiveHostTargetsFromHttpx(c, sanHttpxOutFile, sanHttpxLiveFile)
		if sanLiveCount > 0 {
			reprobeLabel := ""
			if reprobeSkipped {
				reprobeLabel = " (partial)"
			}
			logger.Result(sanLiveCount, "live hosts from SAN subdomains%s", reprobeLabel)
			// Merge live hosts back (then re-collapse http/https dupes across files)
			_ = utils.MergeAndDeduplicate([]string{c.F.HttpxLiveHosts, sanHttpxLiveFile}, c.F.HttpxLiveHosts)
			dedupeHostURLsFile(c.F.HttpxLiveHosts)
		}

		// Append sanHttpxOutFile contents to c.F.HttpxOut
		if fIn, err := os.Open(sanHttpxOutFile); err == nil {
			fOut, openErr := os.OpenFile(c.F.HttpxOut, os.O_APPEND|os.O_WRONLY, 0644)
			if openErr == nil {
				_, _ = io.Copy(fOut, fIn)
				fOut.Close()
			}
			fIn.Close()
		}
	}

	// Merge new SANs back into ConsolidatedSubs
	_ = utils.MergeAndDeduplicate([]string{c.F.ConsolidatedSubs, sanSubsInputFile}, c.F.ConsolidatedSubs)
}

// enrichHostMetadata marks all live hosts in the DB and collects lightweight
// metadata for ROI scoring.
func enrichHostMetadata(c *Ctx) {
	if c.ScanID <= 0 || !utils.FileExists(c.F.HttpxOut) {
		return
	}
	hostTargetCount := collectLiveHostTargetsFromHttpx(c, c.F.HttpxOut, c.F.HttpxLiveHosts)
	if hostTargetCount <= 0 {
		return
	}
	// Mark ALL live hosts in DB (uncapped) — accuracy
	allLive, _ := utils.ReadNonEmptyLines(c.F.HttpxLiveHosts)
	liveHosts := make([]string, 0, len(allLive))
	for _, h := range allLive {
		if parsed, err := neturl.Parse(h); err == nil && parsed.Hostname() != "" {
			liveHosts = append(liveHosts, strings.ToLower(parsed.Hostname()))
		}
	}
	if err := database.UpdateSubdomainsLiveBulk(c.ScanID, liveHosts); err != nil {
		logger.FileDebug("UpdateSubdomainsLiveBulk failed: %v", err)
	}

	logger.SubStep("Collecting lightweight host metadata for ROI scoring...")
	hostTargets := rankLiveHosts(c.ScanID, allLive)
	if len(hostTargets) > metadataHostCap {
		hostTargets = hostTargets[:metadataHostCap]
	}
	if count, err := metadata.CollectHostMetadata(c.GoCtx, c.ScanID, hostTargets, c.Proxy); err != nil {
		logger.Warning("Host metadata enrichment failed: %v", err)
	} else if count > 0 {
		logger.Result(count, "live hosts enriched with metadata")
	}
}

// rankLiveHosts orders live host URLs by DB-derived ROI signals so the
// metadata cap keeps the most interesting hosts instead of the first N in
// file order: JS-secret flags, login surface, open-port breadth, and
// parameterized URL count. Ties preserve input order.
//
// Note: at Step-10 timing the JS-secret/login/URL signals are mostly
// unpopulated (those phases run later), so ranking here effectively leans
// on port breadth; URL-side ranking happens again after Step 16 via
// collectROIMetadataTargetsFromFile. The same ranking is reused by the
// ffuf step (Phase 3), where more signals are available.
func rankLiveHosts(scanID int64, hosts []string) []string {
	score := make(map[string]int)
	if metas, err := database.GetHostMetadata(scanID); err == nil {
		for _, m := range metas {
			h := strings.ToLower(m.Host)
			if m.HasJSSecrets {
				score[h] += 20
			}
			if m.LoginSurface {
				score[h] += 5
			}
		}
	}
	if ports, err := database.GetPorts(scanID); err == nil {
		for _, p := range ports {
			score[strings.ToLower(p.Host)] += 2
		}
	}
	if urls, err := database.GetURLs(scanID); err == nil {
		for _, u := range urls {
			if strings.Contains(u.URL, "?") && strings.Contains(u.URL, "=") {
				score[strings.ToLower(u.Host)]++
			}
		}
	}

	type rankedHost struct {
		url   string
		score int
	}
	ranked := make([]rankedHost, len(hosts))
	for i, h := range hosts {
		host := ""
		if parsed, err := neturl.Parse(h); err == nil {
			host = strings.ToLower(parsed.Hostname())
		}
		ranked[i] = rankedHost{url: h, score: score[host]}
	}
	slices.SortStableFunc(ranked, func(a, b rankedHost) int {
		return cmp.Compare(b.score, a.score)
	})
	out := make([]string, len(ranked))
	for i, r := range ranked {
		out[i] = r.url
	}
	return out
}

// ─────────────────────────────────────────────────────────────
// Step 9 — Port Scanning (Naabu)
// ─────────────────────────────────────────────────────────────

// stepPortScanning runs Naabu against all discovered subdomains.
// Returns true if the scan should be cancelled.
func stepPortScanning(c *Ctx) flowkit.StepResult {
	if skipped, cancelled := c.resumeOrSkip("port_scanning", "Step 8: Port Scanning"); skipped {
		return flowkit.StepResult{Cancelled: cancelled}
	}

	if c.SkipNaabu {
		logger.StepHeader("Step 8: Skipping Naabu (--skip-naabu)")
		c.markStepCompleteIfNoFailure("port_scanning")
	} else {
		writeEmptyFile(c.F.NaabuOut)
		logger.ToolStart("Naabu")
		inputCount, _ := utils.CountFileLines(c.F.ConsolidatedSubs)
		logger.FileDebug("naabu input: %s (%d hosts) out=%s", c.F.ConsolidatedSubs, inputCount, c.F.NaabuOut)

		var naabuSkipped bool
		if err := runWithSkip(c, "naabu", func(sCtx context.Context) error {
			return c.Tb.RunNaabuList(sCtx, c.F.ConsolidatedSubs, c.F.NaabuOut)
		}); err != nil {
			if err == ErrToolSkipped {
				naabuSkipped = true
			} else {
				c.markStepFailedSafe("port_scanning", err)
				logger.Error("Naabu failed: %v", err)
			}
		}
		// Parse and log results regardless of skip/success — partial output may exist
		if c.ScanID > 0 && utils.FileExists(c.F.NaabuOut) {
			count, _ := ingest.ParseNaabuOutput(c.ScanID, c.F.NaabuOut)
			label := ""
			if naabuSkipped {
				label = " (partial)"
			}
			logger.Result(count, "open ports%s", label)
		}

		c.markStepCompleteIfNoFailure("port_scanning")
	}
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

func (c *Ctx) filterSubsToScope(filePath string) {
	if c.ScopeFilter == nil || !utils.FileExists(filePath) {
		return
	}
	subCount, _ := utils.CountFileLines(filePath)
	if err := utils.FilterFileLines(filePath, func(line string) bool {
		line = strings.TrimSpace(line)
		return c.ScopeFilter.IsInScope(line) && !c.ScopeFilter.IsOutOfScope(line)
	}); err == nil {
		afterCount, _ := utils.CountFileLines(filePath)
		if filtered := subCount - afterCount; filtered > 0 {
			logger.Info("Scope filter: removed %d out-of-scope subdomains", filtered)
			logger.FileDebug("scope filter (%s): %d -> %d subdomains", filePath, subCount, afterCount)
		}
	}
}

// syncDBSubdomainsToConsolidated purges DB subdomains that are absent from
// the scope-filtered consolidated file. Runs after Step 6 and is re-run
// after every later subdomain-producing step (TLS-SAN, JS extraction) so
// late discoveries can never leave out-of-scope rows in the database.
func syncDBSubdomainsToConsolidated(c *Ctx) {
	if c.ScanID <= 0 {
		return
	}
	if purged, err := ingest.SyncSubdomainsWithConsolidated(c.ScanID, c.F.ConsolidatedSubs); err == nil && purged > 0 {
		logger.FileDebug("purged %d out-of-scope subdomains from database", purged)
	}
}
