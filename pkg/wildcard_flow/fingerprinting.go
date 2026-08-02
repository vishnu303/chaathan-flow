package wildcard_flow

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/notify"
	"github.com/vishnu303/chaathan/utils"
)

// Phase 5 — Fingerprinting (Step 21)
//
// Runs technology fingerprinting and WAF detection safely at the very end
// to prevent WAF blocks from affecting prior discovery or vulnerability scanning.

// stepFingerprinting runs httpx for tech-detect and nuclei for WAF detection.
func stepFingerprinting(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("tech_waf_fingerprinting", "Step 21: Technology & WAF Fingerprinting"); skipped {
		return cancelled
	}

	if c.SkipFingerprint {
		logger.StepHeader("Step 21: Skipping Fingerprinting (--skip-fingerprint)")
		c.markStepCompleteIfNoFailure("tech_waf_fingerprinting")
		return c.cancelled()
	}

	// 1. HTTPX Tech Detection
	if utils.FileExists(c.F.HttpxLiveHosts) {
		writeEmptyFile(c.F.HttpxTechOut)
		logger.ToolStart("HTTPX Tech Detection")
		if err := runWithSkip(c, "httpx-tech", func(sCtx context.Context) error {
			return c.Tb.RunHttpxFingerprint(sCtx, c.F.HttpxLiveHosts, c.F.HttpxTechOut)
		}); err != nil {
			if err != ErrToolSkipped {
				logger.ToolFail("HTTPX Tech Detection", err.Error())
			}
		}
	} else {
		logger.ToolSkip("HTTPX Tech Detection", "no live hosts")
	}

	// 2. Nuclei WAF Detection
	if utils.FileExists(c.F.HttpxLiveHosts) {
		writeEmptyFile(c.F.NucleiWafOut)

		logger.ToolStart("Nuclei WAF Detection")

		// Snapshot known vulnerabilities to avoid duplicate notifications on resume
		knownVulnIDs := snapshotVulnIDs(c.ScanID)

		var wafSkipped bool
		if err := runWithSkip(c, "nuclei-waf", func(sCtx context.Context) error {
			return c.Tb.RunNucleiWAF(sCtx, c.F.HttpxLiveHosts, c.F.NucleiWafOut)
		}); err != nil {
			if err == ErrToolSkipped {
				wafSkipped = true
			} else {
				logger.ToolFail("Nuclei WAF Detection", err.Error())
			}
		}

		if c.ScanID > 0 && (utils.FileExists(c.F.NucleiWafOut) || wafSkipped) {
			count, _ := ingest.ParseNucleiOutput(c.ScanID, c.F.NucleiWafOut)
			label := ""
			if wafSkipped {
				label = " (partial)"
			}
			logger.Result(count, "WAF/firewall products identified%s", label)

			if count > 0 && c.Notifier != nil {
				sendWafNotifications(c, notify.Finding{
					Target:    c.Domain,
					Type:      "waf",
					Timestamp: time.Now(),
				}, knownVulnIDs)
			}
		}
	}

	// 3. Log detailed findings summary
	logFingerprintSummary(c)

	c.markStepCompleteIfNoFailure("tech_waf_fingerprinting")
	return c.cancelled()
}

// sendWafNotifications sends alerts explicitly for WAF findings
func sendWafNotifications(c *Ctx, base notify.Finding, knownVulnIDs map[int64]bool) {
	vulns, _ := database.GetVulnerabilities(c.ScanID)
	for _, v := range vulns {
		if knownVulnIDs != nil && knownVulnIDs[v.ID] {
			continue
		}

		if strings.Contains(strings.ToLower(v.TemplateID), "waf") || strings.Contains(strings.ToLower(v.Name), "waf") {
			if err := c.Notifier.SendFinding(notify.Finding{
				Target:      base.Target,
				Type:        base.Type,
				Name:        v.Name,
				Severity:    "info",
				Description: v.Description,
				URL:         v.URL,
				TemplateID:  v.TemplateID,
				Timestamp:   base.Timestamp,
			}); err != nil {
				logger.Warning("Failed to send WAF notification: %v", err)
			}
		}
	}
}

// logFingerprintSummary prints a breakdown of detected WAFs (with hosts) and
// technologies after Step 22 completes, so the user can see results at a glance.
func logFingerprintSummary(c *Ctx) {
	// WAF breakdown: group by WAF name (matcher field) → hosts
	if c.ScanID > 0 {
		vulns, _ := database.GetVulnerabilities(c.ScanID)
		wafHosts := make(map[string][]string) // waf-name → [host1, host2, ...]
		for _, v := range vulns {
			if !strings.Contains(strings.ToLower(v.TemplateID), "waf") {
				continue
			}
			wafName := strings.ToUpper(v.Matcher)
			if wafName == "" {
				wafName = "UNKNOWN"
			}
			host := v.Host
			// Deduplicate hosts per WAF
			if !slices.Contains(wafHosts[wafName], host) {
				wafHosts[wafName] = append(wafHosts[wafName], host)
			}
		}
		if len(wafHosts) > 0 {
			for waf, hosts := range wafHosts {
				logger.Info("  ▸ %s → %s", waf, strings.Join(hosts, ", "))
			}
		}
	}

	// Tech breakdown: parse httpx tech JSON and collect unique technologies
	if utils.FileExists(c.F.HttpxTechOut) {
		techCounts := parseTechSummary(c.F.HttpxTechOut)
		if len(techCounts) > 0 {
			var parts []string
			for tech := range techCounts {
				parts = append(parts, tech)
			}
			slices.Sort(parts)
			// Print in compact groups of ~6 technologies per line for readability
			for i := 0; i < len(parts); i += 6 {
				end := i + 6
				if end > len(parts) {
					end = len(parts)
				}
				logger.Info("  ▸ %s", strings.Join(parts[i:end], ", "))
			}
		}
	}
}

// parseTechSummary reads httpx JSON output and returns a map of technology → host count.
func parseTechSummary(filePath string) map[string]int {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	techCounts := make(map[string]int)
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var result struct {
			Tech []string `json:"tech"`
		}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}
		for _, t := range result.Tech {
			techCounts[t]++
		}
	}
	return techCounts
}
