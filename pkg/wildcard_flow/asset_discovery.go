// Phase 1 — Asset Discovery (Steps 2–5)
//
// Collects all possible subdomains/assets before any validation.
// Wayback/GAU are intentionally excluded — they run in Phase 3
// (Content Discovery) after live hosts are known.
//
//  2. Passive Subdomain Enumeration (Subfinder + Assetfinder + Sublist3r) [Parallel]
//  3. Active Subdomain Enumeration (Amass) [Optional]
//  4. GitHub Subdomain Discovery [Requires token]
//  5. Search-Engine Dorking (Uncover) [Optional]
package wildcard_flow

import (
	"context"
	"fmt"
	"sync"

	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// Step 2 — Passive Subdomain Enumeration
// ─────────────────────────────────────────────────────────────

// stepPassiveEnum runs Subfinder, Assetfinder, and Sublist3r in parallel.
// Returns true if the scan should be cancelled.
func stepPassiveEnum(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("passive_enum", "Step 2: Passive Subdomain Enumeration"); skipped {
		return cancelled
	}
	writeEmptyFile(c.F.SubfinderOut)
	writeEmptyFile(c.F.AssetfinderOut)
	writeEmptyFile(c.F.Sublist3rOut)

	var passiveSkipped bool
	var subfinderOK, assetfinderOK, sublist3rOK bool
	var resultMu sync.Mutex

	err := runWithSkip(c, "passive enum", func(sCtx context.Context) error {
		var wg sync.WaitGroup
		wg.Add(3)

		go func() {
			defer wg.Done()
			logger.ToolStart("Subfinder")
			logger.FileDebug("subfinder input: domain=%s out=%s", c.Domain, c.F.SubfinderOut)
			if err := c.Tb.RunSubfinder(sCtx, c.Domain, c.F.SubfinderOut); err != nil {
				if sCtx.Err() == nil {
					logger.ToolFail("Subfinder", err.Error())
				}
			} else {
				resultMu.Lock()
				subfinderOK = true
				resultMu.Unlock()
				logger.ToolDone("Subfinder")
			}
		}()

		go func() {
			defer wg.Done()
			logger.ToolStart("Assetfinder")
			logger.FileDebug("assetfinder input: domain=%s out=%s", c.Domain, c.F.AssetfinderOut)
			if err := c.Tb.RunAssetfinder(sCtx, c.Domain, c.F.AssetfinderOut); err != nil {
				if sCtx.Err() == nil {
					logger.ToolFail("Assetfinder", err.Error())
				}
			} else {
				resultMu.Lock()
				assetfinderOK = true
				resultMu.Unlock()
				logger.ToolDone("Assetfinder")
			}
		}()

		go func() {
			defer wg.Done()
			logger.ToolStart("Sublist3r")
			logger.FileDebug("sublist3r input: domain=%s out=%s", c.Domain, c.F.Sublist3rOut)
			if err := c.Tb.RunSublist3r(sCtx, c.Domain, c.F.Sublist3rOut); err != nil {
				if c.Verbose && sCtx.Err() == nil {
					logger.ToolFail("Sublist3r", err.Error())
				}
				logger.FileDebug("sublist3r failed: %v", err)
			} else {
				resultMu.Lock()
				sublist3rOK = true
				resultMu.Unlock()
				logger.ToolDone("Sublist3r")
			}
		}()

		wg.Wait()
		return nil
	})

	if err == ErrToolSkipped {
		passiveSkipped = true
	}

	if c.ScanID > 0 {
		subfinderCount, _ := ingest.ParseSubdomainsFile(c.ScanID, c.F.SubfinderOut, "subfinder")
		assetfinderCount, _ := ingest.ParseSubdomainsFile(c.ScanID, c.F.AssetfinderOut, "assetfinder")
		sublist3rCount, _ := ingest.ParseSubdomainsFile(c.ScanID, c.F.Sublist3rOut, "sublist3r")
		totalPassive := subfinderCount + assetfinderCount + sublist3rCount
		label := ""
		if passiveSkipped {
			label = " (partial)"
		}
		logger.Result(totalPassive, "subdomains found%s", label)
	}

	subfinderCount, _ := utils.CountFileLines(c.F.SubfinderOut)
	assetfinderCount, _ := utils.CountFileLines(c.F.AssetfinderOut)
	sublist3rCount, _ := utils.CountFileLines(c.F.Sublist3rOut)

	if passiveSkipped || subfinderOK || assetfinderOK || sublist3rOK || subfinderCount > 0 || assetfinderCount > 0 || sublist3rCount > 0 {
		c.markStepCompleteIfNoFailure("passive_enum")
	} else {
		c.markStepFailedSafe("passive_enum", fmt.Errorf("all passive enumeration tools failed"))
	}
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 3 — Active Subdomain Enumeration (Amass)
// ─────────────────────────────────────────────────────────────

// stepActiveEnum runs Amass unless --skip-amass is set.
// Returns true if the scan should be cancelled.
func stepActiveEnum(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("active_enum", "Step 3: Active Subdomain Enumeration (Amass)"); skipped {
		return cancelled
	}

	if c.SkipAmass {
		logger.StepHeader("Step 3: Skipping Amass (--skip-amass)")
		logger.FileDebug("amass skipped via --skip-amass flag")
		c.markStepCompleteSafe("active_enum")
		return c.cancelled()
	}

	writeEmptyFile(c.F.AmassOut)
	logger.ToolStart("Amass")
	logger.FileDebug("amass input: domain=%s out=%s", c.Domain, c.F.AmassOut)

	var amassSkipped bool
	if err := runWithSkip(c, "amass", func(sCtx context.Context) error {
		return c.Tb.RunAmass(sCtx, c.Domain, c.F.AmassOut)
	}); err != nil {
		if err == ErrToolSkipped {
			amassSkipped = true
		} else {
			logger.ToolFail("Amass", err.Error())
			c.markStepFailedSafe("active_enum", err)
		}
	}

	if c.ScanID > 0 {
		count, _ := ingest.ParseSubdomainsFile(c.ScanID, c.F.AmassOut, "amass")
		label := ""
		if amassSkipped {
			label = " (partial)"
		}
		logger.Result(count, "subdomains via Amass%s", label)
	}

	c.markStepCompleteIfNoFailure("active_enum")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 4 — GitHub Subdomain Discovery
// ─────────────────────────────────────────────────────────────

// stepGitHubRecon runs github-subdomains when a token is available.
// Returns true if the scan should be cancelled.
func stepGitHubRecon(c *Ctx) bool {
	if c.GitHubToken == "" {
		logger.StepHeader("Step 4: Skipping GitHub Recon (no token provided)")
		logger.Warning("Set api_keys.github in config.yaml or pass --github-token flag for GitHub recon")
		logger.FileDebug("github_recon skipped: no token provided")
		c.markStepCompleteIfNoFailure("github_recon")
		return c.cancelled()
	}

	if skipped, cancelled := c.resumeOrSkip("github_recon", "Step 4: GitHub Subdomain Discovery"); skipped {
		return cancelled
	}

	writeEmptyFile(c.F.GithubSubsOut)
	logger.ToolStart("github-subdomains")
	logger.FileDebug("github-subdomains input: domain=%s token_len=%d out=%s", c.Domain, len(c.GitHubToken), c.F.GithubSubsOut)

	var githubSkipped bool
	if err := runWithSkip(c, "github-subdomains", func(sCtx context.Context) error {
		return c.Tb.RunGithubSubdomains(sCtx, c.Domain, c.GitHubToken, c.F.GithubSubsOut)
	}); err != nil {
		if err == ErrToolSkipped {
			githubSkipped = true
		} else {
			c.markStepFailedSafe("github_recon", err)
			logger.ToolFail("github-subdomains", err.Error())
		}
	} else {
		logger.ToolDone("github-subdomains")
	}

	if c.ScanID > 0 {
		count, _ := ingest.ParseSubdomainsFile(c.ScanID, c.F.GithubSubsOut, "github")
		label := ""
		if githubSkipped {
			label = " (partial)"
		}
		logger.Result(count, "subdomains via GitHub%s", label)
	}

	c.markStepCompleteIfNoFailure("github_recon")
	return c.cancelled()
}

// ─────────────────────────────────────────────────────────────
// Step 5 — Search-Engine Dorking (Uncover)
// ─────────────────────────────────────────────────────────────

// stepSearchEngineRecon runs Uncover unless --skip-uncover is set.
// Returns true if the scan should be cancelled.
func stepSearchEngineRecon(c *Ctx) bool {
	if skipped, cancelled := c.resumeOrSkip("search_engine_recon", "Step 5: Passive Search Engine Recon (Uncover)"); skipped {
		return cancelled
	}

	if c.SkipUncover {
		logger.StepHeader("Step 5: Skipping Uncover (--skip-uncover)")
		c.markStepCompleteSafe("search_engine_recon")
		return c.cancelled()
	}

	writeEmptyFile(c.F.UncoverOut)
	writeEmptyFile(c.F.UncoverHostsOut)
	logger.ToolStart("Uncover")

	var uncoverSkipped bool
	if err := runWithSkip(c, "uncover", func(sCtx context.Context) error {
		return c.Tb.RunUncover(sCtx, c.Domain, c.F.UncoverOut)
	}); err != nil {
		if err == ErrToolSkipped {
			uncoverSkipped = true
		} else {
			c.markStepFailedSafe("search_engine_recon", err)
			logger.ToolFail("Uncover", err.Error())
		}
	}

	if c.ScanID > 0 {
		subs, ports, _ := ingest.ParseUncoverOutput(c.ScanID, c.F.UncoverOut, c.Domain)
		label := ""
		if uncoverSkipped {
			label = " (partial)"
		}
		logger.Result(subs, "hosts from search engines (%d open ports)%s", ports, label)
	}

	// Extract hostnames into a plain-text file so DNS consolidation can merge them
	if n := extractUncoverHosts(c.F.UncoverOut, c.F.UncoverHostsOut, c.Domain); n > 0 {
		logger.ToolDone("Uncover")
	}

	c.markStepCompleteIfNoFailure("search_engine_recon")
	return c.cancelled()
}
