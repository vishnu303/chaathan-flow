// Phase 0 — Proxy Scraping
//
// Automated proxy scraping, validation, and IP rotation setup.
// This step fetches free proxy lists, validates them with mubeng,
// then starts mubeng as a background rotating proxy server so all
// subsequent tools route through different IP addresses.
//
// Runs once at Step 1 only — proxy pool is not re-scraped between phases.
//
// Activation:  --auto-proxy flag (skipped otherwise)
// Override:    --proxy takes precedence (manual proxy always wins)
// Failure:     Non-fatal — scan continues without proxy on any error
package wildcard_flow

import (
	"context"
	"path/filepath"
	"time"

	"github.com/vishnu303/chaathan/pkg/flowkit"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/proxy_scraping"
	"github.com/vishnu303/chaathan/utils"
)

// stepProxyScraping scrapes free proxies, validates them, and starts a mubeng rotating proxy server.
// Returns true if the scan should be cancelled.
func stepProxyScraping(c *Ctx) flowkit.StepResult {
	const stepName = "proxy_scraping"

	// ── Skip if --proxy was explicitly set (manual always wins) ──
	if c.Proxy != "" {
		logger.StepHeader("Proxy Scraping — skipped (--proxy already set: %s)", c.Proxy)
		c.markStepCompleteIfNoFailure(stepName)
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	// ── Skip if --auto-proxy not requested ──────────────────
	if !c.AutoProxy {
		logger.StepHeader("Proxy Scraping — skipped (use --auto-proxy to enable)")
		c.markStepCompleteIfNoFailure(stepName)
		return flowkit.StepResult{Cancelled: c.cancelled()}
	}

	// ── Resume check ────────────────────────────────────────
	if skipped, cancelled := c.resumeOrSkip(stepName, "Proxy Scraping + Rotation (mubeng)"); skipped {
		if c.AutoProxy && c.Proxy == "" {
			c.restoreProxyRotatorOnResume()
		}
		return flowkit.StepResult{Cancelled: cancelled}
	}

	c.runProxyScrapingAndRotation()

	c.markStepCompleteIfNoFailure(stepName)
	return flowkit.StepResult{Cancelled: c.cancelled()}
}

// runProxyScrapingAndRotation scrapes proxies, validates them against the target,
// and starts a mubeng rotator. Called once at Step 1; the pool persists for the
// remainder of the scan.
func (c *Ctx) runProxyScrapingAndRotation() {
	if c.Rotator != nil {
		logger.Info("Stopping existing proxy rotator...")
		c.Rotator.Stop()
		c.Rotator = nil
		c.Proxy = ""
		if c.Cfg != nil {
			c.Cfg.General.Proxy = ""
		}
	}

	timeoutMin := 10
	maxConcurrent := 512
	proxyTypes := []string{"socks5", "http", "socks4"}
	rotateMethod := "random"
	rotateEvery := 1

	if c.Cfg != nil {
		scrapeCfg := c.Cfg.General.ProxyScraping
		if scrapeCfg.TimeoutMin > 0 {
			timeoutMin = scrapeCfg.TimeoutMin
		}
		if scrapeCfg.MaxConcurrent > 0 {
			maxConcurrent = scrapeCfg.MaxConcurrent
		}
		if len(scrapeCfg.ProxyTypes) > 0 {
			proxyTypes = scrapeCfg.ProxyTypes
		}
		if scrapeCfg.RotateMethod != "" {
			rotateMethod = scrapeCfg.RotateMethod
		}
		if scrapeCfg.RotateEvery > 0 {
			rotateEvery = scrapeCfg.RotateEvery
		}
	}

	harvestCfg := proxy_scraping.HarvestConfig{
		TimeoutMin:    timeoutMin,
		ProxyTypes:    proxyTypes,
		MaxConcurrent: maxConcurrent,
		OutputDir:     filepath.Join(c.ResultDir, "intermediate_files"),
	}

	logger.ToolStart("Proxy Scraping")

	var result *proxy_scraping.HarvestResult
	var harvestErr error
	var harvestSkipped bool

	err := runWithSkip(c, "mubeng proxy check", func(sCtx context.Context) error {
		res, hErr := proxy_scraping.RunHarvest(sCtx, harvestCfg)
		result = res
		harvestErr = hErr
		return hErr
	})

	if err == ErrToolSkipped {
		harvestSkipped = true
	}

	if harvestErr != nil && !harvestSkipped {
		logger.ToolFail("Proxy Scraping", harvestErr.Error())
		return
	}

	if result == nil || result.TotalValid == 0 {
		if harvestSkipped {
			logger.ToolSkip("Proxy Scraping", "no valid proxies found")
		} else {
			logger.ToolSkip("Proxy Scraping", "no valid proxies found")
		}
		return
	}

	c.ProxyTotalScraped = result.TotalScraped
	c.ProxyTotalValid = result.TotalValid

	label := ""
	if harvestSkipped {
		label = " (partial)"
	}
	logger.Success("Scraped %d proxies, %d validated%s (took %s)",
		result.TotalScraped, result.TotalValid, label,
		result.Duration.Round(time.Second))

	logger.ToolStart("mubeng")

	rotatorCfg := proxy_scraping.RotatorConfig{
		ProxyListFile: result.ProxyListFile,
		ListenAddr:    "127.0.0.1:0",
		RotateEvery:   rotateEvery,
		Method:        rotateMethod,
		Verbose:       c.Verbose,
	}

	rotator, err := proxy_scraping.StartRotator(c.GoCtx, rotatorCfg)
	if err != nil {
		logger.ToolFail("mubeng", err.Error())
		return
	}

	c.Rotator = rotator
	c.Proxy = rotator.ProxyURL
	if c.Cfg != nil {
		c.Cfg.General.Proxy = rotator.ProxyURL
	}
	if c.Tb != nil && c.Cfg != nil {
		c.Tb.WithGeneral(&c.Cfg.General)
	}

	logger.Success("Rotating proxy active: %s (%d proxies in pool, method: %s, rotate every: %d req)",
		rotator.ProxyURL, result.TotalValid, rotateMethod, rotateEvery)
}

func (c *Ctx) restoreProxyRotatorOnResume() {
	if !utils.FileExists(c.F.ProxyPool) {
		logger.Info("  Proxy pool file not found on resume — re-scraping proxies...")
		c.runProxyScrapingAndRotation()
		return
	}

	lines, _ := utils.CountFileLines(c.F.ProxyPool)
	if lines == 0 {
		logger.Info("  Proxy pool file is empty on resume — re-scraping proxies...")
		c.runProxyScrapingAndRotation()
		return
	}

	logger.ToolStart("mubeng")
	rotateMethod := "random"
	rotateEvery := 1
	if c.Cfg != nil {
		if c.Cfg.General.ProxyScraping.RotateMethod != "" {
			rotateMethod = c.Cfg.General.ProxyScraping.RotateMethod
		}
		if c.Cfg.General.ProxyScraping.RotateEvery > 0 {
			rotateEvery = c.Cfg.General.ProxyScraping.RotateEvery
		}
	}

	rotatorCfg := proxy_scraping.RotatorConfig{
		ProxyListFile: c.F.ProxyPool,
		ListenAddr:    "127.0.0.1:0",
		RotateEvery:   rotateEvery,
		Method:        rotateMethod,
		Verbose:       c.Verbose,
	}

	rotator, err := proxy_scraping.StartRotator(c.GoCtx, rotatorCfg)
	if err != nil {
		logger.ToolFail("mubeng", err.Error())
		return
	}

	c.Rotator = rotator
	c.Proxy = rotator.ProxyURL
	if c.Cfg != nil {
		c.Cfg.General.Proxy = rotator.ProxyURL
	}
	if c.Tb != nil && c.Cfg != nil {
		c.Tb.WithGeneral(&c.Cfg.General)
	}

	logger.Success("Rotating proxy restarted for resumed scan: %s (%d proxies in pool)", rotator.ProxyURL, lines)
}
