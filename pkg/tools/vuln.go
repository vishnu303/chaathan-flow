package tools

import (
	"context"
	"strconv"
	"time"

	"github.com/vishnu303/chaathan/pkg/runner"
)

// RunNucleiSmartCVE runs tech-targeted CVE scanning using Nuclei's -as (automatic scan).
// Wappalyzer fingerprints each host and selects only templates matching detected technologies.
// This reduces effective template count from ~3,800 to ~100-400 per host.
func (t *ToolBox) RunNucleiSmartCVE(ctx context.Context, targetsFile string, outputFile string) error {
	s, err := t.GetScanner("nuclei")
	if err != nil {
		return err
	}
	return s.Scan(ctx, targetsFile, outputFile, ScanOptions{
		Mode:        "smart-cve",
		Concurrency: t.nucleiConcurrency(),
		RateLimit:   t.effectiveRate(t.nucleiRateLimit()),
		DisableOOB:  t.nucleiDisableOOB(),
		MaxTimeout:  t.nucleiMaxTimeout(),
	})
}

// RunNucleiMisconfig runs generic misconfig/exposure scanning (tech-agnostic).
// These templates catch exposed .env files, default credentials, open debug panels,
// etc. — relevant regardless of the target's technology stack.
func (t *ToolBox) RunNucleiMisconfig(ctx context.Context, targetsFile string, outputFile string) error {
	s, err := t.GetScanner("nuclei")
	if err != nil {
		return err
	}
	return s.Scan(ctx, targetsFile, outputFile, ScanOptions{
		Mode:        "misconfig",
		Concurrency: t.nucleiConcurrency(),
		RateLimit:   t.effectiveRate(t.nucleiRateLimit()),
		DisableOOB:  t.nucleiDisableOOB(),
		MaxTimeout:  t.nucleiMaxTimeout(),
	})
}

// RunNucleiDAST runs Nuclei in DAST fuzzing mode against parameterized URLs.
// Unlike detection-only scanning, DAST sends actual attack payloads (SQLi probes,
// XSS vectors, SSRF callbacks) and validates exploitation evidence.
func (t *ToolBox) RunNucleiDAST(ctx context.Context, urlsFile string, outputFile string) error {
	rateLimit := t.effectiveRate(t.nucleiRateLimit() / 2)
	if rateLimit < 25 {
		rateLimit = 25
	}
	concurrency := t.nucleiConcurrency() / 2
	if concurrency < 5 {
		concurrency = 5
	}
	s, err := t.GetScanner("nuclei")
	if err != nil {
		return err
	}
	return s.Scan(ctx, urlsFile, outputFile, ScanOptions{
		Mode:           "dast",
		Concurrency:    concurrency,
		RateLimit:      rateLimit,
		DASTAggression: t.dastAggression(),
		MaxTimeout:     t.nucleiDASTMaxTimeout(),
	})
}

// --- Cloud & Org ---

// RunNucleiTakeovers runs nuclei specifically for subdomain takeovers.
func (t *ToolBox) RunNucleiTakeovers(ctx context.Context, targetsFile string, outputFile string) error {
	s, err := t.GetScanner("nuclei")
	if err != nil {
		return err
	}
	return s.Scan(ctx, targetsFile, outputFile, ScanOptions{
		Mode:        "takeover",
		Concurrency: t.nucleiConcurrency(),
		RateLimit:   t.effectiveRate(t.nucleiRateLimit()),
		DisableOOB:  t.nucleiDisableOOB(),
		MaxTimeout:  t.nucleiMaxTimeout(),
	})
}

// --- XSS Scanning ---

// RunDalfox scans URLs with parameters for XSS vulnerabilities.
// Takes a list of parameterized URLs and tests for reflected/stored XSS.
func (t *ToolBox) RunDalfox(ctx context.Context, inputFile string, outputFile string) error {
	s, err := t.GetScanner("dalfox")
	if err != nil {
		return err
	}
	concurrency := 20 // Default parallel worker threads for XSS fuzzing
	var maxTimeout time.Duration
	if t.config().Dalfox.MaxTimeout > 0 {
		maxTimeout = time.Duration(t.config().Dalfox.MaxTimeout) * time.Minute
	} else {
		maxTimeout = time.Duration(getDefaultToolsConfig().Dalfox.MaxTimeout) * time.Minute
	}
	return s.Scan(ctx, inputFile, outputFile, ScanOptions{
		Concurrency: concurrency,
		MaxTimeout:  maxTimeout,
	})
}

// --- TLS/SSL Analysis ---

// RunTlsx grabs TLS certificate information from live hosts.
// tlsx v1.2.2 rejects -san/-cn when mixed with other probes, but plain JSON
// output already includes certificate metadata needed for post-processing.

// RunNucleiWAF runs Nuclei specifically for WAF detection with a conservative rate limit.
func (t *ToolBox) RunNucleiWAF(ctx context.Context, inputFile string, outputFile string) error {
	// WAF detection needs a gentler rate limit as sending malicious tags will quickly trigger blocks.
	rateLimit := t.effectiveRate(50)
	concurrency := 10

	args := []string{
		"-l", inputFile,
		"-c", strconv.Itoa(concurrency),
		"-rl", strconv.Itoa(rateLimit),
		"-timeout", "5", // per-request timeout (seconds)
		"-max-host-error", "3", // bail out of unresponsive hosts quickly
		"-tags", "waf",
		"-jsonl",
		"-o", outputFile,
	}

	args = t.appendCommon(args, appendOptions{
		uaHeader:  true,
		proxyFlag: "-proxy",
	})
	// NoRetry: nuclei appends to existing -o files; a retry would duplicate
	// JSONL findings and inflate notification/stats counts.
	_, err := t.Runner.Run(ctx, ToolNuclei, args, runner.WithNoRetry(), runner.WithTimeout(t.nucleiWAFMaxTimeout()))
	return err
}
