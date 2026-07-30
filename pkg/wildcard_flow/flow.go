// Package wildcard_flow implements the Wildcard Reconnaissance Workflow.
// It is separated from the CLI layer (cli/wildcard.go) so that all scan
// logic lives outside cobra and can be tested or embedded independently.
//
// Each scan phase (passive enumeration, DNS, probing, etc.) has its own
// file. All phases share a single *Ctx that carries output paths, tool
// runners, scan state, and option flags.
package wildcard_flow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/notify"
	"github.com/vishnu303/chaathan/pkg/orchestrate"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/proxy_scraping"
	"github.com/vishnu303/chaathan/pkg/report"
	"github.com/vishnu303/chaathan/pkg/scan"
	"github.com/vishnu303/chaathan/pkg/scope"
	"github.com/vishnu303/chaathan/pkg/tools"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// RunConfig — supplied by cli/wildcard.go
// ─────────────────────────────────────────────────────────────

// RunConfig holds every option the CLI passes into the workflow.
type RunConfig struct {
	// Core
	Domain    string
	ResultDir string
	Mode      string
	Verbose   bool
	Cfg       *config.Config

	// Optional flags
	SkipAmass       bool
	SkipNuclei      bool
	SkipNaabu       bool
	SkipCrawl       bool
	SkipTakeovers   bool
	SkipDalfox      bool
	SkipUncover     bool
	SkipTlsx        bool
	SkipX8          bool
	SkipShuffleDNS  bool
	SkipFingerprint bool
	SkipJS          bool

	// Paths / tokens
	WordlistPath    string
	DNSWordlistPath string
	ResolversPath   string
	GitHubToken     string

	// Control parameters
	ResumeScanID int64

	// Post-scan
	GenerateReport bool

	// Logging
	// SaveLog controls whether scan output is mirrored to a log file in
	// ~/.chaathan/logs/ (plain text, ANSI stripped). The filename is
	// generated automatically as <domain>_<scanID>_<timestamp>.log.
	SaveLog bool

	// Playbook - Evasion & Auth Coverage
	CustomCookie  string
	CustomHeaders []string
	CustomToken   string

	// Proxy automation
	AutoProxy bool
}

// ─────────────────────────────────────────────────────────────
// Files — all output file paths (keeps step funcs clean)
// ─────────────────────────────────────────────────────────────

// Files holds every output file path used across the workflow.
type Files struct {
	SubfinderOut        string
	AssetfinderOut      string
	Sublist3rOut        string
	AmassOut            string
	GithubSubsOut       string
	WaybackOut          string
	GauOut              string
	UncoverOut          string
	UncoverHostsOut     string
	ConsolidatedSubs    string
	HttpxInput          string
	DnsxOut             string
	ShufflednsOut       string
	HttpxOut            string
	HttpxLiveHosts      string
	TlsxOut             string
	NaabuOut            string
	KatanaOut           string
	GospiderOut         string
	GoLinkFinderOut     string // deprecated: kept for resume compat
	JSEndpointsOut      string
	JSSecretsOut        string
	JSSubdomainsOut     string
	JSMetadataOut       string
	HakrawlerOut        string // deprecated: kept for resume compat
	X8Out               string
	X8URLsOut           string
	AllURLsRaw          string
	AllURLsLive         string
	JSURLsFile          string
	ROIMetadataTargets  string
	FfufOut             string
	FfufDiscoveredURLs  string
	NucleiOut           string
	NucleiURLTargets    string
	SubjackOut          string
	ParamURLsFile       string
	DalfoxOut           string
	HttpxTechOut        string
	NucleiWafOut        string
	NucleiMisconfigOut  string
	NucleiDASTOut       string
	TakeoverCandidates  string
	ProxyScrapingConfig string // intermediate_files/proxy_scraping_config.toml
	ProxyPool           string // intermediate_files/proxy_pool.txt
	TlsSanNewSubs       string
	TlsSanHttpxOut      string
	TlsSanHttpxLive     string
	X8Input             string
}

// newFiles builds all output paths from the result directory.
// Intermediate tool outputs go into intermediate_files/; the workflow
// reads and writes these during the scan. Final product files are
// exported into final_files/ by finalizeScan after all steps complete.
func newFiles(dir string) Files {
	iDir := filepath.Join(dir, "intermediate_files")
	j := func(name string) string { return filepath.Join(iDir, name) }
	// final_files/ paths for outputs that are also consumed as pipeline inputs
	fDir := filepath.Join(dir, "final_files")
	jf := func(name string) string { return filepath.Join(fDir, name) }
	return Files{
		SubfinderOut:       j("subfinder.txt"),
		AssetfinderOut:     j("assetfinder.txt"),
		Sublist3rOut:       j("sublist3r.txt"),
		AmassOut:           j("amass.txt"),
		GithubSubsOut:      j("github_subdomains.txt"),
		WaybackOut:         j("waybackurls.txt"),
		GauOut:             j("gau.txt"),
		UncoverOut:         j("uncover.json"),
		UncoverHostsOut:    j("uncover_hosts.txt"),
		ConsolidatedSubs:   j("all_subdomains.txt"),
		HttpxInput:         j("httpx_input.txt"),
		DnsxOut:            j("dnsx_resolved.json"),
		ShufflednsOut:      j("shuffledns_bruteforce.txt"),
		HttpxOut:           j("httpx_live.json"),
		HttpxLiveHosts:     j("httpx_live_hosts.txt"),
		TlsxOut:            j("tlsx_certs.json"),
		NaabuOut:           j("naabu_ports.txt"),
		KatanaOut:          j("katana_urls.txt"),
		GospiderOut:        j("gospider_urls.txt"),
		GoLinkFinderOut:    j("golinkfinder_endpoints.txt"), // deprecated
		JSEndpointsOut:     j("js_endpoints.txt"),
		JSSecretsOut:       jf(utils.FileGFSecrets),
		JSSubdomainsOut:    j("js_new_subdomains.txt"),
		JSMetadataOut:      j("js_analysis_metadata.txt"),
		HakrawlerOut:       j("hakrawler_crawl.txt"),
		X8Out:              j("x8_params.json"),
		X8URLsOut:          j("x8_urls.txt"),
		AllURLsRaw:         j("all_urls_raw.txt"),
		AllURLsLive:        j("all_urls_live.txt"),
		JSURLsFile:         j("js_urls.txt"),
		ROIMetadataTargets: j("roi_metadata_targets.txt"),
		FfufOut:            j("ffuf_results.json"),
		FfufDiscoveredURLs: j("ffuf_discovered_urls.txt"),
		// Nuclei JSON outputs go to final_files/ — they are product files
		NucleiOut: jf(utils.FileNucleiVulns),
		DalfoxOut: jf(utils.FileDalfoxXSS),
		// Nuclei working files (URL target lists) stay in intermediate_files/
		NucleiURLTargets:    j("nuclei_url_targets.txt"),
		SubjackOut:          j("subjack_takeovers.txt"),
		ParamURLsFile:       j("param_urls_live.txt"),
		HttpxTechOut:        jf("httpx_tech.json"),
		NucleiWafOut:        jf("nuclei_waf.json"),
		NucleiMisconfigOut:  jf("nuclei_misconfig.json"),
		NucleiDASTOut:       jf("nuclei_dast.json"),
		TakeoverCandidates:  j("takeover_candidates.txt"),
		ProxyScrapingConfig: j("proxy_scraping_config.toml"),
		ProxyPool:           j("proxy_pool.txt"),
		TlsSanNewSubs:       j("tls_san_new_subs.txt"),
		TlsSanHttpxOut:      j("tls_san_httpx_out.json"),
		TlsSanHttpxLive:     j("tls_san_httpx_live.txt"),
		X8Input:             j("x8_input.txt"),
	}
}

// ─────────────────────────────────────────────────────────────
// Ctx — shared state passed to every step function
// ─────────────────────────────────────────────────────────────

// Ctx is the shared execution context for the entire scan workflow.
// Every step function receives a *Ctx instead of a long parameter list.
//
// RunConfig is embedded so that all CLI-supplied options (skip flags,
// paths, tokens, etc.) are accessible directly via c.FieldName.
// Adding a new option to RunConfig automatically makes it available
// to every step function — no manual copy block needed.
type Ctx struct {
	RunConfig // embedded — carries all CLI options

	GoCtx     context.Context
	Cancel    context.CancelFunc
	SkipChan  chan struct{}
	ScanID    int64
	StartTime time.Time

	// Tools & infrastructure
	Tb          *tools.ToolBox
	StateMgr    *scan.Manager
	State       *scan.State
	Notifier    *notify.Notifier
	ScopeFilter *scope.Scope // compiled scope rules from config (nil = no filtering)

	// All file paths
	F Files

	// Notifications
	NotifyStepComplete bool

	// WAF evasion
	Proxy string // proxy URL for collector.go (from config or CLI override)

	// Log file path (set when SaveLog is true and file opened successfully)
	LogFilePath string

	// Proxy rotation
	Rotator           *proxy_scraping.Rotator // mubeng background process (nil if not using auto-proxy)
	ProxyTotalScraped int                     // total proxies found during fetch phase
	ProxyTotalValid   int                     // proxies that passed target domain validation

	// Findings
	FfufTotalFindings int // total valid fuzzing discoveries

}

// cancelled returns true when the parent context has been cancelled.
func (c *Ctx) cancelled() bool {
	return c.GoCtx.Err() != nil
}

// urlSources returns the list of URL source files (used by step 15).
func (c *Ctx) urlSources() []string {
	return []string{
		c.F.WaybackOut,
		c.F.GauOut,
		c.F.KatanaOut,
		c.F.GospiderOut,
		c.F.JSEndpointsOut,
		c.F.X8URLsOut,
		c.F.FfufDiscoveredURLs,
	}
}

// ─────────────────────────────────────────────────────────────
// Run — main entry point (called by cli/wildcard.go)
// ─────────────────────────────────────────────────────────────

// Run executes the full Wildcard Reconnaissance Workflow.
// It returns a non-nil error only for fatal pre-scan failures;
// individual step failures are logged and do not abort the run.
func Run(cfg RunConfig) error {
	startTime := time.Now()

	// ── Context & signal plumbing ────────────────────────────
	goCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	skipChan := make(chan struct{}, 1)

	orchestrate.HandleSignals(goCtx, cancel)

	// Listen for 's'/'S' on stdin — skip the currently running tool.
	// A dedicated reader goroutine feeds bytes into a channel so the outer
	// goroutine can exit promptly on context cancellation (os.Stdin.Read
	// is blocking and cannot be interrupted directly).
	stdinCh := make(chan byte, 1)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				close(stdinCh)
				return
			}
			stdinCh <- buf[0]
		}
	}()
	go func() {
		for {
			select {
			case <-goCtx.Done():
				return
			case b, ok := <-stdinCh:
				if !ok {
					return
				}
				if b == 's' || b == 'S' {
					select {
					case skipChan <- struct{}{}:
						// "Skip requested" is logged by runWithSkip when it receives
						// the signal, ensuring correct message ordering.
					default:
						// already a skip pending; ignore
					}
				}
			}
		}
	}()

	// ── Database record & scan state ─────────────────────────
	configJSON, _ := json.Marshal(map[string]any{
		"skip_amass":       cfg.SkipAmass,
		"skip_nuclei":      cfg.SkipNuclei,
		"skip_naabu":       cfg.SkipNaabu,
		"skip_crawl":       cfg.SkipCrawl,
		"skip_takeovers":   cfg.SkipTakeovers,
		"skip_dalfox":      cfg.SkipDalfox,
		"skip_uncover":     cfg.SkipUncover,
		"skip_tlsx":        cfg.SkipTlsx,
		"skip_x8":          cfg.SkipX8,
		"skip_shuffledns":  cfg.SkipShuffleDNS,
		"skip_fingerprint": cfg.SkipFingerprint,
		"skip_js":          cfg.SkipJS,
		"wordlist":         cfg.WordlistPath,
		"dns_wordlist":     cfg.DNSWordlistPath,
		"resolvers":        cfg.ResolversPath,
		"github":           cfg.GitHubToken != "",
		"auto_proxy":       cfg.AutoProxy,
		"save_log":         cfg.SaveLog,
		"custom_cookie":    cfg.CustomCookie,
		"custom_headers":   cfg.CustomHeaders,
		"custom_token":     cfg.CustomToken,
	})

	stateMgr := scan.NewManager(paths.StateDir())
	var scanState *scan.State
	var scanID int64

	if cfg.ResumeScanID > 0 {
		scanID = cfg.ResumeScanID
		existingState, err := stateMgr.LoadState(scanID)
		if err != nil {
			return fmt.Errorf("cannot resume scan #%d: %w", scanID, err)
		}
		scanState = existingState

		// Validate target match
		if scanState.Target != cfg.Domain {
			return fmt.Errorf("target mismatch for resumed scan #%d: state target is %q, but requested target is %q", scanID, scanState.Target, cfg.Domain)
		}

		// Validate result directory match
		if scanState.ResultDir != "" && scanState.ResultDir != cfg.ResultDir {
			logger.Warning("Result directory mismatch for resumed scan #%d: state directory is %q, but current configuration is %q. Adopting state result directory %q.",
				scanID, scanState.ResultDir, cfg.ResultDir, scanState.ResultDir)
			cfg.ResultDir = scanState.ResultDir
		}

		// Reconcile and compare against persisted scanState.Config
		var persistedMap map[string]any
		if err := json.Unmarshal(scanState.Config, &persistedMap); err == nil && persistedMap != nil {
			checkBoolDiff := func(key string, current bool) {
				if val, ok := persistedMap[key].(bool); ok && val != current {
					logger.Warning("Config change detected for option %s: persisted value is %t, current is %t. Resumed scan will use the persisted state/skip config for steps.", key, val, current)
				}
			}
			checkBoolDiff("skip_amass", cfg.SkipAmass)
			checkBoolDiff("skip_nuclei", cfg.SkipNuclei)
			checkBoolDiff("skip_naabu", cfg.SkipNaabu)
			checkBoolDiff("skip_crawl", cfg.SkipCrawl)
			checkBoolDiff("skip_takeovers", cfg.SkipTakeovers)
			checkBoolDiff("skip_dalfox", cfg.SkipDalfox)
			checkBoolDiff("skip_uncover", cfg.SkipUncover)
			checkBoolDiff("skip_tlsx", cfg.SkipTlsx)
			checkBoolDiff("skip_x8", cfg.SkipX8)
			checkBoolDiff("skip_shuffledns", cfg.SkipShuffleDNS)
			checkBoolDiff("skip_fingerprint", cfg.SkipFingerprint)
			checkBoolDiff("skip_js", cfg.SkipJS)
			checkBoolDiff("auto_proxy", cfg.AutoProxy)
			checkBoolDiff("save_log", cfg.SaveLog)

			checkStringDiff := func(key string, current string) {
				if val, ok := persistedMap[key].(string); ok && val != current {
					logger.Warning("Config change detected for option %s: persisted value is %q, current is %q.", key, val, current)
				}
			}
			checkStringDiff("wordlist", cfg.WordlistPath)
			checkStringDiff("dns_wordlist", cfg.DNSWordlistPath)
			checkStringDiff("resolvers", cfg.ResolversPath)
			checkStringDiff("custom_cookie", cfg.CustomCookie)
			checkStringDiff("custom_token", cfg.CustomToken)
		}

		logger.Info("Resuming scan #%d (%.1f%% complete, %d/%d steps done)",
			scanID, scanState.Progress(), len(scanState.CompletedSteps), scanState.TotalSteps)
	} else {
		dbScan, err := database.CreateScan(cfg.Domain, "wildcard", cfg.ResultDir, string(configJSON))
		if err != nil {
			logger.Warning("Failed to create scan record: %v", err)
		}
		if dbScan != nil {
			scanID = dbScan.ID
		}

		var errState error
		scanState, errState = stateMgr.CreateState(scanID, cfg.Domain, "wildcard", cfg.ResultDir, len(scan.WildcardSteps), configJSON)
		if errState != nil {
			return fmt.Errorf("cannot create scan state: %w", errState)
		}
	}

	// ── File logging ──────────────────────────────────────
	// logFilePath is declared here so it outlives the if-block and can be
	// stored on Ctx for display in next-steps at scan end.
	var logFilePath string
	if cfg.SaveLog {
		timestamp := startTime.Format("20060102_150405")
		logFileName := fmt.Sprintf("%s_%d_%s.log", cfg.Domain, scanID, timestamp)
		logFilePath = filepath.Join(paths.LogsDir(), logFileName)
		if err := logger.InitFileLog(logFilePath); err != nil {
			logger.Warning("Could not open log file: %v", err)
			logFilePath = "" // clear so Ctx doesn't show a broken path
		} else {
			logger.WriteLogHeader(cfg.Domain, scanID, logFilePath)
			logger.Info("Scan log: %s", logFilePath)
			defer logger.CloseFileLog()
		}
	}

	// ── Scan header & state UI ──────────────────────────────
	logger.ScanHeader("Wildcard", cfg.Domain, scanID)
	logger.InitScanUI(len(scan.WildcardSteps))

	// ── Runner, ToolBox & Notifier ──────────────────────────
	infra := orchestrate.NewInfra(cfg.Mode, cfg.Verbose, cfg.Cfg)

	var authHeaders []string
	if cfg.CustomToken != "" {
		authHeaders = append(authHeaders, "Authorization: Bearer "+cfg.CustomToken)
	}
	authHeaders = append(authHeaders, cfg.CustomHeaders...)
	infra.ToolBox.WithCustomAuth(cfg.CustomCookie, authHeaders)
	infra.ToolBox.WithResultDir(cfg.ResultDir)

	// ── Ensure output subdirectories exist ───────────────────
	if err := os.MkdirAll(filepath.Join(cfg.ResultDir, "intermediate_files"), 0755); err != nil {
		return fmt.Errorf("cannot create intermediate_files dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.ResultDir, "final_files"), 0755); err != nil {
		return fmt.Errorf("cannot create final_files dir: %w", err)
	}

	// ── Build shared Ctx ─────────────────────────────────────
	c := &Ctx{
		RunConfig:          cfg,
		GoCtx:              goCtx,
		Cancel:             cancel,
		SkipChan:           skipChan,
		ScanID:             scanID,
		StartTime:          startTime,
		Tb:                 infra.ToolBox,
		StateMgr:           stateMgr,
		State:              scanState,
		Notifier:           infra.Notifier,
		F:                  newFiles(cfg.ResultDir),
		NotifyStepComplete: cfg.Cfg != nil && cfg.Cfg.Notifications.StepComplete,
		LogFilePath:        logFilePath,
	}

	// Wire proxy from config
	if cfg.Cfg != nil && cfg.Cfg.General.Proxy != "" {
		c.Proxy = cfg.Cfg.General.Proxy
	}

	if err := c.SetupResolvers(); err != nil {
		logger.Warning("SetupResolvers failed: %v", err)
	}

	// Wire notification logging (FileDebug no-ops if --log is inactive)
	if c.Notifier != nil {
		c.Notifier.LogFunc = logger.FileDebug
		c.Notifier.Done = goCtx.Done()
	}

	logger.Info("Press 's' at any time to skip the current tool")
	logger.Info("Mode: %s", cfg.Mode)

	// Wire scope from config
	if cfg.Cfg != nil {
		sc, err := scope.New(&cfg.Cfg.Scope)
		if err != nil {
			logger.Warning("Failed to compile scope rules: %v", err)
		} else {
			c.ScopeFilter = sc
			if summary := sc.Summary(); summary != "All domains in scope" {
				logger.Info("Scope: %s", summary)
			}
		}
	}

	// ── Step registry ───────────────────────────────────────
	// Each entry maps a scan.WildcardSteps name to its implementation.
	// Order must match scan.WildcardSteps (the source of truth for
	// step names, descriptions, and resume/progress tracking).
	steps := []struct {
		name  string
		phase string
		fn    func(*Ctx) bool
	}{
		// Phase 0 — Proxy Scraping (Step 1)
		{"proxy_scraping", "Proxy Scraping", stepProxyScraping},

		// Phase 1 — Asset Discovery (Steps 2–5)
		{"passive_enum", "Asset Discovery", stepPassiveEnum},
		{"active_enum", "Asset Discovery", stepActiveEnum},
		{"github_recon", "Asset Discovery", stepGitHubRecon},
		{"search_engine_recon", "Asset Discovery", stepSearchEngineRecon},

		// Phase 2 — Validation & Probing (Steps 6–10)
		{"dns_resolution", "Validation & Probing", stepDNSConsolidation},
		{"dns_bruteforce", "Validation & Probing", stepDNSBruteforce},
		{"port_scanning", "Validation & Probing", stepPortScanning},
		{"http_probing", "Validation & Probing", stepHTTPProbing},
		{"tls_analysis", "Validation & Probing", stepTLSAnalysis},

		// Phase 3 — Content Discovery (Steps 11–16)
		{"url_discovery", "Content Discovery", stepURLDiscovery},
		{"web_crawling", "Content Discovery", stepWebCrawling},
		{"js_deep_analysis", "Content Discovery", stepJSDeepAnalysis},
		{"dir_fuzzing", "Content Discovery", stepDirFuzzing},
		{"param_discovery", "Content Discovery", stepParamDiscovery},
		{"url_consolidation", "Content Discovery", stepURLConsolidation},

		// Phase 4 — Vulnerability Scanning (Steps 17–20)
		{"takeover_detection", "Vulnerability Scanning", stepTakeoverDetection},
		{"vuln_scanning", "Vulnerability Scanning", stepVulnScanningInfra},
		{"vuln_scanning_urls", "Vulnerability Scanning", stepVulnScanningURLs},
		{"xss_scanning", "Vulnerability Scanning", stepXSSScanning},

		// Phase 5 — Fingerprinting (Step 21)
		{"tech_waf_fingerprinting", "Fingerprinting", stepFingerprinting},
	}

	phaseNum := -1
	lastPhase := ""
	for _, step := range steps {
		if step.phase != lastPhase {
			lastPhase = step.phase
			phaseNum++
			logger.PhaseBanner(phaseNum, step.phase)
		}
		if executeStep(c, step.name, step.fn) {
			finalizeScan(c, "cancelled")
			return nil
		}
	}

	finalizeScan(c, "completed")
	return nil
}

func executeStep(c *Ctx, stepName string, fn func(*Ctx) bool) bool {
	alreadyCompleted := c.State != nil && c.State.IsStepCompleted(stepName)
	cancelled := fn(c)
	if !alreadyCompleted && c.State != nil && c.State.IsStepCompleted(stepName) {
		notifyStepCompletion(c, stepName)
	}
	return cancelled
}

func notifyStepCompletion(c *Ctx, stepName string) {
	if c.Notifier == nil || !c.NotifyStepComplete {
		return
	}

	stepNumber := 0
	stepDescription := stepName
	for i, step := range scan.WildcardSteps {
		if step.Name == stepName {
			stepNumber = i + 1
			stepDescription = step.Description
			break
		}
	}

	// For proxy_scraping, enrich the description with both counts so all
	// notification backends (Discord, Slack, Telegram) show the full picture.
	if stepName == "proxy_scraping" && c.ProxyTotalScraped > 0 {
		stepDescription = fmt.Sprintf("%s — %d scraped, %d passed WAF check",
			stepDescription, c.ProxyTotalScraped, c.ProxyTotalValid)
	}

	if err := c.Notifier.SendStepComplete(notify.StepComplete{
		Target:          c.Domain,
		ScanID:          c.ScanID,
		ScanType:        "wildcard",
		StepName:        stepName,
		StepDescription: stepDescription,
		StepNumber:      stepNumber,
		TotalSteps:      len(scan.WildcardSteps),
		Duration:        time.Since(c.StartTime),
		FindingsCount:   countFindingsForStep(c, stepName),
		Timestamp:       time.Now(),
	}); err != nil {
		logger.Warning("Failed to send step completion notification: %v", err)
	}
}

func countFindingsForStep(c *Ctx, stepName string) int {
	countLines := func(files ...string) int {
		total := 0
		for _, file := range files {
			if cnt, err := utils.CountFileLines(file); err == nil {
				total += cnt
			}
		}
		return total
	}

	switch stepName {
	case "proxy_scraping":
		return c.ProxyTotalValid // WAF-passed proxies ready for rotation
	case "passive_enum":
		// Rather than raw lists, the best representation of this step is often the raw results concatenated.
		// Subdomains are consolidated later, but we can count the underlying outputs.
		return countLines(c.F.SubfinderOut, c.F.AssetfinderOut, c.F.Sublist3rOut)
	case "active_enum":
		return countLines(c.F.AmassOut)
	case "github_recon":
		return countLines(c.F.GithubSubsOut)
	case "search_engine_recon":
		return countLines(c.F.UncoverOut)
	case "dns_resolution":
		if cnt, err := utils.CountUniqueDNSxHosts(c.F.DnsxOut); err == nil {
			return cnt
		}
		return 0
	case "dns_bruteforce":
		return countLines(c.F.ShufflednsOut)
	case "http_probing":
		return countLines(c.F.HttpxLiveHosts)
	case "tls_analysis":
		return countLines(c.F.TlsxOut)
	case "port_scanning":
		return countLines(c.F.NaabuOut)
	case "url_discovery":
		return countLines(c.F.WaybackOut, c.F.GauOut)
	case "web_crawling":
		return countLines(c.F.KatanaOut, c.F.GospiderOut)
	case "js_deep_analysis":
		return countLines(c.F.JSEndpointsOut, c.F.JSSecretsOut)
	case "js_subdomain_discovery":
		return 0 // deprecated step — kept for resume compat
	case "param_discovery":
		return countLines(c.F.X8URLsOut)
	case "url_consolidation":
		return countLines(c.F.AllURLsLive)
	case "dir_fuzzing":
		return c.FfufTotalFindings // Uses properly parsed JSON array count, not lines
	case "vuln_scanning":
		return countLines(c.F.NucleiOut, c.F.NucleiMisconfigOut)
	case "vuln_scanning_urls":
		return countLines(c.F.NucleiDASTOut)
	case "takeover_detection":
		return countLines(c.F.SubjackOut)
	case "xss_scanning":
		return countLines(c.F.DalfoxOut)
	case "tech_waf_fingerprinting":
		return countLines(c.F.NucleiWafOut)
	default:
		return 0
	}
}

// totalVulnCount sums all severity counts in the vulnerability map.
func totalVulnCount(vulns map[string]int) int {
	total := 0
	for _, count := range vulns {
		total += count
	}
	return total
}

// ─────────────────────────────────────────────────────────────
// finalizeScan — persist summary, export, notify, report
// ─────────────────────────────────────────────────────────────

func finalizeScan(c *Ctx, status string) {
	duration := time.Since(c.StartTime)

	// Kill mubeng rotating proxy if running
	if c.Rotator != nil {
		c.Rotator.Stop()
		logger.Info("Rotating proxy server stopped")
	}
	if c.ScanID > 0 {
		database.UpdateScanStatus(c.ScanID, status)
	}

	// Clean up state file for completed scans
	if status == "completed" && c.StateMgr != nil && c.State != nil {
		c.StateMgr.DeleteState(c.State.ScanID)
	}

	stats := make([]logger.Stat, 0, 8)
	if c.ScanID > 0 {
		dbStats, err := database.GetScanStats(c.ScanID)
		if err == nil {
			stats = append(stats,
				logger.Stat{Label: "Subdomains", Value: fmt.Sprintf("%d (Live: %d)", dbStats.TotalSubdomains, dbStats.LiveSubdomains)},
				logger.Stat{Label: "Open Ports", Value: fmt.Sprintf("%d", dbStats.TotalPorts)},
				logger.Stat{Label: "URLs", Value: fmt.Sprintf("%d", dbStats.TotalURLs)},
				logger.Stat{Label: "Endpoints", Value: fmt.Sprintf("%d", dbStats.TotalEndpoints)},
			)
			// Canonical severity order first, then any non-standard ones.
			printed := make(map[string]bool, len(dbStats.Vulnerabilities))
			for _, sev := range utils.SeverityOrder() {
				if count, ok := dbStats.Vulnerabilities[sev]; ok {
					stats = append(stats, logger.Stat{Label: "Vuln (" + sev + ")", Value: fmt.Sprintf("%d", count)})
					printed[sev] = true
				}
			}
			for sev, count := range dbStats.Vulnerabilities {
				if printed[sev] {
					continue
				}
				label := sev
				if label == "" {
					label = "unknown"
				}
				stats = append(stats, logger.Stat{Label: "Vuln (" + label + ")", Value: fmt.Sprintf("%d", count)})
			}

			if c.Notifier != nil {
				if err := c.Notifier.SendScanComplete(notify.ScanComplete{
					Target:   c.Domain,
					ScanID:   c.ScanID,
					Duration: duration,
					Stats: map[string]int{
						"subdomains": dbStats.TotalSubdomains,
						"ports":      dbStats.TotalPorts,
						"vulns":      totalVulnCount(dbStats.Vulnerabilities),
					},
				}); err != nil {
					logger.Warning("Failed to send scan complete notification: %v", err)
				}
			}
		}

		logger.ScanSummary(status, c.Domain, c.ScanID, duration, stats)
		logger.Success("Results saved in: %s", c.ResultDir)

		// Export results into final_files/
		if status == "completed" || status == "cancelled" {
			finalDir := filepath.Join(c.ResultDir, "final_files")
			logger.Print("\n")
			logger.Info("Exporting results to final_files/...")
			if err := ingest.ExportResults(c.ScanID, finalDir); err != nil {
				logger.Warning("Failed to export some results: %v", err)
			} else {
				logger.Success("Results exported to final_files/")
			}
			if err := ingest.ExportSummary(c.ScanID, finalDir, c.Domain); err != nil {
				logger.Warning("Failed to create summary: %v", err)
			}
		}

		// Generate report
		if c.GenerateReport && status == "completed" {
			logger.Print("\n")
			logger.Info("Generating report...")
			rpt, err := report.Generate(c.ScanID)
			if err == nil {
				reportPath := filepath.Join(paths.ReportsDir(), fmt.Sprintf("scan_%d.md", c.ScanID))
				if err := rpt.Export(report.FormatMarkdown, reportPath); err == nil {
					logger.Success("Report saved: %s", reportPath)
				}
				localReportPath := filepath.Join(c.ResultDir, "REPORT.md")
				if err := rpt.Export(report.FormatMarkdown, localReportPath); err == nil {
					logger.Success("Report also saved: %s", localReportPath)
				}
			}
		}
	}

	if c.ScanID > 0 {
		hints := []string{
			fmt.Sprintf("chaathan scans show %d       # View scan details", c.ScanID),
			fmt.Sprintf("chaathan query vulns %d      # List vulnerabilities", c.ScanID),
			fmt.Sprintf("chaathan report generate %d  # Generate full report", c.ScanID),
		}
		if c.LogFilePath != "" {
			hints = append([]string{fmt.Sprintf("cat %s  # full scan log", c.LogFilePath)}, hints...)
		}
		logger.NextSteps(hints)
	}
}

// SetupResolvers ensures that a valid resolvers file exists.
// If c.ResolversPath is empty, it writes a default set of public DNS resolvers
// directly to the scan's intermediate directory and sets c.ResolversPath to that file.
func (c *Ctx) SetupResolvers() error {
	if c.ResolversPath == "" {
		destPath := filepath.Join(filepath.Dir(c.F.ConsolidatedSubs), "resolvers.txt")
		if !utils.FileExists(destPath) {
			defaultResolvers := "1.1.1.1\n1.0.0.1\n8.8.8.8\n8.8.4.4\n9.9.9.9\n149.112.112.112\n"
			_ = os.MkdirAll(filepath.Dir(destPath), 0755)
			if err := os.WriteFile(destPath, []byte(defaultResolvers), 0644); err != nil {
				logger.Warning("Failed to create default resolvers file: %v", err)
				return err
			}
			logger.FileDebug("Created default resolvers file at: %s", destPath)
		}
		c.ResolversPath = destPath
	}
	return nil
}
