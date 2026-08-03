// Package cli – Wildcard command
//
// This file is intentionally thin. It only contains the cobra command
// definition, flag wiring, and a single call into pkg/wildcard_flow.Run().
// All scan logic lives in the wildcard_flow package.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan/pkg/logger"
	wf "github.com/vishnu303/chaathan/pkg/wildcard_flow"
	"github.com/vishnu303/chaathan/utils"
)

// ─────────────────────────────────────────────────────────────
// CLI flags (package-level for cobra binding)
// ─────────────────────────────────────────────────────────────

var (
	targetDomain    string
	skipAmass       bool
	skipNuclei      bool
	skipNaabu       bool
	skipCrawl       bool
	skipTakeovers   bool
	skipDalfox      bool
	skipUncover     bool
	skipTlsx        bool
	skipX8          bool
	skipShuffleDNS  bool
	skipFingerprint bool
	skipJS          bool
	wordlistPath    string
	dnsWordlistPath string
	resolversPath   string
	githubToken     string
	resumeScanID    int64
	generateReport  bool
	proxyURL        string
	rateLimitRPS    int
	saveLog         bool
	customCookie    string
	customHeaders   []string
	customToken     string
	autoProxy       bool
)

// ─────────────────────────────────────────────────────────────
// Cobra command
// ─────────────────────────────────────────────────────────────

var wildcardCmd = &cobra.Command{
	Use:     "wildcard",
	Aliases: []string{"scan"},
	Short:   "Run the Wildcard Reconnaissance Workflow",
	Long: `
Runs a comprehensive 22-step recon & vulnerability scanning workflow
organised into 6 clean phases:

  PHASE 0 — PROXY SETUP (Step 1)
  1. Proxy Scraping & IP Rotation Setup (Mubeng) [Optional, --auto-proxy]

  PHASE 1 — ASSET DISCOVERY (Steps 2–5)
  2. Passive Enumeration (Subfinder, Assetfinder, Sublist3r) [Parallel]
  3. Active Enumeration (Amass) [Optional, --skip-amass]
  4. GitHub Subdomain Discovery [Requires GITHUB_TOKEN]
  5. Search Engine Dorking (Uncover/Shodan/Censys) [Optional, --skip-uncover]

  PHASE 2 — VALIDATION & PROBING (Steps 6–10)
  6. Consolidation & DNS Resolution (DNSx)
  7. DNS Brute-force (ShuffleDNS/MassDNS) [Optional, --skip-shuffledns]
  8. Port Scanning on ALL subdomains (Naabu) [Optional, --skip-naabu]
  9. Live Web Probing (Httpx) [+ host metadata collection for ROI]
  10. TLS Certificate Analysis (tlsx) [Optional, --skip-tlsx]

  PHASE 3 — CONTENT DISCOVERY (Steps 11–16)
  11. Historical URL Discovery (Waybackurls, GAU) [Parallel]
  12. Web Crawling (Katana, GoSpider) [Parallel, --skip-crawl]
  13. JavaScript Deep Analysis (jsluice + secrets)
  14. Directory Fuzzing (ffuf) [Requires --wordlist]
  15. HTTP Parameter Discovery (x8) [Optional, --skip-x8]
  16. URL Consolidation & Live Check (httpx)

  PHASE 4 — VULNERABILITY SCANNING (Steps 17–20)
  17. Subdomain Takeover Detection (Nuclei) [Optional, --skip-takeovers]
  18. Vulnerability Scanning — Infra (Nuclei) [Optional, --skip-nuclei]
  19. Vulnerability Scanning — URLs (Nuclei) [Optional, --skip-nuclei]
  20. XSS Scanning (Dalfox) [Optional, --skip-dalfox]

  PHASE 5 — FINGERPRINTING (Step 21)
  21. Technology & WAF Fingerprinting (Httpx, Nuclei) [Optional, --skip-fingerprint]

Press 's' at any time during scanning to skip the current tool.
All results are stored in a SQLite database for querying and reporting.
`,
	Run: runWildcard,
}

func init() {
	wildcardCmd.Flags().StringVarP(&targetDomain, "domain", "d", "", "Target domain (required)")
	wildcardCmd.Flags().BoolVar(&skipAmass, "skip-amass", false, "Skip Amass (slow but thorough)")
	wildcardCmd.Flags().BoolVar(&skipNuclei, "skip-nuclei", false, "Skip vulnerability scanning (Nuclei infra/URLs/takeovers)")
	wildcardCmd.Flags().BoolVar(&skipNaabu, "skip-naabu", false, "Skip Naabu port scanning")
	wildcardCmd.Flags().BoolVar(&skipCrawl, "skip-crawl", false, "Skip web crawling (Katana + GoSpider)")
	wildcardCmd.Flags().BoolVar(&skipDalfox, "skip-dalfox", false, "Skip XSS scanning (Dalfox)")
	wildcardCmd.Flags().BoolVar(&skipTakeovers, "skip-takeovers", false, "Skip subdomain takeover detection (Nuclei takeovers)")
	wildcardCmd.Flags().BoolVar(&skipUncover, "skip-uncover", false, "Skip search engine dorking (Uncover)")
	wildcardCmd.Flags().BoolVar(&skipTlsx, "skip-tlsx", false, "Skip TLS certificate analysis")
	wildcardCmd.Flags().BoolVar(&skipX8, "skip-x8", false, "Skip x8 parameter discovery")
	wildcardCmd.Flags().BoolVar(&skipShuffleDNS, "skip-shuffledns", false, "Skip ShuffleDNS brute-force")
	wildcardCmd.Flags().BoolVar(&skipFingerprint, "skip-fingerprint", false, "Skip Technology & WAF Fingerprinting step")
	wildcardCmd.Flags().BoolVar(&skipJS, "skip-js", false, "Skip JavaScript Deep Analysis (jsluice + secrets)")
	wildcardCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Wordlist for directory fuzzing with ffuf (auto-detects SecLists on device if omitted)")
	wildcardCmd.Flags().StringVar(&dnsWordlistPath, "dns-wordlist", "", "Wordlist for DNS brute-force with ShuffleDNS (auto-detects SecLists on device if omitted)")
	wildcardCmd.Flags().StringVar(&resolversPath, "resolvers", "", "Custom DNS resolvers file for ShuffleDNS")
	wildcardCmd.Flags().StringVar(&githubToken, "github-token", "", "GitHub token for GitHub recon (or use GITHUB_TOKEN env)")
	wildcardCmd.Flags().Int64Var(&resumeScanID, "resume", 0, "Resume a previous scan by ID")
	wildcardCmd.Flags().BoolVar(&generateReport, "report", true, "Generate report after scan")
	wildcardCmd.Flags().StringVar(&proxyURL, "proxy", "", "Proxy URL for target-facing tools (e.g., socks5://127.0.0.1:9050)")
	wildcardCmd.Flags().IntVar(&rateLimitRPS, "rate-limit", 0, "Global rate limit (requests/sec) for all tools (0 = per-tool defaults)")
	wildcardCmd.Flags().BoolVar(&saveLog, "log", false, "Save scan output to ~/.chaathan/logs/ (plain text, ANSI stripped)")
	wildcardCmd.Flags().StringVar(&customCookie, "cookie", "", "Custom session cookie string (e.g. 'auth=123; PHPSESSID=abc')")
	wildcardCmd.Flags().StringSliceVarP(&customHeaders, "header", "H", nil, "Custom request header (can be repeated, e.g. -H 'Authorization: Bearer token')")
	wildcardCmd.Flags().StringVar(&customToken, "token", "", "Bearer token shorthand (injects 'Authorization: Bearer <token>')")
	wildcardCmd.Flags().BoolVar(&autoProxy, "auto-proxy", false, "Auto-scrape free proxies, validate against target, and rotate IPs during scan")
	_ = wildcardCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(wildcardCmd)
}

// ─────────────────────────────────────────────────────────────
// runWildcard — cobra handler
// ─────────────────────────────────────────────────────────────

func runWildcard(cmd *cobra.Command, args []string) {
	// Validate the target domain before doing anything
	if err := utils.ValidateDomain(targetDomain); err != nil {
		logger.Error("Invalid target: %v", err)
		return
	}

	// Resolve GitHub token: --github-token flag takes priority,
	// then the API key set in the chaathan config file.
	// The OS GITHUB_TOKEN env var is intentionally not read here.
	token := githubToken
	if token == "" && Cfg != nil {
		if t := Cfg.GetAPIKey("github"); t != "" {
			token = t
		}
	}

	// Create result directory (reuses root.go helper)
	resultDir, err := CreateOutputDir(targetDomain)
	if err != nil {
		logger.Error("Error creating output dir: %v", err)
		return
	}

	// Forward Ctrl+C / 's'-key to wildcard_flow.Run() which owns signal
	// handling and stdin listener internally.

	overrideConfigOverrides(proxyURL, rateLimitRPS)

	// Resolve wordlist/resolver paths: CLI flag > config > empty (step skips)
	var wl, dnsWl, resolvers string
	if Cfg != nil {
		wl = resolvePath(wordlistPath, Cfg.General.Wordlists.Directories)
		dnsWl = resolvePath(dnsWordlistPath, Cfg.General.Wordlists.Subdomains)
		resolvers = resolvePath(resolversPath, Cfg.General.ResolversFile)
	} else {
		wl = wordlistPath
		dnsWl = dnsWordlistPath
		resolvers = resolversPath
	}

	// Build configuration and delegate to the wildcard_flow package
	cfg := wf.RunConfig{
		Domain:          targetDomain,
		ResultDir:       resultDir,
		Mode:            Mode,
		Verbose:         Verbose,
		Cfg:             Cfg,
		SkipAmass:       skipAmass,
		SkipNuclei:      skipNuclei,
		SkipNaabu:       skipNaabu,
		SkipCrawl:       skipCrawl,
		SkipTakeovers:   skipTakeovers,
		SkipDalfox:      skipDalfox,
		SkipUncover:     skipUncover,
		SkipTlsx:        skipTlsx,
		SkipX8:          skipX8,
		SkipShuffleDNS:  skipShuffleDNS,
		SkipFingerprint: skipFingerprint,
		SkipJS:          skipJS,
		WordlistPath:    wl,
		DNSWordlistPath: dnsWl,
		ResolversPath:   resolvers,
		GitHubToken:     token,
		ResumeScanID:    resumeScanID,
		GenerateReport:  generateReport,
		SaveLog:         saveLog,
		CustomCookie:    customCookie,
		CustomHeaders:   customHeaders,
		CustomToken:     customToken,
		AutoProxy:       autoProxy,
	}

	if err := wf.Run(cfg); err != nil {
		logger.Error("Wildcard scan failed: %v", err)
	}
}
