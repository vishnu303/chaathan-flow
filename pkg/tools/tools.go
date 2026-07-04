package tools

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/runner"
)

// ToolBox wraps the runner and provides methods to invoke external recon tools.
// It reads per-tool settings (threads, timeouts, rate limits) from the config
// so users can tune behavior via config.yaml instead of recompiling.
type ToolBox struct {
	Runner        runner.Runner
	Config        *config.ToolsConfig
	General       *config.GeneralConfig   // WAF evasion settings (UA rotation, proxy, etc.)
	RateLimits    *config.RateLimitConfig // Global rate-limit override
	APIKeys       *config.APIKeysConfig
	CustomCookie  string
	CustomHeaders []string
	ResultDir     string
}

type resultDirRunner struct {
	base runner.Runner
	dir  string
}

func (r *resultDirRunner) Run(ctx context.Context, command string, args []string, opts ...runner.Option) (string, error) {
	if r.dir != "" {
		opts = append(opts, runner.WithDir(r.dir))
	}
	return r.base.Run(ctx, command, args, opts...)
}

// New creates a ToolBox. If cfg is nil, sensible defaults are used.
func New(r runner.Runner, cfg ...*config.ToolsConfig) *ToolBox {
	tb := &ToolBox{Runner: r}
	if len(cfg) > 0 && cfg[0] != nil {
		tb.Config = cfg[0]
	}
	return tb
}

// WithResultDir sets the scan result directory and wraps the runner to inject it in Docker mode.
func (t *ToolBox) WithResultDir(dir string) *ToolBox {
	t.ResultDir = dir
	if dir != "" {
		if wrapped, ok := t.Runner.(*resultDirRunner); ok {
			wrapped.dir = dir
		} else {
			t.Runner = &resultDirRunner{
				base: t.Runner,
				dir:  dir,
			}
		}
	}
	return t
}

// WithCustomAuth attaches custom session headers and cookies to the ToolBox.
func (t *ToolBox) WithCustomAuth(cookie string, headers []string) *ToolBox {
	t.CustomCookie = cookie
	t.CustomHeaders = headers
	return t
}

// appendCustomHeaders appends custom headers (e.g. -H "Authorization: ...") to the argument slice.
func (t *ToolBox) appendCustomHeaders(args []string, flagName string) []string {
	for _, h := range t.CustomHeaders {
		args = append(args, flagName, h)
	}
	return args
}

// appendCustomCookies appends custom cookies using the requested tool flag.
func (t *ToolBox) appendCustomCookies(args []string, flagName string) []string {
	if t.CustomCookie != "" {
		args = append(args, flagName, t.CustomCookie)
	}
	return args
}

// WithGeneral attaches general config to the ToolBox (WAF evasion, etc.).
func (t *ToolBox) WithGeneral(gen *config.GeneralConfig) *ToolBox {
	t.General = gen
	return t
}

// WithRateLimits attaches rate-limit config to the ToolBox.
func (t *ToolBox) WithRateLimits(rl *config.RateLimitConfig) *ToolBox {
	t.RateLimits = rl
	return t
}

// WithAPIKeys attaches API key config to the ToolBox (used by uncover, etc).
func (t *ToolBox) WithAPIKeys(keys *config.APIKeysConfig) *ToolBox {
	t.APIKeys = keys
	return t
}

// --- User-Agent rotation pool ---

// TODO(ua-refresh): The User-Agent pool is currently hardcoded and will age over time.
// RealUserAgents contains common, high-frequency browser User-Agent strings.
// Rotating through these prevents WAF fingerprinting from static tool UAs
// like "httpx - Open-source project" or "Nuclei - Open-source project".
var RealUserAgents = []string{
	// Chrome 147 on Windows 10
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	// Chrome 147 on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	// Chrome 147 on Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	// Firefox 149 on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
	// Firefox 149 on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
	// Edge 147 on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0",
	// Safari 18 on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
}

// RandomUA returns a random User-Agent from the pool.
func RandomUA() string {
	return RealUserAgents[rand.N(len(RealUserAgents))]
}

// uaEnabled returns true when UA rotation is active.
// Controlled by the ua_rotation config field (default: true in DefaultConfig).
func (t *ToolBox) uaEnabled() bool {
	return t.General != nil && (t.General.UARotation || t.General.UserAgent != "")
}

// getUA returns the User-Agent to use: fixed override or random from pool.
func (t *ToolBox) getUA() string {
	if t.General != nil && t.General.UserAgent != "" {
		return t.General.UserAgent
	}
	return RandomUA()
}

type appendOptions struct {
	uaHeader    bool
	tlsOpSec    bool
	customHFlag string // e.g. "-H"
	cookieFlag  string // e.g. "-cookie" or "-b"
	proxyFlag   string // e.g. "-http-proxy" or "-proxy" or "-x"
}

// appendCommon consolidates repetitive appends for User-Agent, TLS opsec,
// custom headers, custom cookies, and proxy parameters into a single call.
func (t *ToolBox) appendCommon(args []string, opts appendOptions) []string {
	if opts.uaHeader {
		args = t.appendUAHeader(args)
	}
	if opts.tlsOpSec {
		args = t.appendTLSOpSec(args)
	}
	if opts.customHFlag != "" {
		args = t.appendCustomHeaders(args, opts.customHFlag)
	}
	if opts.cookieFlag != "" {
		args = t.appendCustomCookies(args, opts.cookieFlag)
	}
	if opts.proxyFlag != "" {
		args = t.appendProxy(args, opts.proxyFlag)
	}
	return args
}

// appendUAHeader appends a -H "User-Agent: ..." flag pair for tools that
// accept the -H syntax (httpx, nuclei, katana, ffuf).
func (t *ToolBox) appendUAHeader(args []string) []string {
	if !t.uaEnabled() {
		return args
	}
	return append(args, "-H", "User-Agent: "+t.getUA())
}

// appendTLSOpSec appends the "-tls-impersonate" flag to the arguments
// to enable browser-like JA3/JA4 TLS fingerprint spoofing for supported tools.
func (t *ToolBox) appendTLSOpSec(args []string) []string {
	return append(args, "-tls-impersonate")
}

// appendDalfoxUA appends --user-agent "..." for dalfox.
func (t *ToolBox) appendDalfoxUA(args []string) []string {
	if !t.uaEnabled() {
		return args
	}
	return append(args, "--user-agent", t.getUA())
}

// appendGoSpiderUA appends -u "..." for gospider.
func (t *ToolBox) appendGoSpiderUA(args []string) []string {
	if !t.uaEnabled() {
		return args
	}
	return append(args, "-u", t.getUA())
}

// appendX8Headers appends headers for x8.
// x8 expects repeated -H arguments: -H "Name: Value".
func (t *ToolBox) appendX8Headers(args []string) []string {
	// Add User-Agent
	if t.uaEnabled() {
		args = append(args, "-H", "User-Agent: "+t.getUA())
	}

	// Merge custom headers
	for _, h := range t.CustomHeaders {
		if strings.Contains(h, ":") {
			args = append(args, "-H", h)
		}
	}

	// Merge custom cookie
	if t.CustomCookie != "" {
		args = append(args, "-H", "Cookie: "+t.CustomCookie)
	}

	return args
}

// --- Proxy helpers ---

// proxy returns the configured proxy URL, or "" if none.
func (t *ToolBox) proxy() string {
	if t.General != nil && t.General.Proxy != "" {
		return t.General.Proxy
	}
	return ""
}

// appendProxy appends the tool-specific proxy flag when a proxy is configured.
func (t *ToolBox) appendProxy(args []string, flagName string) []string {
	if p := t.proxy(); p != "" {
		return append(args, flagName, p)
	}
	return args
}

// --- Rate-limit helpers ---

// globalRPS returns the global rate limit override, or 0 if none.
func (t *ToolBox) globalRPS() int {
	if t.RateLimits != nil && t.RateLimits.GlobalRPS > 0 {
		return t.RateLimits.GlobalRPS
	}
	return 0
}

// effectiveRate returns the lower of globalRPS and perToolRate (ceiling logic).
// When globalRPS is 0 (unset), the per-tool rate is used as-is.
func (t *ToolBox) effectiveRate(perToolRate int) int {
	if grl := t.globalRPS(); grl > 0 && grl < perToolRate {
		return grl
	}
	return perToolRate
}

// --- helpers to read config with fallback defaults ---

func (t *ToolBox) subfinderThreads() int {
	if t.Config != nil && t.Config.Subfinder.Threads > 0 {
		return t.Config.Subfinder.Threads
	}
	return 30
}

func (t *ToolBox) subfinderTimeout() int {
	if t.Config != nil && t.Config.Subfinder.Timeout > 0 {
		return t.Config.Subfinder.Timeout
	}
	return 30
}

func (t *ToolBox) httpxThreads() int {
	if t.Config != nil && t.Config.Httpx.Threads > 0 {
		return t.Config.Httpx.Threads
	}
	return 50
}

func (t *ToolBox) httpxTimeout() int {
	if t.Config != nil && t.Config.Httpx.Timeout > 0 {
		return t.Config.Httpx.Timeout
	}
	return 10
}

func (t *ToolBox) httpxPorts() string {
	if t.Config != nil && len(t.Config.Httpx.Ports) > 0 {
		return strings.Join(t.Config.Httpx.Ports, ",")
	}
	return "80,443,8080,8443,8081,8000,8008,8888"
}

func (t *ToolBox) naabuThreads() int {
	if t.Config != nil && t.Config.Naabu.Threads > 0 {
		return t.Config.Naabu.Threads
	}
	return 25
}

func (t *ToolBox) naabuRate() int {
	if t.Config != nil && t.Config.Naabu.Rate > 0 {
		return t.Config.Naabu.Rate
	}
	return 1000
}

func (t *ToolBox) naabuPorts() string {
	if t.Config != nil && t.Config.Naabu.Ports != "" {
		return t.Config.Naabu.Ports
	}
	return "" // empty means use -top-ports 1000 flag
}

func (t *ToolBox) naabuTopPorts() int {
	// Default to top 1000 ports when no explicit port list is set
	if t.Config != nil && t.Config.Naabu.Ports != "" {
		return 0 // explicit port list set, don't use -top-ports
	}
	return 1000
}

func (t *ToolBox) nucleiConcurrency() int {
	if t.Config != nil && t.Config.Nuclei.Concurrency > 0 {
		return t.Config.Nuclei.Concurrency
	}
	return 25
}

func (t *ToolBox) nucleiRateLimit() int {
	if t.Config != nil && t.Config.Nuclei.RateLimit > 0 {
		return t.Config.Nuclei.RateLimit
	}
	return 150
}

func (t *ToolBox) nucleiExcludeTags() []string {
	if t.Config != nil && len(t.Config.Nuclei.ExcludeTags) > 0 {
		return t.Config.Nuclei.ExcludeTags
	}
	return []string{"dos", "fuzz"}
}

func (t *ToolBox) nucleiDisableOOB() bool {
	if t.Config != nil && t.Config.Nuclei.DisableOOB != nil {
		return *t.Config.Nuclei.DisableOOB
	}
	return true // disabled by default — Interactsh hangs are a major stuck source
}

func (t *ToolBox) nucleiMaxTimeout() time.Duration {
	if t.Config != nil && t.Config.Nuclei.MaxTimeout > 0 {
		return time.Duration(t.Config.Nuclei.MaxTimeout) * time.Minute
	}
	return 300 * time.Minute
}

func (t *ToolBox) dastAggression() string {
	if t.Config != nil && t.Config.Nuclei.DASTAggression != "" {
		return t.Config.Nuclei.DASTAggression
	}
	return "high"
}


func (t *ToolBox) nucleiSeverity() []string {
	if t.Config != nil && len(t.Config.Nuclei.Severity) > 0 {
		return t.Config.Nuclei.Severity
	}
	return nil // default: all severities
}

func (t *ToolBox) nucleiInfraTags() []string {
	return []string{"cve", "rce", "sqli", "ssrf", "lfi", "exposure", "default-login", "misconfig"}
}

func (t *ToolBox) nucleiURLTags() []string {
	// xss is handled by Dalfox (Step 21) — no duplication needed here
	return []string{"sqli", "ssrf", "lfi", "rce", "ssti", "idor"}
}

func (t *ToolBox) ffufThreads() int {
	if t.Config != nil && t.Config.Ffuf.Threads > 0 {
		return t.Config.Ffuf.Threads
	}
	return 50
}

func (t *ToolBox) ffufTimeout() int {
	if t.Config != nil && t.Config.Ffuf.Timeout > 0 {
		return t.Config.Ffuf.Timeout
	}
	return 10
}

func (t *ToolBox) ffufMatchCodes() string {
	if t.Config != nil && len(t.Config.Ffuf.MatchCodes) > 0 {
		var codes []string
		for _, c := range t.Config.Ffuf.MatchCodes {
			codes = append(codes, strconv.Itoa(c))
		}
		return strings.Join(codes, ",")
	}
	return "200,201,204,301,302,307,401,403,405,500"
}

func (t *ToolBox) naabuMaxTimeout() time.Duration {
	if t.Config != nil && t.Config.Naabu.Timeout > 0 {
		return time.Duration(t.Config.Naabu.Timeout) * time.Minute
	}
	return 240 * time.Minute
}

func (t *ToolBox) ffufMaxTimeout() time.Duration {
	if t.Config != nil && t.Config.Ffuf.MaxTimeout > 0 {
		return time.Duration(t.Config.Ffuf.MaxTimeout) * time.Minute
	}
	return 180 * time.Minute
}

func (t *ToolBox) katanaMaxTimeout() time.Duration {
	if t.Config != nil && t.Config.Katana.Timeout > 0 {
		return time.Duration(t.Config.Katana.Timeout) * time.Minute
	}
	return 300 * time.Minute
}

func (t *ToolBox) goSpiderMaxTimeout() time.Duration {
	if t.Config != nil && t.Config.GoSpider.Timeout > 0 {
		return time.Duration(t.Config.GoSpider.Timeout) * time.Minute
	}
	return 300 * time.Minute
}

// --- Passive Enumeration ---

func (t *ToolBox) RunSubfinder(ctx context.Context, domain string, outputFile string) error {
	args := []string{
		"-d", domain,
		"-silent",
		"-t", strconv.Itoa(t.subfinderThreads()),
		"-timeout", strconv.Itoa(t.subfinderTimeout()),
		"-o", outputFile,
	}

	// Pass API keys as env vars so subfinder picks them up as provider keys.
	var opts []runner.Option
	if t.APIKeys != nil {
		var envVars []string
		if t.APIKeys.VirusTotal != "" {
			envVars = append(envVars, "VT_API_KEY="+t.APIKeys.VirusTotal)
		}
		if t.APIKeys.Chaos != "" {
			envVars = append(envVars, "PDCP_API_KEY="+t.APIKeys.Chaos)
		}
		if len(envVars) > 0 {
			opts = append(opts, runner.WithEnv(envVars...))
		}
	}

	_, err := t.Runner.Run(ctx, "subfinder", args, opts...)
	return err
}

func (t *ToolBox) RunAssetfinder(ctx context.Context, domain string, outputFile string) error {
	args := []string{"--subs-only", domain}
	output, err := t.Runner.Run(ctx, "assetfinder", args)
	if strings.TrimSpace(output) != "" {
		if writeErr := writeToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// RunSublist3r runs Sublist3r.
// Note: Sublist3r is a python tool, and the docker image (alpine) doesn't have python.
// Therefore, Sublist3r runs natively only; docker runner will fail due to lack of python in the alpine base.
func (t *ToolBox) RunSublist3r(ctx context.Context, domain string, outputFile string) error {
	args := []string{"-d", domain, "-t", "50", "-v", "-o", outputFile}
	_, err := t.Runner.Run(ctx, "sublist3r", args)
	return err
}

// --- Active Enumeration ---

func (t *ToolBox) RunAmass(ctx context.Context, domain string, outputFile string) error {
	args := []string{"enum", "-active", "-alts", "-d", domain, "-o", outputFile}
	if t.Config != nil && t.Config.Amass.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(t.Config.Amass.Timeout))
	}
	_, err := t.Runner.Run(ctx, "amass", args)
	return err
}

// RunAmassIntel runs `amass intel -whois` to discover root domains owned by an org.
func (t *ToolBox) RunAmassIntel(ctx context.Context, org string, outputFile string) error {
	args := []string{"intel", "-whois", "-d", org, "-o", outputFile}
	if t.Config != nil && t.Config.Amass.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(t.Config.Amass.Timeout))
	}
	_, err := t.Runner.Run(ctx, "amass", args)
	return err
}


func (t *ToolBox) RunGau(ctx context.Context, domain string, outputFile string) error {
	// Use the long --output form: some flag libraries reject "--o" as an
	// ambiguous/invalid abbreviation, which would silently produce an empty file.
	args := []string{domain, "--providers", "wayback", "--subs", "--output", outputFile}
	args = t.appendProxy(args, "--proxy")
	_, err := t.Runner.Run(ctx, "gau", args)
	return err
}

// --- DNS & Brute Force ---

func (t *ToolBox) RunDnsx(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-a", "-aaaa", "-cname", "-mx", "-txt", "-resp", "-json",
		"-timeout", "3", // seconds per DNS query
		"-retry", "2",  // retry failed queries twice before giving up
		"-o", outputFile,
	}
	_, err := t.Runner.Run(ctx, "dnsx", args)
	return err
}

// --- Live Probing ---

func (t *ToolBox) RunHttpx(ctx context.Context, domainsFile string, outputFile string) error {
	args := []string{
		"-l", domainsFile,
		"-ports", t.httpxPorts(),
		"-threads", strconv.Itoa(t.httpxThreads()),
		"-timeout", strconv.Itoa(t.httpxTimeout()),
		"-tech-detect", "-title", "-status-code", "-json",
		"-o", outputFile,
	}
	if t.Config != nil && t.Config.Httpx.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	args = t.appendCommon(args, appendOptions{
		uaHeader:    true,
		tlsOpSec:    true,
		customHFlag: "-H",
		cookieFlag:  "-cookie",
		proxyFlag:   "-http-proxy",
	})
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rl", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, "httpx", args)
	return err
}

// RunNaabuList port-scans all hosts from a file (the correct way for recon).
func (t *ToolBox) RunNaabuList(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-rate", strconv.Itoa(t.effectiveRate(t.naabuRate())),
		"-c", strconv.Itoa(t.naabuThreads()),
		"-timeout", "3", // seconds per probe; prevents hanging on filtered ports
		"-o", outputFile,
	}
	// Use explicit port list if configured, otherwise use -top-ports
	if ports := t.naabuPorts(); ports != "" {
		if strings.ToLower(ports) == "top" || strings.ToLower(ports) == "top-100" {
			args = append(args, "-top-ports", "100")
		} else if strings.ToLower(ports) == "top-1000" {
			args = append(args, "-top-ports", "1000")
		} else if strings.ToLower(ports) == "full" || strings.ToLower(ports) == "-" {
			args = append(args, "-p", "-")
		} else {
			args = append(args, "-p", ports)
		}
	} else {
		args = append(args, "-top-ports", strconv.Itoa(t.naabuTopPorts()))
	}
	args = t.appendProxy(args, "-proxy")
	_, err := t.Runner.Run(ctx, "naabu", args, runner.WithTimeout(t.naabuMaxTimeout()))
	return err
}

// --- Web Crawling & Fuzzing ---

func (t *ToolBox) RunGoSpider(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{"-S", inputFile, "-q", "-c", "10", "-d", "3", "-t", "10"} // -t = per-request timeout (seconds)
	args = t.appendGoSpiderUA(args)
	output, err := t.Runner.Run(ctx, "gospider", args, runner.WithTimeout(t.goSpiderMaxTimeout()))
	if strings.TrimSpace(output) != "" {
		if writeErr := writeToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func (t *ToolBox) RunKatana(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-list", inputFile,
		"-o", outputFile,
		"-jc",
		"-timeout", "10", // seconds per request
	}
	args = t.appendCommon(args, appendOptions{
		uaHeader:    true,
		tlsOpSec:    true,
		customHFlag: "-H",
		proxyFlag:   "-proxy",
	})
	if t.CustomCookie != "" {
		args = append(args, "-H", "Cookie: "+t.CustomCookie)
	}
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, "katana", args, runner.WithTimeout(t.katanaMaxTimeout()))
	return err
}

func (t *ToolBox) buildFfufArgs(url string, wordlist string, outputFile string) []string {
	args := []string{
		"-u", url,
		"-w", wordlist,
		"-mc", t.ffufMatchCodes(),
		"-o", outputFile,
		"-of", "json",
		"-t", strconv.Itoa(t.ffufThreads()),
		"-timeout", strconv.Itoa(t.ffufTimeout()),
	}
	args = t.appendCommon(args, appendOptions{
		uaHeader:    true,
		customHFlag: "-H",
		cookieFlag:  "-b",
		proxyFlag:   "-x",
	})
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rate", strconv.Itoa(rps))
	}
	return args
}

func (t *ToolBox) RunFfuf(ctx context.Context, url string, wordlist string, outputFile string) error {
	if wordlist == "" {
		return fmt.Errorf("ffuf requires a wordlist path")
	}
	args := t.buildFfufArgs(url, wordlist, outputFile)
	_, err := t.Runner.Run(ctx, "ffuf", args, runner.WithTimeout(t.ffufMaxTimeout()))
	return err
}

// RunFfufWithFUZZ runs ffuf with a FUZZ placeholder in the URL
func (t *ToolBox) RunFfufWithFUZZ(ctx context.Context, baseURL string, wordlist string, outputFile string) error {
	if wordlist == "" {
		return fmt.Errorf("ffuf requires a wordlist path")
	}
	// Ensure FUZZ is in URL
	url := baseURL
	if !strings.Contains(url, "FUZZ") {
		url = baseURL + "/FUZZ"
	}
	args := t.buildFfufArgs(url, wordlist, outputFile)
	_, err := t.Runner.Run(ctx, "ffuf", args, runner.WithTimeout(t.ffufMaxTimeout()))
	return err
}

// --- Vulnerability Scanning ---

func (t *ToolBox) RunNuclei(ctx context.Context, targetsFile string, outputFile string) error {
	s, err := t.GetScanner("nuclei")
	if err != nil {
		return err
	}
	return s.Scan(ctx, targetsFile, outputFile, ScanOptions{
		Mode:        "standard",
		Concurrency: t.nucleiConcurrency(),
		RateLimit:   t.effectiveRate(t.nucleiRateLimit()),
		Severity:    t.nucleiSeverity(),
		ExcludeTags: t.nucleiExcludeTags(),
	})
}

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
		MaxTimeout:     t.nucleiMaxTimeout(),
	})
}

// --- Cloud & Org ---

func (t *ToolBox) RunMetabigorNet(ctx context.Context, org string, outputFile string) error {
	args := []string{"net", "--org", "-v", org}
	output, err := t.Runner.Run(ctx, "metabigor", args)
	if strings.TrimSpace(output) != "" {
		if writeErr := writeToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func (t *ToolBox) RunCloudEnum(ctx context.Context, keyword string, outputFile string) error {
	// Note: cloud_enum automatically appends ".json" to the log path specified by -l,
	// so the actual output file created will be outputFile + ".json".
	args := []string{"-k", keyword, "-l", outputFile}
	_, err := t.Runner.Run(ctx, "cloud_enum", args)
	return err
}

func runBypassedCmd(ctx context.Context, cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		// Wait up to 2 seconds for clean exit
		select {
		case err := <-done:
			if err == nil {
				return ctx.Err()
			}
			return err
		case <-time.After(2 * time.Second):
			return ctx.Err()
		}
	}
}

// TODO(config): Add General.HakrawlerTimeout to config.go and use it here.
func (t *ToolBox) hakrawlerMaxTimeout() time.Duration {
	return 30 * time.Minute
}

func (t *ToolBox) RunHakrawler(ctx context.Context, url string, outputFile string) error {
	args := []string{"-subs", "-u", "-d", "3"}
	args = t.appendGoSpiderUA(args)

	output, err := t.Runner.Run(ctx, "hakrawler", args, runner.WithStdin(strings.NewReader(url+"\n")), runner.WithTimeout(t.hakrawlerMaxTimeout()))
	if strings.TrimSpace(output) != "" {
		if writeErr := writeToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// --- URL Discovery ---

// RunWaybackurls fetches historical URLs from Wayback Machine
func (t *ToolBox) RunWaybackurls(ctx context.Context, domain string, outputFile string) error {
	args := []string{domain}
	output, err := t.Runner.Run(ctx, "waybackurls", args)
	if strings.TrimSpace(output) != "" {
		if writeErr := writeToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// RunGoLinkFinder extracts endpoints from JavaScript files found at the given URL.
func (t *ToolBox) RunGoLinkFinder(ctx context.Context, url string, outputFile string) error {
	args := []string{"-d", url, "-o", outputFile}
	// GoLinkFinder does not have a built-in proxy flag, but if it runs in docker we could pass HTTP_PROXY.
	// We'll pass it as a runner env var later if needed, but for now it's skipped as there's no native flag.
	_, err := t.Runner.Run(ctx, "GoLinkFinder", args)
	return err
}

// RunX8 discovers hidden HTTP parameters using x8.
func (t *ToolBox) RunX8(ctx context.Context, inputFile string, outputFile string) error {
	return t.RunX8WithWordlist(ctx, inputFile, outputFile, "")
}

// RunX8WithWordlist discovers hidden HTTP parameters using x8 and the given wordlist.
func (t *ToolBox) RunX8WithWordlist(ctx context.Context, inputFile string, outputFile string, wordlist string) error {
	args := []string{"-u", inputFile, "-o", outputFile, "-O", "json"}
	if wordlist != "" {
		args = append(args, "-w", wordlist)
	} else if t.General != nil && t.General.Wordlists.Parameters != "" {
		args = append(args, "-w", t.General.Wordlists.Parameters)
	}

	args = t.appendX8Headers(args)

	if p := t.proxy(); p != "" {
		args = append(args, "-x", p)
	}

	_, err := t.Runner.Run(ctx, "x8", args)
	return err
}

// RunHttpxURLCheck live-checks a list of URLs (not subdomains) and outputs only live URLs.
// Intentionally omits -status-code to prevent format poisoning in downstream nuclei runs and in-process gf-pattern matching.
func (t *ToolBox) RunHttpxURLCheck(ctx context.Context, urlsFile string, outputFile string) error {
	args := []string{
		"-l", urlsFile,
		"-threads", strconv.Itoa(t.httpxThreads()),
		"-timeout", strconv.Itoa(t.httpxTimeout()),
		"-no-fallback",
		"-o", outputFile,
	}
	if t.Config != nil && t.Config.Httpx.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	args = t.appendCommon(args, appendOptions{
		uaHeader:    true,
		tlsOpSec:    true,
		customHFlag: "-H",
		cookieFlag:  "-cookie",
		proxyFlag:   "-http-proxy",
	})
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rl", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, "httpx", args)
	return err
}

// RunGithubSubdomains searches GitHub for subdomains
func (t *ToolBox) RunGithubSubdomains(ctx context.Context, domain string, githubToken string, outputFile string) error {
	if githubToken == "" {
		return fmt.Errorf("github-subdomains requires a GitHub token")
	}
	args := []string{"-d", domain, "-t", githubToken, "-o", outputFile}
	_, err := t.Runner.Run(ctx, "github-subdomains", args)
	return err
}

// --- DNS Brute-force ---

// RunShuffleDNS performs DNS brute-forcing using shuffledns (massdns wrapper).
// It takes a domain, a wordlist for brute-forcing, and an optional resolvers file.
func (t *ToolBox) RunShuffleDNS(ctx context.Context, domain string, wordlist string, resolversFile string, outputFile string) error {
	if wordlist == "" {
		return fmt.Errorf("shuffledns requires a wordlist path")
	}
	args := []string{
		"-d", domain,
		"-w", wordlist,
		"-o", outputFile,
		"-silent",
	}
	if resolversFile != "" {
		args = append(args, "-r", resolversFile)
	}
	// Check for massdns in PATH and use it
	args = append(args, "-mode", "bruteforce")
	_, err := t.Runner.Run(ctx, "shuffledns", args)
	return err
}

// --- Subdomain Takeover ---

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
	return s.Scan(ctx, inputFile, outputFile, ScanOptions{})
}

// --- TLS/SSL Analysis ---

// RunTlsx grabs TLS certificate information from live hosts.
// tlsx v1.2.2 rejects -san/-cn when mixed with other probes, but plain JSON
// output already includes certificate metadata needed for post-processing.
func (t *ToolBox) RunTlsx(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-o", outputFile,
		"-json",
		"-silent",
		"-nc",
		"-duc",
		"-c", "50",
		"-timeout", "5", // seconds per TLS handshake; prevents hanging on blocked hosts
	}
	_, err := t.Runner.Run(ctx, "tlsx", args)
	return err
}

// --- Passive Search Engine Recon ---

// RunUncover queries search engines (Shodan, Censys, Fofa, etc.) for exposed assets.
// 100% passive — no packets sent to the target.
// Returns ErrNoAPIKeys if no API keys are configured for any engine.
func (t *ToolBox) RunUncover(ctx context.Context, domain string, outputFile string) error {
	if t.APIKeys != nil && t.APIKeys.Fofa != "" {
		logger.Warning("FOFA is configured but not wired (missing FofaEmail). Skipping FOFA engine.")
	}

	engines := t.uncoverEngines()
	if len(engines) == 0 {
		return fmt.Errorf("no uncover API keys configured — set shodan/censys/fofa keys in config.yaml")
	}

	args := []string{
		"-q", domain,
		"-o", outputFile,
		"-json",
		"-silent",
		"-e", strings.Join(engines, ","),
	}

	var opts []runner.Option
	if t.APIKeys != nil {
		var envVars []string
		if t.APIKeys.Shodan != "" {
			envVars = append(envVars, "SHODAN_API_KEY="+t.APIKeys.Shodan)
		}
		if t.APIKeys.CensysID != "" && t.APIKeys.CensysSecret != "" {
			envVars = append(envVars, "CENSYS_API_ID="+t.APIKeys.CensysID, "CENSYS_API_SECRET="+t.APIKeys.CensysSecret)
		} else if t.APIKeys.Censys != "" {
			parts := strings.SplitN(t.APIKeys.Censys, ":", 2)
			if len(parts) == 2 {
				envVars = append(envVars, "CENSYS_API_ID="+parts[0], "CENSYS_API_SECRET="+parts[1])
			}
		}
		if len(envVars) > 0 {
			opts = append(opts, runner.WithEnv(envVars...))
		}
	}

	_, err := t.Runner.Run(ctx, "uncover", args, opts...)
	return err
}

// uncoverEngines returns only the engines for which API keys are configured.
// If no keys are set, returns an empty slice so RunUncover can skip gracefully.
// TODO: Add support for fofa once FofaEmail field is added to APIKeysConfig.
func (t *ToolBox) uncoverEngines() []string {
	if t.APIKeys == nil {
		return nil
	}
	var engines []string
	if t.APIKeys.Shodan != "" {
		engines = append(engines, "shodan")
	}
	if t.APIKeys.Censys != "" || (t.APIKeys.CensysID != "" && t.APIKeys.CensysSecret != "") {
		engines = append(engines, "censys")
	}
	return engines
}

// --- Fingerprinting & WAF ---

// RunHttpxFingerprint runs HTTPX purely for tech detection, gathering technologies used by live hosts.
func (t *ToolBox) RunHttpxFingerprint(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-threads", strconv.Itoa(t.httpxThreads()),
		"-timeout", strconv.Itoa(t.httpxTimeout()),
		"-tech-detect", "-json",
		"-o", outputFile,
	}
	args = t.appendCommon(args, appendOptions{
		uaHeader:    true,
		tlsOpSec:    true,
		customHFlag: "-H",
		cookieFlag:  "-cookie",
		proxyFlag:   "-http-proxy",
	})
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rl", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, "httpx", args)
	return err
}

// RunNucleiWAF runs Nuclei specifically for WAF detection with a conservative rate limit.
func (t *ToolBox) RunNucleiWAF(ctx context.Context, inputFile string, outputFile string) error {
	// WAF detection needs a gentler rate limit as sending malicious tags will quickly trigger blocks.
	rateLimit := t.effectiveRate(50)
	concurrency := 10

	args := []string{
		"-l", inputFile,
		"-c", strconv.Itoa(concurrency),
		"-rl", strconv.Itoa(rateLimit),
		"-timeout", "5",        // per-request timeout (seconds)
		"-max-host-error", "3", // bail out of unresponsive hosts quickly
		"-tags", "waf",
		"-jsonl",
		"-o", outputFile,
	}

	args = t.appendCommon(args, appendOptions{
		uaHeader:  true,
		proxyFlag: "-proxy",
	})
	_, err := t.Runner.Run(ctx, "nuclei", args)
	return err
}

// Helper
func writeToFile(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.WriteString(content); err != nil {
		return err
	}
	return f.Sync()
}
