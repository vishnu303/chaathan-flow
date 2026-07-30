package tools

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/runner"
	"github.com/vishnu303/chaathan/utils"
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

var (
	defaultToolsConfig *config.ToolsConfig
	defaultToolsOnce   sync.Once
)

func getDefaultToolsConfig() *config.ToolsConfig {
	defaultToolsOnce.Do(func() {
		defaultToolsConfig = &config.DefaultConfig().Tools
	})
	return defaultToolsConfig
}

func (t *ToolBox) config() *config.ToolsConfig {
	if t.Config != nil {
		return t.Config
	}
	return getDefaultToolsConfig()
}

// New creates a ToolBox. If cfg is nil, sensible defaults are used.
func New(r runner.Runner, cfg ...*config.ToolsConfig) *ToolBox {
	tb := &ToolBox{Runner: r}
	if len(cfg) > 0 && cfg[0] != nil {
		tb.Config = cfg[0]
	} else {
		tb.Config = getDefaultToolsConfig()
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
// realUserAgents contains common, high-frequency browser User-Agent strings.
// Rotating through these prevents WAF fingerprinting from static tool UAs
// like "httpx - Open-source project" or "Nuclei - Open-source project".
var realUserAgents = []string{
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
	return realUserAgents[rand.N(len(realUserAgents))]
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

// --- Timeouts and Config Helpers ---

const (
	subfinderMaxTimeout        = 15 * time.Minute
	sublist3rMaxTimeout        = 15 * time.Minute
	gauMaxTimeout              = 30 * time.Minute
	waybackurlsMaxTimeout      = 20 * time.Minute
	x8MaxTimeout               = 120 * time.Minute
	uncoverMaxTimeout          = 10 * time.Minute
	githubSubdomainsMaxTimeout = 15 * time.Minute
	hakrawlerMaxTimeout        = 30 * time.Minute
)

func (t *ToolBox) subfinderThreads() int {
	if val := t.config().Subfinder.Threads; val > 0 {
		return val
	}
	return getDefaultToolsConfig().Subfinder.Threads
}

func (t *ToolBox) subfinderTimeout() int {
	if val := t.config().Subfinder.Timeout; val > 0 {
		return val
	}
	return getDefaultToolsConfig().Subfinder.Timeout
}

func (t *ToolBox) httpxThreads() int {
	if val := t.config().Httpx.Threads; val > 0 {
		return val
	}
	return getDefaultToolsConfig().Httpx.Threads
}

func (t *ToolBox) httpxTimeout() int {
	if val := t.config().Httpx.Timeout; val > 0 {
		return val
	}
	return getDefaultToolsConfig().Httpx.Timeout
}

func (t *ToolBox) httpxPorts() string {
	ports := t.config().Httpx.Ports
	if len(ports) == 0 {
		ports = getDefaultToolsConfig().Httpx.Ports
	}
	return strings.Join(ports, ",")
}

func (t *ToolBox) naabuThreads() int {
	if val := t.config().Naabu.Threads; val > 0 {
		return val
	}
	return getDefaultToolsConfig().Naabu.Threads
}

func (t *ToolBox) naabuRate() int {
	if val := t.config().Naabu.Rate; val > 0 {
		return val
	}
	return getDefaultToolsConfig().Naabu.Rate
}

func (t *ToolBox) naabuPorts() string {
	return t.config().Naabu.Ports
}

func (t *ToolBox) naabuTopPorts() int {
	if t.config().Naabu.Ports != "" {
		return 0
	}
	return 1000
}

func (t *ToolBox) nucleiConcurrency() int {
	if val := t.config().Nuclei.Concurrency; val > 0 {
		return val
	}
	return getDefaultToolsConfig().Nuclei.Concurrency
}

func (t *ToolBox) nucleiRateLimit() int {
	if val := t.config().Nuclei.RateLimit; val > 0 {
		return val
	}
	return getDefaultToolsConfig().Nuclei.RateLimit
}

func (t *ToolBox) nucleiExcludeTags() []string {
	tags := t.config().Nuclei.ExcludeTags
	if len(tags) == 0 {
		tags = getDefaultToolsConfig().Nuclei.ExcludeTags
	}
	return tags
}

func (t *ToolBox) nucleiDisableOOB() bool {
	if val := t.config().Nuclei.DisableOOB; val != nil {
		return *val
	}
	val := getDefaultToolsConfig().Nuclei.DisableOOB
	if val != nil {
		return *val
	}
	return true
}

func (t *ToolBox) nucleiMaxTimeout() time.Duration {
	val := t.config().Nuclei.MaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().Nuclei.MaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) dastAggression() string {
	if val := t.config().Nuclei.DASTAggression; val != "" {
		return val
	}
	return getDefaultToolsConfig().Nuclei.DASTAggression
}

func (t *ToolBox) nucleiSeverity() []string {
	return t.config().Nuclei.Severity
}

func (t *ToolBox) nucleiInfraTags() []string {
	return []string{"cve", "rce", "sqli", "ssrf", "lfi", "exposure", "default-login", "misconfig"}
}

func (t *ToolBox) nucleiURLTags() []string {
	return []string{"sqli", "ssrf", "lfi", "rce", "ssti", "idor"}
}

func (t *ToolBox) ffufThreads() int {
	if val := t.config().Ffuf.Threads; val > 0 {
		return val
	}
	return getDefaultToolsConfig().Ffuf.Threads
}

func (t *ToolBox) ffufTimeout() int {
	if val := t.config().Ffuf.Timeout; val > 0 {
		return val
	}
	return getDefaultToolsConfig().Ffuf.Timeout
}

func (t *ToolBox) ffufMatchCodes() string {
	codes := t.config().Ffuf.MatchCodes
	if len(codes) == 0 {
		codes = getDefaultToolsConfig().Ffuf.MatchCodes
	}
	var strCodes []string
	for _, c := range codes {
		strCodes = append(strCodes, strconv.Itoa(c))
	}
	return strings.Join(strCodes, ",")
}

func (t *ToolBox) naabuMaxTimeout() time.Duration {
	val := t.config().Naabu.Timeout
	if val <= 0 {
		val = getDefaultToolsConfig().Naabu.Timeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) ffufMaxTimeout() time.Duration {
	val := t.config().Ffuf.MaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().Ffuf.MaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) katanaMaxTimeout() time.Duration {
	val := t.config().Katana.Timeout
	if val <= 0 {
		val = getDefaultToolsConfig().Katana.Timeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) goSpiderMaxTimeout() time.Duration {
	val := t.config().GoSpider.Timeout
	if val <= 0 {
		val = getDefaultToolsConfig().GoSpider.Timeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) amassMaxTimeout() time.Duration {
	val := t.config().Amass.Timeout
	if val <= 0 {
		val = getDefaultToolsConfig().Amass.Timeout
	}
	return time.Duration(val) * time.Minute
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
		if t.APIKeys.SecurityTrails != "" {
			envVars = append(envVars, "SECURITYTRAILS_API_KEY="+t.APIKeys.SecurityTrails)
		}
		if len(envVars) > 0 {
			opts = append(opts, runner.WithEnv(envVars...))
		}
	}

	opts = append(opts, runner.WithTimeout(subfinderMaxTimeout))
	_, err := t.Runner.Run(ctx, "subfinder", args, opts...)
	return err
}

func (t *ToolBox) RunAssetfinder(ctx context.Context, domain string, outputFile string) error {
	args := []string{"--subs-only", domain}
	output, err := t.Runner.Run(ctx, "assetfinder", args)
	if strings.TrimSpace(output) != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
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
	_, err := t.Runner.Run(ctx, "sublist3r", args, runner.WithTimeout(sublist3rMaxTimeout))
	return err
}

// --- Active Enumeration ---

func (t *ToolBox) RunAmass(ctx context.Context, domain string, outputFile string) error {
	args := []string{"enum", "-active", "-alts", "-d", domain, "-o", outputFile}
	if t.Config != nil && t.Config.Amass.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(t.Config.Amass.Timeout))
	}
	_, err := t.Runner.Run(ctx, "amass", args, runner.WithTimeout(t.amassMaxTimeout()))
	return err
}

// RunAmassIntel runs `amass intel -whois` to discover root domains owned by an org.
func (t *ToolBox) RunAmassIntel(ctx context.Context, org string, outputFile string) error {
	args := []string{"intel", "-whois", "-d", org, "-o", outputFile}
	if t.Config != nil && t.Config.Amass.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(t.Config.Amass.Timeout))
	}
	_, err := t.Runner.Run(ctx, "amass", args, runner.WithTimeout(t.amassMaxTimeout()))
	return err
}

func (t *ToolBox) RunGau(ctx context.Context, domain string, outputFile string) error {
	args := []string{"--providers", "wayback,commoncrawl,otx,urlscan", "--subs", domain}
	args = t.appendProxy(args, "--proxy")
	output, err := t.Runner.Run(ctx, "gau", args, runner.WithTimeout(gauMaxTimeout))
	if strings.TrimSpace(output) != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// --- DNS & Brute Force ---

func (t *ToolBox) RunDnsx(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-a", "-aaaa", "-cname", "-mx", "-txt", "-resp", "-json",
		"-timeout", "3", // seconds per DNS query
		"-retry", "2", // retry failed queries twice before giving up
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
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
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
		"-timeout", "15", // seconds per request; extra headroom for proxy pools
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
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
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

func (t *ToolBox) RunHakrawler(ctx context.Context, url string, outputFile string) error {
	args := []string{"-subs", "-u", "-d", "3"}
	if t.uaEnabled() {
		args = append(args, "-h", "User-Agent: "+t.getUA())
	}
	args = t.appendProxy(args, "-proxy")

	output, err := t.Runner.Run(ctx, "hakrawler", args, runner.WithStdin(strings.NewReader(url+"\n")), runner.WithTimeout(hakrawlerMaxTimeout))
	if strings.TrimSpace(output) != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// --- URL Discovery ---

// RunWaybackurls fetches historical URLs from Wayback Machine
func (t *ToolBox) RunWaybackurls(ctx context.Context, domain string, outputFile string) error {
	args := []string{}
	// waybackurls reads the domain from standard input
	output, err := t.Runner.Run(ctx, "waybackurls", args, runner.WithStdin(strings.NewReader(domain+"\n")), runner.WithTimeout(waybackurlsMaxTimeout))
	if strings.TrimSpace(output) != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// RunJsluiceURLs extracts URLs and API routes from a local JavaScript file
// using jsluice's AST-based analysis. Output is JSON lines written to outputFile.
func (t *ToolBox) RunJsluiceURLs(ctx context.Context, jsFile string, outputFile string) error {
	args := []string{"urls", jsFile}
	output, err := t.Runner.Run(ctx, "jsluice", args, runner.WithNoRetry())
	if strings.TrimSpace(output) != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// RunJsluiceObjects extracts custom objects and interesting method calls from a
// local JavaScript file using jsluice. Output is JSON lines written to outputFile.
func (t *ToolBox) RunJsluiceObjects(ctx context.Context, jsFile string, outputFile string) error {
	args := []string{"objects", jsFile}
	output, err := t.Runner.Run(ctx, "jsluice", args, runner.WithNoRetry())
	if strings.TrimSpace(output) != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
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
		if _, err := os.Stat(wordlist); err == nil {
			args = append(args, "-w", wordlist)
		}
	} else if t.General != nil && t.General.Wordlists.Parameters != "" {
		if _, err := os.Stat(t.General.Wordlists.Parameters); err == nil {
			args = append(args, "-w", t.General.Wordlists.Parameters)
		}
	}

	args = t.appendX8Headers(args)

	if p := t.proxy(); p != "" {
		args = append(args, "-x", p)
	}

	_, err := t.Runner.Run(ctx, "x8", args, runner.WithTimeout(x8MaxTimeout))
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
	_, err := t.Runner.Run(ctx, "github-subdomains", args, runner.WithTimeout(githubSubdomainsMaxTimeout))
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
	engines := t.uncoverEngines()
	if len(engines) == 0 {
		return fmt.Errorf("no uncover API keys configured — set shodan/censys/fofa/quake/zoomeye keys in config.yaml")
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
		// FOFA classic two-factor auth requires both key + email.
		if t.APIKeys.Fofa != "" && t.APIKeys.FofaEmail != "" {
			envVars = append(envVars, "FOFA_KEY="+t.APIKeys.Fofa, "FOFA_EMAIL="+t.APIKeys.FofaEmail)
		}
		// Quake (360) — email + key pair.
		if t.APIKeys.Quake != "" && t.APIKeys.QuakeEmail != "" {
			envVars = append(envVars, "QUAKE_KEY="+t.APIKeys.Quake, "QUAKE_EMAIL="+t.APIKeys.QuakeEmail)
		}
		// ZoomEye — email + key pair.
		if t.APIKeys.ZoomEye != "" && t.APIKeys.ZoomEyeEmail != "" {
			envVars = append(envVars, "ZOOMEYE_KEY="+t.APIKeys.ZoomEye, "ZOOMEYE_EMAIL="+t.APIKeys.ZoomEyeEmail)
		}
		if len(envVars) > 0 {
			opts = append(opts, runner.WithEnv(envVars...))
		}
	}

	opts = append(opts, runner.WithTimeout(uncoverMaxTimeout))
	_, err := t.Runner.Run(ctx, "uncover", args, opts...)
	return err
}

// uncoverEngines returns only the engines for which API keys are configured.
// If no keys are set, returns an empty slice so RunUncover can skip gracefully.
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
	// FOFA classic needs both key and email; anything less is treated as unconfigured.
	if t.APIKeys.Fofa != "" && t.APIKeys.FofaEmail != "" {
		engines = append(engines, "fofa")
	}
	// Quake (360) needs both key and email.
	if t.APIKeys.Quake != "" && t.APIKeys.QuakeEmail != "" {
		engines = append(engines, "quake")
	}
	// ZoomEye needs both key and email.
	if t.APIKeys.ZoomEye != "" && t.APIKeys.ZoomEyeEmail != "" {
		engines = append(engines, "zoomeye")
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
	_, err := t.Runner.Run(ctx, "nuclei", args)
	return err
}
