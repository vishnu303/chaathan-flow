package tools

import (
	"context"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
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
	githubSubdomainsMaxTimeout = 15 * time.Minute
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

func (t *ToolBox) subfinderMaxTimeout() time.Duration {
	val := t.config().Subfinder.MaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().Subfinder.MaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) sublist3rMaxTimeout() time.Duration {
	val := t.config().Sublist3r.MaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().Sublist3r.MaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) gauMaxTimeout() time.Duration {
	val := t.config().GAU.MaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().GAU.MaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) waybackurlsMaxTimeout() time.Duration {
	val := t.config().Waybackurls.MaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().Waybackurls.MaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) x8MaxTimeout() time.Duration {
	val := t.config().X8.MaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().X8.MaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) tlsxMaxTimeout() time.Duration {
	val := t.config().Tlsx.MaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().Tlsx.MaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) shufflednsMaxTimeout() time.Duration {
	val := t.config().ShuffleDNS.MaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().ShuffleDNS.MaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) dnsxMaxTimeout() time.Duration {
	val := t.config().DNSx.MaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().DNSx.MaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) nucleiDASTMaxTimeout() time.Duration {
	val := t.config().Nuclei.DASTMaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().Nuclei.DASTMaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) nucleiWAFMaxTimeout() time.Duration {
	val := t.config().Nuclei.WAFMaxTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().Nuclei.WAFMaxTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) httpxFingerprintTimeout() time.Duration {
	val := t.config().Httpx.FingerprintTimeout
	if val <= 0 {
		val = getDefaultToolsConfig().Httpx.FingerprintTimeout
	}
	return time.Duration(val) * time.Minute
}

func (t *ToolBox) assetfinderTimeout() time.Duration {
	if val := t.config().Assetfinder.Timeout; val > 0 {
		return time.Duration(val) * time.Second
	}
	return time.Duration(getDefaultToolsConfig().Assetfinder.Timeout) * time.Second
}

func (t *ToolBox) uncoverTimeout() time.Duration {
	if val := t.config().Uncover.Timeout; val > 0 {
		return time.Duration(val) * time.Second
	}
	return time.Duration(getDefaultToolsConfig().Uncover.Timeout) * time.Second
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
