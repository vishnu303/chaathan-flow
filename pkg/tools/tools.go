package tools

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/vishnu303/chaathan-flow/pkg/config"
	"github.com/vishnu303/chaathan-flow/pkg/runner"
)

// ToolBox wraps the runner and provides methods to invoke external recon tools.
// It reads per-tool settings (threads, timeouts, rate limits) from the config
// so users can tune behavior via config.yaml instead of recompiling.
type ToolBox struct {
	Runner runner.Runner
	Config *config.ToolsConfig
}

// New creates a ToolBox. If cfg is nil, sensible defaults are used.
func New(r runner.Runner, cfg ...*config.ToolsConfig) *ToolBox {
	tb := &ToolBox{Runner: r}
	if len(cfg) > 0 && cfg[0] != nil {
		tb.Config = cfg[0]
	}
	return tb
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
	return "top-1000"
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

func (t *ToolBox) nucleiSeverity() []string {
	if t.Config != nil && len(t.Config.Nuclei.Severity) > 0 {
		return t.Config.Nuclei.Severity
	}
	return nil // default: all severities
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

// --- Passive Enumeration ---

func (t *ToolBox) RunSubfinder(ctx context.Context, domain string, outputFile string) error {
	args := []string{
		"-d", domain,
		"-silent",
		"-t", strconv.Itoa(t.subfinderThreads()),
		"-timeout", strconv.Itoa(t.subfinderTimeout()),
		"-o", outputFile,
	}
	_, err := t.Runner.Run(ctx, "subfinder", args)
	return err
}

func (t *ToolBox) RunAssetfinder(ctx context.Context, domain string, outputFile string) error {
	args := []string{"--subs-only", domain}
	output, err := t.Runner.Run(ctx, "assetfinder", args)
	if err != nil {
		return err
	}
	return writeToFile(outputFile, output)
}

func (t *ToolBox) RunSublist3r(ctx context.Context, domain string, outputFile string) error {
	args := []string{"-d", domain, "-t", "50", "-v", "-o", outputFile}
	_, err := t.Runner.Run(ctx, "sublist3r", args)
	return err
}

// --- Active Enumeration ---

func (t *ToolBox) RunAmass(ctx context.Context, domain string, outputFile string) error {
	args := []string{"enum", "-active", "-alts", "-brute", "-min-for-recursive", "2", "-d", domain, "-o", outputFile}
	if t.Config != nil && t.Config.Amass.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(t.Config.Amass.Timeout))
	}
	_, err := t.Runner.Run(ctx, "amass", args)
	return err
}

func (t *ToolBox) RunGau(ctx context.Context, domain string, outputFile string) error {
	args := []string{domain, "--providers", "wayback", "--subs", "--o", outputFile}
	_, err := t.Runner.Run(ctx, "gau", args)
	return err
}

// --- DNS & Brute Force ---

func (t *ToolBox) RunDnsx(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{"-l", inputFile, "-a", "-aaaa", "-cname", "-mx", "-txt", "-resp", "-json", "-o", outputFile}
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
	_, err := t.Runner.Run(ctx, "httpx", args)
	return err
}

// RunNaabu port-scans a single host.
func (t *ToolBox) RunNaabu(ctx context.Context, host string, outputFile string) error {
	args := []string{
		"-host", host,
		"-p", t.naabuPorts(),
		"-rate", strconv.Itoa(t.naabuRate()),
		"-c", strconv.Itoa(t.naabuThreads()),
		"-o", outputFile,
	}
	_, err := t.Runner.Run(ctx, "naabu", args)
	return err
}

// RunNaabuList port-scans all hosts from a file (the correct way for recon).
func (t *ToolBox) RunNaabuList(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-p", t.naabuPorts(),
		"-rate", strconv.Itoa(t.naabuRate()),
		"-c", strconv.Itoa(t.naabuThreads()),
		"-o", outputFile,
	}
	_, err := t.Runner.Run(ctx, "naabu", args)
	return err
}

// --- Web Crawling & Fuzzing ---

func (t *ToolBox) RunGoSpider(ctx context.Context, url string, outputFile string) error {
	args := []string{"-s", url, "-o", outputFile, "-c", "10", "-d", "3"}
	_, err := t.Runner.Run(ctx, "gospider", args)
	return err
}

func (t *ToolBox) RunKatana(ctx context.Context, url string, outputFile string) error {
	args := []string{"-u", url, "-o", outputFile, "-jc"}
	_, err := t.Runner.Run(ctx, "katana", args)
	return err
}

func (t *ToolBox) RunFfuf(ctx context.Context, url string, wordlist string, outputFile string) error {
	if wordlist == "" {
		return fmt.Errorf("ffuf requires a wordlist path")
	}
	args := []string{
		"-u", url,
		"-w", wordlist,
		"-mc", t.ffufMatchCodes(),
		"-o", outputFile,
		"-of", "json",
		"-t", strconv.Itoa(t.ffufThreads()),
		"-timeout", strconv.Itoa(t.ffufTimeout()),
	}
	_, err := t.Runner.Run(ctx, "ffuf", args)
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
	args := []string{
		"-u", url,
		"-w", wordlist,
		"-mc", t.ffufMatchCodes(),
		"-o", outputFile,
		"-of", "json",
		"-t", strconv.Itoa(t.ffufThreads()),
		"-timeout", strconv.Itoa(t.ffufTimeout()),
	}
	_, err := t.Runner.Run(ctx, "ffuf", args)
	return err
}

// --- Vulnerability Scanning ---

func (t *ToolBox) RunNuclei(ctx context.Context, targetsFile string, outputFile string) error {
	args := []string{
		"-l", targetsFile,
		"-c", strconv.Itoa(t.nucleiConcurrency()),
		"-rl", strconv.Itoa(t.nucleiRateLimit()),
		"-jsonl",
		"-o", outputFile,
	}

	// Apply exclude tags from config
	excludeTags := t.nucleiExcludeTags()
	if len(excludeTags) > 0 {
		args = append(args, "-etags", strings.Join(excludeTags, ","))
	}

	// Apply severity filter from config
	severity := t.nucleiSeverity()
	if len(severity) > 0 {
		args = append(args, "-severity", strings.Join(severity, ","))
	}

	_, err := t.Runner.Run(ctx, "nuclei", args)
	return err
}

// --- Cloud & Org ---

func (t *ToolBox) RunMetabigorNet(ctx context.Context, org string, outputFile string) error {
	args := []string{"net", "--org", "-v", org}
	output, err := t.Runner.Run(ctx, "metabigor", args)
	if err != nil {
		return err
	}
	return writeToFile(outputFile, output)
}

func (t *ToolBox) RunCloudEnum(ctx context.Context, keyword string, outputFile string) error {
	args := []string{"-k", keyword, "-f", "json", "-l", outputFile}
	_, err := t.Runner.Run(ctx, "cloud_enum", args)
	return err
}

func (t *ToolBox) RunSubdomainizer(ctx context.Context, url string, outputFile string) error {
	args := []string{"-u", url, "-o", outputFile}
	_, err := t.Runner.Run(ctx, "subdomainizer", args)
	return err
}

// --- URL Discovery ---

// RunWaybackurls fetches historical URLs from Wayback Machine
func (t *ToolBox) RunWaybackurls(ctx context.Context, domain string, outputFile string) error {
	args := []string{domain}
	output, err := t.Runner.Run(ctx, "waybackurls", args)
	if err != nil {
		return err
	}
	return writeToFile(outputFile, output)
}

// RunLinkfinder extracts endpoints from JavaScript files
func (t *ToolBox) RunLinkfinder(ctx context.Context, url string, outputFile string) error {
	args := []string{"-i", url, "-o", "cli"}
	output, err := t.Runner.Run(ctx, "linkfinder", args)
	if err != nil {
		return err
	}
	return writeToFile(outputFile, output)
}

// RunLinkfinderOnFile runs linkfinder on a local JS file
func (t *ToolBox) RunLinkfinderOnFile(ctx context.Context, jsFile string, outputFile string) error {
	args := []string{"-i", jsFile, "-o", "cli"}
	output, err := t.Runner.Run(ctx, "linkfinder", args)
	if err != nil {
		return err
	}
	return writeToFile(outputFile, output)
}

// --- Wordlist Generation ---

// RunCewl generates custom wordlists from a target website
func (t *ToolBox) RunCewl(ctx context.Context, url string, outputFile string, opts ...CewlOption) error {
	cewlOpts := &cewlOptions{
		minWordLen: 5,
		depth:      2,
		withCount:  false,
	}
	for _, opt := range opts {
		opt(cewlOpts)
	}

	args := []string{
		"-m", fmt.Sprintf("%d", cewlOpts.minWordLen),
		"-d", fmt.Sprintf("%d", cewlOpts.depth),
		"-w", outputFile,
		url,
	}
	if cewlOpts.withCount {
		args = append([]string{"-c"}, args...)
	}
	_, err := t.Runner.Run(ctx, "cewl", args)
	return err
}

type cewlOptions struct {
	minWordLen int
	depth      int
	withCount  bool
}

type CewlOption func(*cewlOptions)

func CewlMinWordLen(n int) CewlOption {
	return func(o *cewlOptions) {
		o.minWordLen = n
	}
}

func CewlDepth(n int) CewlOption {
	return func(o *cewlOptions) {
		o.depth = n
	}
}

func CewlWithCount() CewlOption {
	return func(o *cewlOptions) {
		o.withCount = true
	}
}

// --- GitHub Reconnaissance ---

// RunGithubEndpoints searches GitHub for exposed endpoints/secrets
func (t *ToolBox) RunGithubEndpoints(ctx context.Context, domain string, githubToken string, outputFile string) error {
	if githubToken == "" {
		return fmt.Errorf("github-endpoints requires a GitHub token (set GITHUB_TOKEN env var)")
	}
	args := []string{"-d", domain}
	output, err := t.Runner.Run(ctx, "github-endpoints", args)
	if err != nil {
		return err
	}
	return writeToFile(outputFile, output)
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

// --- Subdomain Permutation ---

// RunAlterx generates smart subdomain permutations from discovered subdomains.
// Takes an input file of known subdomains and outputs permutation candidates.
func (t *ToolBox) RunAlterx(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{"-l", inputFile, "-o", outputFile, "-en"}
	_, err := t.Runner.Run(ctx, "alterx", args)
	return err
}

// --- Subdomain Takeover ---

// RunSubjack checks discovered subdomains for potential subdomain takeover vulnerabilities
// by looking for dangling CNAME records pointing to claimable services.
func (t *ToolBox) RunSubjack(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-w", inputFile,
		"-o", outputFile,
		"-ssl",
		"-t", "50",
		"-timeout", "30",
		"-a",
	}
	_, err := t.Runner.Run(ctx, "subjack", args)
	return err
}

// --- XSS Scanning ---

// RunDalfox scans URLs with parameters for XSS vulnerabilities.
// Takes a list of parameterized URLs and tests for reflected/stored XSS.
func (t *ToolBox) RunDalfox(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"file", inputFile,
		"-o", outputFile,
		"--silence",
		"--no-color",
		"--output-all",
	}
	_, err := t.Runner.Run(ctx, "dalfox", args)
	return err
}

// RunDalfoxURL scans a single URL for XSS.
func (t *ToolBox) RunDalfoxURL(ctx context.Context, targetURL string, outputFile string) error {
	args := []string{
		"url", targetURL,
		"-o", outputFile,
		"--silence",
		"--no-color",
	}
	_, err := t.Runner.Run(ctx, "dalfox", args)
	return err
}

// --- TLS/SSL Analysis ---

// RunTlsx grabs TLS certificate information from live hosts.
// Extracts SANs (extra subdomains), expiry info, and cipher details.
func (t *ToolBox) RunTlsx(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-o", outputFile,
		"-json",
		"-san", "-cn", "-so", "-ex", // SANs, Common Name, Subject Org, Expiry
		"-resp-only",
		"-c", "50",
	}
	_, err := t.Runner.Run(ctx, "tlsx", args)
	return err
}

// RunTlsxHost checks TLS for a single host.
func (t *ToolBox) RunTlsxHost(ctx context.Context, host string, outputFile string) error {
	args := []string{
		"-u", host,
		"-o", outputFile,
		"-json",
		"-san", "-cn", "-so", "-ex",
	}
	_, err := t.Runner.Run(ctx, "tlsx", args)
	return err
}

// --- Passive Search Engine Recon ---

// RunUncover queries search engines (Shodan, Censys, Fofa, etc.) for exposed assets.
// 100% passive — no packets sent to the target.
func (t *ToolBox) RunUncover(ctx context.Context, domain string, outputFile string) error {
	args := []string{
		"-q", domain,
		"-o", outputFile,
		"-json",
		"-silent",
	}

	// Add configured search engines
	engines := t.uncoverEngines()
	if len(engines) > 0 {
		args = append(args, "-e", strings.Join(engines, ","))
	}

	_, err := t.Runner.Run(ctx, "uncover", args)
	return err
}

func (t *ToolBox) uncoverEngines() []string {
	// Default to common search engines
	return []string{"shodan", "censys", "fofa"}
}

// Helper
func writeToFile(path string, content string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}
