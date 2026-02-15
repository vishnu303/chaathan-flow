package tools

import (
	"context"
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/runner"
	"os"
	"strings"
)

type ToolBox struct {
	Runner runner.Runner
}

func New(r runner.Runner) *ToolBox {
	return &ToolBox{Runner: r}
}

// --- Passive Enumeration ---

func (t *ToolBox) RunSubfinder(ctx context.Context, domain string, outputFile string) error {
	args := []string{"-d", domain, "-silent", "-o", outputFile}
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
	// Amass is heavy, using -passive for quicker initial check or enum for full
	args := []string{"enum", "-active", "-alts", "-brute", "-min-for-recursive", "2", "-d", domain, "-o", outputFile}
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
		"-ports", "80,443,8080,8443,8081,8000,8008,8888",
		"-tech-detect", "-title", "-status-code", "-json",
		"-o", outputFile,
	}
	_, err := t.Runner.Run(ctx, "httpx", args)
	return err
}

func (t *ToolBox) RunNaabu(ctx context.Context, host string, outputFile string) error {
	args := []string{"-host", host, "-o", outputFile}
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
		"-mc", "200,201,204,301,302,307,401,403,405,500",
		"-o", outputFile,
		"-of", "json",
		"-t", "50",
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
	if !contains(url, "FUZZ") {
		url = baseURL + "/FUZZ"
	}
	args := []string{
		"-u", url,
		"-w", wordlist,
		"-mc", "200,201,204,301,302,307,401,403,405,500",
		"-o", outputFile,
		"-of", "json",
		"-t", "50",
	}
	_, err := t.Runner.Run(ctx, "ffuf", args)
	return err
}

// --- Vulnerability Scanning ---

func (t *ToolBox) RunNuclei(ctx context.Context, targetsFile string, outputFile string) error {
	args := []string{"-l", targetsFile, "-c", "25", "-rl", "150", "-jsonl", "-o", outputFile}
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
	// Run with environment variable
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

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
