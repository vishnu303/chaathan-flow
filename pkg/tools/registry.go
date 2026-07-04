// Package tools — registry.go
//
// Single source of truth for the tool catalogue. Both the CLI
// (tools list / tools check) and the setup installer derive their
// tool lists from AllTools, ensuring names, categories, and
// descriptions never drift.
package tools

import (
	"os/exec"
)

// ToolInfo describes one external tool that Chaathan integrates with.
type ToolInfo struct {
	Name        string // binary name (e.g. "subfinder")
	Category    string // display group (e.g. "Enum", "DNS", "Vuln")
	Description string // one-line purpose
	Required    bool   // Required = blocks chaathan setup success if missing; does NOT mean every scan uses it (most have --skip-* flags)
	InstallURL  string // `go install` URL — empty for non-Go tools
}

// AllTools is the canonical tool catalogue. Order determines display
// order in `chaathan tools list` and `chaathan tools check`.
var AllTools = []ToolInfo{
	// Subdomain Enumeration
	{"subfinder", "Enum", "Passive subdomain discovery", true, "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	{"assetfinder", "Enum", "Passive subdomain discovery", true, "github.com/tomnomnom/assetfinder@latest"},
	{"sublist3r", "Enum", "Passive subdomain discovery (Python)", false, ""},
	{"amass", "Enum", "Active DNS enumeration", false, "github.com/owasp-amass/amass/v4/...@latest"},

	// DNS & Resolution
	{"dnsx", "DNS", "DNS resolution & record lookup", true, "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	{"shuffledns", "DNS", "DNS brute-force with massdns", false, "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"},
	{"massdns", "DNS", "High-performance DNS resolver (from source)", false, ""},

	// Web Probing
	{"httpx", "Probe", "HTTP probing & tech detection", true, "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
	{"tlsx", "Probe", "TLS certificate analysis & SAN extraction", false, "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
	{"naabu", "Probe", "Port scanning (SYN/TCP)", false, "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},

	// URL Discovery
	{"waybackurls", "URLs", "Wayback Machine URL extraction", false, "github.com/tomnomnom/waybackurls@latest"},
	{"gau", "URLs", "Historical URL discovery", false, "github.com/lc/gau/v2/cmd/gau@latest"},
	{"x8", "URLs", "Hidden HTTP parameter discovery (Rust)", false, ""},
	{"katana", "Crawl", "Web crawling & spidering", false, "github.com/projectdiscovery/katana/cmd/katana@latest"},
	{"gospider", "Crawl", "Web crawling & spidering", false, "github.com/jaeles-project/gospider@latest"},

	// Analysis
	{"GoLinkFinder", "Analysis", "JavaScript endpoint extraction (Go)", false, "github.com/rix4uni/GoLinkFinder@latest"},
	{"hakrawler", "Crawl", "Fast web crawler for endpoint & asset discovery", false, "github.com/hakluke/hakrawler@latest"},

	// Fuzzing & Scanning
	{"ffuf", "Fuzz", "Web fuzzer & directory brute-force", false, "github.com/ffuf/ffuf/v2@latest"},
	{"nuclei", "Vuln", "Template-based vulnerability scanner", true, "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	{"dalfox", "Vuln", "XSS vulnerability scanner", false, "github.com/hahwul/dalfox/v2@latest"},

	// Recon
	{"uncover", "Recon", "Shodan/Censys/Fofa search dorking", false, "github.com/projectdiscovery/uncover/cmd/uncover@latest"},
	{"metabigor", "Recon", "ASN & org discovery", false, "github.com/j3ssie/metabigor@latest"},
	{"github-subdomains", "Recon", "GitHub subdomain scraping", false, "github.com/gwen001/github-subdomains@latest"},
	{"cloud_enum", "Cloud", "Cloud infrastructure enumeration (Python)", false, ""},

	// Utility
	{"anew", "Util", "Append unique lines to file", false, "github.com/tomnomnom/anew@latest"},
	{"gf", "Util", "Pattern-based URL/param filtering", false, "github.com/tomnomnom/gf@latest"},

	// Proxy Automation
	{"mubeng", "Proxy", "Proxy scraper, checker & IP rotator (Go)", false, "github.com/mubeng/mubeng@latest"},
}

// GoInstallableTools returns the subset of AllTools that have a non-empty
// InstallURL — these are the tools that `go install` can install.
func GoInstallableTools() []ToolInfo {
	var out []ToolInfo
	for _, t := range AllTools {
		if t.InstallURL != "" {
			out = append(out, t)
		}
	}
	return out
}

// CountRequired returns the number of tools marked as Required.
func CountRequired() int {
	count := 0
	for _, t := range AllTools {
		if t.Required {
			count++
		}
	}
	return count
}

// CheckStatus checks if the tool is installed on the system.
// Returns true and the resolved binary path if found, or false and empty string.
func (t ToolInfo) CheckStatus() (bool, string) {
	path, err := exec.LookPath(t.Name)
	if err == nil {
		return true, path
	}
	// Also check common Python script names if standard lookup fails
	if t.Name == "sublist3r" || t.Name == "cloud_enum" {
		if p, err := exec.LookPath(t.Name + ".py"); err == nil {
			return true, p
		}
	}
	return false, ""
}
