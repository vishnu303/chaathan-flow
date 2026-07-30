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

// allTools is the canonical tool catalogue. Order determines display
// order in `chaathan tools list` and `chaathan tools check`.
var allTools = []ToolInfo{
	// Subdomain Enumeration
	{Name: "subfinder", Category: "Enum", Description: "Passive subdomain discovery", Required: true, InstallURL: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	{Name: "assetfinder", Category: "Enum", Description: "Passive subdomain discovery", Required: true, InstallURL: "github.com/tomnomnom/assetfinder@latest"},
	{Name: "sublist3r", Category: "Enum", Description: "Passive subdomain discovery (Python)", Required: false, InstallURL: ""},
	{Name: "amass", Category: "Enum", Description: "Active DNS enumeration", Required: false, InstallURL: "github.com/owasp-amass/amass/v4/...@latest"},

	// DNS & Resolution
	{Name: "dnsx", Category: "DNS", Description: "DNS resolution & record lookup", Required: true, InstallURL: "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	{Name: "shuffledns", Category: "DNS", Description: "DNS brute-force with massdns", Required: false, InstallURL: "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"},
	{Name: "massdns", Category: "DNS", Description: "High-performance DNS resolver (from source)", Required: false, InstallURL: ""},

	// Web Probing
	{Name: "httpx", Category: "Probe", Description: "HTTP probing & tech detection", Required: true, InstallURL: "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
	{Name: "tlsx", Category: "Probe", Description: "TLS certificate analysis & SAN extraction", Required: false, InstallURL: "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
	{Name: "naabu", Category: "Probe", Description: "Port scanning (SYN/TCP)", Required: false, InstallURL: "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},

	// URL Discovery
	{Name: "waybackurls", Category: "URLs", Description: "Wayback Machine URL extraction", Required: false, InstallURL: "github.com/tomnomnom/waybackurls@latest"},
	{Name: "gau", Category: "URLs", Description: "Historical URL discovery", Required: false, InstallURL: "github.com/lc/gau/v2/cmd/gau@latest"},
	{Name: "x8", Category: "URLs", Description: "Hidden HTTP parameter discovery (Rust)", Required: false, InstallURL: ""},
	{Name: "katana", Category: "Crawl", Description: "Web crawling & spidering", Required: false, InstallURL: "github.com/projectdiscovery/katana/cmd/katana@latest"},
	{Name: "gospider", Category: "Crawl", Description: "Web crawling & spidering", Required: false, InstallURL: "github.com/jaeles-project/gospider@latest"},

	// Analysis
	{Name: "jsluice", Category: "Analysis", Description: "AST-based JavaScript URL & secret extraction", Required: false, InstallURL: "github.com/BishopFox/jsluice/cmd/jsluice@latest"},
	{Name: "hakrawler", Category: "Crawl", Description: "Fast web crawler for endpoint & asset discovery", Required: false, InstallURL: "github.com/hakluke/hakrawler@latest"},

	// Fuzzing & Scanning
	{Name: "ffuf", Category: "Fuzz", Description: "Web fuzzer & directory brute-force", Required: false, InstallURL: "github.com/ffuf/ffuf/v2@latest"},
	{Name: "nuclei", Category: "Vuln", Description: "Template-based vulnerability scanner", Required: true, InstallURL: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	{Name: "dalfox", Category: "Vuln", Description: "XSS vulnerability scanner", Required: false, InstallURL: "github.com/hahwul/dalfox/v2@latest"},

	// Recon
	{Name: "uncover", Category: "Recon", Description: "Shodan/Censys/Fofa search dorking", Required: false, InstallURL: "github.com/projectdiscovery/uncover/cmd/uncover@latest"},
	{Name: "metabigor", Category: "Recon", Description: "ASN & org discovery", Required: false, InstallURL: "github.com/j3ssie/metabigor@latest"},
	{Name: "github-subdomains", Category: "Recon", Description: "GitHub subdomain scraping", Required: false, InstallURL: "github.com/gwen001/github-subdomains@latest"},
	{Name: "cloud_enum", Category: "Cloud", Description: "Cloud infrastructure enumeration (Python)", Required: false, InstallURL: ""},

	// Utility
	{Name: "anew", Category: "Util", Description: "Append unique lines to file", Required: false, InstallURL: "github.com/tomnomnom/anew@latest"},

	// Proxy Automation
	{Name: "mubeng", Category: "Proxy", Description: "Proxy scraper, checker & IP rotator (Go)", Required: false, InstallURL: "github.com/mubeng/mubeng@latest"},
}

// GetAllTools returns a copy of the canonical tool catalogue to prevent accidental mutations.
func GetAllTools() []ToolInfo {
	return append([]ToolInfo(nil), allTools...)
}

// GoInstallableTools returns the subset of allTools that have a non-empty
// InstallURL — these are the tools that `go install` can install.
func GoInstallableTools() []ToolInfo {
	var out []ToolInfo
	for _, t := range allTools {
		if t.InstallURL != "" {
			out = append(out, t)
		}
	}
	return out
}

// CountRequired returns the number of tools marked as Required.
func CountRequired() int {
	count := 0
	for _, t := range allTools {
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
