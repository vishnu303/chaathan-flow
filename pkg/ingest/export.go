package ingest

// export.go owns the DB→text-file exporters (final_files/* and SUMMARY.txt).
// These functions were extracted from utils/export.go as part of the §3.4
// leaf-package inversion so utils could drop its pkg/database import. The
// public file-name constants and the canonical severity ordering stay in
// utils because they are shared with non-DB callers; ingest reads them via
// the utils.* getters.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/utils"
)

// exportManifest describes each exported file for the SUMMARY.txt listing.
var exportManifest = []struct{ File, Desc string }{
	{utils.FileFinalSubdomains, "All discovered subdomains"},
	{utils.FileLiveSubdomains, "Live/responsive subdomains (with IP)"},
	{utils.FileOpenPorts, "Open ports (host:port proto/service)"},
	{utils.FileAllURLs, "All discovered URLs with status codes"},
	{utils.FileURLs200, "URLs returning HTTP 200 OK"},
	{utils.FileVulnerabilities, "All vulnerabilities (detailed)"},
	{utils.FileVulnCriticalHigh, "Critical/High severity vulns only"},
	{utils.FileEndpoints, "All discovered endpoints (with method)"},
	{utils.FileEndpointsInteresting, "Interesting endpoints (API, admin, etc.)"},
	{utils.FileGFSecrets, "JS secrets from JavaScript deep analysis"},
	{utils.FileNucleiVulns, "Nuclei infra scan raw output"},
	{utils.FileNucleiURLVulns, "Nuclei URL scan raw output"},
	{utils.FileDalfoxXSS, "Dalfox XSS scan structured JSONL output"},
}

// writeAndSync writes all lines to the given file, flushes the buffer, and runs Sync()
func writeAndSync(filePath string, lines []string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}

	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}

	// f.Sync() is best-effort, ignore EINVAL on pipes/devices
	_ = f.Sync()
	return f.Close()
}

// ExportResults exports all scan results to text files in the result directory
func ExportResults(scanID int64, resultDir string) error {
	if err := os.MkdirAll(resultDir, 0755); err != nil {
		return err
	}

	// Export subdomains
	if err := ExportSubdomains(scanID, resultDir); err != nil {
		return fmt.Errorf("export subdomains: %w", err)
	}

	// Export live subdomains
	if err := ExportLiveSubdomains(scanID, resultDir); err != nil {
		return fmt.Errorf("export live subdomains: %w", err)
	}

	// Export ports
	if err := ExportPorts(scanID, resultDir); err != nil {
		return fmt.Errorf("export ports: %w", err)
	}

	// Export URLs
	if err := ExportURLs(scanID, resultDir); err != nil {
		return fmt.Errorf("export urls: %w", err)
	}

	// Export vulnerabilities
	if err := ExportVulnerabilities(scanID, resultDir); err != nil {
		return fmt.Errorf("export vulns: %w", err)
	}

	// Export endpoints
	if err := ExportEndpoints(scanID, resultDir); err != nil {
		return fmt.Errorf("export endpoints: %w", err)
	}

	return nil
}

// ExportSubdomains exports all subdomains to a text file
func ExportSubdomains(scanID int64, resultDir string) error {
	subs, err := database.GetSubdomains(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, utils.FileFinalSubdomains)
	var lines []string
	for _, s := range subs {
		lines = append(lines, s.Domain)
	}
	return writeAndSync(path, lines)
}

// ExportLiveSubdomains exports only live subdomains.
// Format: "domain,ip" when IP is known, otherwise just "domain".
func ExportLiveSubdomains(scanID int64, resultDir string) error {
	subs, err := database.GetLiveSubdomains(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, utils.FileLiveSubdomains)
	var lines []string
	for _, s := range subs {
		if s.IPAddress != "" {
			lines = append(lines, fmt.Sprintf("%s,%s", s.Domain, s.IPAddress))
		} else {
			lines = append(lines, s.Domain)
		}
	}
	return writeAndSync(path, lines)
}

// ExportPorts exports open ports.
// Format: "host:port (protocol/service)" — one file with full detail.
func ExportPorts(scanID int64, resultDir string) error {
	ports, err := database.GetPorts(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, utils.FileOpenPorts)
	var lines []string
	for _, p := range ports {
		service := p.Service
		if service == "" {
			service = "unknown"
		}
		lines = append(lines, fmt.Sprintf("%s:%d (%s/%s)", p.Host, p.Port, p.Protocol, service))
	}
	return writeAndSync(path, lines)
}

// ExportURLs exports discovered URLs.
// all_urls.txt — all URLs with inline status code.
// urls_200.txt  — 200 OK URLs only.
func ExportURLs(scanID int64, resultDir string) error {
	urls, err := database.GetURLs(scanID)
	if err != nil {
		return err
	}

	// All URLs with status
	path := filepath.Join(resultDir, utils.FileAllURLs)
	var lines []string
	for _, u := range urls {
		if u.StatusCode > 0 {
			lines = append(lines, fmt.Sprintf("[%d] %s", u.StatusCode, u.URL))
		} else {
			lines = append(lines, u.URL)
		}
	}
	if err := writeAndSync(path, lines); err != nil {
		return err
	}

	// 200 OK URLs only
	path200 := filepath.Join(resultDir, utils.FileURLs200)
	var lines200 []string
	for _, u := range urls {
		if u.StatusCode == 200 {
			lines200 = append(lines200, u.URL)
		}
	}
	return writeAndSync(path200, lines200)
}

// ExportVulnerabilities exports vulnerabilities.
// vulnerabilities.txt              — all vulns in detailed block format.
// vulnerabilities_critical_high.txt — critical/high only, compact format.
func ExportVulnerabilities(scanID int64, resultDir string) error {
	vulns, err := database.GetVulnerabilities(scanID)
	if err != nil {
		return err
	}

	// All vulns — detailed blocks
	path := filepath.Join(resultDir, utils.FileVulnerabilities)
	var lines []string
	for _, v := range vulns {
		lines = append(lines, "================================================================================")
		lines = append(lines, fmt.Sprintf("[%s] %s", strings.ToUpper(v.Severity), v.Name))
		lines = append(lines, "================================================================================")
		lines = append(lines, fmt.Sprintf("Host:     %s", v.Host))
		if v.URL != "" {
			lines = append(lines, fmt.Sprintf("URL:      %s", v.URL))
		}
		if v.TemplateID != "" {
			lines = append(lines, fmt.Sprintf("Template: %s", v.TemplateID))
		}
		if v.Description != "" {
			lines = append(lines, fmt.Sprintf("Description:\n%s", v.Description))
		}
		if v.Evidence != "" {
			lines = append(lines, fmt.Sprintf("Evidence:\n%s", v.Evidence))
		}
		lines = append(lines, "")
	}
	if err := writeAndSync(path, lines); err != nil {
		return err
	}

	// Critical and High only — compact
	pathCritical := filepath.Join(resultDir, utils.FileVulnCriticalHigh)
	var linesCritical []string
	for _, v := range vulns {
		// Perform case-insensitive check by matching lowercased severity values
		if strings.EqualFold(v.Severity, "critical") || strings.EqualFold(v.Severity, "high") {
			linesCritical = append(linesCritical, fmt.Sprintf("[%s] %s", strings.ToUpper(v.Severity), v.Name))
			linesCritical = append(linesCritical, fmt.Sprintf("  Host: %s", v.Host))
			if v.URL != "" {
				linesCritical = append(linesCritical, fmt.Sprintf("  URL:  %s", v.URL))
			}
			linesCritical = append(linesCritical, "")
		}
	}
	return writeAndSync(pathCritical, linesCritical)
}

// ExportEndpoints exports API endpoints.
// endpoints.txt             — all endpoints with method inline.
// endpoints_interesting.txt — filtered to API, admin, auth, etc.
func ExportEndpoints(scanID int64, resultDir string) error {
	endpoints, err := database.GetEndpoints(scanID)
	if err != nil {
		return err
	}

	// All endpoints with method
	path := filepath.Join(resultDir, utils.FileEndpoints)
	var lines []string
	for _, e := range endpoints {
		if e.Method != "" {
			lines = append(lines, fmt.Sprintf("%s %s", e.Method, e.URL))
		} else {
			lines = append(lines, e.URL)
		}
	}
	if err := writeAndSync(path, lines); err != nil {
		return err
	}

	// Interesting endpoints (API, admin, etc.) using shared utils patterns
	pathInteresting := filepath.Join(resultDir, utils.FileEndpointsInteresting)
	patterns := utils.InterestingEndpointsPatterns()
	var linesInteresting []string
	for _, e := range endpoints {
		urlLower := strings.ToLower(e.URL)
		for _, pattern := range patterns {
			if strings.Contains(urlLower, pattern) {
				if e.Method != "" {
					linesInteresting = append(linesInteresting, fmt.Sprintf("%s %s", e.Method, e.URL))
				} else {
					linesInteresting = append(linesInteresting, e.URL)
				}
				break
			}
		}
	}
	return writeAndSync(pathInteresting, linesInteresting)
}

// ExportSummary creates a summary text file
func ExportSummary(scanID int64, resultDir string, target string) error {
	stats, err := database.GetScanStats(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, utils.FileSummary)
	var lines []string

	lines = append(lines, "================================================================================")
	lines = append(lines, "                        CHAATHAN SCAN SUMMARY")
	lines = append(lines, "================================================================================")
	lines = append(lines, fmt.Sprintf("\nTarget: %s", target))
	lines = append(lines, fmt.Sprintf("Scan ID: %d\n", scanID))

	lines = append(lines, "STATISTICS")
	lines = append(lines, "----------")
	lines = append(lines, fmt.Sprintf("Total Subdomains:    %d", stats.TotalSubdomains))
	lines = append(lines, fmt.Sprintf("Live Subdomains:     %d", stats.LiveSubdomains))
	lines = append(lines, fmt.Sprintf("Open Ports:          %d", stats.TotalPorts))
	lines = append(lines, fmt.Sprintf("URLs Discovered:     %d", stats.TotalURLs))
	lines = append(lines, fmt.Sprintf("Endpoints Found:     %d", stats.TotalEndpoints))

	lines = append(lines, "\nVULNERABILITIES")
	lines = append(lines, "---------------")
	totalVulns := 0

	// Canonical severities first, then any non-standard ones (dedup-guarded).
	printed := make(map[string]bool)
	for _, sev := range utils.SeverityOrder() {
		if count, ok := stats.Vulnerabilities[sev]; ok {
			lines = append(lines, fmt.Sprintf("%-10s: %d", strings.ToUpper(sev), count))
			totalVulns += count
			printed[sev] = true
		}
	}
	for sev, count := range stats.Vulnerabilities {
		if !printed[sev] {
			lines = append(lines, fmt.Sprintf("%-10s: %d", strings.ToUpper(sev), count))
			totalVulns += count
			printed[sev] = true
		}
	}
	lines = append(lines, fmt.Sprintf("%-10s: %d", "TOTAL", totalVulns))

	lines = append(lines, "\nOUTPUT FILES  (all files are inside final_files/)")
	lines = append(lines, "------------")
	for _, entry := range exportManifest {
		lines = append(lines, fmt.Sprintf("%-34s - %s", entry.File, entry.Desc))
	}
	lines = append(lines, "")
	lines = append(lines, "Raw tool outputs are in intermediate_files/ (subfinder, gau, httpx, etc.)")

	lines = append(lines, "\n================================================================================")
	lines = append(lines, "Generated by Chaathan - https://github.com/vishnu303/chaathan")
	lines = append(lines, "================================================================================")

	return writeAndSync(path, lines)
}
