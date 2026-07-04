package utils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishnu303/chaathan/pkg/database"
)

// NOTE: keep in sync with pkg/wildcard_flow output filenames
var exportManifest = []struct{ File, Desc string }{
	{"final_subdomains.txt", "All discovered subdomains"},
	{"live_subdomains.txt", "Live/responsive subdomains (with IP)"},
	{"open_ports.txt", "Open ports (host:port proto/service)"},
	{"all_urls.txt", "All discovered URLs with status codes"},
	{"urls_200.txt", "URLs returning HTTP 200 OK"},
	{"vulnerabilities.txt", "All vulnerabilities (detailed)"},
	{"vulnerabilities_critical_high.txt", "Critical/High severity vulns only"},
	{"endpoints.txt", "All discovered endpoints (with method)"},
	{"endpoints_interesting.txt", "Interesting endpoints (API, admin, etc.)"},
	{"gf_secrets_findings.txt", "JS secret and JS sink matches from downloaded JS"},
	{"nuclei_vulns.json", "Nuclei infra scan raw output"},
	{"nuclei_url_vulns.json", "Nuclei URL scan raw output"},
	{"dalfox_xss.jsonl", "Dalfox XSS scan structured JSONL output"},
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

	path := filepath.Join(resultDir, "final_subdomains.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, s := range subs {
		if _, err := fmt.Fprintln(w, s.Domain); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ExportLiveSubdomains exports only live subdomains.
// Format: "domain,ip" when IP is known, otherwise just "domain".
func ExportLiveSubdomains(scanID int64, resultDir string) error {
	subs, err := database.GetLiveSubdomains(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, "live_subdomains.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, s := range subs {
		var err error
		if s.IPAddress != "" {
			_, err = fmt.Fprintf(w, "%s,%s\n", s.Domain, s.IPAddress)
		} else {
			_, err = fmt.Fprintln(w, s.Domain)
		}
		if err != nil {
			return err
		}
	}
	return w.Flush()
}

// ExportPorts exports open ports.
// Format: "host:port (protocol/service)" — one file with full detail.
func ExportPorts(scanID int64, resultDir string) error {
	ports, err := database.GetPorts(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, "open_ports.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, p := range ports {
		service := p.Service
		if service == "" {
			service = "unknown"
		}
		if _, err := fmt.Fprintf(w, "%s:%d (%s/%s)\n", p.Host, p.Port, p.Protocol, service); err != nil {
			return err
		}
	}
	return w.Flush()
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
	path := filepath.Join(resultDir, "all_urls.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, u := range urls {
		var err error
		if u.StatusCode > 0 {
			_, err = fmt.Fprintf(w, "[%d] %s\n", u.StatusCode, u.URL)
		} else {
			_, err = fmt.Fprintln(w, u.URL)
		}
		if err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// 200 OK URLs only
	path200 := filepath.Join(resultDir, "urls_200.txt")
	f200, err := os.Create(path200)
	if err != nil {
		return err
	}
	defer f200.Close()

	w200 := bufio.NewWriter(f200)
	for _, u := range urls {
		if u.StatusCode == 200 {
			if _, err := fmt.Fprintln(w200, u.URL); err != nil {
				return err
			}
		}
	}
	return w200.Flush()
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
	path := filepath.Join(resultDir, "vulnerabilities.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, v := range vulns {
		if _, err := fmt.Fprintf(w, "================================================================================\n"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "[%s] %s\n", strings.ToUpper(v.Severity), v.Name); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "================================================================================\n"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "Host:     %s\n", v.Host); err != nil {
			return err
		}
		if v.URL != "" {
			if _, err := fmt.Fprintf(w, "URL:      %s\n", v.URL); err != nil {
				return err
			}
		}
		if v.TemplateID != "" {
			if _, err := fmt.Fprintf(w, "Template: %s\n", v.TemplateID); err != nil {
				return err
			}
		}
		if v.Description != "" {
			if _, err := fmt.Fprintf(w, "Description:\n%s\n", v.Description); err != nil {
				return err
			}
		}
		if v.Evidence != "" {
			if _, err := fmt.Fprintf(w, "Evidence:\n%s\n", v.Evidence); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// Critical and High only — compact
	pathCritical := filepath.Join(resultDir, "vulnerabilities_critical_high.txt")
	fCritical, err := os.Create(pathCritical)
	if err != nil {
		return err
	}
	defer fCritical.Close()

	wCritical := bufio.NewWriter(fCritical)
	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" {
			if _, err := fmt.Fprintf(wCritical, "[%s] %s\n", strings.ToUpper(v.Severity), v.Name); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(wCritical, "  Host: %s\n", v.Host); err != nil {
				return err
			}
			if v.URL != "" {
				if _, err := fmt.Fprintf(wCritical, "  URL:  %s\n", v.URL); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(wCritical); err != nil {
				return err
			}
		}
	}
	return wCritical.Flush()
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
	path := filepath.Join(resultDir, "endpoints.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, e := range endpoints {
		var err error
		if e.Method != "" {
			_, err = fmt.Fprintf(w, "%s %s\n", e.Method, e.URL)
		} else {
			_, err = fmt.Fprintln(w, e.URL)
		}
		if err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// Interesting endpoints (API, admin, etc.) using package patterns
	pathInteresting := filepath.Join(resultDir, "endpoints_interesting.txt")
	fInteresting, err := os.Create(pathInteresting)
	if err != nil {
		return err
	}
	defer fInteresting.Close()

	wInteresting := bufio.NewWriter(fInteresting)
	for _, e := range endpoints {
		urlLower := strings.ToLower(e.URL)
		for _, pattern := range InterestingEndpointsPatterns {
			if strings.Contains(urlLower, pattern) {
				var err error
				if e.Method != "" {
					_, err = fmt.Fprintf(wInteresting, "%s %s\n", e.Method, e.URL)
				} else {
					_, err = fmt.Fprintln(wInteresting, e.URL)
				}
				if err != nil {
					return err
				}
				break
			}
		}
	}
	return wInteresting.Flush()
}

// ExportSummary creates a summary text file
func ExportSummary(scanID int64, resultDir string, target string) error {
	stats, err := database.GetScanStats(scanID)
	if err != nil {
		return err
	}

	path := filepath.Join(resultDir, "SUMMARY.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	if _, err := fmt.Fprintln(w, "================================================================================"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "                        CHAATHAN SCAN SUMMARY"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "================================================================================"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\nTarget: %s\n", target); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Scan ID: %d\n\n", scanID); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "STATISTICS"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "----------"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Total Subdomains:    %d\n", stats.TotalSubdomains); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Live Subdomains:     %d\n", stats.LiveSubdomains); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Open Ports:          %d\n", stats.TotalPorts); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "URLs Discovered:     %d\n", stats.TotalURLs); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Endpoints Found:     %d\n", stats.TotalEndpoints); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "\nVULNERABILITIES"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "---------------"); err != nil {
		return err
	}
	totalVulns := 0
	severities := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range severities {
		if count, ok := stats.Vulnerabilities[sev]; ok {
			if _, err := fmt.Fprintf(w, "%-10s: %d\n", strings.ToUpper(sev), count); err != nil {
				return err
			}
			totalVulns += count
		}
	}
	for sev, count := range stats.Vulnerabilities {
		isStandard := false
		for _, s := range severities {
			if s == sev {
				isStandard = true
				break
			}
		}
		if !isStandard {
			if _, err := fmt.Fprintf(w, "%-10s: %d\n", strings.ToUpper(sev), count); err != nil {
				return err
			}
			totalVulns += count
		}
	}
	if _, err := fmt.Fprintf(w, "%-10s: %d\n", "TOTAL", totalVulns); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "\nOUTPUT FILES  (all files are inside final_files/)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "------------"); err != nil {
		return err
	}
	for _, entry := range exportManifest {
		if _, err := fmt.Fprintf(w, "%-34s - %s\n", entry.File, entry.Desc); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, ""); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "Raw tool outputs are in intermediate_files/ (subfinder, gau, httpx, etc.)"); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "\n================================================================================"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "Generated by Chaathan - https://github.com/vishnu303/chaathan"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "================================================================================"); err != nil {
		return err
	}

	return w.Flush()
}
