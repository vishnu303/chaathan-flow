package utils

import (
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"os"
	"path/filepath"
	"strings"
)

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

	for _, s := range subs {
		fmt.Fprintln(f, s.Domain)
	}

	return nil
}

// ExportLiveSubdomains exports only live subdomains to a text file
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

	for _, s := range subs {
		fmt.Fprintln(f, s.Domain)
	}

	// Also create a file with IPs
	pathWithIP := filepath.Join(resultDir, "live_subdomains_with_ip.txt")
	fIP, err := os.Create(pathWithIP)
	if err != nil {
		return err
	}
	defer fIP.Close()

	for _, s := range subs {
		if s.IPAddress != "" {
			fmt.Fprintf(fIP, "%s,%s\n", s.Domain, s.IPAddress)
		} else {
			fmt.Fprintln(fIP, s.Domain)
		}
	}

	return nil
}

// ExportPorts exports open ports to text files
func ExportPorts(scanID int64, resultDir string) error {
	ports, err := database.GetPorts(scanID)
	if err != nil {
		return err
	}

	// Format: host:port
	path := filepath.Join(resultDir, "open_ports.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, p := range ports {
		fmt.Fprintf(f, "%s:%d\n", p.Host, p.Port)
	}

	// Also create detailed format
	pathDetailed := filepath.Join(resultDir, "open_ports_detailed.txt")
	fDetailed, err := os.Create(pathDetailed)
	if err != nil {
		return err
	}
	defer fDetailed.Close()

	for _, p := range ports {
		service := p.Service
		if service == "" {
			service = "unknown"
		}
		fmt.Fprintf(fDetailed, "%s:%d (%s/%s)\n", p.Host, p.Port, p.Protocol, service)
	}

	// Create unique hosts with open ports for further scanning
	pathHosts := filepath.Join(resultDir, "hosts_with_ports.txt")
	fHosts, err := os.Create(pathHosts)
	if err != nil {
		return err
	}
	defer fHosts.Close()

	hostSet := make(map[string][]int)
	for _, p := range ports {
		hostSet[p.Host] = append(hostSet[p.Host], p.Port)
	}
	for host, portList := range hostSet {
		var portStrs []string
		for _, p := range portList {
			portStrs = append(portStrs, fmt.Sprintf("%d", p))
		}
		fmt.Fprintf(fHosts, "%s [%s]\n", host, strings.Join(portStrs, ","))
	}

	return nil
}

// ExportURLs exports discovered URLs to text files
func ExportURLs(scanID int64, resultDir string) error {
	urls, err := database.GetURLs(scanID)
	if err != nil {
		return err
	}

	// All URLs
	path := filepath.Join(resultDir, "all_urls.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, u := range urls {
		fmt.Fprintln(f, u.URL)
	}

	// URLs with status codes (for filtering)
	pathWithStatus := filepath.Join(resultDir, "urls_with_status.txt")
	fStatus, err := os.Create(pathWithStatus)
	if err != nil {
		return err
	}
	defer fStatus.Close()

	for _, u := range urls {
		if u.StatusCode > 0 {
			fmt.Fprintf(fStatus, "[%d] %s\n", u.StatusCode, u.URL)
		} else {
			fmt.Fprintln(fStatus, u.URL)
		}
	}

	// 200 OK URLs only (usually most interesting)
	path200 := filepath.Join(resultDir, "urls_200.txt")
	f200, err := os.Create(path200)
	if err != nil {
		return err
	}
	defer f200.Close()

	for _, u := range urls {
		if u.StatusCode == 200 {
			fmt.Fprintln(f200, u.URL)
		}
	}

	// URLs with titles (useful for manual review)
	pathTitles := filepath.Join(resultDir, "urls_with_titles.txt")
	fTitles, err := os.Create(pathTitles)
	if err != nil {
		return err
	}
	defer fTitles.Close()

	for _, u := range urls {
		if u.Title != "" {
			fmt.Fprintf(fTitles, "%s | %s\n", u.URL, u.Title)
		}
	}

	return nil
}

// ExportVulnerabilities exports vulnerabilities to text files
func ExportVulnerabilities(scanID int64, resultDir string) error {
	vulns, err := database.GetVulnerabilities(scanID)
	if err != nil {
		return err
	}

	// All vulns summary
	path := filepath.Join(resultDir, "vulnerabilities.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, v := range vulns {
		fmt.Fprintf(f, "[%s] %s - %s\n", strings.ToUpper(v.Severity), v.Name, v.Host)
	}

	// Detailed vulns
	pathDetailed := filepath.Join(resultDir, "vulnerabilities_detailed.txt")
	fDetailed, err := os.Create(pathDetailed)
	if err != nil {
		return err
	}
	defer fDetailed.Close()

	for _, v := range vulns {
		fmt.Fprintf(fDetailed, "================================================================================\n")
		fmt.Fprintf(fDetailed, "[%s] %s\n", strings.ToUpper(v.Severity), v.Name)
		fmt.Fprintf(fDetailed, "================================================================================\n")
		fmt.Fprintf(fDetailed, "Host:     %s\n", v.Host)
		if v.URL != "" {
			fmt.Fprintf(fDetailed, "URL:      %s\n", v.URL)
		}
		if v.TemplateID != "" {
			fmt.Fprintf(fDetailed, "Template: %s\n", v.TemplateID)
		}
		if v.Description != "" {
			fmt.Fprintf(fDetailed, "Description:\n%s\n", v.Description)
		}
		if v.Evidence != "" {
			fmt.Fprintf(fDetailed, "Evidence:\n%s\n", v.Evidence)
		}
		fmt.Fprintln(fDetailed)
	}

	// Critical and High only (for quick review)
	pathCritical := filepath.Join(resultDir, "vulnerabilities_critical_high.txt")
	fCritical, err := os.Create(pathCritical)
	if err != nil {
		return err
	}
	defer fCritical.Close()

	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" {
			fmt.Fprintf(fCritical, "[%s] %s\n", strings.ToUpper(v.Severity), v.Name)
			fmt.Fprintf(fCritical, "  Host: %s\n", v.Host)
			if v.URL != "" {
				fmt.Fprintf(fCritical, "  URL:  %s\n", v.URL)
			}
			fmt.Fprintln(fCritical)
		}
	}

	// Unique vulnerable hosts
	pathHosts := filepath.Join(resultDir, "vulnerable_hosts.txt")
	fHosts, err := os.Create(pathHosts)
	if err != nil {
		return err
	}
	defer fHosts.Close()

	hostSet := make(map[string]bool)
	for _, v := range vulns {
		hostSet[v.Host] = true
	}
	for host := range hostSet {
		fmt.Fprintln(fHosts, host)
	}

	return nil
}

// ExportEndpoints exports API endpoints to text files
func ExportEndpoints(scanID int64, resultDir string) error {
	endpoints, err := database.GetEndpoints(scanID)
	if err != nil {
		return err
	}

	// All endpoints
	path := filepath.Join(resultDir, "endpoints.txt")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, e := range endpoints {
		fmt.Fprintln(f, e.URL)
	}

	// Endpoints with methods
	pathWithMethod := filepath.Join(resultDir, "endpoints_with_methods.txt")
	fMethod, err := os.Create(pathWithMethod)
	if err != nil {
		return err
	}
	defer fMethod.Close()

	for _, e := range endpoints {
		if e.Method != "" {
			fmt.Fprintf(fMethod, "%s %s\n", e.Method, e.URL)
		} else {
			fmt.Fprintln(fMethod, e.URL)
		}
	}

	// Interesting endpoints (API, admin, etc.)
	pathInteresting := filepath.Join(resultDir, "endpoints_interesting.txt")
	fInteresting, err := os.Create(pathInteresting)
	if err != nil {
		return err
	}
	defer fInteresting.Close()

	interestingPatterns := []string{
		"/api/", "/v1/", "/v2/", "/v3/",
		"/admin", "/login", "/auth",
		"/graphql", "/rest/",
		"/upload", "/download",
		"/config", "/settings",
		"/debug", "/test",
		".json", ".xml",
		"/swagger", "/docs",
	}

	for _, e := range endpoints {
		urlLower := strings.ToLower(e.URL)
		for _, pattern := range interestingPatterns {
			if strings.Contains(urlLower, pattern) {
				fmt.Fprintln(fInteresting, e.URL)
				break
			}
		}
	}

	return nil
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

	fmt.Fprintln(f, "================================================================================")
	fmt.Fprintln(f, "                        CHAATHAN SCAN SUMMARY")
	fmt.Fprintln(f, "================================================================================")
	fmt.Fprintf(f, "\nTarget: %s\n", target)
	fmt.Fprintf(f, "Scan ID: %d\n\n", scanID)

	fmt.Fprintln(f, "STATISTICS")
	fmt.Fprintln(f, "----------")
	fmt.Fprintf(f, "Total Subdomains:    %d\n", stats.TotalSubdomains)
	fmt.Fprintf(f, "Live Subdomains:     %d\n", stats.LiveSubdomains)
	fmt.Fprintf(f, "Open Ports:          %d\n", stats.TotalPorts)
	fmt.Fprintf(f, "URLs Discovered:     %d\n", stats.TotalURLs)
	fmt.Fprintf(f, "Endpoints Found:     %d\n", stats.TotalEndpoints)

	fmt.Fprintln(f, "\nVULNERABILITIES")
	fmt.Fprintln(f, "---------------")
	totalVulns := 0
	for sev, count := range stats.Vulnerabilities {
		fmt.Fprintf(f, "%-10s: %d\n", strings.ToUpper(sev), count)
		totalVulns += count
	}
	fmt.Fprintf(f, "%-10s: %d\n", "TOTAL", totalVulns)

	fmt.Fprintln(f, "\nOUTPUT FILES")
	fmt.Fprintln(f, "------------")
	fmt.Fprintln(f, "final_subdomains.txt        - All discovered subdomains")
	fmt.Fprintln(f, "live_subdomains.txt         - Only live/responsive subdomains")
	fmt.Fprintln(f, "open_ports.txt              - Open ports (host:port format)")
	fmt.Fprintln(f, "all_urls.txt                - All discovered URLs")
	fmt.Fprintln(f, "urls_200.txt                - URLs returning 200 OK")
	fmt.Fprintln(f, "vulnerabilities.txt         - All vulnerabilities summary")
	fmt.Fprintln(f, "vulnerabilities_critical_high.txt - Critical/High vulns only")
	fmt.Fprintln(f, "endpoints.txt               - All discovered endpoints")
	fmt.Fprintln(f, "endpoints_interesting.txt   - Interesting endpoints (API, admin, etc.)")

	fmt.Fprintln(f, "\n================================================================================")
	fmt.Fprintln(f, "Generated by Chaathan - https://github.com/yourusername/chaathan")
	fmt.Fprintln(f, "================================================================================")

	return nil
}
