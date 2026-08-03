package report_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/report"
)

func TestReportGenerationAndExport(t *testing.T) {
	// Initialize temporary database
	dbFile := filepath.Join(t.TempDir(), "test_report.db")
	if err := database.Initialize(dbFile); err != nil {
		t.Fatalf("failed to initialize test database: %v", err)
	}
	defer func() {
		database.Close()
		os.Remove(dbFile)
	}()

	// Seed scan data
	scan, err := database.CreateScan("example.com", "wildcard", t.TempDir(), "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}

	// Add subdomains
	if err := database.AddSubdomains(scan.ID, []string{"www.example.com"}, "test"); err != nil {
		t.Fatalf("failed to add subdomain: %v", err)
	}
	if err := database.UpdateSubdomainLive(scan.ID, "www.example.com", true, "1.2.3.4"); err != nil {
		t.Fatalf("failed to update subdomain live: %v", err)
	}

	// Add port
	if err := database.AddPorts(scan.ID, []database.Port{{Host: "www.example.com", Port: 443, Protocol: "tcp", Service: "https"}}); err != nil {
		t.Fatalf("failed to add port: %v", err)
	}

	// Add URL
	if err := database.AddURL(scan.ID, database.URLRecord{RawURL: "https://www.example.com/", StatusCode: 200, ContentType: "text/html", Title: "Example Domain", Tech: `["wordpress"]`, Source: "httpx"}); err != nil {
		t.Fatalf("failed to add URL: %v", err)
	}

	// Add vuln
	if err := database.AddVulnerability(scan.ID, database.VulnRecord{Host: "www.example.com", URL: "https://www.example.com/", TemplateID: "test-cve", Name: "Test Vuln", Severity: "high", Description: "A test vuln", Matcher: "pattern", Evidence: "evidence line"}); err != nil {
		t.Fatalf("failed to add vuln: %v", err)
	}

	// Add endpoint
	if err := database.AddEndpoints(scan.ID, []database.Endpoint{{URL: "https://www.example.com/api", Method: "GET", Source: "katana"}}); err != nil {
		t.Fatalf("failed to add endpoint: %v", err)
	}

	// Generate report
	rpt, err := report.Generate(scan.ID)
	if err != nil {
		t.Fatalf("failed to generate report: %v", err)
	}

	if rpt.Scan.Target != "example.com" {
		t.Errorf("expected target example.com, got %q", rpt.Scan.Target)
	}

	// Export formats
	formats := []report.ReportFormat{report.FormatMarkdown, report.FormatJSON, report.FormatHTML, report.FormatText}
	for _, fmtStr := range formats {
		outPath := filepath.Join(t.TempDir(), "report"+report.ExtensionFor(string(fmtStr)))
		if err := rpt.Export(fmtStr, outPath); err != nil {
			t.Errorf("failed to export format %s: %v", fmtStr, err)
		}

		// Verify file exists and is not empty
		info, err := os.Stat(outPath)
		if err != nil {
			t.Errorf("exported file not found for format %s: %v", fmtStr, err)
		} else if info.Size() == 0 {
			t.Errorf("exported file is empty for format %s", fmtStr)
		}
	}
}

func TestMarkdownTableEscaping(t *testing.T) {
	// Initialize temporary database
	dbFile := filepath.Join(t.TempDir(), "test_md_escape.db")
	if err := database.Initialize(dbFile); err != nil {
		t.Fatalf("failed to initialize test database: %v", err)
	}
	defer func() {
		database.Close()
		os.Remove(dbFile)
	}()

	scan, err := database.CreateScan("example.com", "wildcard", t.TempDir(), "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}

	// Add subdomain with dangerous markdown chars: |, `, *
	if err := database.AddSubdomains(scan.ID, []string{"www.example|portal`code*bold.com"}, "test"); err != nil {
		t.Fatalf("failed to add subdomain: %v", err)
	}
	if err := database.UpdateSubdomainLive(scan.ID, "www.example|portal`code*bold.com", true, "1.2.3.4"); err != nil {
		t.Fatalf("failed to update subdomain live: %v", err)
	}

	rpt, err := report.Generate(scan.ID)
	if err != nil {
		t.Fatalf("failed to generate report: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "report.md")
	if err := rpt.Export(report.FormatMarkdown, outPath); err != nil {
		t.Fatalf("failed to export markdown: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read exported markdown: %v", err)
	}

	contentStr := string(content)
	// Must contain escaped versions: \|, \`, \*
	expected := []string{`www.example\|portal\` + "`" + `code\*bold.com`}
	for _, exp := range expected {
		if !strings.Contains(contentStr, exp) {
			t.Errorf("expected escaped content %q in markdown report, but not found. Report content:\n%s", exp, contentStr)
		}
	}
}

func TestReportEmptySlices(t *testing.T) {
	// Initialize temporary database
	dbFile := filepath.Join(t.TempDir(), "test_empty_report.db")
	if err := database.Initialize(dbFile); err != nil {
		t.Fatalf("failed to initialize test database: %v", err)
	}
	defer func() {
		database.Close()
		os.Remove(dbFile)
	}()

	scan, err := database.CreateScan("empty.com", "wildcard", t.TempDir(), "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}

	rpt, err := report.Generate(scan.ID)
	if err != nil {
		t.Fatalf("failed to generate report: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "report.json")
	if err := rpt.Export(report.FormatJSON, outPath); err != nil {
		t.Fatalf("failed to export json: %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read exported json: %v", err)
	}

	contentStr := string(content)
	// Assert JSON contains empty arrays, not nulls
	emptyArrays := []string{
		`"subdomains": []`,
		`"live_subdomains": []`,
		`"ports": []`,
		`"urls": []`,
		`"top_targets": []`,
		`"vulnerabilities": []`,
		`"endpoints": []`,
	}
	for _, arr := range emptyArrays {
		if !strings.Contains(contentStr, arr) {
			t.Errorf("expected JSON to contain empty array %q, got: %s", arr, contentStr)
		}
	}
}
