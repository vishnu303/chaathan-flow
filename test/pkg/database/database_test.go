package database_test

import (
	"path/filepath"
	"testing"

	"github.com/vishnu303/chaathan/pkg/database"
)

func TestDatabaseOperations(t *testing.T) {
	// NOT t.Parallel
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	// 1. Initialize
	err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("failed to initialize database: %v", err)
	}
	defer database.Close()

	// 2. Create Scan
	scan, err := database.CreateScan("testdomain.com", "wildcard", tempDir, `{"test": true}`)
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}
	if scan.Target != "testdomain.com" {
		t.Errorf("expected target testdomain.com, got %q", scan.Target)
	}

	// 3. Update Scan Status
	err = database.UpdateScanStatus(scan.ID, "completed")
	if err != nil {
		t.Errorf("failed to update scan status: %v", err)
	}

	// 4. Add Subdomain
	err = database.AddSubdomain(scan.ID, "sub.testdomain.com", "subfinder")
	if err != nil {
		t.Errorf("failed to add subdomain: %v", err)
	}

	// 5. Update Subdomain Live
	err = database.UpdateSubdomainLive(scan.ID, "sub.testdomain.com", true, "192.168.1.1")
	if err != nil {
		t.Errorf("failed to update subdomain live: %v", err)
	}

	// 6. Get Live Subdomains
	liveSubs, err := database.GetLiveSubdomains(scan.ID)
	if err != nil {
		t.Fatalf("failed to get live subdomains: %v", err)
	}
	if len(liveSubs) != 1 {
		t.Fatalf("expected 1 live subdomain, got %d", len(liveSubs))
	}
	if liveSubs[0].Domain != "sub.testdomain.com" || liveSubs[0].IPAddress != "192.168.1.1" {
		t.Errorf("subdomain details mismatch: %+v", liveSubs[0])
	}

	// 7. Add Port
	err = database.AddPort(scan.ID, "sub.testdomain.com", 80, "tcp", "http")
	if err != nil {
		t.Errorf("failed to add port: %v", err)
	}

	// 8. Add URL
	err = database.AddURL(scan.ID, "http://sub.testdomain.com/index.html", 200, "text/html", "Home Page", `["jquery"]`, "httpx")
	if err != nil {
		t.Errorf("failed to add URL: %v", err)
	}

	// 9. Add Endpoint
	err = database.AddEndpoint(scan.ID, "http://sub.testdomain.com/api/v1", "GET", "katana")
	if err != nil {
		t.Errorf("failed to add endpoint: %v", err)
	}

	// 10. Add Vulnerability
	err = database.AddVulnerability(scan.ID, "sub.testdomain.com", "http://sub.testdomain.com/index.html", "xss", "Reflected XSS", "medium", "XSS vulnerability", "matcher", "evidence")
	if err != nil {
		t.Errorf("failed to add vulnerability: %v", err)
	}

	// 11. Get Vulnerabilities
	vulns, err := database.GetVulnerabilities(scan.ID)
	if err != nil {
		t.Fatalf("failed to get vulnerabilities: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].Name != "Reflected XSS" || vulns[0].Severity != "medium" {
		t.Errorf("vulnerability details mismatch: %+v", vulns[0])
	}

	// 12. Upsert Host Metadata
	err = database.UpsertHostMetadata(scan.ID, database.HostMetadata{
		Host:       "sub.testdomain.com",
		SSLExpired: true,
		WeakTLS:    false,
	})
	if err != nil {
		t.Errorf("failed to upsert host metadata: %v", err)
	}

	// 13. Upsert URL Metadata
	err = database.UpsertURLMetadata(scan.ID, database.URLMetadata{
		URL:          "http://sub.testdomain.com/index.html",
		Host:         "sub.testdomain.com",
		LoginSurface: true,
	})
	if err != nil {
		t.Errorf("failed to upsert URL metadata: %v", err)
	}

	// 14. GF Matches
	gfMatches := []database.GFMatch{
		{URL: "http://sub.testdomain.com/js/app.js", Pattern: "sqli"},
		{URL: "http://sub.testdomain.com/js/app.js", Pattern: "xss"},
		{URL: "http://sub.testdomain.com/js/lib.js", Pattern: "rce"},
		{URL: "http://sub.testdomain.com/js/lib.js", Pattern: "rce"}, // Duplicate to check INSERT OR IGNORE
	}
	err = database.InsertGFMatches(scan.ID, gfMatches)
	if err != nil {
		t.Errorf("failed to insert gf matches: %v", err)
	}

	fetchedGF, err := database.GetGFMatchesByScan(scan.ID)
	if err != nil {
		t.Fatalf("failed to get gf matches: %v", err)
	}

	if len(fetchedGF) != 2 {
		t.Errorf("expected 2 URLs with gf matches, got %d", len(fetchedGF))
	}

	appMatches := fetchedGF["http://sub.testdomain.com/js/app.js"]
	if len(appMatches) != 2 {
		t.Errorf("expected 2 pattern matches for app.js, got %d: %v", len(appMatches), appMatches)
	}

	libMatches := fetchedGF["http://sub.testdomain.com/js/lib.js"]
	if len(libMatches) != 1 {
		t.Errorf("expected 1 pattern match for lib.js (deduplicated), got %d: %v", len(libMatches), libMatches)
	}
}

func TestNullStringMetadataReads(t *testing.T) {
	// NOT t.Parallel
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_nulls.db")

	err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("failed to initialize database: %v", err)
	}
	defer database.Close()

	scanID := int64(12345)
	hosts := []string{"target-null.com"}
	err = database.MarkHostsJSSecrets(scanID, hosts)
	if err != nil {
		t.Fatalf("failed to insert partial host metadata: %v", err)
	}

	metas, err := database.GetHostMetadata(scanID)
	if err != nil {
		t.Fatalf("failed to get host metadata with nulls: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("expected 1 host metadata record, got %d", len(metas))
	}
	if metas[0].Host != "target-null.com" {
		t.Errorf("expected host 'target-null.com', got %q", metas[0].Host)
	}
	if metas[0].BaseURL != "" {
		t.Errorf("expected empty BaseURL for NULL value, got %q", metas[0].BaseURL)
	}
	if metas[0].HeadersJSON != "" {
		t.Errorf("expected empty HeadersJSON for NULL value, got %q", metas[0].HeadersJSON)
	}

	err = database.InsertRawURLMetadataForTest(scanID, "http://target-null.com/path", "target-null.com")
	if err != nil {
		t.Fatalf("failed to insert partial url metadata: %v", err)
	}

	urlMetas, err := database.GetURLMetadata(scanID)
	if err != nil {
		t.Fatalf("failed to get url metadata with nulls: %v", err)
	}
	if len(urlMetas) != 1 {
		t.Fatalf("expected 1 url metadata record, got %d", len(urlMetas))
	}
	if urlMetas[0].HeadersJSON != "" {
		t.Errorf("expected empty HeadersJSON for NULL value, got %q", urlMetas[0].HeadersJSON)
	}
}

func TestNilDBGuard(t *testing.T) {
	database.Close()
	oldDB := database.DB
	database.DB = nil
	defer func() {
		database.DB = oldDB
	}()

	_, err := database.CreateScan("test.com", "wildcard", "", "")
	if err != database.ErrDBNotInitialized {
		t.Errorf("expected ErrDBNotInitialized, got %v", err)
	}
}
