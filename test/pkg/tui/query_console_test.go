package tui_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/rivo/tview"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/tui"
)

func TestQueryConsoleLoadAndCapping(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "chaathan_query_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	if err := database.Initialize(dbPath); err != nil {
		t.Fatalf("failed to initialize db: %v", err)
	}
	defer func() {
		if database.DB != nil {
			database.DB.Close()
			database.DB = nil
		}
	}()

	scanObj, err := database.CreateScan("example.com", "wildcard", tempDir, "{}")
	if err != nil {
		t.Fatalf("failed to insert scan: %v", err)
	}
	scanID := scanObj.ID

	for i := 1; i <= 5005; i++ {
		domain := fmt.Sprintf("sub%d.example.com", i)
		err := database.AddSubdomains(scanID, []string{domain}, "test")
		if err != nil {
			t.Fatalf("failed to insert subdomain %d: %v", i, err)
		}
		err = database.UpdateSubdomainLive(scanID, domain, true, "127.0.0.1")
		if err != nil {
			t.Fatalf("failed to update subdomain live %d: %v", i, err)
		}
	}

	err = database.AddURL(scanID, database.URLRecord{RawURL: "https://example.com/api", StatusCode: 200, ContentType: "application/json", Title: "API Title", Tech: `["Node.js","Express"]`, Source: "test"})
	if err != nil {
		t.Fatalf("failed to insert URL: %v", err)
	}

	q := &tui.QueryConsole{}
	q.FilterInput = tview.NewInputField()
	q.FooterText = tview.NewTextView()
	for i := 0; i < 6; i++ {
		q.Tables[i] = tview.NewTable()
	}

	q.LoadScanData(scanID)

	if q.GetSubdomainsTotalCount() != 5005 {
		t.Errorf("expected subdomainsTotalCount to be 5005, got %d", q.GetSubdomainsTotalCount())
	}

	if len(q.GetSubdomains()) != 5005 {
		t.Errorf("expected loaded subdomains slice to have length 5005, got %d", len(q.GetSubdomains()))
	}

	q.LoadActiveTab(3) // Switch to URLs tab (index 3) to lazy-load URL data

	cachedTech := q.GetTechCacheValue("https://example.com/api")
	if cachedTech == "" {
		t.Fatal("expected tech cache to contain entry for URL")
	}

	if cachedTech != "Node.js, Express" {
		t.Errorf("expected techCache string to be 'Node.js, Express', got %q", cachedTech)
	}
}
