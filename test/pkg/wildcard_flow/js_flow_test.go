package wildcard_flow_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

// TestGatherJSURLs_IncludesFfuf verifies JS URL gathering pulls from crawler
// outputs AND ffuf discoveries, dedupes across sources, and filters out
// third-party vendor libraries and non-JS URLs.
func TestGatherJSURLs_IncludesFfuf(t *testing.T) {
	tmpDir := t.TempDir()

	katanaFile := filepath.Join(tmpDir, "katana.txt")
	katanaLines := []string{
		"http://example.com/static/app.js",
		"http://example.com/vendor/jquery.min.js", // vendor lib -> filtered
		"http://example.com/index.html",           // not JS -> filtered
		"http://example.com/assets/main.js [script]", // gospider-style tagged line
	}
	if err := os.WriteFile(katanaFile, []byte(strings.Join(katanaLines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ffufFile := filepath.Join(tmpDir, "ffuf_discovered_urls.txt")
	ffufLines := []string{
		"http://example.com/discovered/bundle.js",
		"http://example.com/static/app.js", // duplicate of katana entry
	}
	if err := os.WriteFile(ffufFile, []byte(strings.Join(ffufLines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := &wildcard_flow.Ctx{}
	c.F.KatanaOut = katanaFile
	c.F.FfufDiscoveredURLs = ffufFile

	got := wildcard_flow.GatherJSURLs(c)

	want := map[string]bool{
		"http://example.com/static/app.js":     false,
		"http://example.com/assets/main.js":    false,
		"http://example.com/discovered/bundle.js": false,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d JS URLs, got %v", len(want), got)
	}
	for _, u := range got {
		if _, ok := want[u]; !ok {
			t.Errorf("unexpected JS URL: %q", u)
		}
		want[u] = true
	}
	for u, seen := range want {
		if !seen {
			t.Errorf("missing expected JS URL: %q", u)
		}
	}
}

// TestWriteJSOutputFiles_SyncsSubdomainsToDB verifies late-discovered JS
// subdomains are persisted into the subdomains table with source "js" and
// appended to the consolidated subdomain list.
func TestWriteJSOutputFiles_SyncsSubdomainsToDB(t *testing.T) {
	paths.ResetForTest()
	tempDir := t.TempDir()
	t.Setenv("CHAATHAN_HOME", tempDir)
	_ = paths.Init()

	dbPath := filepath.Join(tempDir, "test.db")
	if err := database.Initialize(dbPath); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()

	scanRecord, err := database.CreateScan("example.com", "wildcard", tempDir, "{}")
	if err != nil {
		t.Fatalf("failed to create scan: %v", err)
	}

	consolidated := filepath.Join(tempDir, "all_subdomains.txt")
	if err := os.WriteFile(consolidated, []byte("known.example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := &wildcard_flow.Ctx{ScanID: scanRecord.ID}
	c.F.JSEndpointsOut = filepath.Join(tempDir, "js_endpoints.txt")
	c.F.JSSecretsOut = filepath.Join(tempDir, "js_secrets.txt")
	c.F.JSSubdomainsOut = filepath.Join(tempDir, "js_subdomains.txt")
	c.F.ConsolidatedSubs = consolidated

	_, subs := wildcard_flow.WriteJSOutputFiles(c, nil, nil, []string{
		"js.example.com",
		"js.example.com", // duplicate -> deduped
	})

	if len(subs) != 1 || subs[0] != "js.example.com" {
		t.Fatalf("expected [js.example.com], got %v", subs)
	}

	dbSubs, err := database.GetSubdomains(scanRecord.ID)
	if err != nil {
		t.Fatalf("failed to query subdomains: %v", err)
	}
	found := false
	for _, s := range dbSubs {
		if s.Domain == "js.example.com" {
			found = true
			if s.Source != "js" {
				t.Errorf("expected source 'js', got %q", s.Source)
			}
		}
	}
	if !found {
		t.Error("expected js.example.com to be synced into the subdomains table")
	}

	data, err := os.ReadFile(consolidated)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "js.example.com") {
		t.Error("expected js.example.com appended to consolidated subdomains")
	}
}
