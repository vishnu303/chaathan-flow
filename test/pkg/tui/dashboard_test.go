package tui_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/scan"
	"github.com/vishnu303/chaathan/pkg/tui"
)

func TestTruncateTextMultibyte(t *testing.T) {
	tests := []struct {
		input    string
		limit    int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello", 4, "h..."},
		{"hello", 2, "he"},
		{"你好世界hello", 6, "你好世..."},
		{"🌟🔥🚀🛸", 3, "🌟🔥🚀"},
		{"🌟🔥🚀🛸", 2, "🌟🔥"},
	}

	for _, tt := range tests {
		got := tui.TruncateText(tt.input, tt.limit)
		if got != tt.expected {
			t.Errorf("TruncateText(%q, %d) = %q, want %q", tt.input, tt.limit, got, tt.expected)
		}
	}
}

func TestPickStepsByType(t *testing.T) {
	tests := []struct {
		scanType string
		expected int
	}{
		{"wildcard", len(scan.WildcardSteps)},
		{"company", len(scan.CompanySteps)},
		{"other", len(scan.WildcardSteps)},
	}

	for _, tt := range tests {
		steps := tui.PickStepsForType(tt.scanType)
		if len(steps) != tt.expected {
			t.Errorf("PickStepsForType(%q) returned %d steps, want %d", tt.scanType, len(steps), tt.expected)
		}
	}
}

func TestGetTopTechnologiesAggregation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "chaathan_dashboard_test_*")
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

	mockURLs := []struct {
		url  string
		tech string
	}{
		{"http://example.com/1", `["Go","React","Nginx"]`},
		{"http://example.com/2", `["Go","Nginx"]`},
		{"http://example.com/3", `Go, Nginx`},
		{"http://example.com/4", `Nginx`},
		{"http://example.com/5", ""},
	}

	for _, mu := range mockURLs {
		err := database.AddURL(scanID, mu.url, 200, "text/html", "Title", mu.tech, "test")
		if err != nil {
			t.Fatalf("failed to insert URL: %v", err)
		}
	}

	topTechs := tui.GetTopTechnologies(scanID)
	
	if len(topTechs) != 3 {
		t.Fatalf("expected 3 top technologies, got %d: %v", len(topTechs), topTechs)
	}

	expectedOrder := []string{
		"Nginx (4)",
		"Go (3)",
		"React (1)",
	}

	for i, expected := range expectedOrder {
		if topTechs[i] != expected {
			t.Errorf("at index %d: expected %q, got %q", i, expected, topTechs[i])
		}
	}
}
