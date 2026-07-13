package wildcard_flow_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

func TestPathKeyAndROIScore(t *testing.T) {
	// 1. Test pathKey
	pathTests := []struct {
		url      string
		expected string
	}{
		{"http://example.com/api/v1/user?id=123&token=abc", "http://example.com/api/v1/user"},
		{"HTTPS://EXAMPLE.COM/PATH/", "https://example.com/path/"},
		{"malformed_url", "malformed_url"},
	}
	for _, tc := range pathTests {
		got := wildcard_flow.PathKey(tc.url)
		if got != tc.expected {
			t.Errorf("PathKey(%q) = %q; want %q", tc.url, got, tc.expected)
		}
	}

	// 2. Test urlROIScore
	score1 := wildcard_flow.URLROIScore("http://example.com/api/v1/user")
	score2 := wildcard_flow.URLROIScore("http://example.com/api/v1/user?id=123")
	score3 := wildcard_flow.URLROIScore("http://example.com/api/v1/user?id=123&redirect=http://other.com")

	if score2 <= score1 {
		t.Errorf("expected score with query param (%d) to be higher than without (%d)", score2, score1)
	}
	if score3 <= score2 {
		t.Errorf("expected score with interesting param name (%d) to be higher than standard param name (%d)", score3, score2)
	}
}

func TestConvertX8ToURLs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "x8_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	x8JSONPath := filepath.Join(tmpDir, "x8.json")
	outputPath := filepath.Join(tmpDir, "output.txt")

	// Create dummy x8 output
	results := []wildcard_flow.X8Result{
		{
			URL: "http://example.com/api",
			FoundParams: []wildcard_flow.X8FoundParameter{
				{Name: "debug"},
				{Name: "admin"},
			},
		},
		{
			URL: "http://example.com/search?q=1",
			FoundParams: []wildcard_flow.X8FoundParameter{
				{Name: "page"},
			},
		},
		{
			URL:         "http://example.com/empty",
			FoundParams: nil,
		},
	}
	data, _ := json.Marshal(results)
	_ = os.WriteFile(x8JSONPath, data, 0644)

	count := wildcard_flow.ConvertX8ToURLs(x8JSONPath, outputPath)
	if count != 2 {
		t.Errorf("expected 2 URLs converted, got %d", count)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in output, got %d", len(lines))
	}

	if !strings.Contains(lines[0], "http://example.com/api?debug=1&admin=1") && !strings.Contains(lines[0], "admin=1&debug=1") {
		t.Errorf("unexpected line 1: %q", lines[0])
	}
	if lines[1] != "http://example.com/search?q=1&page=1" {
		t.Errorf("unexpected line 2: %q", lines[1])
	}
}

func TestCollectScopedURLs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "collect_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	inputPath := filepath.Join(tmpDir, "urls.txt")
	outputPath := filepath.Join(tmpDir, "scoped_urls.txt")

	// Write dummy URLs
	urls := []string{
		"http://example.com/path?param=value",
		"http://example.com/path?redirect=http://evil.com",
		"http://example.com/static.png?q=1",
		"http://googleapis.com/path?q=1",
		"http://otherdomain.com/another?param=1",
	}
	_ = os.WriteFile(inputPath, []byte(strings.Join(urls, "\n")+"\n"), 0644)

	c := &wildcard_flow.Ctx{}
	c.RunConfig.Domain = "example.com"

	// Test Bounded (maxURLs = 2)
	count := wildcard_flow.CollectScopedURLs(c, inputPath, outputPath, 2)
	if count != 2 {
		t.Errorf("expected 2 scoped URLs, got %d", count)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 output URLs, got %v", lines)
	}

	if !strings.Contains(string(content), "redirect=http://evil.com") {
		t.Errorf("expected output to contain higher-scoring URL: %q", string(content))
	}
}

func TestSafeStateHelpers(t *testing.T) {
	c := &wildcard_flow.Ctx{}
	// Since State and StateMgr are nil, safe helpers should not panic
	c.MarkStepFailedSafe("test_step", nil)
	c.MarkStepCompleteSafe("test_step")
	c.MarkStepCompleteIfNoFailure("test_step")

	skipped, cancelled := c.ResumeOrSkip("test_step", "Testing Safe Helpers")
	if skipped || cancelled {
		t.Error("expected ResumeOrSkip to return false, false when state is nil")
	}
}

func BenchmarkPathKey(b *testing.B) {
	url := "http://example.com/api/v1/user?id=123&token=abc"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wildcard_flow.PathKey(url)
	}
}

func BenchmarkURLROIScore(b *testing.B) {
	url := "http://example.com/api/v1/user?id=123&redirect=http://other.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wildcard_flow.URLROIScore(url)
	}
}
