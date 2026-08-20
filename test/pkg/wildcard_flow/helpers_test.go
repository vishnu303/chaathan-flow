package wildcard_flow_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/scan"
	"github.com/vishnu303/chaathan/pkg/scope"
	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

func TestPathKeyAndROIScore(t *testing.T) {
	// 1. Test pathKey
	pathTests := []struct {
		url      string
		expected string
	}{
		{"http://example.com/api/v1/user?id=123&token=abc", "http://example.com/api/v1/user"},
		// Path case is preserved (only scheme+host lowercased) so dynamic
		// routes with case-sensitive segments are not collapsed wrongly.
		{"HTTPS://EXAMPLE.COM/PATH/", "https://example.com/PATH/"},
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

	// Interesting params count even when their value is empty (?debug=).
	scoreEmptyVal := wildcard_flow.URLROIScore("http://example.com/api/v1/user?debug=")
	if scoreEmptyVal <= score1 {
		t.Errorf("expected score with empty-value interesting param (%d) to be higher than without (%d)", scoreEmptyVal, score1)
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

func TestScopeFilterAfterMerges(t *testing.T) {
	tempDir := t.TempDir()
	subsFile := filepath.Join(tempDir, "consolidated_subs.txt")

	content := "in.example.com\nout.example.com\n"
	if err := os.WriteFile(subsFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write subs file: %v", err)
	}

	scopeCfg := &config.ScopeConfig{
		InScope:    []string{`^.*\.example\.com$`},
		OutOfScope: []string{`^out\.example\.com$`},
	}
	scFilter, err := scope.New(scopeCfg)
	if err != nil {
		t.Fatalf("failed to create scope filter: %v", err)
	}

	c := &wildcard_flow.Ctx{
		ScopeFilter: scFilter,
	}

	c.FilterSubsToScope(subsFile)

	data, err := os.ReadFile(subsFile)
	if err != nil {
		t.Fatalf("failed to read filtered subs file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	if len(lines) != 1 {
		t.Fatalf("expected 1 line after scope filtering, got %d: %v", len(lines), lines)
	}
	if lines[0] != "in.example.com" {
		t.Errorf("expected 'in.example.com', got %q", lines[0])
	}
}

func TestPurgeUnconsolidatedSubdomains(t *testing.T) {
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

	_ = database.AddSubdomains(scanRecord.ID, []string{"in.example.com", "out.example.com"}, "subfinder")

	subs, _ := database.GetSubdomains(scanRecord.ID)
	if len(subs) != 2 {
		t.Fatalf("expected 2 subdomains initially, got %d", len(subs))
	}

	consolidatedFile := filepath.Join(tempDir, "consolidated.txt")
	_ = os.WriteFile(consolidatedFile, []byte("in.example.com\n"), 0644)

	deleted, err := ingest.SyncSubdomainsWithConsolidated(scanRecord.ID, consolidatedFile)
	if err != nil {
		t.Fatalf("failed to sync consolidated subdomains: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted out-of-scope subdomain, got %d", deleted)
	}

	subsAfter, _ := database.GetSubdomains(scanRecord.ID)
	if len(subsAfter) != 1 {
		t.Fatalf("expected 1 subdomain after purge, got %d", len(subsAfter))
	}
	if subsAfter[0].Domain != "in.example.com" {
		t.Errorf("expected 'in.example.com' to remain, got %q", subsAfter[0].Domain)
	}
}

// TestMarkStepFailedSafe_CancellationNotFailure verifies that a parent
// context cancellation (Ctrl-C) never records the step as failed — the step
// must stay incomplete so resume re-runs it instead of skipping it.
func TestMarkStepFailedSafe_CancellationNotFailure(t *testing.T) {
	paths.ResetForTest()
	tempDir := t.TempDir()
	t.Setenv("CHAATHAN_HOME", tempDir)
	_ = paths.Init()

	stateMgr := scan.NewManager(paths.StateDir())
	state, err := stateMgr.CreateState(456, "example.com", "wildcard", tempDir, len(scan.WildcardSteps), nil)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	// Cancelled context: failure marking must be suppressed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &wildcard_flow.Ctx{
		RunConfig: wildcard_flow.RunConfig{Domain: "example.com"},
		GoCtx:     ctx,
		StateMgr:  stateMgr,
		State:     state,
	}
	c.MarkStepFailedSafe("passive_enum", errors.New("context canceled"))
	if state.IsStepFailed("passive_enum") {
		t.Error("expected cancelled step NOT to be marked failed")
	}
	if state.IsStepCompleted("passive_enum") {
		t.Error("expected cancelled step to remain incomplete")
	}

	// Control: live context still records genuine failures.
	c2 := &wildcard_flow.Ctx{
		RunConfig: wildcard_flow.RunConfig{Domain: "example.com"},
		GoCtx:     context.Background(),
		StateMgr:  stateMgr,
		State:     state,
	}
	c2.MarkStepFailedSafe("active_enum", errors.New("tool crashed"))
	if !state.IsStepFailed("active_enum") {
		t.Error("expected genuine failure to be recorded when not cancelled")
	}
}
