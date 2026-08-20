package wildcard_flow_test

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

// TestCollectX8Targets_RankedCap verifies that when more than the cap
// (150) targets exist, the highest ROI-scored URLs survive the cap instead
// of whichever URLs happened to be read first.
func TestCollectX8Targets_RankedCap(t *testing.T) {
	tmpDir := t.TempDir()

	// 160 low-signal ffuf discoveries (no query params).
	var ffufLines []string
	for i := 0; i < 160; i++ {
		ffufLines = append(ffufLines, fmt.Sprintf("http://example.com/page%d", i))
	}
	// One high-signal target appended LAST — under the old first-150-wins
	// behavior it would be truncated away.
	highValue := "http://example.com/admin/panel?redirect=http://evil.com&id="
	ffufLines = append(ffufLines, highValue)

	ffufFile := filepath.Join(tmpDir, "ffuf_discovered_urls.txt")
	if err := os.WriteFile(ffufFile, []byte(strings.Join(ffufLines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := &wildcard_flow.Ctx{}
	c.RunConfig.Domain = "example.com"
	c.F.FfufDiscoveredURLs = ffufFile

	targets := wildcard_flow.CollectX8Targets(c)
	if len(targets) != 150 {
		t.Fatalf("expected cap of 150 targets, got %d", len(targets))
	}

	found := false
	for _, target := range targets {
		if target == highValue {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected high-ROI target to survive the cap via ranking")
	}
}

// TestCollectX8Targets_ScopeAndStaticFilters verifies crawler endpoints are
// scope-filtered and static-extension URLs are rejected before x8.
func TestCollectX8Targets_ScopeAndStaticFilters(t *testing.T) {
	tmpDir := t.TempDir()

	katanaFile := filepath.Join(tmpDir, "katana.txt")
	lines := []string{
		"http://example.com/search?q=1",        // high signal: keyword + query
		"http://example.com/image.png?id=1",    // static extension -> rejected
		"http://external.com/api/v1/data",      // out of scope -> rejected
		"http://example.com/plainpage",         // no signal -> rejected
		"http://evil-example.com/api/v1/steal", // suffix trap -> rejected
	}
	if err := os.WriteFile(katanaFile, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := &wildcard_flow.Ctx{}
	c.RunConfig.Domain = "example.com"
	c.F.KatanaOut = katanaFile

	targets := wildcard_flow.CollectX8Targets(c)
	if len(targets) != 1 {
		t.Fatalf("expected exactly 1 target, got %v", targets)
	}
	if targets[0] != "http://example.com/search?q=1" {
		t.Errorf("unexpected target: %q", targets[0])
	}
}

func TestIsHighSignalURL(t *testing.T) {
	extensions := []string{".php", ".aspx"}
	keywords := []string{"/api/", "/login"}

	tests := []struct {
		raw  string
		want bool
	}{
		{"http://example.com/img.png?id=1", false}, // static + query still rejected
		{"http://example.com/logo.png", false},
		{"http://example.com/index.php", true},
		{"http://example.com/api/users", true},
		{"http://example.com/page?id=1", true}, // query params = dynamic
		{"http://example.com/about", false},
	}
	for _, tc := range tests {
		parsed, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatalf("failed to parse %q: %v", tc.raw, err)
		}
		if got := wildcard_flow.IsHighSignalURL(parsed, extensions, keywords); got != tc.want {
			t.Errorf("IsHighSignalURL(%q) = %t, want %t", tc.raw, got, tc.want)
		}
	}
}
