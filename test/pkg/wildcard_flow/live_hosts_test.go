package wildcard_flow_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/scope"
	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
	"github.com/vishnu303/chaathan/utils"
)

func writeJSONL(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// TestCollectLiveHostTargetsFromHttpx pins the live-host target rules:
// out-of-scope redirect destinations are dropped, http+https duplicates of a
// host collapse to the https variant, and explicit non-default ports (naabu
// discoveries) remain separate targets.
func TestCollectLiveHostTargetsFromHttpx(t *testing.T) {
	tmpDir := t.TempDir()
	input := filepath.Join(tmpDir, "httpx.json")
	output := filepath.Join(tmpDir, "live_hosts.txt")

	writeJSONL(t, input, []string{
		`{"url":"http://app.example.com"}`,
		`{"url":"https://app.example.com"}`,
		`{"url":"https://redirect.example.com/login"}`,
		`{"url":"https://evil.com/phish"}`,
		`{"url":"http://app.example.com:8080"}`,
		// Suffix trap: evil-example.com is NOT a subdomain of example.com.
		`{"url":"https://sub.evil-example.com"}`,
	})

	c := &wildcard_flow.Ctx{}
	c.RunConfig.Domain = "example.com"

	count := wildcard_flow.CollectLiveHostTargetsFromHttpx(c, input, output)
	if count != 3 {
		t.Fatalf("expected 3 live host targets, got %d", count)
	}

	lines := readLines(t, output)
	want := []string{
		"https://app.example.com", // upgraded from first-seen http://
		"https://redirect.example.com/login",
		"http://app.example.com:8080",
	}
	if len(lines) != len(want) {
		t.Fatalf("expected %v, got %v", want, lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, lines[i], want[i])
		}
	}
}

// TestCollectLiveHostTargetsFromHttpx_ScopeFilter verifies that an explicit
// scope configuration (in/out patterns) wins over the domain-suffix default.
func TestCollectLiveHostTargetsFromHttpx_ScopeFilter(t *testing.T) {
	tmpDir := t.TempDir()
	input := filepath.Join(tmpDir, "httpx.json")
	output := filepath.Join(tmpDir, "live_hosts.txt")

	writeJSONL(t, input, []string{
		`{"url":"https://app.example.com"}`,
		`{"url":"https://redirect.example.com/login"}`,
	})

	scFilter, err := scope.New(&config.ScopeConfig{
		InScope:    []string{`^.*\.example\.com$`},
		OutOfScope: []string{`^redirect\.example\.com$`},
	})
	if err != nil {
		t.Fatalf("failed to create scope filter: %v", err)
	}

	c := &wildcard_flow.Ctx{ScopeFilter: scFilter}
	c.RunConfig.Domain = "example.com"

	count := wildcard_flow.CollectLiveHostTargetsFromHttpx(c, input, output)
	if count != 1 {
		t.Fatalf("expected 1 in-scope target, got %d", count)
	}
	lines := readLines(t, output)
	if lines[0] != "https://app.example.com" {
		t.Errorf("expected https://app.example.com, got %q", lines[0])
	}
}

func TestHostInScope(t *testing.T) {
	c := &wildcard_flow.Ctx{}
	c.RunConfig.Domain = "example.com"

	inScope := []string{"example.com", "app.example.com", "DEEP.SUB.EXAMPLE.COM"}
	for _, h := range inScope {
		if !c.HostInScope(h) {
			t.Errorf("expected %q to be in scope", h)
		}
	}
	outOfScope := []string{"evil-example.com", "example.com.evil.com", "other.com"}
	for _, h := range outOfScope {
		if c.HostInScope(h) {
			t.Errorf("expected %q to be out of scope", h)
		}
	}
}

// TestDedupeHostURLsFile covers the in-place dedupe used after SAN merges:
// https wins over http for the same host, explicit ports stay separate, and
// unparseable lines are dropped.
func TestDedupeHostURLsFile(t *testing.T) {
	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "live_hosts.txt")

	writeJSONL(t, file, []string{
		"http://site.example.com",
		"https://site.example.com",
		"http://site.example.com:8443",
		"not a url",
	})

	wildcard_flow.DedupeHostURLsFile(file)

	lines := readLines(t, file)
	want := []string{
		"https://site.example.com",
		"http://site.example.com:8443",
	}
	if len(lines) != len(want) {
		t.Fatalf("expected %v, got %v", want, lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, lines[i], want[i])
		}
	}
}

// TestMapFileLinesLowercaseDedupe verifies the normalization pass used by
// stepDNSConsolidation: lines are transformed (lowercased) and deduplicated.
func TestMapFileLinesLowercaseDedupe(t *testing.T) {
	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "subs.txt")

	writeJSONL(t, file, []string{
		"FOO.Example.COM",
		"foo.example.com",
		"BAR.example.com",
	})

	if err := utils.MapFileLines(file, strings.ToLower); err != nil {
		t.Fatalf("MapFileLines failed: %v", err)
	}

	lines := readLines(t, file)
	if len(lines) != 2 {
		t.Fatalf("expected 2 deduplicated lines, got %v", lines)
	}
	for _, line := range lines {
		if line != strings.ToLower(line) {
			t.Errorf("expected lowercased line, got %q", line)
		}
	}
}
