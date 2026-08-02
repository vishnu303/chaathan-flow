package wildcard_flow_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

func TestRankJSURLs(t *testing.T) {
	urls := []string{
		"https://example.com/random/page.js",
		"https://example.com/app.js",
		"https://example.com/_next/static/chunks/main.js",
		"https://example.com/assets/js/vendor.js",
	}

	ranked := wildcard_flow.RankJSURLs(urls)
	if len(ranked) != len(urls) {
		t.Fatalf("RankJSURLs returned %d urls, want %d", len(ranked), len(urls))
	}

	// app.js should be ranked first (Priority 1: +100)
	if ranked[0] != "https://example.com/app.js" {
		t.Errorf("expected app.js first, got %q", ranked[0])
	}

	// _next/static should be second (Priority 1: +100 via /_next/static/)
	if ranked[1] != "https://example.com/_next/static/chunks/main.js" {
		t.Errorf("expected _next/static second, got %q", ranked[1])
	}

	// assets/js should be third (Priority 2: +50)
	if ranked[2] != "https://example.com/assets/js/vendor.js" {
		t.Errorf("expected assets/js third, got %q", ranked[2])
	}

	// random/page.js should be last (Priority 4: +0)
	if ranked[3] != "https://example.com/random/page.js" {
		t.Errorf("expected random/page.js last, got %q", ranked[3])
	}
}

func TestExtractSubdomainsFromJS(t *testing.T) {
	content := `
		var api = "https://api.example.com/v1";
		var cdn = "https://cdn.example.com/assets";
		var staging = "https://staging.example.com";
		var external = "https://other.domain.com";
	`

	subs := wildcard_flow.ExtractSubdomainsFromJS(content, "example.com")

	found := make(map[string]bool)
	for _, s := range subs {
		found[s] = true
	}

	if !found["api.example.com"] {
		t.Error("expected api.example.com to be extracted")
	}
	if !found["cdn.example.com"] {
		t.Error("expected cdn.example.com to be extracted")
	}
	if !found["staging.example.com"] {
		t.Error("expected staging.example.com to be extracted")
	}
	if found["other.domain.com"] {
		t.Error("other.domain.com should not be extracted (different domain)")
	}
}

func TestConvertX8ToURLs_NoisyAndTruncatedJSON(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	validJSON := `[
		{"method": "GET", "url": "https://example.com/search", "found_params": [{"name": "q"}, {"name": "page"}]},
		{"method": "POST", "url": "https://example.com/api", "found_params": [{"name": "token"}]}
	]`

	t.Run("valid array parses", func(t *testing.T) {
		in := write("valid.json", validJSON)
		out := filepath.Join(dir, "valid_urls.txt")
		count := wildcard_flow.ConvertX8ToURLs(in, out)
		if count != 2 {
			t.Fatalf("expected 2 URLs, got %d", count)
		}
		data, _ := os.ReadFile(out)
		if !strings.Contains(string(data), "https://example.com/search?q=1&page=1") {
			t.Errorf("missing parameterized URL in output: %s", data)
		}
	})

	t.Run("concatenated JSONL with noise still parses", func(t *testing.T) {
		content := `{"method": "GET", "url": "https://example.com/a", "found_params": [{"name": "id"}]}
garbage line that is not json
{"method": "GET", "url": "https://example.com/b", "found_params": [{"name": "x"}]}`
		in := write("jsonl.json", content)
		out := filepath.Join(dir, "jsonl_urls.txt")
		count := wildcard_flow.ConvertX8ToURLs(in, out)
		if count != 2 {
			t.Fatalf("expected 2 URLs from JSONL, got %d", count)
		}
	})

	t.Run("truncated trailing line is skipped", func(t *testing.T) {
		content := `{"method": "GET", "url": "https://example.com/c", "found_params": [{"name": "z"}]}
{"method": "GET", "url": "https://example.com/d", "found_par`
		in := write("truncated.json", content)
		out := filepath.Join(dir, "truncated_urls.txt")
		count := wildcard_flow.ConvertX8ToURLs(in, out)
		if count != 1 {
			t.Fatalf("expected 1 URL from truncated file, got %d", count)
		}
	})

	t.Run("duplicate URLs are deduplicated", func(t *testing.T) {
		content := `{"method": "GET", "url": "https://example.com/dup", "found_params": [{"name": "a"}]}
{"method": "GET", "url": "https://example.com/dup", "found_params": [{"name": "b"}]}`
		in := write("dup.json", content)
		out := filepath.Join(dir, "dup_urls.txt")
		count := wildcard_flow.ConvertX8ToURLs(in, out)
		if count != 1 {
			t.Fatalf("expected 1 URL after dedup, got %d", count)
		}
	})

	t.Run("all-noise file yields zero", func(t *testing.T) {
		in := write("noise.json", "not json at all\nmore noise\n")
		out := filepath.Join(dir, "noise_urls.txt")
		count := wildcard_flow.ConvertX8ToURLs(in, out)
		if count != 0 {
			t.Fatalf("expected 0 URLs from noise file, got %d", count)
		}
	})
}

func TestJSAnalysisConfigDefaults(t *testing.T) {
	cfg := config.DefaultConfig()
	js := cfg.General.JSAnalysis

	if js.JSLimit != 5000 {
		t.Errorf("expected default JSLimit 5000, got %d", js.JSLimit)
	}
	if js.Threads != 15 {
		t.Errorf("expected default Threads 15, got %d", js.Threads)
	}
	if js.MaxFileMB != 15 {
		t.Errorf("expected default MaxFileMB 15, got %d", js.MaxFileMB)
	}
	if js.MapMaxMB != 20 {
		t.Errorf("expected default MapMaxMB 20, got %d", js.MapMaxMB)
	}
	if js.ValidateLimit != 50 {
		t.Errorf("expected default ValidateLimit 50, got %d", js.ValidateLimit)
	}
	if js.MaxTimeout != 120 {
		t.Errorf("expected default MaxTimeout 120, got %d", js.MaxTimeout)
	}
	if js.SkipValidation != false {
		t.Error("expected default SkipValidation false")
	}
}
