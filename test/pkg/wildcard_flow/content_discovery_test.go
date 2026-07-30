package wildcard_flow_test

import (
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
	if js.JsluiceTimeout != 30 {
		t.Errorf("expected default JsluiceTimeout 30, got %d", js.JsluiceTimeout)
	}
	if js.SkipValidation != false {
		t.Error("expected default SkipValidation false")
	}
}
