// Phase 3 — JavaScript Deep Analysis (unified Step 13)

// Replaces the old Step 14 (GoLinkFinder) and Step 18 (gf Secret Scan) with a
// single pass that fetches each JS file once and runs multiple analyzers:
//
//	14.1  Collect & rank JS URLs from crawler outputs
//	14.2  Unified concurrent fetch (in-memory, proxy-aware)
//	14.3  Analyzers: jsluice URLs/objects, secret patterns, source maps, subdomains
//	14.4  Secret validation (live checks against provider APIs)
//	14.5  Output routing to DB, files, and ROI
package wildcard_flow

import (
	"bytes"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
)

func fetchJSFile(c *Ctx, client *http.Client, jsURL string, maxBytes int64) []byte {
	req, err := http.NewRequestWithContext(c.GoCtx, "GET", jsURL, nil)
	if err != nil {
		return nil
	}

	ua := localUserAgents[rand.N(len(localUserAgents))]
	if c.Tb.General != nil && c.Tb.General.UserAgent != "" {
		ua = c.Tb.General.UserAgent
	}
	req.Header.Set("User-Agent", ua)

	if c.Tb.CustomCookie != "" {
		req.Header.Set("Cookie", c.Tb.CustomCookie)
	}
	for _, h := range c.Tb.CustomHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil || len(body) == 0 {
		return nil
	}
	return body
}

// fetchSourceMap attempts to fetch the .map file for a given JS URL.
func fetchSourceMap(c *Ctx, client *http.Client, jsURL string, maxBytes int64) []byte {
	mapURL := jsURL + ".map"
	req, err := http.NewRequestWithContext(c.GoCtx, "GET", mapURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil || len(body) == 0 {
		return nil
	}

	// Validate it's actually JSON (source maps are JSON)
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	return body
}

// ─────────────────────────────────────────────────────────────
// jsluice integration
// ─────────────────────────────────────────────────────────────

// runJsluiceOnContent writes JS content to a temp file, runs jsluice urls,
// and returns extracted endpoints. Falls back to regex extraction on failure.
// The step-level timeout (2h) governs overall execution; no per-file timeout.

// localUserAgents contains common browser User-Agent strings.
var localUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
}

// shannonEntropy calculates the Shannon entropy of a string.
