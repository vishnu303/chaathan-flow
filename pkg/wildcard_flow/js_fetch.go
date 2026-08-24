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
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func fetchJSFile(c *Ctx, fetchCtx context.Context, client *http.Client, jsURL string, maxBytes int64) []byte {
	req, err := http.NewRequestWithContext(fetchCtx, "GET", jsURL, nil)
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

// sourceMappingURLRe matches the source map directive comment
// ("//# sourceMappingURL=..." or legacy "//@ sourceMappingURL=...").
var sourceMappingURLRe = regexp.MustCompile(`(?://#|//@)\s*sourceMappingURL=(\S+)`)

// sourceMapCandidates returns candidate source map URLs for a JS file:
// first the sourceMappingURL directive resolved against the JS URL, then
// the conventional jsURL+".map" fallback. Data URIs are skipped (inline
// maps carry no fetchable extra content).
func sourceMapCandidates(jsURL string, body []byte) []string {
	var candidates []string
	seen := make(map[string]bool)
	if len(body) > 0 {
		// The directive must appear at the end of the file — scan only the
		// tail instead of regexing multi-MB bodies.
		tail := body
		if len(tail) > 512 {
			tail = tail[len(tail)-512:]
		}
		if m := sourceMappingURLRe.FindSubmatch(tail); m != nil {
			ref := strings.TrimSpace(string(m[1]))
			if !strings.HasPrefix(ref, "data:") {
				if base, err := url.Parse(jsURL); err == nil {
					if resolved, err2 := base.Parse(ref); err2 == nil {
						seen[resolved.String()] = true
						candidates = append(candidates, resolved.String())
					}
				}
			}
		}
	}
	if fallback := jsURL + ".map"; !seen[fallback] {
		candidates = append(candidates, fallback)
	}
	return candidates
}

// fetchSourceMap attempts to fetch the source map for a given JS URL,
// preferring the sourceMappingURL directive from the JS body and falling
// back to the conventional .map suffix.
func fetchSourceMap(fetchCtx context.Context, client *http.Client, jsURL string, body []byte, maxBytes int64) []byte {
	for _, mapURL := range sourceMapCandidates(jsURL, body) {
		req, err := http.NewRequestWithContext(fetchCtx, "GET", mapURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		mapBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
		resp.Body.Close()
		if readErr != nil || len(mapBody) == 0 || resp.StatusCode != http.StatusOK {
			continue
		}

		// Validate it's actually JSON (source maps are JSON)
		trimmed := bytes.TrimSpace(mapBody)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			continue
		}
		return mapBody
	}
	return nil
}

// ─────────────────────────────────────────────────────────────
// jsluice integration
// ─────────────────────────────────────────────────────────────

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
