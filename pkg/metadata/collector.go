package metadata

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/tools"
	"github.com/vishnu303/chaathan/utils"
)

const (
	defaultConcurrency = 4
	// maxBodyBytes limits the response body reading to 64KB.
	// Note: Any form or input fields located past the first 64KB
	// of the HTML response will not be analyzed or counted.
	maxBodyBytes = 65536
)

// sessionCookiePrefixes are common cookie name patterns that indicate
// session or authentication cookies.
var sessionCookiePrefixes = []string{
	"session", "sess", "sid", "jsessionid", "phpsessid",
	"asp.net_sessionid", "connect.sid", "_session",
	"auth", "token", "jwt", "access_token",
}

// We reuse the central User-Agent pool defined in pkg/tools.

type httpSignal struct {
	URL                 string
	Host                string
	HeadersJSON         string
	HasCSP              bool
	HasCacheHeaders     bool
	LoginSurface        bool
	ResponseBytes       int
	FormCount           int
	HasFileUpload       bool
	HiddenInputCount    int
	CORSWildcard        bool
	HasInsecureCookies  bool
	HasSessionCookie    bool
	HasDangerousMethods bool
}

// CollectHostMetadata fetches lightweight metadata for live host URLs and
// stores one record per host for ROI scoring. The ctx is propagated to every
// HTTP request so the scan cancels promptly on SIGINT/SIGTERM.
func CollectHostMetadata(ctx context.Context, scanID int64, urls []string, proxy string) (int, error) {
	targets := DedupeByHost(urls)
	if len(targets) == 0 {
		return 0, nil
	}

	results := collectSignals(ctx, targets, proxy)
	count := 0
	for _, signal := range results {
		err := database.UpsertHostMetadata(scanID, database.HostMetadata{
			Host:                signal.Host,
			BaseURL:             signal.URL,
			HeadersJSON:         signal.HeadersJSON,
			HasCSP:              signal.HasCSP,
			HasCacheHeaders:     signal.HasCacheHeaders,
			LoginSurface:        signal.LoginSurface,
			ResponseBytes:       signal.ResponseBytes,
			CORSWildcard:        signal.CORSWildcard,
			HasInsecureCookies:  signal.HasInsecureCookies,
			HasSessionCookie:    signal.HasSessionCookie,
			HasDangerousMethods: signal.HasDangerousMethods,
		})
		if err == nil {
			count++
		}
	}

	return count, nil
}

// CollectURLMetadata fetches lightweight metadata for selected high-value URLs
// and stores per-path signals for ROI scoring. The ctx is propagated to every
// HTTP request so the scan cancels promptly on SIGINT/SIGTERM.
func CollectURLMetadata(ctx context.Context, scanID int64, urls []string, proxy string) (int, error) {
	targets := DedupeByURL(urls)
	if len(targets) == 0 {
		return 0, nil
	}

	results := collectSignals(ctx, targets, proxy)
	count := 0
	for _, signal := range results {
		err := database.UpsertURLMetadata(scanID, database.URLMetadata{
			URL:              signal.URL,
			Host:             signal.Host,
			HeadersJSON:      signal.HeadersJSON,
			HasCSP:           signal.HasCSP,
			HasCacheHeaders:  signal.HasCacheHeaders,
			LoginSurface:     signal.LoginSurface,
			ResponseBytes:    signal.ResponseBytes,
			FormCount:        signal.FormCount,
			HasFileUpload:    signal.HasFileUpload,
			HiddenInputCount: signal.HiddenInputCount,
		})
		if err == nil {
			count++
		}
	}

	return count, nil
}

func collectSignals(ctx context.Context, urls []string, proxy string) []httpSignal {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       utils.ModernBrowserTLSConfig(),
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 6 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   2,
	}
	if proxy != "" {
		if proxyURL, err := neturl.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	client := &http.Client{
		Timeout:   12 * time.Second,
		Transport: transport,
	}

	jobs := make(chan string)
	results := make(chan httpSignal, defaultConcurrency*4)
	var wg sync.WaitGroup

	for range defaultConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				if signal, ok := fetchSignal(ctx, client, target); ok {
					results <- signal
				}
			}
		}()
	}

	go func() {
		// Rate limit: max 5 requests/sec to avoid WAF bans on targets.
		// Each URL triggers a GET + an OPTIONS request, so effective rate
		// is ~10 HTTP requests/sec across all workers.
		limiter := time.NewTicker(200 * time.Millisecond)
		defer limiter.Stop()
		for _, target := range urls {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case <-limiter.C:
				select {
				case jobs <- target:
				case <-ctx.Done():
					close(jobs)
					return
				}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var collected []httpSignal
	for result := range results {
		collected = append(collected, result)
	}

	return collected
}

func fetchSignal(ctx context.Context, client *http.Client, rawURL string) (httpSignal, bool) {
	parsed, err := neturl.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" {
		return httpSignal{}, false
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return httpSignal{}, false
	}
	req.Header.Set("User-Agent", tools.RandomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return httpSignal{}, false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return httpSignal{}, false
	}

	lowerBody := strings.ToLower(string(body))
	formCount, hasFileUpload, hiddenInputCount := analyzeForms(lowerBody)

	// Cookie security analysis
	hasInsecureCookies, hasSessionCookie := AnalyzeCookies(resp.Header["Set-Cookie"])

	// OPTIONS method detection (follow-up request for dangerous methods)
	hasDangerousMethods := checkDangerousMethods(ctx, client, rawURL)

	return httpSignal{
		URL:                 rawURL,
		Host:                strings.ToLower(parsed.Hostname()),
		HeadersJSON:         marshalHeaders(resp.Header),
		HasCSP:              resp.Header.Get("Content-Security-Policy") != "",
		HasCacheHeaders:     hasCacheHeaders(resp.Header),
		LoginSurface:        detectLoginSurface(lowerBody),
		ResponseBytes:       len(body),
		FormCount:           formCount,
		HasFileUpload:       hasFileUpload,
		HiddenInputCount:    hiddenInputCount,
		CORSWildcard:        resp.Header.Get("Access-Control-Allow-Origin") == "*",
		HasInsecureCookies:  hasInsecureCookies,
		HasSessionCookie:    hasSessionCookie,
		HasDangerousMethods: hasDangerousMethods,
	}, true
}

// marshalHeaders serializes response headers to JSON, collapsing
// single-value headers to a plain string.
func marshalHeaders(header http.Header) string {
	headers := make(map[string]any, len(header))
	for key, values := range header {
		if len(values) == 1 {
			headers[key] = values[0]
		} else {
			headers[key] = values
		}
	}
	headersJSON, _ := json.Marshal(headers)
	return string(headersJSON)
}

// hasCacheHeaders reports whether any common caching header is present.
func hasCacheHeaders(header http.Header) bool {
	return header.Get("Cache-Control") != "" ||
		header.Get("ETag") != "" ||
		header.Get("Expires") != "" ||
		header.Get("Vary") != ""
}

// detectLoginSurface reports whether the (lowercased) body looks like a
// login page: a form or password input plus login-related text.
func detectLoginSurface(lowerBody string) bool {
	hasFormOrPasswordInput := strings.Contains(lowerBody, "<form") ||
		strings.Contains(lowerBody, `type="password"`) ||
		strings.Contains(lowerBody, `type='password'`) ||
		strings.Contains(lowerBody, `type=password`)

	return hasFormOrPasswordInput && (strings.Contains(lowerBody, "password") ||
		strings.Contains(lowerBody, "sign in") ||
		strings.Contains(lowerBody, "signin") ||
		strings.Contains(lowerBody, "log in") ||
		strings.Contains(lowerBody, "login") ||
		strings.Contains(lowerBody, "forgot password") ||
		strings.Contains(lowerBody, "oauth"))
}

// analyzeForms counts forms and hidden inputs and detects file upload
// fields in the (lowercased) body.
func analyzeForms(lowerBody string) (formCount int, hasFileUpload bool, hiddenInputCount int) {
	formCount = strings.Count(lowerBody, "<form")
	hasFileUpload = strings.Contains(lowerBody, `type="file"`) ||
		strings.Contains(lowerBody, `type='file'`) ||
		strings.Contains(lowerBody, "type=file")
	hiddenInputCount = strings.Count(lowerBody, `type="hidden"`) +
		strings.Count(lowerBody, `type='hidden'`)
	return formCount, hasFileUpload, hiddenInputCount
}

func DedupeByHost(urls []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range urls {
		parsed, err := neturl.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if !seen[host] {
			seen[host] = true
			out = append(out, raw)
		}
	}
	return out
}

func DedupeByURL(urls []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true
		out = append(out, raw)
	}
	return out
}

// AnalyzeCookies inspects Set-Cookie headers for missing security flags.
// Returns (hasInsecureCookies, hasSessionCookie).
func AnalyzeCookies(setCookies []string) (bool, bool) {
	if len(setCookies) == 0 {
		return false, false
	}

	var hasInsecure, hasSession bool

	for _, cookie := range setCookies {
		// Check if this looks like a session cookie by name
		nameEnd := strings.Index(cookie, "=")
		if nameEnd > 0 {
			name := strings.ToLower(strings.TrimSpace(cookie[:nameEnd]))
			for _, prefix := range sessionCookiePrefixes {
				if strings.Contains(name, prefix) {
					hasSession = true
					break
				}
			}
		}

		// Parse attributes after the first ';' to check security flags.
		// Only check the attribute portion, not the name=value part,
		// to avoid false positives from values containing "secure".
		parts := strings.Split(cookie, ";")
		hasSecureFlag := false
		hasHTTPOnlyFlag := false
		for _, part := range parts[1:] { // skip name=value
			attr := strings.ToLower(strings.TrimSpace(part))
			if attr == "secure" {
				hasSecureFlag = true
			}
			if attr == "httponly" {
				hasHTTPOnlyFlag = true
			}
		}
		if !hasSecureFlag || !hasHTTPOnlyFlag {
			hasInsecure = true
		}
	}

	return hasInsecure, hasSession
}

// checkDangerousMethods sends an OPTIONS request and checks if the server
// advertises PUT or DELETE in the Allow header.
func checkDangerousMethods(ctx context.Context, client *http.Client, rawURL string) bool {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", tools.RandomUA())

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Drain body to allow connection reuse
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	allow := resp.Header.Get("Allow")
	if allow == "" {
		return false
	}
	// Split on comma and check exact method names to avoid substring
	// false positives (e.g., "OUTPUT" matching "PUT").
	for _, method := range strings.Split(allow, ",") {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "PUT" || method == "DELETE" {
			return true
		}
	}
	return false
}
