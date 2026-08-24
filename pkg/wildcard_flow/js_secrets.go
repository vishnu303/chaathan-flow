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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type secretPattern struct {
	Name  string
	Regex *regexp.Regexp
}

var jsSecretPatterns = []secretPattern{
	{"aws-keys", regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`)},
	{"google-api", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"stripe", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"github", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`)},
	{"slack-webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`)},
	{"jwt", regexp.MustCompile(`eyJhbGciOi[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
	{"private-key", regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`)},
	{"db-connection", regexp.MustCompile(`(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s"'<>]+`)},
	{"firebase", regexp.MustCompile(`[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)`)},
	{"generic-secret", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password)\s*[=:]\s*["']([A-Za-z0-9+/=_\-]{16,})["']`)},
}

// ─────────────────────────────────────────────────────────────
// Secret findings
// ─────────────────────────────────────────────────────────────

type secretFinding struct {
	URL     string
	Pattern string
	Status  string // confirmed, invalid, unverified
	Context string
}

func scanSecrets(body []byte, sourceURL string) []secretFinding {
	var findings []secretFinding
	content := string(body)

	for _, sp := range jsSecretPatterns {
		matches := sp.Regex.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			val := m[0]
			if len(m) >= 2 && m[1] != "" {
				val = m[1]
			}

			if !isLikelySecret(sp.Name, val) {
				continue
			}

			ctx := extractSecretContext(content, sp.Regex, m[0])

			// Filter false positives based on context (e.g., Datadog RUM tokens).
			if isFalsePositiveContext(ctx) {
				continue
			}

			findings = append(findings, secretFinding{
				URL:     sourceURL,
				Pattern: sp.Name,
				Status:  "unverified",
				Context: ctx,
			})
		}
	}
	return findings
}

// falsePositiveContextPatterns matches context snippets that indicate a
// matched "secret" is actually a public-by-design value.
var falsePositiveContextPatterns = []*regexp.Regexp{
	// Datadog RUM/SDK client tokens (public, embedded in frontend code)
	regexp.MustCompile(`(?i)clientToken\s*[=:]`),
	regexp.MustCompile(`(?i)datadoghq\.com`),
	regexp.MustCompile(`(?i)datadogRum`),
	// React PropTypes internal constant
	regexp.MustCompile(`ReactPropTypesSecret`),
}

// isFalsePositiveContext returns true if the surrounding context indicates
// the matched secret is a known false positive.
func isFalsePositiveContext(ctx string) bool {
	for _, re := range falsePositiveContextPatterns {
		if re.MatchString(ctx) {
			return true
		}
	}
	return false
}

// scanSourceMapContent parses a source map JSON and scans sourcesContent for secrets.
func scanSourceMapContent(mapBody []byte, jsURL string) []secretFinding {
	var sm struct {
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
	}
	if err := json.Unmarshal(mapBody, &sm); err != nil {
		return nil
	}

	var findings []secretFinding
	for i, content := range sm.SourcesContent {
		if content == "" {
			continue
		}
		source := jsURL + ".map"
		if i < len(sm.Sources) {
			source = sm.Sources[i]
		}
		for _, sp := range jsSecretPatterns {
			matches := sp.Regex.FindAllStringSubmatch(content, -1)
			for _, m := range matches {
				val := m[0]
				if len(m) >= 2 && m[1] != "" {
					val = m[1]
				}
				if !isLikelySecret(sp.Name, val) {
					continue
				}
				ctx := extractSecretContext(content, sp.Regex, m[0])
				// Same false-positive gate as scanSecrets — public-by-design
				// values (Datadog RUM tokens etc.) must not surface from
				// source maps either.
				if isFalsePositiveContext(ctx) {
					continue
				}
				findings = append(findings, secretFinding{
					URL:     source,
					Pattern: sp.Name,
					Status:  "unverified",
					Context: "[sourcemap] " + ctx,
				})
			}
		}
	}
	return findings
}

// extractEndpointsFromSourceMap pulls URL-like paths from source map sources array.

func validateSecrets(ctx context.Context, client *http.Client, findings []secretFinding) {
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for i := range findings {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			sf := &findings[idx]
			switch sf.Pattern {
			case "aws-keys":
				sf.Status = validateAWSKey(ctx, client, sf.Context)
			case "github":
				sf.Status = validateGitHubToken(ctx, client, sf.Context)
			case "google-api":
				sf.Status = validateGoogleAPIKey(ctx, client, sf.Context)
			case "stripe":
				sf.Status = validateStripeKey(ctx, client, sf.Context)
			case "firebase":
				sf.Status = validateFirebase(ctx, client, sf.Context)
			case "slack-webhook":
				sf.Status = validateSlackWebhook(ctx, client, sf.Context)
			case "jwt":
				sf.Status = validateJWT(sf.Context)
			default:
				// No validation available — leave as unverified
			}
		}(i)
	}
	wg.Wait()
}

func extractTokenFromContext(pattern, ctx string) string {
	for _, sp := range jsSecretPatterns {
		if sp.Name == pattern {
			m := sp.Regex.FindStringSubmatch(ctx)
			if len(m) >= 1 {
				if len(m) >= 2 && m[1] != "" {
					return m[1]
				}
				return m[0]
			}
		}
	}
	return ""
}

// validateAWSKey verifies an AWS access key ID by signing a proper SigV4
// GetCallerIdentity request with the secret key found alongside it. An
// unsigned request to STS reveals nothing about key validity, so without a
// secret key the finding stays unverified — a bare 403 never confirms.
func validateAWSKey(ctx context.Context, client *http.Client, context string) string {
	key := extractTokenFromContext("aws-keys", context)
	if key == "" || !strings.HasPrefix(key, "AKIA") {
		return "unverified"
	}
	secret := extractAWSSecretFromContext(context)
	if secret == "" {
		// Cannot sign without the secret key; STS responses to unsigned
		// requests are uninformative, so leave the finding unverified.
		return "unverified"
	}
	req, err := newAWSSignedGetCallerIdentity(ctx, key, secret)
	if err != nil {
		return "unverified"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return "confirmed"
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	switch awsErrorCode(string(body)) {
	case "InvalidClientTokenId", "UnrecognizedClientException":
		return "invalid"
	case "AccessDenied", "UnauthorizedAccess":
		// Signed request was accepted (credentials parsed) but the identity
		// lacks sts:GetCallerIdentity — the key pair is real.
		return "confirmed"
	default:
		// IncompleteSignature, throttling, network-layer rejections, etc.
		return "unverified"
	}
}

// awsSecretContextRe matches a secret access key assigned near the access
// key ID (e.g. secretAccessKey: "…", AWS_SECRET_ACCESS_KEY=…).
var awsSecretContextRe = regexp.MustCompile(`(?i)(?:secret[_-]?access[_-]?key|aws[_-]?secret(?:[_-]?access)?[_-]?key|secret[_-]?key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?`)

// extractAWSSecretFromContext returns a plausible AWS secret access key from
// the finding context, or "" when none is present.
func extractAWSSecretFromContext(context string) string {
	m := awsSecretContextRe.FindStringSubmatch(context)
	if m == nil {
		return ""
	}
	return m[1]
}

// newAWSSignedGetCallerIdentity builds a SigV4-signed STS GetCallerIdentity
// POST using stdlib crypto only (no AWS SDK dependency).
func newAWSSignedGetCallerIdentity(ctx context.Context, accessKey, secretKey string) (*http.Request, error) {
	const (
		awsHost    = "sts.amazonaws.com"
		awsRegion  = "us-east-1"
		awsService = "sts"
	)
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	contentType := "application/x-www-form-urlencoded; charset=utf-8"
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	canonicalHeaders := "content-type:" + contentType + "\nhost:" + awsHost + "\nx-amz-date:" + amzDate + "\n"
	signedHeaders := "content-type;host;x-amz-date"
	canonicalRequest := strings.Join([]string{"POST", "/", "", canonicalHeaders, signedHeaders, awsSHA256Hex(body)}, "\n")
	scope := dateStamp + "/" + awsRegion + "/" + awsService + "/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, awsSHA256Hex(canonicalRequest)}, "\n")

	kDate := awsHMACSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := awsHMACSHA256(kDate, awsRegion)
	kService := awsHMACSHA256(kRegion, awsService)
	kSigning := awsHMACSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(awsHMACSHA256(kSigning, stringToSign))

	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+awsHost+"/", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, scope, signedHeaders, signature))
	return req, nil
}

func awsSHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func awsHMACSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

var awsErrorCodeRe = regexp.MustCompile(`<Code>([A-Za-z]+)</Code>`)

// awsErrorCode extracts the <Code> element from an STS XML error body.
func awsErrorCode(body string) string {
	m := awsErrorCodeRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

func validateGitHubToken(ctx context.Context, client *http.Client, context string) string {
	token := extractTokenFromContext("github", context)
	if token == "" {
		return "unverified"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return "unverified"
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "chaathan")
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return "confirmed"
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return "invalid"
	}
	return "unverified"
}

func validateGoogleAPIKey(ctx context.Context, client *http.Client, context string) string {
	key := extractTokenFromContext("google-api", context)
	if key == "" {
		return "unverified"
	}
	// tokeninfo only understands OAuth access tokens, so AIza API keys can
	// never be confirmed there. Use the read-only Timezone API instead: OK
	// proves the key works, an explicit "invalid key" denial proves it does
	// not, and everything else (restricted keys, quota, errors) stays
	// unverified.
	checkURL := "https://maps.googleapis.com/maps/api/timezone?location=0,0&timestamp=0&key=" + key
	req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
	if err != nil {
		return "unverified"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "unverified"
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	var res struct {
		Status       string `json:"status"`
		ErrorMessage string `json:"error_message"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "unverified"
	}
	switch res.Status {
	case "OK":
		return "confirmed"
	case "REQUEST_DENIED":
		if strings.Contains(strings.ToLower(res.ErrorMessage), "invalid") {
			return "invalid"
		}
	}
	return "unverified"
}

func validateStripeKey(ctx context.Context, client *http.Client, context string) string {
	key := extractTokenFromContext("stripe", context)
	if key == "" {
		return "unverified"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.stripe.com/v1/account", nil)
	if err != nil {
		return "unverified"
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return "confirmed"
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return "invalid"
	}
	return "unverified"
}

func validateFirebase(ctx context.Context, client *http.Client, context string) string {
	// Extract firebase project URL (legacy *.firebaseio.com and current
	// *.firebasedatabase.app default RTDB domains).
	re := regexp.MustCompile(`([a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app))`)
	m := re.FindString(context)
	if m == "" {
		return "unverified"
	}
	checkURL := "https://" + m + "/.json"
	req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
	if err != nil {
		return "unverified"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	resp.Body.Close()
	// 200 = world-readable (critical), 401/403 = secured
	if resp.StatusCode == http.StatusOK {
		return "confirmed"
	}
	return "unverified"
}

func validateSlackWebhook(ctx context.Context, client *http.Client, context string) string {
	re := regexp.MustCompile(`https://hooks\.slack\.com/services/[^\s"'<>]+`)
	webhookURL := re.FindString(context)
	if webhookURL == "" {
		return "unverified"
	}
	// Empty JSON body: Slack rejects it with 400 ("no_text") without posting
	// anything. 400 proves the webhook is alive, 404 proves it is dead. A 200
	// would imply a message was posted, which must never happen here, so it
	// is deliberately not treated as confirmation.
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, strings.NewReader("{}"))
	if err != nil {
		return "unverified"
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "unverified"
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusBadRequest:
		return "confirmed"
	case http.StatusNotFound:
		return "invalid"
	}
	return "unverified"
}

func validateJWT(context string) string {
	re := regexp.MustCompile(`eyJhbGciOi[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	token := re.FindString(context)
	if token == "" {
		return "unverified"
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "unverified"
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "unverified"
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "unverified"
	}

	// A structurally valid, unexpired token is still only a static
	// observation — there is no safe live check for it. JWTs therefore never
	// reach "confirmed" so they do not fire confirmed-secret notifications or
	// inflate the "verified active" count.
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return "invalid" // expired
		}
	}
	return "unverified"
}

// ─────────────────────────────────────────────────────────────
// Subdomain extraction
// ─────────────────────────────────────────────────────────────

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range counts {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isLikelySecret checks if a matched value is likely a real secret.
func isLikelySecret(patternName, val string) bool {
	valLower := strings.ToLower(val)
	placeholders := []string{"placeholder", "undefined", "null", "false", "true", "your_token", "your_secret", "api_key_here", "example", "test", "dummy", "changeme", "xxxxx"}
	for _, ph := range placeholders {
		if valLower == ph || strings.Contains(valLower, ph) {
			return false
		}
	}

	// Filter known false-positive patterns.
	if isKnownFalsePositive(val) {
		return false
	}

	// Entropy check for generic patterns
	if patternName == "generic-secret" || patternName == "api-keys" {
		if len(val) < 8 {
			return false
		}
		if shannonEntropy(val) < 3.0 {
			return false
		}
	}

	// Filter repeating sequences
	if len(val) >= 10 {
		allSame := true
		for i := 1; i < len(val); i++ {
			if val[i] != val[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return false
		}
	}
	return true
}

// knownFalsePositivePatterns matches values that are commonly flagged as secrets
// but are public by design or well-known non-secrets.
var knownFalsePositivePatterns = []*regexp.Regexp{
	// Datadog RUM client tokens (public by design, prefixed with "pub")
	regexp.MustCompile(`^pub[0-9a-f]{32}$`),
	// React PropTypes secret (well-known non-secret constant)
	regexp.MustCompile(`(?i)SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED`),
	// Datadog application IDs (UUIDs, not secrets)
	regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
}

// isKnownFalsePositive returns true if the value matches a known false-positive pattern.
func isKnownFalsePositive(val string) bool {
	for _, re := range knownFalsePositivePatterns {
		if re.MatchString(val) {
			return true
		}
	}
	return false
}

// extractSecretContext returns surrounding context for a secret match.
func extractSecretContext(content string, re *regexp.Regexp, match string) string {
	idx := strings.Index(content, match)
	if idx < 0 {
		return match
	}
	ctxSize := 100
	start := idx - ctxSize
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + ctxSize
	if end > len(content) {
		end = len(content)
	}

	snippet := strings.TrimSpace(content[start:end])
	// Collapse whitespace for readability
	snippet = strings.Join(strings.Fields(snippet), " ")

	prefix := ""
	if start > 0 {
		prefix = "..."
	}
	suffix := ""
	if end < len(content) {
		suffix = "..."
	}
	return prefix + snippet + suffix
}
