package wildcard_flow_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

// rewriteTransport redirects every request to a local test server so secret
// validation status-code semantics can be exercised without touching the
// real provider endpoints.
type rewriteTransport struct {
	host string
}

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = r.host
	return http.DefaultTransport.RoundTrip(req)
}

// newRewriteClient returns an HTTP client whose requests all land on srv.
func newRewriteClient(srv *httptest.Server) *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: rewriteTransport{host: strings.TrimPrefix(srv.URL, "http://")},
	}
}

// makeJWT builds a structurally valid JWT with the given exp claim.
func makeJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"test","exp":%d}`, exp)))
	return header + "." + payload + ".c2lnbmF0dXJl"
}

// TestValidateJWT_NeverConfirmed pins the JWT policy: a structurally valid,
// unexpired token is only ever "unverified" (never "confirmed") so JWTs do
// not fire confirmed-secret notifications; expired tokens are "invalid".
func TestValidateJWT_NeverConfirmed(t *testing.T) {
	future := makeJWT(time.Now().Add(24 * time.Hour).Unix())
	if got := wildcard_flow.ValidateJWT("token: " + future); got != "unverified" {
		t.Errorf("valid unexpired JWT: got %q, want unverified", got)
	}

	past := makeJWT(time.Now().Add(-24 * time.Hour).Unix())
	if got := wildcard_flow.ValidateJWT("token: " + past); got != "invalid" {
		t.Errorf("expired JWT: got %q, want invalid", got)
	}

	if got := wildcard_flow.ValidateJWT("no token here"); got != "unverified" {
		t.Errorf("no JWT in context: got %q, want unverified", got)
	}

	// Corrupt payload (not base64 JSON) must not confirm either.
	corrupt := "eyJhbGciOiJIUzI1NiJ9.!!!not-base64!!!.c2ln"
	if got := wildcard_flow.ValidateJWT(corrupt); got != "unverified" {
		t.Errorf("corrupt JWT: got %q, want unverified", got)
	}
}

func TestAWSErrorCode(t *testing.T) {
	tests := []struct {
		body string
		want string
	}{
		{`<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>x</Message></Error></ErrorResponse>`, "InvalidClientTokenId"},
		{`<Error><Code>AccessDenied</Code></Error>`, "AccessDenied"},
		{`<Error><Code>UnrecognizedClientException</Code></Error>`, "UnrecognizedClientException"},
		{`<html>403 Forbidden</html>`, ""},
		{``, ""},
	}
	for _, tc := range tests {
		if got := wildcard_flow.AWSErrorCode(tc.body); got != tc.want {
			t.Errorf("AWSErrorCode(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func TestExtractAWSSecretFromContext(t *testing.T) {
	withSecret := `accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
	if got := wildcard_flow.ExtractAWSSecretFromContext(withSecret); got != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("expected secret extraction, got %q", got)
	}

	envStyle := `AWS_SECRET_ACCESS_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/ab`
	if got := wildcard_flow.ExtractAWSSecretFromContext(envStyle); got != "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/ab" {
		t.Errorf("expected env-style secret extraction, got %q", got)
	}

	if got := wildcard_flow.ExtractAWSSecretFromContext(`accessKeyId: "AKIAIOSFODNN7EXAMPLE"`); got != "" {
		t.Errorf("expected empty secret when none present, got %q", got)
	}
}

// TestValidateAWSKey_SignedSemantics verifies the SigV4-based validation
// decision table, including the core regression: a bare 403 never confirms.
func TestValidateAWSKey_SignedSemantics(t *testing.T) {
	var statusCode int
	var respBody string
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(statusCode)
		_, _ = io.WriteString(w, respBody)
	}))
	defer srv.Close()
	client := newRewriteClient(srv)
	ctx := context.Background()

	// AKIA key + secret key present -> a signed request is made.
	fullCtx := `accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`

	tests := []struct {
		name    string
		code    int
		body    string
		context string
		want    string
	}{
		{"200 confirms", http.StatusOK, `<GetCallerIdentityResponse/>`, fullCtx, "confirmed"},
		{"InvalidClientTokenId is invalid", http.StatusForbidden, `<Error><Code>InvalidClientTokenId</Code></Error>`, fullCtx, "invalid"},
		{"UnrecognizedClientException is invalid", http.StatusForbidden, `<Error><Code>UnrecognizedClientException</Code></Error>`, fullCtx, "invalid"},
		{"signed 403 AccessDenied confirms", http.StatusForbidden, `<Error><Code>AccessDenied</Code></Error>`, fullCtx, "confirmed"},
		{"bare 403 never confirms", http.StatusForbidden, `<html>Forbidden</html>`, fullCtx, "unverified"},
	}
	for _, tc := range tests {
		statusCode, respBody = tc.code, tc.body
		if got := wildcard_flow.ValidateAWSKey(ctx, client, tc.context); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}

	// Key without a secret: no request may be made (an unsigned STS call is
	// uninformative) — the finding stays unverified.
	requests = 0
	keyOnlyCtx := `accessKeyId: "AKIAIOSFODNN7EXAMPLE"`
	if got := wildcard_flow.ValidateAWSKey(ctx, client, keyOnlyCtx); got != "unverified" {
		t.Errorf("key-only context: got %q, want unverified", got)
	}
	if requests != 0 {
		t.Errorf("expected no network request without secret key, made %d", requests)
	}

	// No AKIA key at all.
	if got := wildcard_flow.ValidateAWSKey(ctx, client, "nothing to see"); got != "unverified" {
		t.Errorf("no-key context: got %q, want unverified", got)
	}
}

// TestValidateSlackWebhook_Semantics verifies the non-destructive probe:
// 400 = alive (Slack rejected the empty payload without posting), 404 = dead,
// and a 200 must never confirm since it would mean a message was posted.
func TestValidateSlackWebhook_Semantics(t *testing.T) {
	var statusCode int
	var lastMethod, lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		lastBody = string(b)
		w.WriteHeader(statusCode)
	}))
	defer srv.Close()
	client := newRewriteClient(srv)
	ctx := context.Background()

	// Deliberately not in the live Txxxxxxxx/Bxxxxxxxx/24-alnum shape —
	// secret scanners block pushes containing canonical-format webhook URLs.
	// The validator only needs the hooks.slack.com/services/ prefix.
	webhookCtx := `hook: https://hooks.slack.com/services/EXAMPLE-TEAM/EXAMPLE-CHANNEL/not-a-real-webhook-token`

	statusCode = http.StatusBadRequest
	if got := wildcard_flow.ValidateSlackWebhook(ctx, client, webhookCtx); got != "confirmed" {
		t.Errorf("400: got %q, want confirmed", got)
	}
	if lastMethod != http.MethodPost || lastBody != "{}" {
		t.Errorf("expected POST with empty-JSON probe body, got %s %q", lastMethod, lastBody)
	}

	statusCode = http.StatusNotFound
	if got := wildcard_flow.ValidateSlackWebhook(ctx, client, webhookCtx); got != "invalid" {
		t.Errorf("404: got %q, want invalid", got)
	}

	statusCode = http.StatusOK
	if got := wildcard_flow.ValidateSlackWebhook(ctx, client, webhookCtx); got != "unverified" {
		t.Errorf("200: got %q, want unverified (a post must never be treated as confirmation)", got)
	}

	if got := wildcard_flow.ValidateSlackWebhook(ctx, client, "no webhook here"); got != "unverified" {
		t.Errorf("no-webhook context: got %q, want unverified", got)
	}
}

// TestValidateGoogleAPIKey_Semantics verifies the Timezone-API based check
// replaced the broken tokeninfo call.
func TestValidateGoogleAPIKey_Semantics(t *testing.T) {
	var statusCode int
	var respBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = io.WriteString(w, respBody)
	}))
	defer srv.Close()
	client := newRewriteClient(srv)
	ctx := context.Background()

	googleCtx := `apiKey: "AIzaSyDUMMYKEY0123456789abcdefghijklmno"`

	tests := []struct {
		name string
		code int
		body string
		want string
	}{
		{"OK confirms", http.StatusOK, `{"status":"OK"}`, "confirmed"},
		{"explicit invalid denial", http.StatusOK, `{"status":"REQUEST_DENIED","error_message":"The provided API key is invalid."}`, "invalid"},
		{"restriction denial stays unverified", http.StatusOK, `{"status":"REQUEST_DENIED","error_message":"Referer not allowed"}`, "unverified"},
		{"403 stays unverified", http.StatusForbidden, `{}`, "unverified"},
	}
	for _, tc := range tests {
		statusCode, respBody = tc.code, tc.body
		if got := wildcard_flow.ValidateGoogleAPIKey(ctx, client, googleCtx); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}

	if got := wildcard_flow.ValidateGoogleAPIKey(ctx, client, "no key here"); got != "unverified" {
		t.Errorf("no-key context: got %q, want unverified", got)
	}
}
