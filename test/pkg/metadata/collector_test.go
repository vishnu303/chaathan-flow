package metadata_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vishnu303/chaathan/pkg/metadata"
)

func TestAnalyzeCookies_NoCookies(t *testing.T) {
	insecure, session := metadata.AnalyzeCookies(nil)
	if insecure || session {
		t.Fatal("empty cookies should return false/false")
	}
}

func TestAnalyzeCookies_SecureHTTPOnly(t *testing.T) {
	cookies := []string{
		"JSESSIONID=abc123; Path=/; Secure; HttpOnly",
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	if insecure {
		t.Fatal("cookie with Secure+HttpOnly should NOT be flagged insecure")
	}
	if !session {
		t.Fatal("JSESSIONID should be detected as a session cookie")
	}
}

func TestAnalyzeCookies_MissingSecure(t *testing.T) {
	cookies := []string{
		"session_id=xyz789; Path=/; HttpOnly",
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	if !insecure {
		t.Fatal("cookie missing Secure flag should be flagged insecure")
	}
	if !session {
		t.Fatal("session_id should be detected as a session cookie")
	}
}

func TestAnalyzeCookies_MissingHTTPOnly(t *testing.T) {
	cookies := []string{
		"auth_token=abc; Path=/; Secure",
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	if !insecure {
		t.Fatal("cookie missing HttpOnly flag should be flagged insecure")
	}
	if !session {
		t.Fatal("auth_token should be detected as a session cookie")
	}
}

func TestAnalyzeCookies_NonSessionCookie(t *testing.T) {
	cookies := []string{
		"theme=dark; Path=/",
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	if !insecure {
		t.Fatal("cookie with no security flags should be flagged insecure")
	}
	if session {
		t.Fatal("theme cookie should NOT be detected as a session cookie")
	}
}

func TestAnalyzeCookies_MultipleCookies(t *testing.T) {
	cookies := []string{
		"_ga=GA1.2.123; Path=/",                      // tracking, insecure
		"PHPSESSID=abc123; Path=/; Secure; HttpOnly", // session, secure
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	if !insecure {
		t.Fatal("at least one cookie lacks security flags — should be insecure")
	}
	if !session {
		t.Fatal("PHPSESSID should be detected as a session cookie")
	}
}

func TestAnalyzeCookies_CaseInsensitive(t *testing.T) {
	cookies := []string{
		"Connect.Sid=abc; Path=/; SECURE; HTTPONLY",
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	// Attributes are checked case-insensitively
	if insecure {
		t.Fatal("cookie with both flags (case-insensitive) should not be insecure")
	}
	if !session {
		t.Fatal("connect.sid should be detected as a session cookie")
	}
}

func TestDedupeByHost(t *testing.T) {
	urls := []string{
		"https://example.com/path1",
		"https://example.com/path2",
		"https://sub.example.com/path1",
		"https://EXAMPLE.COM/path3",
	}
	result := metadata.DedupeByHost(urls)
	if len(result) != 2 {
		t.Fatalf("expected 2 unique hosts, got %d: %v", len(result), result)
	}
}

func TestDedupeByURL(t *testing.T) {
	urls := []string{
		"https://example.com/path1",
		"https://example.com/path1",
		"https://example.com/path2",
		"",
		"  ",
	}
	result := metadata.DedupeByURL(urls)
	if len(result) != 2 {
		t.Fatalf("expected 2 unique URLs, got %d: %v", len(result), result)
	}
}

func TestFetchSignal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "GET, POST, OPTIONS, PUT")
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Set-Cookie", "session_id=abc; Secure; HttpOnly")

		body := `<html>
			<body>
				<h1>Welcome to Login page</h1>
				<form action="/login" method="POST">
					<input type="text" name="username">
					<input type="password" name="password">
					<input type="hidden" name="csrf" value="123">
					<input type="file" name="upload">
				</form>
			</body>
		</html>`
		w.Write([]byte(body))
	}))
	defer server.Close()

	client := server.Client()

	signal, ok := metadata.FetchSignal(client, server.URL)
	if !ok {
		t.Fatal("fetchSignal failed")
	}

	if !signal.HasCSP {
		t.Error("expected HasCSP to be true")
	}
	if !signal.CORSWildcard {
		t.Error("expected CORSWildcard to be true")
	}
	if !signal.LoginSurface {
		t.Error("expected LoginSurface to be true")
	}
	if signal.FormCount != 1 {
		t.Errorf("expected FormCount = 1, got %d", signal.FormCount)
	}
	if !signal.HasFileUpload {
		t.Error("expected HasFileUpload to be true")
	}
	if signal.HiddenInputCount != 1 {
		t.Errorf("expected HiddenInputCount = 1, got %d", signal.HiddenInputCount)
	}
	if signal.HasInsecureCookies {
		t.Error("expected HasInsecureCookies to be false")
	}
	if !signal.HasSessionCookie {
		t.Error("expected HasSessionCookie to be true")
	}
	if !signal.HasDangerousMethods {
		t.Error("expected HasDangerousMethods to be true due to PUT in Allow header")
	}
}

func BenchmarkFetchSignal(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Hello World</body></html>"))
	}))
	defer server.Close()

	client := server.Client()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = metadata.FetchSignal(client, server.URL)
	}
}
