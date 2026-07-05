package metadata

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDedupeByHost(t *testing.T) {
	urls := []string{
		"http://example.com/page1",
		"https://example.com/page2",
		"http://sub.example.com/page1",
		"https://sub.example.com/page2",
		"http://EXAMPLE.COM/page3", // case insensitive dedupe
	}
	expected := []string{
		"http://example.com/page1",
		"http://sub.example.com/page1",
	}

	got := DedupeByHost(urls)
	if len(got) != len(expected) {
		t.Fatalf("expected %d deduped hosts, got %d: %v", len(expected), len(got), got)
	}

	for i, v := range expected {
		if got[i] != v {
			t.Errorf("at index %d: expected %q, got %q", i, v, got[i])
		}
	}
}

func TestDedupeByURL(t *testing.T) {
	urls := []string{
		"http://example.com/page1",
		"http://example.com/page1", // exact duplicate
		"http://example.com/page2",
		" http://example.com/page2 ", // space trimming dedupe
	}
	expected := []string{
		"http://example.com/page1",
		"http://example.com/page2",
	}

	got := DedupeByURL(urls)
	if len(got) != len(expected) {
		t.Fatalf("expected %d deduped URLs, got %d: %v", len(expected), len(got), got)
	}

	for i, v := range expected {
		if got[i] != v {
			t.Errorf("at index %d: expected %q, got %q", i, v, got[i])
		}
	}
}

func TestAnalyzeCookies(t *testing.T) {
	tests := []struct {
		name               string
		cookies            []string
		wantHasInsecure    bool
		wantHasSession     bool
	}{
		{
			"Secure + HttpOnly session cookie",
			[]string{"session_id=123; Secure; HttpOnly"},
			false,
			true,
		},
		{
			"Insecure session cookie (missing HttpOnly)",
			[]string{"session_id=123; Secure"},
			true,
			true,
		},
		{
			"Insecure session cookie (missing Secure)",
			[]string{"session_id=123; HttpOnly"},
			true,
			true,
		},
		{
			"Non-session secure cookie",
			[]string{"theme=dark; Secure; HttpOnly"},
			false,
			false,
		},
		{
			"Multiple cookies, one insecure",
			[]string{
				"session_id=123; Secure; HttpOnly",
				"theme=dark; HttpOnly", // missing Secure
			},
			true,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotInsecure, gotSession := AnalyzeCookies(tt.cookies)
			if gotInsecure != tt.wantHasInsecure {
				t.Errorf("AnalyzeCookies() gotInsecure = %v, want %v", gotInsecure, tt.wantHasInsecure)
			}
			if gotSession != tt.wantHasSession {
				t.Errorf("AnalyzeCookies() gotSession = %v, want %v", gotSession, tt.wantHasSession)
			}
		})
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

	signal, ok := fetchSignal(client, server.URL)
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
