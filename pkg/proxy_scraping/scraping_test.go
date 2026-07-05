package proxy_scraping

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchProxySources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/http") {
			w.Write([]byte("192.168.1.1:8080\nhttp://192.168.1.2:8080\n192.168.1.1:8080\nbad-line\n"))
			return
		}
		if strings.Contains(r.URL.Path, "/socks5") {
			w.Write([]byte("socks5://10.0.0.1:1080\n10.0.0.1:1080\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	origHttp := httpSources
	origSocks4 := socks4Sources
	origSocks5 := socks5Sources

	httpSources = []string{server.URL + "/http"}
	socks4Sources = nil
	socks5Sources = []string{server.URL + "/socks5"}

	defer func() {
		httpSources = origHttp
		socks4Sources = origSocks4
		socks5Sources = origSocks5
	}()

	tempDir, err := os.MkdirTemp("", "chaathan_scraping_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outPath := filepath.Join(tempDir, "raw_proxies.txt")

	ctx := context.Background()
	total, err := fetchProxySources(ctx, []string{"http", "socks5"}, outPath)
	if err != nil {
		t.Fatalf("fetchProxySources failed: %v", err)
	}

	if total != 3 {
		t.Errorf("expected 3 unique proxies, got %d", total)
	}

	contentBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	content := string(contentBytes)
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines in output file, got %d:\n%s", len(lines), content)
	}
}
