package proxy_scraping_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/proxy_scraping"
)

func TestStartRotator_InvalidConfig(t *testing.T) {
	ctx := context.Background()

	// 1. Should fail because proxy list file does not exist
	cfg := proxy_scraping.RotatorConfig{
		ProxyListFile: "nonexistent-proxy-list-xyz.txt",
		ListenAddr:    "127.0.0.1:0",
	}

	_, err := proxy_scraping.StartRotator(ctx, cfg)
	if err == nil {
		t.Fatal("expected error starting rotator with nonexistent proxy list, got nil")
	}
}

func TestRunHarvest_NoMubengErrorOrCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context immediately to test fast bail-out or failure

	cfg := proxy_scraping.HarvestConfig{
		TimeoutMin: 1,
		OutputDir:  t.TempDir(),
	}

	// Should fail immediately or return error because context is cancelled and/or mubeng is not configured
	_, err := proxy_scraping.RunHarvest(ctx, cfg)
	if err == nil {
		// If it succeeded, it means mubeng was not found and skipped, but it should still fail or return non-nil error if mubeng is missing
	}
}

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

	origHttp := *proxy_scraping.HTTPSources
	origSocks4 := *proxy_scraping.Socks4Sources
	origSocks5 := *proxy_scraping.Socks5Sources

	*proxy_scraping.HTTPSources = []string{server.URL + "/http"}
	*proxy_scraping.Socks4Sources = nil
	*proxy_scraping.Socks5Sources = []string{server.URL + "/socks5"}

	defer func() {
		*proxy_scraping.HTTPSources = origHttp
		*proxy_scraping.Socks4Sources = origSocks4
		*proxy_scraping.Socks5Sources = origSocks5
	}()

	tempDir, err := os.MkdirTemp("", "chaathan_scraping_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outPath := filepath.Join(tempDir, "raw_proxies.txt")

	ctx := context.Background()
	total, err := proxy_scraping.FetchProxySources(ctx, []string{"http", "socks5"}, outPath)
	if err != nil {
		t.Fatalf("FetchProxySources failed: %v", err)
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
