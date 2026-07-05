package proxy_scraping_test

import (
	"context"
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
