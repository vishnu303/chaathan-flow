package orchestrate_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/orchestrate"
)

func TestNewInfra(t *testing.T) {
	// Test NewInfra with nil config
	infraNil := orchestrate.NewInfra("native", false, nil)
	if infraNil.Runner == nil {
		t.Error("expected non-nil runner")
	}
	if infraNil.ToolBox == nil {
		t.Error("expected non-nil ToolBox")
	}
	if infraNil.Notifier != nil {
		t.Error("expected nil notifier since config was nil")
	}

	// Test NewInfra with default config
	cfg := config.DefaultConfig()
	cfg.Notifications.Enabled = true
	infraVal := orchestrate.NewInfra("native", true, cfg)
	if infraVal.Runner == nil {
		t.Error("expected non-nil runner")
	}
	if infraVal.ToolBox == nil {
		t.Error("expected non-nil ToolBox")
	}
	if infraVal.Notifier == nil {
		t.Error("expected non-nil notifier since notification was enabled")
	}
}

func TestHandleSignals_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	orchestrate.HandleSignals(ctx, cancel)
	
	// Simply cancel the context and verify it doesn't hang
	cancel()
	
	select {
	case <-ctx.Done():
		// OK
	case <-time.After(1 * time.Second):
		t.Error("timed out waiting for context cancel")
	}
}

func TestHandleSignals_Signal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	orchestrate.HandleSignals(ctx, cancel)

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("failed to find own process: %v", err)
	}

	err = p.Signal(os.Interrupt)
	if err != nil {
		t.Fatalf("failed to send interrupt signal: %v", err)
	}

	select {
	case <-ctx.Done():
		// OK
	case <-time.After(2 * time.Second):
		t.Error("timed out waiting for SIGINT/Interrupt to cancel context")
	}
}
