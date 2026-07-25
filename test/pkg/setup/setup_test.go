package setup_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/setup"
)

func TestSetupContextHelpers(t *testing.T) {
	ctx := &setup.SetupContext{
		Config: setup.RunConfig{
			Verbose:     true,
			ForceUpdate: false,
		},
	}

	if !ctx.IsVerbose() {
		t.Error("expected IsVerbose to be true")
	}

	if ctx.IsForceUpdate() {
		t.Error("expected IsForceUpdate to be false")
	}
}

func TestSetupLogger(t *testing.T) {
	t.Setenv("CHAATHAN_HOME", t.TempDir())
	paths.ResetForTest()
	defer paths.ResetForTest()

	logger, err := setup.NewSetupLogger()
	if err != nil {
		t.Fatalf("unexpected error creating NewSetupLogger: %v", err)
	}
	defer logger.Close()

	if logger.Path() == "" {
		t.Error("expected logger path to be non-empty")
	}

	base := filepath.Base(logger.Path())
	if !strings.HasPrefix(base, "setup_") || !strings.HasSuffix(base, ".log") {
		t.Errorf("expected setup log file name of format setup_*.log, got %q (path %q)", base, logger.Path())
	}

	logger.Write("Test setup log entry")
	
	logger.Close()

	content, err := os.ReadFile(logger.Path())
	if err != nil {
		t.Fatalf("failed to read setup log: %v", err)
	}

	if !strings.Contains(string(content), "Test setup log entry") {
		t.Error("expected log file to contain the write message")
	}
}

func TestResolveGOPATH(t *testing.T) {
	// When GOPATH is set, it must be honoured verbatim.
	t.Setenv("GOPATH", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}
	if got, gerr := setup.ResolveGOPATH(); gerr != nil || got != filepath.Join(home, "go") {
		t.Errorf("ResolveGOPATH() with empty GOPATH = (%q, %v), want %q", got, gerr, filepath.Join(home, "go"))
	}

	// Explicit GOPATH wins.
	custom := filepath.Join(t.TempDir(), "custom_gopath")
	t.Setenv("GOPATH", custom)
	got, err := setup.ResolveGOPATH()
	if err != nil {
		t.Fatalf("ResolveGOPATH() error: %v", err)
	}
	if got != custom {
		t.Errorf("ResolveGOPATH() = %q, want %q", got, custom)
	}
}
