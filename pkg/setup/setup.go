// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// RunConfig holds the configuration options passed from the CLI layer.
type RunConfig struct {
	Verbose     bool
	ForceUpdate bool // reinstall all tools even if already present
}

// SetupContext holds the configurations and resources for the current setup execution.
type SetupContext struct {
	Context context.Context
	Config  RunConfig
	Logger  *SetupLogger
}

// IsVerbose returns true when verbose logging is enabled.
func (c *SetupContext) IsVerbose() bool {
	return c.Config.Verbose
}

// IsForceUpdate returns true when tools should be reinstalled even if present.
func (c *SetupContext) IsForceUpdate() bool {
	return c.Config.ForceUpdate
}

// RunCommand executes a command with a default timeout, streaming/logging via SetupLogger.
func (c *SetupContext) RunCommand(displayName string, name string, args ...string) error {
	return c.RunCommandInDir("", displayName, name, args...)
}

// RunCommandInDir executes a command in a specified directory with a default timeout, streaming/logging via SetupLogger.
func (c *SetupContext) RunCommandInDir(dir string, displayName string, name string, args ...string) error {
	parentCtx := c.Context
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	setPGID(cmd) // Ensure process group is set so children are killed together

	if c.Logger != nil {
		return c.Logger.CaptureCommandOutput(cmd, displayName, c.IsVerbose())
	}
	return cmd.Run()
}

// Run executes the complete chaathan setup workflow. Returns an error if any installer fails.
func Run(ctx context.Context, cfg RunConfig) error {
	start := time.Now()

	title := "🔧 Chaathan Setup"
	if cfg.ForceUpdate {
		title = "🔄 Chaathan Setup (update mode — reinstalling all tools)"
	}
	progress.Header(title)

	logger, err := NewSetupLogger()
	if err == nil {
		defer logger.Close()
		progress.ItemInfo(fmt.Sprintf("📝 Log file: %s", logger.Path()))
	}

	setupCtx := &SetupContext{
		Context: ctx,
		Config:  cfg,
		Logger:  logger,
	}

	installPrerequisites(setupCtx)

	ensureSystemGoOnPath()
	if ok, _ := checkGoVersion(); !ok {
		progress.ItemFail("Go runtime validation failed", "Please install Go 1.26+ manually")
		return fmt.Errorf("Go runtime validation failed: Go version >= 1.26 is required")
	}

	var totalInstalled, totalSkipped, totalFailed int32

	sections := []struct {
		name string
		fn   func(*SetupContext) (int, int, int)
	}{
		{"go_tools", installGoToolsSection},
		{"gf_patterns", installGFPatternsSection},
		{"python_tools", installPythonToolsSection},
		{"x8", installX8Section},
		{"massdns", installMassDNSSection},
		{"seclists", installSecListsSection},
	}

	for _, section := range sections {
		if setupCtx.Context != nil && setupCtx.Context.Err() != nil {
			break
		}
		i, s, f := section.fn(setupCtx)
		totalInstalled += int32(i)
		totalSkipped += int32(s)
		totalFailed += int32(f)
	}

	if setupCtx.Logger != nil {
		setupCtx.Logger.Write("=== Setup Complete ===")
		setupCtx.Logger.Write("Duration: %s", time.Since(start).Round(time.Second))
		setupCtx.Logger.Write("Installed: %d, Skipped: %d, Failed: %d", totalInstalled, totalSkipped, totalFailed)
	}

	progress.Summary(totalInstalled, totalSkipped, totalFailed, time.Since(start))
	progress.Tip("Ensure $GOPATH/bin is in your $PATH")

	if totalFailed > 0 && logger != nil {
		progress.Tip(fmt.Sprintf("Check log for errors: %s", logger.Path()))
	}

	if totalFailed > 0 {
		return fmt.Errorf("setup completed with %d failures", totalFailed)
	}
	return nil
}


// resolveGOPATH returns the resolved GOPATH directory path, or an error if the user home directory cannot be found.
func resolveGOPATH() (string, error) {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		gopath = filepath.Join(home, "go")
	}
	return gopath, nil
}
