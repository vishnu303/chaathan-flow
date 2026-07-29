// Package cli – Setup command
//
// This file is intentionally thin. It only contains the cobra command
// definition and a single call into pkg/setup.Run().
// All installation logic lives in the setup package.
package cli

import (
	"github.com/spf13/cobra"

	s "github.com/vishnu303/chaathan/pkg/setup"
)

// ─────────────────────────────────────────────────────────────
// CLI flags
// ─────────────────────────────────────────────────────────────

var setupUpdate bool

// ─────────────────────────────────────────────────────────────
// Cobra command
// ─────────────────────────────────────────────────────────────

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install all dependency tools",
	Long: `Installs the tools required for native execution mode.

Categories:
  - Go runtime:   installed to ~/.local/go (no sudo required)
  - Go tools:     subfinder, httpx, nuclei, katana, naabu, etc. (installed to ~/go/bin)
  - Python tools: sublist3r (installed to ~/.local/bin)
  - Rust tools:   x8 (installed to ~/.local/bin)
  - From source:  massdns (installed to ~/go/bin)

Already-installed tools are skipped automatically.
Use --update to force reinstallation of every tool (useful after a version
mismatch or broken install).
All output is logged to ~/.chaathan/logs/setup_<timestamp>.log for debugging.

Usage:
  chaathan setup              # Install missing tools (parallel)
  chaathan setup --update     # Reinstall ALL tools (force update)
  chaathan setup --verbose    # Show live install output`,
	RunE: runSetup,
}

func init() {
	setupCmd.Flags().BoolVar(&setupUpdate, "update", false, "Reinstall all tools even if already installed")
	rootCmd.AddCommand(setupCmd)
}

// ─────────────────────────────────────────────────────────────
// runSetup — cobra handler
// ─────────────────────────────────────────────────────────────

func runSetup(cmd *cobra.Command, args []string) error {
	return s.Run(cmd.Context(), s.RunConfig{
		Verbose:     Verbose,
		ForceUpdate: setupUpdate,
	})
}
