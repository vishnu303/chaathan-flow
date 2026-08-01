// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/progress"
)

// installSecListsSection clones and installs SecLists wordlists.
// It checks if seclists already exists in:
// 1. ~/.chaathan/seclists
// 2. /usr/share/seclists
// 3. /usr/share/wordlists/seclists
// If not, it clones the SecLists repo to ~/.chaathan/seclists using git.
func installSecListsSection(ctx *SetupContext) (installed, skipped, failed int) {
	progress.Section("[6/6] Wordlists (SecLists)", "")

	localPath := filepath.Join(paths.ChaathanHome(), "seclists")

	if !ctx.IsForceUpdate() {
		basePath := config.ResolveSecListsBase()
		discPath := filepath.Join(basePath, "Discovery")
		if info, err := os.Stat(discPath); err == nil && info.IsDir() {
			progress.ItemOK(fmt.Sprintf("Already installed at %s", basePath))
			return 0, 1, 0
		}
	}

	tracker := progress.NewTracker(1)
	tracker.RunSpinner()
	tracker.Start("clone")

	// Ensure parent directory of ~/.chaathan/seclists exists
	if err := os.MkdirAll(paths.ChaathanHome(), 0755); err != nil {
		tracker.Fail("clone", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}

	// For force updates, remove the existing local directory first
	if ctx.IsForceUpdate() {
		_ = os.RemoveAll(localPath)
		// Warn if system-wide copies exist
		for _, path := range []string{"/usr/share/seclists", "/usr/share/wordlists/seclists"} {
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				progress.ItemInfo(fmt.Sprintf("Warning: System SecLists copy at %s is left untouched by update. Run apt/pacman update to update it.", path))
			}
		}
	} else {
		// Clean up any incomplete/broken previous clones in localPath so git clone can succeed
		if _, err := os.Stat(localPath); err == nil {
			_ = os.RemoveAll(localPath)
		}
	}

	err := ctx.RunCommand("seclists (clone)", "git", "clone", "--depth", "1",
		"https://github.com/danielmiessler/SecLists.git", localPath)
	if err != nil {
		tracker.Fail("clone", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}

	tracker.Complete("clone")
	tracker.StopSpinner()
	return 1, 0, 0
}
