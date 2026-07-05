// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// installGFPatternsSection clones upstream GFpattern pack and installs the JSON files.
func installGFPatternsSection(ctx *SetupContext) (installed, skipped, failed int) {
	progress.Section("gf Patterns", "cloning upstream GFpattern pack for workflow scanning")

	if _, err := exec.LookPath("gf"); err != nil {
		progress.ItemInfo("gf binary not installed yet — pattern install blocked")
		return 0, 0, 0
	}
	if _, err := exec.LookPath("git"); err != nil {
		progress.ItemFail("git", "git is required to install gf patterns")
		return 0, 0, 1
	}

	home, err := os.UserHomeDir()
	if err != nil {
		progress.ItemFail("gf patterns", "cannot determine home directory")
		return 0, 0, 1
	}

	gfDir := filepath.Join(home, ".gf")
	if err := os.MkdirAll(gfDir, 0755); err != nil {
		progress.ItemFail("gf patterns", err.Error())
		return 0, 0, 1
	}

	if !ctx.IsForceUpdate() {
		hasPatterns := false
		if files, err := os.ReadDir(gfDir); err == nil {
			for _, f := range files {
				if !f.IsDir() && filepath.Ext(f.Name()) == ".json" {
					hasPatterns = true
					break
				}
			}
		}
		if hasPatterns {
			progress.ItemInfo("gf pattern pack already present")
			files, _ := os.ReadDir(gfDir)
			skipped := 0
			for _, f := range files {
				if !f.IsDir() && filepath.Ext(f.Name()) == ".json" {
					skipped++
				}
			}
			return 0, skipped, 0
		}
	}

	tempDir, err := os.MkdirTemp("", "chaathan-gf-*")
	if err != nil {
		progress.ItemFail("gf patterns", "failed to create temp directory")
		return 0, 0, 1
	}
	defer os.RemoveAll(tempDir)

	err = ctx.RunCommand("gf-patterns (clone)", "git", "clone", "--depth", "1", "https://github.com/coffinxp/GFpattren", tempDir)
	if err != nil {
		progress.ItemFail("gf patterns", err.Error())
		return 0, 0, 1
	}

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		progress.ItemFail("gf patterns", "failed to read cloned pattern pack")
		return 0, 0, 1
	}

	installedCount := 0
	skippedCount := 0
	failedCount := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		srcPath := filepath.Join(tempDir, entry.Name())
		dstPath := filepath.Join(gfDir, entry.Name())
		if !ctx.IsForceUpdate() {
			if _, err := os.Stat(dstPath); err == nil {
				skippedCount++
				continue
			}
		}

		data, err := os.ReadFile(srcPath)
		if err != nil {
			progress.ItemFail(entry.Name(), err.Error())
			failedCount++
			continue
		}
		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			progress.ItemFail(entry.Name(), err.Error())
			failedCount++
			continue
		}
		installedCount++
	}

	if installedCount > 0 {
		progress.ItemOK(fmt.Sprintf("%d gf patterns installed", installedCount))
	}
	if installedCount == 0 && failedCount == 0 {
		progress.ItemInfo("gf pattern pack already present")
	}

	return installedCount, skippedCount, failedCount
}
