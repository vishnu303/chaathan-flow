// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/vishnu303/chaathan/pkg/progress"
	"github.com/vishnu303/chaathan/pkg/tools"
)

// installGoToolsSection checks and installs Go-based tools sequentially.
func installGoToolsSection(ctx *SetupContext) (int, int, int) {
	type goTool struct{ name, url string }
	var toInstall []goTool
	skippedCount := 0
	for _, t := range tools.GoInstallableTools() {
		if !ctx.IsForceUpdate() {
			if found, _ := t.CheckStatus(); found {
				skippedCount++
				continue
			}
		}
		toInstall = append(toInstall, goTool{t.Name, t.InstallURL})
	}

	detail := fmt.Sprintf("%d to install, %d already installed", len(toInstall), skippedCount)
	if skippedCount == 0 {
		detail = fmt.Sprintf("%d to install", len(toInstall))
	}
	progress.Section("[2/7] Go Tools", detail)

	if len(toInstall) == 0 {
		progress.ItemInfo("Nothing to do")
		maybeUpdateNucleiTemplates(ctx)
		return 0, skippedCount, 0
	}

	tracker := progress.NewTracker(len(toInstall))
	tracker.RunSpinner()

	for _, t := range toInstall {
		tracker.Start(t.name)
		if err := installGoTool(ctx, t.name, t.url); err != nil {
			tracker.Fail(t.name, err.Error())
		} else {
			tracker.Complete(t.name)
		}
	}

	tracker.StopSpinner()

	maybeUpdateNucleiTemplates(ctx)

	i, _, f := tracker.Stats()
	return i, skippedCount, f
}

// installGoTool runs `go install -v <url>` without timeout.
func installGoTool(ctx *SetupContext, name, url string) error {
	return ctx.RunCommand(name, "go", "install", "-v", url)
}

func maybeUpdateNucleiTemplates(ctx *SetupContext) {
	nucleiFound := false
	for _, t := range tools.GoInstallableTools() {
		if t.Name == "nuclei" {
			if ok, _ := t.CheckStatus(); ok {
				nucleiFound = true
			}
		}
	}
	if nucleiFound {
		progress.ItemPending("Updating nuclei templates...")
		if err := downloadNucleiTemplates(ctx); err != nil {
			progress.ItemFail("nuclei templates update", err.Error())
		} else {
			progress.ItemOK("nuclei templates update")
		}
	}
}

// downloadNucleiTemplates runs nuclei -update-templates to populate the templates directory.
func downloadNucleiTemplates(ctx *SetupContext) error {
	nucleiPath := ""
	if p, errLook := exec.LookPath("nuclei"); errLook == nil {
		nucleiPath = p
	} else {
		// Fallback to GOPATH/bin
		if gopath, err := resolveGOPATH(); err == nil { // Resolve GOPATH and check errors
			candidate := filepath.Join(gopath, "bin", "nuclei")
			if _, errStat := os.Stat(candidate); errStat == nil {
				nucleiPath = candidate
			}
		}
	}

	if nucleiPath == "" {
		return fmt.Errorf("nuclei binary not found")
	}

	return ctx.RunCommand("nuclei-templates", nucleiPath, "-update-templates")
}
