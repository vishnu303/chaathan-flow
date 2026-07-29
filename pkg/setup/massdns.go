// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// installMassDNSSection clones, compiles, and installs MassDNS from source.
// This is done as a multi-step compilation process (Clone -> Compile -> Install).
func installMassDNSSection(ctx *SetupContext) (installed, skipped, failed int) {
	progress.Section("[6/7] DNS Engines (MassDNS)", "")

	if !ctx.IsForceUpdate() {
		if _, err := exec.LookPath("massdns"); err == nil {
			progress.ItemOK("Already installed")
			return 0, 1, 0
		}
	}

	if runtime.GOOS == "windows" {
		progress.ItemInfo("Windows requires manual install from github.com/blechschmidt/massdns")
		return 0, 0, 0
	}

	tracker := progress.NewTracker(3) // 3 stages: clone, compile, and install
	tracker.RunSpinner()

	goPath, err := resolveGOPATH() // Resolve GOPATH and check errors
	if err != nil {
		tracker.StopSpinner()
		progress.ItemFail("massdns", "failed to resolve GOPATH: "+err.Error())
		return 0, 0, 1
	}
	binDir := filepath.Join(goPath, "bin")

	tempDir, err := os.MkdirTemp("", "massdns_*")
	if err != nil {
		tracker.StopSpinner()
		progress.ItemFail("massdns", "failed to create temp directory")
		return 0, 0, 1
	}
	defer os.RemoveAll(tempDir)

	// Stage 1 — Clone the Git repository
	tracker.Start("clone")
	cloneErr := ctx.RunCommand("massdns (clone)", "git", "clone", "--depth", "1",
		"https://github.com/blechschmidt/massdns.git", tempDir)
	if cloneErr != nil {
		tracker.Fail("clone", cloneErr.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	tracker.Complete("clone")

	// Stage 2 — Compile the source code
	tracker.Start("compile")
	compileErr := ctx.RunCommandInDir(tempDir, "massdns (compile)", "make", "-j", fmt.Sprintf("%d", runtime.NumCPU()))
	if compileErr != nil {
		tracker.Fail("compile", compileErr.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	tracker.Complete("compile")

	// Stage 3 — Install the compiled binary to $GOPATH/bin
	tracker.Start("install")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		tracker.Fail("install", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	src := filepath.Join(tempDir, "bin", "massdns")
	dst := filepath.Join(binDir, "massdns")
	input, err := os.ReadFile(src)
	if err != nil {
		tracker.Fail("install", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	if err := os.WriteFile(dst, input, 0755); err != nil {
		tracker.Fail("install", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	tracker.Complete("install")
	tracker.StopSpinner()

	return 1, 0, 0
}
