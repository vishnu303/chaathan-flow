// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// moduleRegex validates Python module identifiers to prevent command injection or malformed paths.
var moduleRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func isValidPythonModule(module string) bool {
	return moduleRegex.MatchString(module)
}

// pyTools defines the Python-based security tools installed via pip.
var pyTools = []struct {
	name     string
	package_ string
	cmdName  string
	module   string
}{
	{"cloud_enum", "git+https://github.com/initstring/cloud_enum.git", "cloud_enum.py", "cloud_enum"},
	{"sublist3r", "sublist3r", "sublist3r", "sublist3r"},
}

// sublist3rPinArgs specifies the pip arguments used to pin urllib3 and requests for sublist3r compatibility.
var sublist3rPinArgs = []string{"install", "--break-system-packages", "requests", "urllib3<2"}

// installPythonToolsSection checks and installs Python-based tools sequentially.
func installPythonToolsSection(ctx *SetupContext) (installed, skipped, failed int) {
	pip := resolvePip()
	if pip == "" {
		progress.Section("Python Tools", "")
		progress.ItemInfo("pip not found — skipping")
		return 0, 0, 0
	}

	type pyTool struct{ name, pkg, cmd, module string }
	var toInstall []pyTool
	skippedCount := 0
	for _, t := range pyTools {
		if !isValidPythonModule(t.module) {
			progress.ItemFail(t.name, fmt.Sprintf("invalid module identifier: %s", t.module))
			continue
		}
		if !ctx.IsForceUpdate() && pythonToolInstalled(t.name, t.cmdName, t.module) {
			_ = ensurePythonToolShim(t.name, t.module)
			skippedCount++
			continue
		}
		toInstall = append(toInstall, pyTool{t.name, t.package_, t.cmdName, t.module})
	}

	totalToInstall := len(toInstall)
	detail := fmt.Sprintf("%d to install, %d already installed", totalToInstall, skippedCount)
	if skippedCount == 0 {
		detail = fmt.Sprintf("%d to install", totalToInstall)
	}
	progress.Section("Python Tools", detail)

	if totalToInstall == 0 {
		progress.ItemInfo("Nothing to do")
		return 0, skippedCount, 0
	}

	tracker := progress.NewTracker(totalToInstall)
	tracker.RunSpinner()

	for _, t := range toInstall {
		tracker.Start(t.name)
		args := []string{"install", "--break-system-packages", t.pkg}
		err := ctx.RunCommand(t.name, pip, args...)
		if err != nil {
			tracker.Fail(t.name, err.Error())
			continue
		}

		// sublist3r depends on requests/urllib3, but urllib3 v2.x dropped
		// urllib3.packages.six.moves, which it relies on.
		// Force urllib3<2 to guarantee the working 1.26.x series is on disk.
		if t.name == "sublist3r" {
			pinErr := ctx.RunCommand(t.name+" (urllib3/requests pin)", pip, sublist3rPinArgs...)
			if pinErr != nil {
				tracker.Fail(t.name, "pin requests/urllib3 failed: "+pinErr.Error())
				continue
			}
		}

		if err := ensurePythonToolShim(t.name, t.module); err != nil {
			tracker.Fail(t.name, err.Error())
		} else {
			tracker.Complete(t.name)
		}
	}

	tracker.StopSpinner()

	i, _, f := tracker.Stats()
	return i, skippedCount, f
}

// resolvePip returns the first available pip binary name, or "" if none found.
func resolvePip() string {
	for _, name := range []string{"pip3", "pip"} {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	return ""
}

// pythonToolInstalled checks if a tool or Python module is already installed on the system.
func pythonToolInstalled(name, cmdName, module string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	if cmdName != "" {
		if _, err := exec.LookPath(cmdName); err == nil {
			return true
		}
	}
	if module != "" && isValidPythonModule(module) && pythonModuleInstalled(module) {
		return true
	}
	return false
}

// pythonModuleInstalled checks if a python module is importable.
func pythonModuleInstalled(module string) bool {
	if module == "" || !isValidPythonModule(module) {
		return false
	}
	return exec.Command("python3", "-c", "import "+module).Run() == nil
}

// ensurePythonToolShim ensures a wrapper bash script is created in ~/.local/bin to invoke python modules easily.
func ensurePythonToolShim(name, module string) error {
	if name == "" || module == "" {
		return nil
	}
	if !isValidPythonModule(module) {
		return fmt.Errorf("invalid module identifier: %s", module)
	}
	if _, err := exec.LookPath(name); err == nil {
		return nil
	}
	if !pythonModuleInstalled(module) {
		return fmt.Errorf("%s module is not importable after install", module)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return err
	}

	shimPath := filepath.Join(binDir, name)
	shim := fmt.Sprintf("#!/usr/bin/env bash\npython3 -m %s \"$@\"\n", module)
	return os.WriteFile(shimPath, []byte(shim), 0755)
}
