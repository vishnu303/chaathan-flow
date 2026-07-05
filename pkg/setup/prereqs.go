// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// distroFamily identifies the Linux distribution family for package management.
type distroFamily int

const (
	distroUnknown distroFamily = iota
	distroDebian               // Debian, Ubuntu, Kali, etc.
	distroArch                 // Arch, CachyOS, Manjaro, EndeavourOS, etc.
)

// detectDistro reads /etc/os-release and returns the distro family.
// Falls back to distroUnknown if the file is missing or unrecognised.
func detectDistro() distroFamily {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return distroUnknown
	}
	defer f.Close()

	var id, idLike string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		} else if strings.HasPrefix(line, "ID_LIKE=") {
			idLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), "\"")
		}
	}

	// Check ID first, then ID_LIKE for derivatives
	combined := id + " " + idLike
	switch {
	case containsWord(combined, "arch"):
		return distroArch
	case containsWord(combined, "debian") || containsWord(combined, "ubuntu"):
		return distroDebian
	}
	return distroUnknown
}

// containsWord checks if any whitespace-separated token in s equals word.
func containsWord(s, word string) bool {
	for _, w := range strings.Fields(s) {
		if w == word {
			return true
		}
	}
	return false
}

// installPrerequisites checks and installs system-level packages.
func installPrerequisites(ctx *SetupContext) {
	progress.Section("Prerequisites", "")

	if runtime.GOOS != "linux" {
		progress.ItemInfo("Auto-install only supported on Linux (Debian/Ubuntu, Arch/CachyOS).")
		progress.ItemInfo("Please ensure: go, pip3, git, make, gcc, libpcap")
		return
	}

	// Ensure Go runtime is installed and at least 1.26
	if _, err := EnsureGoInstalled(ctx); err != nil {
		progress.ItemFail("Go setup failed", err.Error())
		return
	}

	distro := detectDistro()
	if distro == distroUnknown {
		progress.ItemInfo("Unrecognised Linux distribution — cannot auto-install other prerequisites.")
		progress.ItemInfo("Please ensure: pip3, gem, git, make, gcc, libpcap")
		ensurePathSetup()
		return
	}

	type prereq struct {
		name       string
		binary     string
		aptPkg     string // Debian/Ubuntu
		pacmanPkg  string // Arch/CachyOS
		dpkgPkg    string // dpkg -l check on Debian
		pacmanQPkg string // pacman -Qi check on Arch
	}

	prereqs := []prereq{
		{"pip3", "pip3", "python3-pip", "python-pip", "", ""},
		{"Cargo", "cargo", "cargo", "rust", "", ""},
		{"pkg-config", "pkg-config", "pkg-config", "pkgconf", "", ""},
		{"libssl-dev", "", "libssl-dev", "openssl", "libssl-dev", "openssl"},
		{"Git", "git", "git", "git", "", ""},
		{"Make", "make", "make", "make", "", ""},
		{"GCC", "gcc", "gcc", "gcc", "", ""},
		{"libpcap", "", "libpcap-dev", "libpcap", "libpcap-dev", "libpcap"},
	}

	var toInstall []string
	for _, p := range prereqs {
		if isPrereqInstalled(p.binary, p.dpkgPkg, p.pacmanQPkg, distro) {
			progress.ItemOK(p.name)
		} else {
			progress.ItemPending(p.name)
			switch distro {
			case distroDebian:
				toInstall = append(toInstall, p.aptPkg)
			case distroArch:
				toInstall = append(toInstall, p.pacmanPkg)
			}
		}
	}

	if len(toInstall) == 0 {
		progress.ItemInfo("All prerequisites ready")
		ensurePathSetup()
		return
	}

	switch distro {
	case distroDebian:
		progress.ItemInfo(fmt.Sprintf("Installing %d packages via apt...", len(toInstall)))
		_ = runSysCmd(ctx, "sudo", "apt", "update", "-qq")
		if err := runSysCmd(ctx, "sudo", append([]string{"apt", "install", "-y", "-qq"}, toInstall...)...); err != nil {
			progress.ItemFail("apt install", err.Error())
		} else {
			progress.ItemOK(fmt.Sprintf("%d packages installed", len(toInstall)))
		}
	case distroArch:
		progress.ItemInfo(fmt.Sprintf("Installing %d packages via pacman...", len(toInstall)))
		if err := runSysCmd(ctx, "sudo", append([]string{"pacman", "-S", "--noconfirm", "--needed"}, toInstall...)...); err != nil {
			progress.ItemFail("pacman install", err.Error())
		} else {
			progress.ItemOK(fmt.Sprintf("%d packages installed", len(toInstall)))
		}
	}

	ensurePathSetup()
}

// isPrereqInstalled check binary presence or package-manager install status.
func isPrereqInstalled(binary, dpkgPkg, pacmanQPkg string, distro distroFamily) bool {
	// Prefer binary check — works on all distros
	if binary != "" {
		_, err := exec.LookPath(binary)
		return err == nil
	}
	// Fall back to package-manager query for header-only packages
	switch distro {
	case distroDebian:
		if dpkgPkg != "" {
			return exec.Command("dpkg", "-l", dpkgPkg).Run() == nil
		}
	case distroArch:
		if pacmanQPkg != "" {
			return exec.Command("pacman", "-Qi", pacmanQPkg).Run() == nil
		}
	}
	return false
}

// runSysCmd runs a system command, redirecting to SetupLogger and terminal live (M5).
func runSysCmd(ctx *SetupContext, name string, args ...string) error {
	if ctx.Logger != nil {
		ctx.Logger.Write("Running system command: %s %s", name, strings.Join(args, " "))
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin

	var stdout, stderr bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &stdout)
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)

	setPGID(cmd) // M1: Setpgid true

	err := cmd.Run()
	if ctx.Logger != nil {
		ctx.Logger.Write("--- [system_cmd: %s] ---", name)
		ctx.Logger.Write("Command: %s", cmd.String())
		if stdout.Len() > 0 {
			ctx.Logger.Write("STDOUT:\n%s", stdout.String())
		}
		if stderr.Len() > 0 {
			ctx.Logger.Write("STDERR:\n%s", stderr.String())
		}
		if err != nil {
			ctx.Logger.Write("System command failed: %v", err)
		} else {
			ctx.Logger.Write("System command completed successfully")
		}
		ctx.Logger.Write("")
	}
	return err
}

// ensurePathSetup adds ~/.local/bin and ~/go/bin to PATH in shell configuration files.
func ensurePathSetup() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	// POSIX shell exports (bash, zsh)
	pathsToAdd := []string{
		`export PATH="$HOME/.local/bin:$PATH"`,
		`export PATH="$HOME/go/bin:$PATH"`,
	}

	rcFiles := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
	}

	comment := "# Chaathan PATH configuration"

	for _, rc := range rcFiles {
		if _, err := os.Stat(rc); os.IsNotExist(err) {
			continue // skip if the user doesn't use this shell
		}

		if added, err := appendLinesToFile(rc, pathsToAdd, comment); err == nil && added {
			progress.ItemOK(fmt.Sprintf("Added paths to %s (Restart terminal to apply)", filepath.Base(rc)))
		}
	}

	// Fish shell support (CachyOS default)
	fishConfig := filepath.Join(home, ".config", "fish", "config.fish")
	if _, err := os.Stat(fishConfig); err == nil {
		fishPaths := []string{
			`fish_add_path -g $HOME/.local/bin`,
			`fish_add_path -g $HOME/go/bin`,
		}
		if added, err := appendLinesToFile(fishConfig, fishPaths, comment); err == nil && added {
			progress.ItemOK("Added paths to config.fish (Restart terminal to apply)")
		}
	}

	// Update the current Go process's PATH so that subsequent setup functions
	// or tool runs in this same execution session can find the new paths instantly.
	currentPath := os.Getenv("PATH")
	localBin := filepath.Join(home, ".local", "bin")
	goBin := filepath.Join(home, "go", "bin")

	if !pathListContains(currentPath, localBin) {
		currentPath = localBin + string(os.PathListSeparator) + currentPath
	}
	if !pathListContains(currentPath, goBin) {
		currentPath = goBin + string(os.PathListSeparator) + currentPath
	}
	_ = os.Setenv("PATH", currentPath)
}

// appendLinesToFile checks if lines exist in the file, and appends them with a preceding comment if any are missing.
func appendLinesToFile(filePath string, lines []string, comment string) (bool, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false, err
	}

	fileContent := string(content)
	var toAdd []string
	for _, line := range lines {
		if !strings.Contains(fileContent, line) {
			toAdd = append(toAdd, line)
		}
	}

	if len(toAdd) == 0 {
		return false, nil
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return false, err
	}
	defer f.Close()

	if _, err := f.WriteString("\n" + comment + "\n"); err != nil {
		return false, err
	}
	for _, line := range toAdd {
		if _, err := f.WriteString(line + "\n"); err != nil {
			return false, err
		}
	}

	return true, nil
}
