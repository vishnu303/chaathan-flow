package cli

import (
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install all dependency tools",
	Long: `
Installs the necessary pentesting tools required for native execution mode.
- Go tools are installed via 'go install'
- Python tools are installed via 'pip3 install' (if available) or git clone instructions provided
- MassDNS is built from source
`,
	Run: runSetup,
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

func runSetup(cmd *cobra.Command, args []string) {
	logger.Info("Starting Chaathan Setup...")

	// 0. Install prerequisites (Go, pip3, gem, git, make, gcc)
	installPrerequisites()

	// Check for Go (must be available after prerequisites)
	if _, err := exec.LookPath("go"); err != nil {
		logger.Error("Go is not installed or not in PATH. Please install Go 1.21+ manually.")
		os.Exit(1)
	}

	// 1. Install Go Tools
	goTools := []struct {
		Name string
		URL  string
	}{
		{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{"amass", "github.com/owasp-amass/amass/v4/...@latest"},
		{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
		{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
		{"assetfinder", "github.com/tomnomnom/assetfinder@latest"},
		{"gau", "github.com/lc/gau/v2/cmd/gau@latest"},
		{"metabigor", "github.com/j3ssie/metabigor@latest"},
		{"shuffledns", "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"},
		{"anew", "github.com/tomnomnom/anew@latest"},
		{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
		{"katana", "github.com/projectdiscovery/katana/cmd/katana@latest"},
		{"ffuf", "github.com/ffuf/ffuf/v2@latest"},
		{"gospider", "github.com/jaeles-project/gospider@latest"},
		{"waybackurls", "github.com/tomnomnom/waybackurls@latest"},
		{"github-subdomains", "github.com/gwen001/github-subdomains@latest"},
	}

	logger.Section("Installing Go Tools")
	for _, tool := range goTools {
		logger.SubStep("Installing %s...", tool.Name)
		installCmd := exec.Command("go", "install", "-v", tool.URL)
		if Verbose {
			installCmd.Stdout = os.Stdout
			installCmd.Stderr = os.Stderr
		}
		if err := installCmd.Run(); err != nil {
			logger.Error("Failed to install %s: %v", tool.Name, err)
		} else {
			logger.Success("%s installed", tool.Name)
		}
	}

	// 2. Install Python Tools
	installPythonTools()

	// 3. Install Ruby Tools
	installRubyTools()

	// 4. Install MassDNS
	installMassDNS()

	logger.Section("Setup Complete")
	logger.Info("Ensure your $GOPATH/bin is in your $PATH.")
}

func installPrerequisites() {
	logger.Section("Installing Prerequisites")

	if runtime.GOOS != "linux" {
		logger.Warning("Automatic prerequisite installation is only supported on Ubuntu/Debian Linux.")
		logger.Warning("Please manually install: go, pip3, gem, git, make, gcc")
		return
	}

	prerequisites := []struct {
		Name   string // display name
		Binary string // binary to check in PATH
		AptPkg string // apt package name
	}{
		{"Go", "go", "golang-go"},
		{"pip3", "pip3", "python3-pip"},
		{"Ruby gem", "gem", "ruby-full"},
		{"Git", "git", "git"},
		{"Make", "make", "make"},
		{"GCC", "gcc", "gcc"},
	}

	toInstall := []string{}

	for _, p := range prerequisites {
		if _, err := exec.LookPath(p.Binary); err == nil {
			logger.Success("%s is already installed, skipping.", p.Name)
		} else {
			logger.SubStep("%s not found, will install via apt.", p.Name)
			toInstall = append(toInstall, p.AptPkg)
		}
	}

	if len(toInstall) == 0 {
		logger.Success("All prerequisites are already installed!")
		return
	}

	// Run apt update first
	logger.SubStep("Running apt update...")
	updateCmd := exec.Command("sudo", "apt", "update", "-y")
	if Verbose {
		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr
	}
	if err := updateCmd.Run(); err != nil {
		logger.Error("Failed to run apt update: %v", err)
		logger.Warning("You may need to run 'sudo apt update' manually.")
	}

	// Install missing packages
	args := append([]string{"apt", "install", "-y"}, toInstall...)
	logger.SubStep("Installing: %v", toInstall)
	installCmd := exec.Command("sudo", args...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		logger.Error("Failed to install prerequisites: %v", err)
		logger.Warning("Try running manually: sudo apt install -y %s", joinStrings(toInstall))
	} else {
		logger.Success("All prerequisites installed successfully!")
	}
}

func joinStrings(s []string) string {
	result := ""
	for i, v := range s {
		if i > 0 {
			result += " "
		}
		result += v
	}
	return result
}

func installPythonTools() {
	logger.Section("Checking/Installing Python Tools")

	pip := "pip3"
	if _, err := exec.LookPath("pip3"); err != nil {
		if _, err := exec.LookPath("pip"); err != nil {
			logger.Warning("pip3/pip not found. Skipping Python tool installation.")
			logger.Warning("Please manually install: cloud_enum, sublist3r, subdomainizer")
			return
		}
		pip = "pip"
	}

	pyTools := []struct {
		Name    string
		Package string // pip package name or git url
	}{
		{"cloud_enum", "git+https://github.com/initstring/cloud_enum.git"},
		{"sublist3r", "git+https://github.com/aboul3la/Sublist3r.git"},
		{"subdomainizer", "git+https://github.com/nsonaniya2010/SubDomainizer.git"},
		{"github-search", "git+https://github.com/gwen001/github-search.git"},
		{"linkfinder", "git+https://github.com/GerbenJavado/LinkFinder.git"},
	}

	for _, tool := range pyTools {
		logger.SubStep("Installing %s...", tool.Name)
		cmd := exec.Command(pip, "install", tool.Package)
		if Verbose {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		if err := cmd.Run(); err != nil {
			logger.Error("Failed to install %s: %v", tool.Name, err)
			logger.Warning("Try manual install: %s install %s", pip, tool.Package)
		} else {
			logger.Success("%s installed", tool.Name)
		}
	}
}

func installRubyTools() {
	logger.Section("Checking/Installing Ruby Tools")

	// Check for gem
	if _, err := exec.LookPath("gem"); err != nil {
		logger.Warning("Ruby gem not found. Skipping Ruby tool installation.")
		logger.Warning("Please manually install: cewl (gem install cewl)")
		return
	}

	rubyTools := []struct {
		Name    string
		GemName string
	}{
		{"cewl", "cewl"},
	}

	for _, tool := range rubyTools {
		logger.SubStep("Installing %s...", tool.Name)
		cmd := exec.Command("gem", "install", tool.GemName)
		if Verbose {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		if err := cmd.Run(); err != nil {
			logger.Error("Failed to install %s: %v", tool.Name, err)
			logger.Warning("Try: sudo gem install %s", tool.GemName)
		} else {
			logger.Success("%s installed", tool.Name)
		}
	}
}

func installMassDNS() {
	logger.Section("Checking for MassDNS")

	if _, err := exec.LookPath("massdns"); err == nil {
		logger.Success("MassDNS is already installed.")
		return
	}

	if runtime.GOOS == "windows" {
		logger.Warning("MassDNS installation on Windows is manual. Please compile from https://github.com/blechschmidt/massdns and add to PATH.")
		return
	}

	// Attempt to build on Linux/Mac
	logger.Info("MassDNS not found. Attempting to build from source...")

	tempDir, err := os.MkdirTemp("", "massdns_build")
	if err != nil {
		logger.Error("Failed to create temp dir: %v", err)
		return
	}
	defer os.RemoveAll(tempDir)

	// Clone
	logger.SubStep("Cloning repository...")
	cloneCmd := exec.Command("git", "clone", "https://github.com/blechschmidt/massdns.git", tempDir)
	if err := cloneCmd.Run(); err != nil {
		logger.Error("Failed to clone MassDNS: %v", err)
		return
	}

	// Make
	logger.SubStep("Compiling (make)...")
	makeCmd := exec.Command("make")
	makeCmd.Dir = tempDir
	if err := makeCmd.Run(); err != nil {
		logger.Error("Failed to compile MassDNS: %v", err)
		logger.Warning("Please install 'make' and 'gcc' and try again.")
		return
	}

	// Install (copy to GOPATH/bin)
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		home, _ := os.UserHomeDir()
		goPath = filepath.Join(home, "go")
	}
	binDir := filepath.Join(goPath, "bin")

	srcPath := filepath.Join(tempDir, "bin", "massdns")
	destPath := filepath.Join(binDir, "massdns")

	logger.SubStep("Installing to %s...", destPath)

	input, err := os.ReadFile(srcPath)
	if err != nil {
		logger.Error("Failed to read compiled binary: %v", err)
		return
	}

	// Write dest
	// Check if bin exists
	os.MkdirAll(binDir, 0755)

	if err := os.WriteFile(destPath, input, 0755); err != nil {
		logger.Error("Failed to install binary: %v", err)
		logger.Warning("You may need to sudo cp the binary manually.")
	} else {
		logger.Success("MassDNS installed successfully!")
	}
}
