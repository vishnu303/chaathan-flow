package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install all dependency tools",
	Long: `Installs the necessary pentesting tools required for native execution mode.
- Go tools are installed via 'go install' (parallel)
- Python tools are installed via 'pip3 install'
- MassDNS is built from source`,
	Run: runSetup,
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

type installResult struct {
	name string
	err  error
}

type tool struct {
	name       string
	url        string
	skipIf     func() bool
	installCmd func() error
}

var goTools = []struct {
	name string
	url  string
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

var pyTools = []struct {
	name     string
	package_ string
}{
	{"cloud_enum", "git+https://github.com/initstring/cloud_enum.git"},
	{"sublist3r", "git+https://github.com/aboul3la/Sublist3r.git"},
	{"subdomainizer", "git+https://github.com/nsonaniya2010/SubDomainizer.git"},
	{"github-search", "git+https://github.com/gwen001/github-search.git"},
	{"linkfinder", "git+https://github.com/GerbenJavado/LinkFinder.git"},
}

var rubyTools = []struct {
	name    string
	gemName string
}{
	{"cewl", "cewl"},
}

func runSetup(cmd *cobra.Command, args []string) {
	logger.Info("Starting Chaathan Setup...")
	start := time.Now()

	installPrerequisites()

	if _, err := exec.LookPath("go"); err != nil {
		logger.Error("Go is not installed. Please install Go 1.21+ manually.")
		os.Exit(1)
	}

	stats := installAllTools()

	logger.Section("Setup Complete (%s)", time.Since(start).Round(time.Second))
	logger.Info("Installed: %d | Skipped: %d | Failed: %d", stats.installed, stats.skipped, stats.failed)
	logger.Info("Ensure your $GOPATH/bin is in your $PATH.")
}

type installStats struct {
	installed, skipped, failed int32
}

func (s *installStats) incInstalled() { atomic.AddInt32(&s.installed, 1) }
func (s *installStats) incSkipped()   { atomic.AddInt32(&s.skipped, 1) }
func (s *installStats) incFailed()    { atomic.AddInt32(&s.failed, 1) }

func installAllTools() *installStats {
	stats := &installStats{}
	var wg sync.WaitGroup
	results := make(chan installResult, len(goTools))
	workers := runtime.NumCPU()

	goToolsToInstall := filterGoTools()
	sem := make(chan struct{}, workers)

	for _, t := range goToolsToInstall {
		wg.Add(1)
		go func(tool struct {
			name string
			url  string
		}) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			err := installGoTool(tool.name, tool.url)
			results <- installResult{name: tool.name, err: err}
		}(t)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.err != nil {
			logger.Error("Failed to install %s: %v", r.name, r.err)
			stats.incFailed()
		} else {
			logger.Success("%s installed", r.name)
			stats.incInstalled()
		}
	}

	installPythonTools(stats)
	installRubyTools(stats)
	installMassDNS(stats)

	return stats
}

func filterGoTools() []struct {
	name string
	url  string
} {
	var toInstall []struct {
		name string
		url  string
	}
	for _, t := range goTools {
		if _, err := exec.LookPath(t.name); err == nil {
			logger.Success("%s already installed, skipping.", t.name)
			continue
		}
		toInstall = append(toInstall, t)
	}
	return toInstall
}

func installGoTool(name, url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "install", "-v", url)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if Verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

func installPrerequisites() {
	logger.Section("Installing Prerequisites")

	if runtime.GOOS != "linux" {
		logger.Warning("Auto-install only supported on Ubuntu/Debian. Please install: go, pip3, gem, git, make, gcc, libpcap-dev")
		return
	}

	type prereq struct {
		name, binary, aptPkg, dpkgPkg string
	}

	prereqs := []prereq{
		{"Go", "go", "golang-go", ""},
		{"pip3", "pip3", "python3-pip", ""},
		{"Ruby gem", "gem", "ruby-full", ""},
		{"Git", "git", "git", ""},
		{"Make", "make", "make", ""},
		{"GCC", "gcc", "gcc", ""},
		{"libpcap-dev", "", "libpcap-dev", "libpcap-dev"},
	}

	var toInstall []string
	for _, p := range prereqs {
		if isInstalled(p.binary, p.dpkgPkg) {
			logger.Success("%s already installed.", p.name)
			continue
		}
		logger.SubStep("%s not found, will install.", p.name)
		toInstall = append(toInstall, p.aptPkg)
	}

	if len(toInstall) == 0 {
		logger.Success("All prerequisites installed!")
		return
	}

	runCmd("sudo", "apt", "update", "-y")
	runCmd("sudo", append([]string{"apt", "install", "-y"}, toInstall...)...)
}

func isInstalled(binary, dpkgPkg string) bool {
	if binary != "" {
		_, err := exec.LookPath(binary)
		return err == nil
	}
	if dpkgPkg != "" {
		return exec.Command("dpkg", "-l", dpkgPkg).Run() == nil
	}
	return false
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if Verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

func installPythonTools(stats *installStats) {
	logger.Section("Installing Python Tools")

	pip := "pip3"
	if _, err := exec.LookPath("pip3"); err != nil {
		if _, err := exec.LookPath("pip"); err != nil {
			logger.Warning("pip not found. Skipping Python tools.")
			return
		}
		pip = "pip"
	}

	for _, t := range pyTools {
		logger.SubStep("Installing %s...", t.name)
		cmd := exec.Command(pip, "install", "--break-system-packages", t.package_)
		if Verbose {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		if err := cmd.Run(); err != nil {
			logger.Error("Failed: %s (%v)", t.name, err)
			stats.incFailed()
		} else {
			logger.Success("%s installed", t.name)
			stats.incInstalled()
		}
	}
}

func installRubyTools(stats *installStats) {
	logger.Section("Installing Ruby Tools")

	if _, err := exec.LookPath("gem"); err != nil {
		logger.Warning("gem not found. Skipping Ruby tools.")
		return
	}

	for _, t := range rubyTools {
		logger.SubStep("Installing %s...", t.name)
		cmd := exec.Command("sudo", "gem", "install", t.gemName)
		if Verbose {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		if err := cmd.Run(); err != nil {
			logger.Error("Failed: %s (%v)", t.name, err)
			stats.incFailed()
		} else {
			logger.Success("%s installed", t.name)
			stats.incInstalled()
		}
	}
}

func installMassDNS(stats *installStats) {
	logger.Section("Checking MassDNS")

	if _, err := exec.LookPath("massdns"); err == nil {
		logger.Success("MassDNS already installed.")
		stats.incSkipped()
		return
	}

	if runtime.GOOS == "windows" {
		logger.Warning("MassDNS on Windows requires manual install from https://github.com/blechschmidt/massdns")
		return
	}

	logger.Info("Building MassDNS from source...")

	tempDir, err := os.MkdirTemp("", "massdns_*")
	if err != nil {
		logger.Error("Failed to create temp dir: %v", err)
		stats.incFailed()
		return
	}
	defer os.RemoveAll(tempDir)

	steps := []struct {
		name string
		fn   func() error
	}{
		{"clone", func() error {
			return exec.Command("git", "clone", "--depth", "1", "https://github.com/blechschmidt/massdns.git", tempDir).Run()
		}},
		{"compile", func() error {
			cmd := exec.Command("make", "-j", fmt.Sprintf("%d", runtime.NumCPU()))
			cmd.Dir = tempDir
			return cmd.Run()
		}},
		{"install", func() error {
			goPath := os.Getenv("GOPATH")
			if goPath == "" {
				home, _ := os.UserHomeDir()
				goPath = filepath.Join(home, "go")
			}
			binDir := filepath.Join(goPath, "bin")
			if err := os.MkdirAll(binDir, 0755); err != nil {
				return err
			}

			src := filepath.Join(tempDir, "bin", "massdns")
			dst := filepath.Join(binDir, "massdns")

			input, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			return os.WriteFile(dst, input, 0755)
		}},
	}

	for _, step := range steps {
		logger.SubStep("%s...", step.name)
		if err := step.fn(); err != nil {
			logger.Error("MassDNS %s failed: %v", step.name, err)
			stats.incFailed()
			return
		}
	}

	logger.Success("MassDNS installed!")
	stats.incInstalled()
}

func joinStrings(s []string) string {
	return strings.Join(s, " ")
}
