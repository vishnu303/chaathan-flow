package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/tools"
	"github.com/vishnu303/chaathan/pkg/update"
)

var (
	Mode       string
	OutputDir  string
	Verbose    bool
	ConfigPath string
	Cfg        *config.Config
)

// Version and BuildTime are injected at build time via ldflags.
// See Makefile: -X github.com/vishnu303/chaathan/cli.Version=...
var (
	Version   = "dev"
	BuildTime = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "chaathan",
	Short: "Chaathan — pentesting recon framework",
	Long: `
   _____ _                 _   _                 
  / ____| |               | | | |                
 | |    | |__   __ _  __ _| |_| |__   __ _ _ __  
 | |    | '_ \ / _' |/ _' | __| '_ \ / _' | '_ \ 
 | |____| | | | (_| | (_| | |_| | | | (_| | | | |
  \_____|_| |_|\__,_|\__,_|\__|_| |_|\__,_|_| |_|

  Automated bug bounty recon — 27 tools, 2 workflows, 1 binary.

Workflows:
  wildcard  23-step domain recon & vulnerability assessment
  company   3-step org discovery (ASN, root domains, cloud assets)

Key capabilities:
  • Subdomain enumeration (passive, active, DNS brute-force, JS extraction)
  • Live host probing, TLS analysis, port scanning
  • Web crawling, URL discovery, parameter fuzzing
  • JS secret scanning, vulnerability scanning, XSS detection
  • Subdomain takeover detection, cloud infrastructure enumeration
  • Persistent SQLite database — query, diff, and export results
  • Reports in Markdown, HTML, and JSON
  • Discord, Slack, and Telegram notifications
  • WAF evasion (UA rotation, proxy, rate limiting)
  • Resume interrupted scans at any step

Modes:
  native    Tools installed in $PATH (default)
  docker    Tools run inside Docker containers

Getting started:
  chaathan setup                     Install all tools
  chaathan wildcard -d target.com    Run full 23-step recon
  chaathan company -n "Company Inc"  Run company discovery
  chaathan status                    View scan dashboard
  chaathan query vulns 1             Query vulnerabilities
  chaathan report generate 1         Generate report`,
	PersistentPreRun: initializeApp,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&Mode, "mode", "m", "native", "Execution mode: 'native' or 'docker'")
	rootCmd.PersistentFlags().StringVarP(&OutputDir, "output", "o", "", "Directory to store results")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&ConfigPath, "config", "", "Config file path (default: ~/.chaathan/config.yaml)")
}

func initializeApp(cmd *cobra.Command, args []string) {
	// Skip initialization for setup command
	if cmd.Name() == "setup" {
		return
	}

	// Determine config path
	cfgPath := ConfigPath
	if cfgPath == "" {
		cfgPath = config.GetDefaultConfigPath()
	}

	// Load or create config
	var err error
	Cfg, err = config.LoadOrCreate(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warning("Config file not found, using defaults: %v", err)
			Cfg = config.DefaultConfig()
		} else {
			logger.Error("Fatal: failed to load or parse configuration: %v", err)
			os.Exit(1)
		}
	}

	// Apply config values if not overridden by flags
	if OutputDir == "" {
		OutputDir = Cfg.General.OutputDir
	}
	if !Verbose && Cfg.General.Verbose {
		Verbose = true
	}
	if Mode == "native" && Cfg.General.Mode != "" {
		Mode = Cfg.General.Mode
	}

	// Validate mode
	if Mode != "native" && Mode != "docker" {
		logger.Error("Invalid mode '%s'. Must be 'native' or 'docker'.", Mode)
		os.Exit(1)
	}

	// Initialize database
	dbPath := Cfg.General.DatabasePath
	if dbPath == "" {
		dbPath = database.GetDefaultDBPath()
	}

	if err := database.Initialize(dbPath); err != nil {
		logger.Warning("Failed to initialize database: %v", err)
		logger.Warning("Some features (history, reports) may not work.")
	}
}

func CreateOutputDir(target string) (string, error) {
	baseDir := OutputDir
	if baseDir == "" {
		baseDir = paths.ScansDir()
	}

	path := filepath.Join(baseDir, target)
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", err
	}
	return path, nil
}

// Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s%sChaathan%s %s\n", logger.BrightCyan, logger.Bold, logger.Reset, Version)
		fmt.Printf("%sBuilt: %s%s\n", logger.Dim, BuildTime, logger.Reset)
		fmt.Printf("%sPentesting Recon Framework%s\n", logger.Dim, logger.Reset)
		fmt.Printf("%s%d tools • 23-step wildcard • 3-step company%s\n", logger.Dim, len(tools.AllTools), logger.Reset)
		fmt.Printf("%shttps://github.com/vishnu303/chaathan%s\n", logger.Dim, logger.Reset)

		fmt.Printf("\n%sChecking for updates...%s\n", logger.Dim, logger.Reset)
		info, err := update.CheckForUpdates(Version)
		if err != nil {
			if Verbose {
				logger.Warning("Update check failed: %v", err)
			} else {
				fmt.Printf("%s(Could not connect to GitHub to check for updates)%s\n", logger.Dim, logger.Reset)
			}
			return
		}

		if info.IsNewer {
			fmt.Printf("\n  %s🔥 A new version is available: %s%s %s(latest)%s\n", logger.BrightYellow+logger.Bold, logger.BrightGreen, info.LatestVersion, logger.Dim, logger.Reset)
			fmt.Printf("  %sDownload / Changelog: %s%s\n\n", logger.Dim, info.URL, logger.Reset)
		} else {
			if Version == "dev" || strings.HasPrefix(Version, "dev-") {
				fmt.Printf("  %sLatest stable version is %s (you are running a local dev build)%s\n", logger.Dim, info.LatestVersion, logger.Reset)
			} else {
				fmt.Printf("  %sYou are running the latest version! (%s)%s\n", logger.BrightGreen, Version, logger.Reset)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
