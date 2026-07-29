package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/scan"
	wf "github.com/vishnu303/chaathan/pkg/wildcard_flow"
	"github.com/vishnu303/chaathan/utils"
)

var scansCmd = &cobra.Command{
	Use:   "scans",
	Short: "Manage and view scan history",
	Long:  `View, resume, or delete past scans stored in the database.`,
}

var scansListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent scans",
	Run:   runScansList,
}

var scansShowCmd = &cobra.Command{
	Use:   "show [scan_id]",
	Short: "Show details of a specific scan",
	Args:  cobra.ExactArgs(1),
	Run:   runScansShow,
}

var scansResumeCmd = &cobra.Command{
	Use:   "resume [scan_id]",
	Short: "Resume an interrupted scan",
	Args:  cobra.ExactArgs(1),
	Run:   runScansResume,
}

var scansDeleteCmd = &cobra.Command{
	Use:   "delete [scan_id]",
	Short: "Delete a scan and its data",
	Args:  cobra.ExactArgs(1),
	Run:   runScansDelete,
}

var (
	listLimit  int
	listTarget string
)

func init() {
	scansListCmd.Flags().IntVarP(&listLimit, "limit", "n", 20, "Number of scans to show")
	scansListCmd.Flags().StringVarP(&listTarget, "target", "t", "", "Filter by target domain")

	scansCmd.AddCommand(scansListCmd)
	scansCmd.AddCommand(scansShowCmd)
	scansCmd.AddCommand(scansResumeCmd)
	scansCmd.AddCommand(scansDeleteCmd)
	rootCmd.AddCommand(scansCmd)
}

func runScansList(cmd *cobra.Command, args []string) {
	var scans []database.Scan
	var err error

	if listTarget != "" {
		scans, err = database.GetScansByTarget(listTarget)
	} else {
		scans, err = database.GetRecentScans(listLimit)
	}

	if err != nil {
		logger.Error("Failed to fetch scans: %v", err)
		return
	}

	if len(scans) == 0 {
		logger.Info("No scans found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTARGET\tTYPE\tSTATUS\tSTARTED\tDURATION")
	fmt.Fprintln(w, "--\t------\t----\t------\t-------\t--------")

	for _, s := range scans {
		duration := "-"
		if s.CompletedAt != nil {
			duration = s.CompletedAt.Sub(s.StartedAt).Round(time.Second).String()
		} else if s.Status == "running" {
			duration = time.Since(s.StartedAt).Round(time.Second).String() + " (running)"
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
			s.ID,
			utils.Truncate(s.Target, 30),
			s.Type,
			logger.ColorStatus(s.Status),
			s.StartedAt.Format("2006-01-02 15:04"),
			duration,
		)
	}
	w.Flush()
}

func runScansShow(cmd *cobra.Command, args []string) {
	scanID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}

	s, err := database.GetScan(scanID)
	if err != nil {
		logger.Error("Scan not found: %v", err)
		return
	}

	stats, err := database.GetScanStats(scanID)
	if err != nil {
		logger.Error("Failed to get stats: %v", err)
		return
	}

	logger.Section("Scan #%d", s.ID)
	fmt.Printf("Target:     %s\n", s.Target)
	fmt.Printf("Type:       %s\n", s.Type)
	fmt.Printf("Status:     %s\n", logger.ColorStatus(s.Status))
	fmt.Printf("Started:    %s\n", s.StartedAt.Format("2006-01-02 15:04:05"))
	if s.CompletedAt != nil {
		fmt.Printf("Completed:  %s\n", s.CompletedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Duration:   %s\n", s.CompletedAt.Sub(s.StartedAt).Round(time.Second))
	}
	fmt.Printf("Results:    %s\n", s.ResultDir)

	logger.Section("Statistics")
	fmt.Printf("Subdomains: %d (Live: %d)\n", stats.TotalSubdomains, stats.LiveSubdomains)
	fmt.Printf("Ports:      %d\n", stats.TotalPorts)
	fmt.Printf("URLs:       %d\n", stats.TotalURLs)
	fmt.Printf("Endpoints:  %d\n", stats.TotalEndpoints)

	if len(stats.Vulnerabilities) > 0 {
		logger.Section("Vulnerabilities")
		for sev, count := range stats.Vulnerabilities {
			fmt.Printf("  %s: %d\n", logger.ColorSeverity(sev), count)
		}
	}

	// Show top 5 critical/high vulns
	vulns, _ := database.GetVulnerabilities(scanID)
	criticalHigh := 0
	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" {
			criticalHigh++
			if criticalHigh <= 5 {
				fmt.Printf("\n[%s] %s\n  Host: %s\n", logger.ColorSeverity(v.Severity), v.Name, v.Host)
			}
		}
	}
	if criticalHigh > 5 {
		fmt.Printf("\n... and %d more critical/high vulnerabilities\n", criticalHigh-5)
	}
}

func runScansResume(cmd *cobra.Command, args []string) {
	scanID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}
	resumeScanByID(scanID)
}

func resumeScanByID(scanID int64) {
	mgr := scan.NewManager(paths.StateDir())

	state, err := mgr.LoadState(scanID)
	if err != nil {
		logger.Error("Cannot resume scan: %v", err)
		logger.Info("Scan may have completed or state file was deleted.")
		return
	}

	if !state.CanResume() {
		logger.Error("Scan #%d cannot be resumed (completed or not started)", scanID)
		return
	}

	logger.Section("Resuming Scan #%d", scanID)
	logger.Info("Target: %s", state.Target)
	logger.Info("Progress: %.1f%% (%d/%d steps)", state.Progress(), len(state.CompletedSteps), state.TotalSteps)

	nextStep := state.GetNextStep()
	if nextStep != nil {
		logger.Info("Next step: %s", nextStep.Description)
	}

	logger.Info("\nCompleted steps:")
	for _, step := range state.CompletedSteps {
		logger.Success("  %s", step)
	}

	if len(state.FailedSteps) > 0 {
		logger.Warning("\nFailed steps:")
		for _, fs := range state.FailedSteps {
			logger.Error("  %s: %s (retries: %d)", fs.Name, fs.Error, fs.Retries)
		}
	}

	// Recover options from stored config JSON
	var opts map[string]interface{}
	if err := json.Unmarshal(state.Config, &opts); err != nil {
		logger.Warning("Could not parse stored config: %v — resuming with default flags", err)
		opts = map[string]interface{}{}
	}
	boolOpt := func(key string) bool {
		v, _ := opts[key].(bool)
		return v
	}
	strOpt := func(key string) string {
		v, _ := opts[key].(string)
		return v
	}
	sliceOpt := func(key string) []string {
		raw, exists := opts[key]
		if !exists {
			return nil
		}
		interfaces, ok := raw.([]interface{})
		if !ok {
			return nil
		}
		var result []string
		for _, item := range interfaces {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}

	switch state.Type {
	case "wildcard":
		// Resolve GitHub token from config file (token not stored in state for security)
		token := ""
		if Cfg != nil {
			if t := Cfg.GetAPIKey("github"); t != "" {
				token = t
			}
		}

		if err := wf.Run(wf.RunConfig{
			Domain:          state.Target,
			ResultDir:       state.ResultDir,
			Mode:            Mode,
			Verbose:         Verbose,
			Cfg:             Cfg,
			SkipAmass:       boolOpt("skip_amass"),
			SkipNuclei:      boolOpt("skip_nuclei"),
			SkipNaabu:       boolOpt("skip_naabu"),
			SkipCrawl:       boolOpt("skip_crawl"),
			SkipTakeovers:   boolOpt("skip_takeovers"),
			SkipDalfox:      boolOpt("skip_dalfox"),
			SkipUncover:     boolOpt("skip_uncover"),
			SkipTlsx:        boolOpt("skip_tlsx"),
			SkipX8:          boolOpt("skip_x8"),
			SkipShuffleDNS:  boolOpt("skip_shuffledns"),
			SkipHakrawler:   boolOpt("skip_hakrawler"),
			SkipFingerprint: boolOpt("skip_fingerprint"),
			WordlistPath:    strOpt("wordlist"),
			DNSWordlistPath: strOpt("dns_wordlist"),
			ResolversPath:   strOpt("resolvers"),
			GitHubToken:     token,
			ResumeScanID:    scanID,
			GenerateReport:  true,
			SaveLog:         boolOpt("save_log"),
			CustomCookie:    strOpt("custom_cookie"),
			CustomHeaders:   sliceOpt("custom_headers"),
			CustomToken:     strOpt("custom_token"),
			AutoProxy:       boolOpt("auto_proxy"),
		}); err != nil {
			logger.Error("Resume failed: %v", err)
		}

	default:
		logger.Error("Resume not supported for scan type: %s", state.Type)
		logger.Info("Only wildcard scans support automatic resume.")
	}
}

func runScansDelete(cmd *cobra.Command, args []string) {
	scanID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}

	s, err := database.GetScan(scanID)
	if err != nil {
		logger.Error("Scan not found: %v", err)
		return
	}

	logger.Warning("This will delete scan #%d for %s", s.ID, s.Target)
	logger.Warning("This action cannot be undone.")

	logger.Info("Deleting scan data...")

	if err := database.DeleteScan(scanID); err != nil {
		logger.Error("Failed to delete scan #%d: %v", scanID, err)
		return
	}

	logger.Success("Scan #%d deleted", scanID)
}
