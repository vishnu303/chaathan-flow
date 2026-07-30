package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
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
	logger.TableHeader(w, "ID", "TARGET", "TYPE", "STATUS", "STARTED", "DURATION")

	var mgr *scan.Manager
	for _, s := range scans {
		duration := "-"
		if s.CompletedAt != nil {
			duration = s.CompletedAt.Sub(s.StartedAt).Round(time.Second).String()
		} else if s.Status == "running" {
			duration = time.Since(s.StartedAt).Round(time.Second).String() + " (running)"
		}

		status := logger.ColorStatus(s.Status)
		if s.Status == "running" {
			if mgr == nil {
				mgr = scan.NewManager(paths.StateDir())
			}
			if st, err := mgr.LoadState(s.ID); err == nil {
				pct := st.Progress()
				status += " " + logger.Bar(pct, 8) + fmt.Sprintf(" %d%%", int(pct))
			}
		}

		logger.TableRow(w,
			fmt.Sprintf("%d", s.ID),
			utils.Truncate(s.Target, 30),
			s.Type,
			status,
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

	lines := []string{
		fmt.Sprintf("%s%-10s%s %s", logger.Dim, "Target", logger.Reset, s.Target),
		fmt.Sprintf("%s%-10s%s %s", logger.Dim, "Type", logger.Reset, s.Type),
		fmt.Sprintf("%s%-10s%s %s", logger.Dim, "Status", logger.Reset, logger.ColorStatus(s.Status)),
		fmt.Sprintf("%s%-10s%s %s", logger.Dim, "Started", logger.Reset, s.StartedAt.Format("2006-01-02 15:04:05")),
	}
	if s.CompletedAt != nil {
		lines = append(lines,
			fmt.Sprintf("%s%-10s%s %s", logger.Dim, "Completed", logger.Reset, s.CompletedAt.Format("2006-01-02 15:04:05")),
			fmt.Sprintf("%s%-10s%s %s", logger.Dim, "Duration", logger.Reset, s.CompletedAt.Sub(s.StartedAt).Round(time.Second)),
		)
	}
	lines = append(lines, fmt.Sprintf("%s%-10s%s %s", logger.Dim, "Results", logger.Reset, s.ResultDir))
	logger.Box(fmt.Sprintf("SCAN #%d", s.ID), lines)

	logger.Section("Statistics")
	logger.Result(stats.LiveSubdomains, "live subdomains (%d total)", stats.TotalSubdomains)
	logger.Result(stats.TotalPorts, "open ports")
	logger.Result(stats.TotalURLs, "URLs discovered")
	logger.Result(stats.TotalEndpoints, "endpoints discovered")

	if len(stats.Vulnerabilities) > 0 {
		logger.Section("Vulnerabilities")
		sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
		sevs := make([]string, 0, len(stats.Vulnerabilities))
		for sev := range stats.Vulnerabilities {
			sevs = append(sevs, sev)
		}
		sort.Slice(sevs, func(i, j int) bool {
			ri, oki := sevRank[sevs[i]]
			rj, okj := sevRank[sevs[j]]
			if !oki {
				ri = 99
			}
			if !okj {
				rj = 99
			}
			return ri < rj
		})
		for _, sev := range sevs {
			logger.ResultSev(sev, stats.Vulnerabilities[sev], "%s findings", sev)
		}
	}

	// Show top 5 critical/high vulns
	vulns, _ := database.GetVulnerabilities(scanID)
	var top []database.Vulnerability
	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" {
			top = append(top, v)
		}
	}
	if len(top) > 0 {
		logger.Section("Top Critical/High Findings")
		for i, v := range top {
			if i >= 5 {
				break
			}
			logger.Print("  %s●%s %s%s%s %s· %s%s\n",
				logger.SevColor(v.Severity), logger.Reset,
				logger.Bold, v.Name, logger.Reset,
				logger.Dim, v.Host, logger.Reset)
		}
		if len(top) > 5 {
			logger.Print("  %s… and %d more critical/high vulnerabilities%s\n", logger.Dim, len(top)-5, logger.Reset)
		}
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
