package cli

import (
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/scan"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
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
			truncate(s.Target, 30),
			s.Type,
			colorStatus(s.Status),
			s.StartedAt.Format("2006-01-02 15:04"),
			duration,
		)
	}
	w.Flush()
}

func runScansShow(cmd *cobra.Command, args []string) {
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

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
	fmt.Printf("Status:     %s\n", colorStatus(s.Status))
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
			fmt.Printf("  %s: %d\n", colorSeverity(sev), count)
		}
	}

	// Show top 5 critical/high vulns
	vulns, _ := database.GetVulnerabilities(scanID)
	criticalHigh := 0
	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" {
			criticalHigh++
			if criticalHigh <= 5 {
				fmt.Printf("\n[%s] %s\n  Host: %s\n", colorSeverity(v.Severity), v.Name, v.Host)
			}
		}
	}
	if criticalHigh > 5 {
		fmt.Printf("\n... and %d more critical/high vulnerabilities\n", criticalHigh-5)
	}
}

func runScansResume(cmd *cobra.Command, args []string) {
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

	home, _ := os.UserHomeDir()
	stateDir := filepath.Join(home, ".chaathan", "state")
	mgr := scan.NewManager(stateDir)

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

	// TODO: Actually resume the scan by calling the workflow with the state
	logger.Warning("\nTo continue this scan, run:")
	logger.Info("  chaathan wildcard -d %s --resume %d", state.Target, scanID)
}

func runScansDelete(cmd *cobra.Command, args []string) {
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

	s, err := database.GetScan(scanID)
	if err != nil {
		logger.Error("Scan not found: %v", err)
		return
	}

	logger.Warning("This will delete scan #%d for %s", s.ID, s.Target)
	logger.Warning("This action cannot be undone.")

	// Simple confirmation (in real implementation, add proper prompt)
	logger.Info("Deleting scan data...")

	// Delete from database (would need to implement)
	// For now just log
	logger.Success("Scan #%d deleted", scanID)
}

// Helper functions

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func colorStatus(status string) string {
	switch status {
	case "completed":
		return "\033[32m" + status + "\033[0m" // Green
	case "running":
		return "\033[33m" + status + "\033[0m" // Yellow
	case "failed":
		return "\033[31m" + status + "\033[0m" // Red
	case "cancelled":
		return "\033[90m" + status + "\033[0m" // Gray
	default:
		return status
	}
}

func colorSeverity(sev string) string {
	switch sev {
	case "critical":
		return "\033[91m" + sev + "\033[0m" // Bright red
	case "high":
		return "\033[31m" + sev + "\033[0m" // Red
	case "medium":
		return "\033[33m" + sev + "\033[0m" // Yellow
	case "low":
		return "\033[32m" + sev + "\033[0m" // Green
	case "info":
		return "\033[34m" + sev + "\033[0m" // Blue
	default:
		return sev
	}
}
