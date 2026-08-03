package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/scan"
	"github.com/vishnu303/chaathan/pkg/tui"
	"github.com/vishnu303/chaathan/utils"
)

var showPlainStatus bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show a quick status dashboard",
	Long: `Displays an overview of Chaathan's status including:
- Recent scans and their status
- Running scans with progress
- Summary statistics
- Available tool check`,
	Run: runStatus,
}

func init() {
	statusCmd.Flags().BoolVar(&showPlainStatus, "plain", false, "Output plain text instead of starting the interactive TUI dashboard")
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) {
	if !showPlainStatus {
		if err := tui.StartDashboard(); err != nil {
			if resumeSig, ok := err.(tui.ResumeSignal); ok {
				resumeScanByID(resumeSig.ScanID)
				return
			}
			logger.Error("Failed to start TUI dashboard: %v", err)
			// Fallback to plain text status on dashboard failure
		} else {
			return
		}
	}

	logger.ScanHeader("Status", "Dashboard", 0)

	// ── Recent Scans ──
	logger.Section("Recent Scans")
	scans, err := database.GetRecentScans(10)
	if err != nil || len(scans) == 0 {
		logger.Info("No scans found yet. Run: chaathan scan -d example.com")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		logger.TableHeader(w, "ID", "TARGET", "TYPE", "STATUS", "AGE")
		for _, s := range scans {
			age := time.Since(s.StartedAt).Round(time.Minute)
			var ageStr string
			if age.Hours() > 24 {
				ageStr = fmt.Sprintf("%.0fd ago", age.Hours()/24)
			} else if age.Hours() >= 1 {
				ageStr = fmt.Sprintf("%.0fh ago", age.Hours())
			} else {
				ageStr = fmt.Sprintf("%.0fm ago", age.Minutes())
			}

			logger.TableRow(w, fmt.Sprintf("%d", s.ID), s.Target, s.Type, logger.ColorStatus(s.Status), ageStr)
		}
		w.Flush()
	}

	// ── Running Scans with Progress ──
	stateMgr := scan.NewManager(paths.StateDir())

	states, _ := stateMgr.ListResumableScans()
	if len(states) > 0 {
		logger.Print("\n")
		logger.Section("Running Scans")
		for _, state := range states {
			completed := len(state.CompletedSteps)
			total := state.TotalSteps
			if total == 0 {
				total = 1
			}
			pct := float64(completed) / float64(total) * 100

			logger.Info("Scan #%d — %s", state.ScanID, state.Target)
			logger.Info("  Progress: %s %.0f%% (%d/%d steps)", logger.Bar(pct, utils.ProgressBarWidth), pct, completed, total)

			// Show current step index
			if state.CurrentStep < len(scan.WildcardSteps) {
				logger.Info("  Current:  %s", scan.WildcardSteps[state.CurrentStep].Description)
			}
		}
	}

	// ── Quick Stats ──
	logger.Print("\n")
	logger.Section("Overall Statistics")
	totalScans, _ := database.GetTotalScansCount()
	totalSubs, _ := database.GetTotalSubdomainsCount()
	totalVulns, _ := database.GetTotalVulnerabilitiesCount()
	totalPorts, _ := database.GetTotalPortsCount()

	logger.Info("Total Scans:           %d", totalScans)
	logger.Info("Total Subdomains:      %d", totalSubs)
	logger.Info("Total Open Ports:      %d", totalPorts)
	logger.Info("Total Vulnerabilities: %d", totalVulns)

	// ── Usage Hints ──
	logger.Print("\n")
	logger.Info("Quick commands:")
	logger.Info("  chaathan wildcard -d example.com    # Start a new scan")
	logger.Info("  chaathan company -n \"Company Inc\"   # Company discovery")
	logger.Info("  chaathan scans list                 # List all scans")
	logger.Info("  chaathan query vulns <scan_id>      # View vulnerabilities")
	logger.Info("  chaathan tools check                # Check installed tools")
}
