package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/scan"
)

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
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) {
	logger.Info("Chaathan Status Dashboard")

	// ── Recent Scans ──
	logger.Section("Recent Scans")
	scans, err := database.GetRecentScans(10)
	if err != nil || len(scans) == 0 {
		logger.Info("No scans found yet. Run: chaathan scan -d example.com")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tTARGET\tTYPE\tSTATUS\tAGE")
		fmt.Fprintln(w, "──\t──────\t────\t──────\t───")
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

			status := s.Status
			switch status {
			case "completed":
				status = "✅ completed"
			case "running":
				status = "🔄 running"
			case "failed":
				status = "❌ failed"
			case "cancelled":
				status = "⚠️  cancelled"
			}

			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", s.ID, s.Target, s.Type, status, ageStr)
		}
		w.Flush()
	}

	// ── Running Scans with Progress ──
	home, _ := os.UserHomeDir()
	stateDir := filepath.Join(home, ".chaathan", "state")
	stateMgr := scan.NewManager(stateDir)

	states, _ := stateMgr.ListResumableScans()
	if len(states) > 0 {
		fmt.Println()
		logger.Section("Running Scans")
		for _, state := range states {
			completed := len(state.CompletedSteps)
			total := state.TotalSteps
			if total == 0 {
				total = 1
			}
			pct := float64(completed) / float64(total) * 100

			// Build progress bar
			barWidth := 30
			filled := int(float64(barWidth) * pct / 100)
			bar := ""
			for i := 0; i < barWidth; i++ {
				if i < filled {
					bar += "█"
				} else {
					bar += "░"
				}
			}

			logger.Info("Scan #%d — %s", state.ScanID, state.Target)
			logger.Info("  Progress: [%s] %.0f%% (%d/%d steps)", bar, pct, completed, total)

			// Show current step index
			if state.CurrentStep < len(scan.WildcardSteps) {
				logger.Info("  Current:  %s", scan.WildcardSteps[state.CurrentStep].Description)
			}
		}
	}

	// ── Quick Stats ──
	fmt.Println()
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
	fmt.Println()
	logger.Info("Quick commands:")
	logger.Info("  chaathan scan -d example.com        # Start a new scan")
	logger.Info("  chaathan scans list                 # List all scans")
	logger.Info("  chaathan query vulns <scan_id>      # View vulnerabilities")
	logger.Info("  chaathan tools check                # Check installed tools")
}
