package cli

import (
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete scan data from database",
	Long:  `Delete scans and related data from the database when you're done with a target.`,
}

var deleteTargetCmd = &cobra.Command{
	Use:   "target [domain]",
	Short: "Delete all data for a specific target",
	Long: `Delete all scans and related data (subdomains, ports, URLs, vulnerabilities, endpoints) 
for a specific target domain when you're done working on it.

This helps keep your database clean and saves disk space.`,
	Args: cobra.ExactArgs(1),
	Run:  runDeleteTarget,
}

var deleteScanCmd = &cobra.Command{
	Use:   "scan [scan_id]",
	Short: "Delete a specific scan by ID",
	Args:  cobra.ExactArgs(1),
	Run:   runDeleteScan,
}

var deleteOldCmd = &cobra.Command{
	Use:   "old [days]",
	Short: "Delete scans older than specified days",
	Args:  cobra.ExactArgs(1),
	Run:   runDeleteOld,
}

var deleteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all targets in database",
	Run:   runDeleteList,
}

var (
	deleteFiles  bool
	deleteVacuum bool
)

func init() {
	deleteTargetCmd.Flags().BoolVar(&deleteFiles, "files", false, "Also delete result files from disk")
	deleteTargetCmd.Flags().BoolVar(&deleteVacuum, "vacuum", true, "Run VACUUM after deletion to reclaim space")

	deleteScanCmd.Flags().BoolVar(&deleteFiles, "files", false, "Also delete result files from disk")

	deleteOldCmd.Flags().BoolVar(&deleteVacuum, "vacuum", true, "Run VACUUM after deletion")

	deleteCmd.AddCommand(deleteTargetCmd)
	deleteCmd.AddCommand(deleteScanCmd)
	deleteCmd.AddCommand(deleteOldCmd)
	deleteCmd.AddCommand(deleteListCmd)
	rootCmd.AddCommand(deleteCmd)
}

func runDeleteTarget(cmd *cobra.Command, args []string) {
	target := args[0]

	// Get stats for this target
	stats, err := database.GetTargetStats(target)
	if err != nil {
		logger.Error("Failed to get target stats: %v", err)
		return
	}

	if stats["scans"] == 0 {
		logger.Warning("No scans found for target: %s", target)
		return
	}

	// Show what will be deleted
	logger.Info("Deleting data for: %s", target)
	logger.Info("  Scans: %d, Subdomains: %d, Ports: %d, URLs: %d, Vulns: %d",
		stats["scans"], stats["subdomains"], stats["ports"], stats["urls"], stats["vulnerabilities"])

	// Delete from database
	deleted, err := database.DeleteScansByTarget(target)
	if err != nil {
		logger.Error("Failed to delete: %v", err)
		return
	}

	logger.Success("Deleted %d scan(s) for target: %s", deleted, target)

	// Optionally delete files
	if deleteFiles {
		logger.Info("Deleting result files...")
		deleteResultFiles(target)
	}

	// Vacuum database
	if deleteVacuum {
		logger.Info("Reclaiming disk space...")
		if err := database.VacuumDatabase(); err != nil {
			logger.Warning("VACUUM failed: %v", err)
		}
	}

	logger.Success("Cleanup complete for: %s", target)
}

func runDeleteScan(cmd *cobra.Command, args []string) {
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

	// Get scan info
	scan, err := database.GetScan(scanID)
	if err != nil {
		logger.Error("Scan not found: %v", err)
		return
	}

	logger.Info("Deleting scan #%d for %s...", scanID, scan.Target)

	// Delete from database
	if err := database.DeleteScan(scanID); err != nil {
		logger.Error("Failed to delete: %v", err)
		return
	}

	logger.Success("Scan #%d deleted", scanID)

	// Optionally delete files
	if deleteFiles && scan.ResultDir != "" {
		logger.Info("Deleting result files: %s", scan.ResultDir)
		if err := os.RemoveAll(scan.ResultDir); err != nil {
			logger.Warning("Failed to delete files: %v", err)
		} else {
			logger.Success("Result files deleted")
		}
	}
}

func runDeleteOld(cmd *cobra.Command, args []string) {
	var days int
	fmt.Sscanf(args[0], "%d", &days)

	if days < 1 {
		logger.Error("Days must be at least 1")
		return
	}

	logger.Info("Deleting scans older than %d days...", days)

	// Delete old scans
	deleted, err := database.PurgeOldScans(days)
	if err != nil {
		logger.Error("Failed to purge old scans: %v", err)
		return
	}

	if deleted == 0 {
		logger.Info("No scans older than %d days found.", days)
		return
	}

	logger.Success("Deleted %d old scan(s)", deleted)

	// Vacuum database
	if deleteVacuum {
		logger.Info("Reclaiming disk space...")
		if err := database.VacuumDatabase(); err != nil {
			logger.Warning("VACUUM failed: %v", err)
		}
	}
}

func runDeleteList(cmd *cobra.Command, args []string) {
	targets, err := database.GetAllTargets()
	if err != nil {
		logger.Error("Failed to get targets: %v", err)
		return
	}

	if len(targets) == 0 {
		logger.Info("No targets found in database.")
		return
	}

	logger.Section("Targets in Database")

	for _, target := range targets {
		stats, _ := database.GetTargetStats(target)
		logger.Info("%-40s  [%d scans, %d subs, %d vulns]",
			target,
			stats["scans"],
			stats["subdomains"],
			stats["vulnerabilities"])
	}

	logger.Info("\nTotal: %d targets", len(targets))
	logger.Info("\nTo delete a target's data:")
	logger.Info("  chaathan delete target <domain>")
}

func deleteResultFiles(target string) {
	// Get all scans for this target to find result directories
	scans, err := database.GetScansByTarget(target)
	if err != nil {
		logger.Warning("Could not get scan directories: %v", err)
		return
	}

	for _, scan := range scans {
		if scan.ResultDir != "" {
			if _, err := os.Stat(scan.ResultDir); err == nil {
				if err := os.RemoveAll(scan.ResultDir); err != nil {
					logger.Warning("Failed to delete %s: %v", scan.ResultDir, err)
				} else {
					logger.SubStep("Deleted: %s", scan.ResultDir)
				}
			}
		}
	}

	// Also try the default location
	home, _ := os.UserHomeDir()
	defaultDir := filepath.Join(home, ".chaathan", "scans", target)
	if _, err := os.Stat(defaultDir); err == nil {
		if err := os.RemoveAll(defaultDir); err != nil {
			logger.Warning("Failed to delete %s: %v", defaultDir, err)
		} else {
			logger.SubStep("Deleted: %s", defaultDir)
		}
	}
}
