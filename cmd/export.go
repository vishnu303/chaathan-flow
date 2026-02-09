package cmd

import (
	"chaathan/pkg/database"
	"chaathan/pkg/logger"
	"chaathan/pkg/utils"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export [scan_id]",
	Short: "Export scan results to text files",
	Long: `Export all results from a scan to organized text files.

Output files created:
  - final_subdomains.txt          All discovered subdomains
  - live_subdomains.txt           Only live/responsive subdomains  
  - live_subdomains_with_ip.txt   Live subdomains with IP addresses
  - open_ports.txt                Open ports (host:port format)
  - open_ports_detailed.txt       Ports with protocol and service info
  - all_urls.txt                  All discovered URLs
  - urls_200.txt                  Only URLs returning 200 OK
  - urls_with_status.txt          URLs with status codes
  - urls_with_titles.txt          URLs with page titles
  - vulnerabilities.txt           All vulnerabilities summary
  - vulnerabilities_detailed.txt  Full vulnerability details
  - vulnerabilities_critical_high.txt  Critical/High severity only
  - vulnerable_hosts.txt          Unique hosts with vulnerabilities
  - endpoints.txt                 All discovered endpoints
  - endpoints_interesting.txt     API/admin/interesting endpoints
  - SUMMARY.txt                   Overall scan summary
`,
	Args: cobra.ExactArgs(1),
	Run:  runExport,
}

var (
	exportOutput string
)

func init() {
	exportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Output directory (default: scan's result directory)")
	rootCmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) {
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

	// Get scan info
	scan, err := database.GetScan(scanID)
	if err != nil {
		logger.Error("Scan not found: %v", err)
		return
	}

	// Determine output directory
	outputDir := exportOutput
	if outputDir == "" {
		outputDir = scan.ResultDir
		if outputDir == "" {
			home, _ := os.UserHomeDir()
			outputDir = filepath.Join(home, ".chaathan", "exports", fmt.Sprintf("scan_%d", scanID))
		}
	}

	logger.Info("Exporting scan #%d for %s", scanID, scan.Target)
	logger.Info("Output directory: %s", outputDir)

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.Error("Failed to create output directory: %v", err)
		return
	}

	// Export all results
	logger.Section("Exporting Results")

	// Subdomains
	logger.SubStep("Exporting subdomains...")
	if err := utils.ExportSubdomains(scanID, outputDir); err != nil {
		logger.Warning("Subdomains export failed: %v", err)
	} else {
		logger.Success("final_subdomains.txt created")
	}

	// Live subdomains
	logger.SubStep("Exporting live subdomains...")
	if err := utils.ExportLiveSubdomains(scanID, outputDir); err != nil {
		logger.Warning("Live subdomains export failed: %v", err)
	} else {
		logger.Success("live_subdomains.txt created")
	}

	// Ports
	logger.SubStep("Exporting ports...")
	if err := utils.ExportPorts(scanID, outputDir); err != nil {
		logger.Warning("Ports export failed: %v", err)
	} else {
		logger.Success("open_ports.txt created")
	}

	// URLs
	logger.SubStep("Exporting URLs...")
	if err := utils.ExportURLs(scanID, outputDir); err != nil {
		logger.Warning("URLs export failed: %v", err)
	} else {
		logger.Success("all_urls.txt created")
	}

	// Vulnerabilities
	logger.SubStep("Exporting vulnerabilities...")
	if err := utils.ExportVulnerabilities(scanID, outputDir); err != nil {
		logger.Warning("Vulnerabilities export failed: %v", err)
	} else {
		logger.Success("vulnerabilities.txt created")
	}

	// Endpoints
	logger.SubStep("Exporting endpoints...")
	if err := utils.ExportEndpoints(scanID, outputDir); err != nil {
		logger.Warning("Endpoints export failed: %v", err)
	} else {
		logger.Success("endpoints.txt created")
	}

	// Summary
	logger.SubStep("Creating summary...")
	if err := utils.ExportSummary(scanID, outputDir, scan.Target); err != nil {
		logger.Warning("Summary creation failed: %v", err)
	} else {
		logger.Success("SUMMARY.txt created")
	}

	logger.Section("Export Complete")
	logger.Success("All files saved to: %s", outputDir)

	// List created files
	logger.Info("\nCreated files:")
	files, _ := os.ReadDir(outputDir)
	for _, f := range files {
		if !f.IsDir() {
			info, _ := f.Info()
			logger.SubStep("%s (%d bytes)", f.Name(), info.Size())
		}
	}
}
