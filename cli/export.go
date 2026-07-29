package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/ingest"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/utils"
)

var exportCmd = &cobra.Command{
	Use:   "export [scan_id]",
	Short: "Export scan results to text files",
	Long: `Export all results from a scan to organized text files.

Output files created:
  - final_subdomains.txt             All discovered subdomains
  - live_subdomains.txt              Live/responsive subdomains (with IP when known)
  - open_ports.txt                   Open ports (host:port with protocol/service)
  - all_urls.txt                     All discovered URLs with status codes
  - urls_200.txt                     Only URLs returning 200 OK
  - vulnerabilities.txt              All vulnerabilities (detailed)
  - vulnerabilities_critical_high.txt  Critical/High severity only
  - endpoints.txt                    All discovered endpoints (with method)
  - endpoints_interesting.txt        API/admin/interesting endpoints
  - SUMMARY.txt                      Overall scan summary
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
	scanID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}

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
			outputDir = filepath.Join(paths.ChaathanHome(), "exports", fmt.Sprintf("scan_%d", scanID))
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
	if err := ingest.ExportSubdomains(scanID, outputDir); err != nil {
		logger.Warning("Subdomains export failed: %v", err)
	} else {
		logger.Success("%s created", utils.FileFinalSubdomains)
	}

	// Live subdomains
	logger.SubStep("Exporting live subdomains...")
	if err := ingest.ExportLiveSubdomains(scanID, outputDir); err != nil {
		logger.Warning("Live subdomains export failed: %v", err)
	} else {
		logger.Success("%s created", utils.FileLiveSubdomains)
	}

	// Ports
	logger.SubStep("Exporting ports...")
	if err := ingest.ExportPorts(scanID, outputDir); err != nil {
		logger.Warning("Ports export failed: %v", err)
	} else {
		logger.Success("%s created", utils.FileOpenPorts)
	}

	// URLs
	logger.SubStep("Exporting URLs...")
	if err := ingest.ExportURLs(scanID, outputDir); err != nil {
		logger.Warning("URLs export failed: %v", err)
	} else {
		logger.Success("%s created", utils.FileAllURLs)
	}

	// Vulnerabilities
	logger.SubStep("Exporting vulnerabilities...")
	if err := ingest.ExportVulnerabilities(scanID, outputDir); err != nil {
		logger.Warning("Vulnerabilities export failed: %v", err)
	} else {
		logger.Success("%s created", utils.FileVulnerabilities)
	}

	// Endpoints
	logger.SubStep("Exporting endpoints...")
	if err := ingest.ExportEndpoints(scanID, outputDir); err != nil {
		logger.Warning("Endpoints export failed: %v", err)
	} else {
		logger.Success("%s created", utils.FileEndpoints)
	}

	// Summary
	logger.SubStep("Creating summary...")
	if err := ingest.ExportSummary(scanID, outputDir, scan.Target); err != nil {
		logger.Warning("Summary creation failed: %v", err)
	} else {
		logger.Success("%s created", utils.FileSummary)
	}

	logger.Section("Export Complete")
	logger.Success("All files saved to: %s", outputDir)

	// List created files
	logger.Info("\nCreated files:")
	files, _ := os.ReadDir(outputDir)
	for _, f := range files {
		if !f.IsDir() {
			info, err := f.Info()
			if err != nil {
				logger.SubStep("%s", f.Name())
			} else {
				logger.SubStep("%s (%d bytes)", f.Name(), info.Size())
			}
		}
	}
}
