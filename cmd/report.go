package cmd

import (
	"chaathan/pkg/logger"
	"chaathan/pkg/report"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate reports from scan data",
	Long:  `Generate reports in various formats (Markdown, JSON, HTML, Text) from completed scans.`,
}

var reportGenerateCmd = &cobra.Command{
	Use:   "generate [scan_id]",
	Short: "Generate a report for a scan",
	Args:  cobra.ExactArgs(1),
	Run:   runReportGenerate,
}

var (
	reportFormat string
	reportOutput string
)

func init() {
	reportGenerateCmd.Flags().StringVarP(&reportFormat, "format", "f", "markdown", "Report format: markdown, json, html, text")
	reportGenerateCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "Output file path (default: auto-generated)")

	reportCmd.AddCommand(reportGenerateCmd)
	rootCmd.AddCommand(reportCmd)
}

func runReportGenerate(cmd *cobra.Command, args []string) {
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

	logger.Info("Generating report for scan #%d...", scanID)

	// Generate report
	rpt, err := report.Generate(scanID)
	if err != nil {
		logger.Error("Failed to generate report: %v", err)
		return
	}

	// Determine output path
	outputPath := reportOutput
	if outputPath == "" {
		home, _ := os.UserHomeDir()
		reportsDir := filepath.Join(home, ".chaathan", "reports")
		os.MkdirAll(reportsDir, 0755)
		
		ext := getExtension(reportFormat)
		timestamp := time.Now().Format("20060102_150405")
		outputPath = filepath.Join(reportsDir, fmt.Sprintf("scan_%d_%s%s", scanID, timestamp, ext))
	}

	// Export
	format := report.ReportFormat(reportFormat)
	if err := rpt.Export(format, outputPath); err != nil {
		logger.Error("Failed to export report: %v", err)
		return
	}

	logger.Success("Report saved to: %s", outputPath)
	
	// Print quick summary
	logger.Info("\nSummary: %s", rpt.QuickSummary())
}

func getExtension(format string) string {
	switch format {
	case "markdown":
		return ".md"
	case "json":
		return ".json"
	case "html":
		return ".html"
	case "text":
		return ".txt"
	default:
		return ".md"
	}
}
