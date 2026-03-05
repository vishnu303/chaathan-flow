package cli

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan-flow/pkg/config"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/runner"
	"github.com/vishnu303/chaathan-flow/pkg/tools"
)

var (
	targetCompany string
)

var companyCmd = &cobra.Command{
	Use:   "company",
	Short: "Run the Company Reconnaissance Workflow",
	Long: `
Runs a full organization discovery workflow:
1. ASN & Network Range Discovery (Metabigor)
2. Root Domain Discovery (Amass Intel, Reverse Whois)
3. Cloud Enumeration (Cloud Enum)
`,
	Run: runCompany,
}

func init() {
	companyCmd.Flags().StringVarP(&targetCompany, "name", "n", "", "Target Company Name (required)")
	companyCmd.MarkFlagRequired("name")
	rootCmd.AddCommand(companyCmd)
}

func runCompany(cmd *cobra.Command, args []string) {
	// Validate input
	if strings.TrimSpace(targetCompany) == "" {
		logger.Error("Company name cannot be empty")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Warning("Received interrupt signal. Stopping...")
		cancel()
	}()

	logger.Info("Starting Company Workflow for: %s", targetCompany)

	resultDir, err := CreateOutputDir(targetCompany)
	if err != nil {
		logger.Error("Error creating output dir: %v", err)
		return
	}

	r := runner.New(Mode, Verbose)
	var toolsCfg *config.ToolsConfig
	if Cfg != nil {
		toolsCfg = &Cfg.Tools
	}
	tb := tools.New(r, toolsCfg)

	// Step 1: ASN Discovery
	logger.Section("Step 1: ASN Discovery")
	asnOut := filepath.Join(resultDir, "asn_ranges.txt")
	logger.SubStep("Running Metabigor...")
	if err := tb.RunMetabigorNet(ctx, targetCompany, asnOut); err != nil {
		logger.Error("Metabigor failed: %v", err)
	}

	if ctx.Err() != nil {
		return
	}

	// Step 2: Root Domain Discovery
	logger.Section("Step 2: Root Domain Discovery")
	logger.SubStep("(Placeholder) Extracting domains from ASN data...")

	// Step 3: Cloud Enumeration
	logger.Section("Step 3: Cloud Enumeration")
	cloudOut := filepath.Join(resultDir, "cloud_enum.json")
	logger.SubStep("Running Cloud Enum...")
	if err := tb.RunCloudEnum(ctx, targetCompany, cloudOut); err != nil {
		logger.Warning("Cloud Enum failed (is it installed?): %v", err)
	}

	logger.Section("Company Workflow Completed")

}
