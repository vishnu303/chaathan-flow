// Package cli – Company command
//
// This file is intentionally thin. It only contains the cobra command
// definition, flag wiring, and a single call into pkg/company_flow.Run().
// All scan logic lives in the company_flow package.
package cli

import (
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	cf "github.com/vishnu303/chaathan/pkg/company_flow"
	"github.com/vishnu303/chaathan/pkg/logger"
)

// ─────────────────────────────────────────────────────────────
// CLI flags (package-level for cobra binding)
// ─────────────────────────────────────────────────────────────

var (
	targetCompany    string
	skipCloudEnum    bool
	skipMetabigor    bool
	skipAmassIntel   bool
	companyProxy     string
	companyRateLimit int
)

// ─────────────────────────────────────────────────────────────
// Cobra command
// ─────────────────────────────────────────────────────────────

var companyCmd = &cobra.Command{
	Use:   "company",
	Short: "Run the Company Reconnaissance Workflow",
	Long: `
Runs a full organization discovery workflow:
  1. ASN & Network Range Discovery (Metabigor) [Optional, --skip-metabigor]
  2. Root Domain Discovery (Amass Intel) [Optional, --skip-amass-intel]
  3. Cloud Enumeration (Cloud Enum) [Optional, --skip-cloud-enum]

All results are stored in the database for querying and reporting.
`,
	Run: runCompany,
}

func init() {
	companyCmd.Flags().StringVarP(&targetCompany, "name", "n", "", "Target Company Name (required)")
	companyCmd.Flags().BoolVar(&skipMetabigor, "skip-metabigor", false, "Skip Metabigor ASN discovery")
	companyCmd.Flags().BoolVar(&skipAmassIntel, "skip-amass-intel", false, "Skip Amass Intel root domain discovery")
	companyCmd.Flags().BoolVar(&skipCloudEnum, "skip-cloud-enum", false, "Skip Cloud Enum cloud enumeration")
	companyCmd.Flags().StringVar(&companyProxy, "proxy", "", "Proxy URL for target-facing tools (e.g., socks5://127.0.0.1:9050)")
	companyCmd.Flags().IntVar(&companyRateLimit, "rate-limit", 0, "Global rate limit (requests/sec) for all tools (0 = per-tool defaults)")
	companyCmd.Flags().BoolVar(&saveLog, "log", false, "Save scan output to ~/.chaathan/logs/ (plain text, ANSI stripped)")
	companyCmd.MarkFlagRequired("name")
	rootCmd.AddCommand(companyCmd)
}

// ─────────────────────────────────────────────────────────────
// runCompany — cobra handler
// ─────────────────────────────────────────────────────────────

func runCompany(cmd *cobra.Command, args []string) {
	if strings.TrimSpace(targetCompany) == "" {
		logger.Error("Company name cannot be empty")
		return
	}

	// Sanitize target to prevent path traversal and filesystem issues
	safe := sanitizeTarget(targetCompany)
	if safe == "" {
		logger.Error("Company name is invalid after sanitization")
		return
	}

	resultDir, err := CreateOutputDir(safe)
	if err != nil {
		logger.Error("Error creating output dir: %v", err)
		return
	}

	overrideConfigOverrides(companyProxy, companyRateLimit)

	if err := cf.Run(cf.RunConfig{
		Company:        safe,
		ResultDir:      resultDir,
		Mode:           Mode,
		Verbose:        Verbose,
		Cfg:            Cfg,
		SkipMetabigor:  skipMetabigor,
		SkipAmassIntel: skipAmassIntel,
		SkipCloudEnum:  skipCloudEnum,
		SaveLog:        saveLog,
	}); err != nil {
		logger.Error("Company scan failed: %v", err)
	}
}

// sanitizeTarget makes a company name safe for use as a directory name.
// It strips path separators, collapses whitespace, and removes leading dots
// to prevent path traversal (e.g. "../../etc/passwd") or hidden directories.
func sanitizeTarget(name string) string {
	// Remove path separators
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")

	// Clean the path (resolves .., removes trailing slashes)
	name = filepath.Base(filepath.Clean(name))

	// Strip leading dots (prevents hidden directories)
	name = strings.TrimLeft(name, ".")

	// Collapse internal whitespace to single space, trim edges
	fields := strings.Fields(name)
	name = strings.Join(fields, " ")

	return name
}
