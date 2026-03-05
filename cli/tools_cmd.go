package cli

import (
	"fmt"
	"os"
	"os/exec"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
)

// allTools defines the complete list of tools Chaathan uses with metadata
var allTools = []struct {
	Name        string
	Category    string
	Description string
	Required    bool
}{
	// Subdomain Enumeration
	{"subfinder", "Enum", "Passive subdomain discovery", true},
	{"assetfinder", "Enum", "Passive subdomain discovery", true},
	{"sublist3r", "Enum", "Passive subdomain discovery (Python)", false},
	{"amass", "Enum", "Active DNS enumeration & brute-force", false},
	{"alterx", "Enum", "Smart subdomain permutation", false},

	// DNS & Resolution
	{"dnsx", "DNS", "DNS resolution & record lookup", true},
	{"shuffledns", "DNS", "DNS brute-force with massdns", false},

	// Web Probing
	{"httpx", "Probe", "HTTP probing & tech detection", true},
	{"tlsx", "Probe", "TLS certificate analysis & SAN extraction", false},
	{"naabu", "Probe", "Port scanning (SYN/TCP)", false},

	// URL Discovery
	{"waybackurls", "URLs", "Wayback Machine URL extraction", false},
	{"gau", "URLs", "Historical URL discovery", false},
	{"katana", "Crawl", "Web crawling & spidering", false},
	{"gospider", "Crawl", "Web crawling & spidering", false},

	// Analysis
	{"linkfinder", "Analysis", "JavaScript endpoint extraction (Python)", false},
	{"cewl", "Analysis", "Custom wordlist generation", false},

	// Fuzzing & Scanning
	{"ffuf", "Fuzz", "Web fuzzer & directory brute-force", false},
	{"nuclei", "Vuln", "Template-based vulnerability scanner", true},
	{"subjack", "Vuln", "Subdomain takeover detection", false},
	{"dalfox", "Vuln", "XSS vulnerability scanner", false},

	// Recon
	{"uncover", "Recon", "Shodan/Censys/Fofa search dorking", false},
	{"metabigor", "Recon", "ASN & org discovery", false},
	{"github-subdomains", "Recon", "GitHub subdomain scraping", false},
	{"cloud_enum", "Cloud", "Cloud infrastructure enumeration (Python)", false},
}

var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "Manage and check external tools",
	Long:  "List, check, and manage the external security tools used by Chaathan.",
}

var toolsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tools and their categories",
	Run:   runToolsList,
}

var toolsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check which tools are installed",
	Run:   runToolsCheck,
}

func init() {
	toolsCmd.AddCommand(toolsListCmd)
	toolsCmd.AddCommand(toolsCheckCmd)
	rootCmd.AddCommand(toolsCmd)
}

func runToolsList(cmd *cobra.Command, args []string) {
	logger.Section("Chaathan Tool Suite")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TOOL\tCATEGORY\tREQUIRED\tDESCRIPTION")
	fmt.Fprintln(w, "────\t────────\t────────\t───────────")

	for _, t := range allTools {
		req := ""
		if t.Required {
			req = "✓"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Name, t.Category, req, t.Description)
	}
	w.Flush()

	fmt.Println()
	logger.Info("Total: %d tools (%d required)", len(allTools), countRequired())
	logger.Info("Run 'chaathan tools check' to see installation status")
}

func runToolsCheck(cmd *cobra.Command, args []string) {
	logger.Section("Tool Installation Check")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TOOL\tSTATUS\tPATH")
	fmt.Fprintln(w, "────\t──────\t────")

	installed := 0
	missing := 0
	missingRequired := 0

	for _, t := range allTools {
		path, err := exec.LookPath(t.Name)
		if err != nil {
			// Also check common Python script locations
			if t.Name == "sublist3r" || t.Name == "linkfinder" || t.Name == "cloud_enum" {
				path, err = exec.LookPath(t.Name + ".py")
			}
		}

		if err != nil {
			status := "❌ missing"
			if t.Required {
				status = "🔴 MISSING (required)"
				missingRequired++
			}
			fmt.Fprintf(w, "%s\t%s\t-\n", t.Name, status)
			missing++
		} else {
			fmt.Fprintf(w, "%s\t✅ installed\t%s\n", t.Name, path)
			installed++
		}
	}
	w.Flush()

	fmt.Println()
	logger.Info("Installed: %d/%d", installed, len(allTools))

	if missingRequired > 0 {
		logger.Error("%d required tool(s) missing! Run: chaathan setup", missingRequired)
	} else if missing > 0 {
		logger.Warning("%d optional tool(s) missing. Run 'chaathan setup' to install all.", missing)
	} else {
		logger.Success("All tools installed!")
	}
}

func countRequired() int {
	count := 0
	for _, t := range allTools {
		if t.Required {
			count++
		}
	}
	return count
}
