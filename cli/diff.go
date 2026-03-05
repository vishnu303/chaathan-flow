package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
)

var diffCmd = &cobra.Command{
	Use:   "diff <scan_id_1> <scan_id_2>",
	Short: "Compare two scans to find new/removed assets",
	Long: `Compares two scans of the same target and shows:
- New subdomains discovered in the newer scan
- Removed subdomains (no longer resolving)
- New open ports
- New vulnerabilities
- New URLs and endpoints

Useful for continuous monitoring — run periodic scans and diff to spot changes.`,
	Args: cobra.ExactArgs(2),
	Run:  runDiff,
}

func init() {
	rootCmd.AddCommand(diffCmd)
}

func runDiff(cmd *cobra.Command, args []string) {
	oldID, err := utils.ParseScanID(args[0])
	if err != nil {
		logger.Error("%v", err)
		return
	}
	newID, err := utils.ParseScanID(args[1])
	if err != nil {
		logger.Error("%v", err)
		return
	}

	// Get scan info
	oldScan, err := database.GetScan(oldID)
	if err != nil {
		logger.Error("Scan #%d not found: %v", oldID, err)
		return
	}
	newScan, err := database.GetScan(newID)
	if err != nil {
		logger.Error("Scan #%d not found: %v", newID, err)
		return
	}

	logger.Section("Scan Diff: #%d vs #%d", oldID, newID)
	logger.Info("Old: #%d — %s (%s)", oldScan.ID, oldScan.Target, oldScan.StartedAt.Format("2006-01-02 15:04"))
	logger.Info("New: #%d — %s (%s)", newScan.ID, newScan.Target, newScan.StartedAt.Format("2006-01-02 15:04"))
	fmt.Println()

	// ── Subdomain Diff ──
	diffSubdomains(oldID, newID)

	// ── Port Diff ──
	diffPorts(oldID, newID)

	// ── Vulnerability Diff ──
	diffVulns(oldID, newID)

	// ── URL Diff ──
	diffURLs(oldID, newID)
}

func diffSubdomains(oldID, newID int64) {
	oldSubs, _ := database.GetSubdomains(oldID)
	newSubs, _ := database.GetSubdomains(newID)

	oldSet := make(map[string]bool)
	for _, s := range oldSubs {
		oldSet[s.Domain] = true
	}
	newSet := make(map[string]bool)
	for _, s := range newSubs {
		newSet[s.Domain] = true
	}

	var added, removed []string
	for _, s := range newSubs {
		if !oldSet[s.Domain] {
			added = append(added, s.Domain)
		}
	}
	for _, s := range oldSubs {
		if !newSet[s.Domain] {
			removed = append(removed, s.Domain)
		}
	}

	logger.Section("Subdomains")
	logger.Info("Old: %d | New: %d | Added: %d | Removed: %d", len(oldSubs), len(newSubs), len(added), len(removed))

	if len(added) > 0 {
		fmt.Println()
		logger.Success("New subdomains:")
		for _, s := range added {
			fmt.Printf("  + %s\n", s)
		}
	}

	if len(removed) > 0 {
		fmt.Println()
		logger.Warning("Removed subdomains:")
		for _, s := range removed {
			fmt.Printf("  - %s\n", s)
		}
	}

	if len(added) == 0 && len(removed) == 0 {
		logger.Info("  No changes")
	}
	fmt.Println()
}

func diffPorts(oldID, newID int64) {
	oldPorts, _ := database.GetPorts(oldID)
	newPorts, _ := database.GetPorts(newID)

	type portKey struct {
		Host string
		Port int
	}

	oldSet := make(map[portKey]bool)
	for _, p := range oldPorts {
		oldSet[portKey{p.Host, p.Port}] = true
	}

	var added []database.Port
	for _, p := range newPorts {
		if !oldSet[portKey{p.Host, p.Port}] {
			added = append(added, p)
		}
	}

	logger.Section("Open Ports")
	logger.Info("Old: %d | New: %d | New ports: %d", len(oldPorts), len(newPorts), len(added))

	if len(added) > 0 {
		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  + HOST\tPORT\tPROTOCOL\tSERVICE")
		for _, p := range added {
			fmt.Fprintf(w, "  + %s\t%d\t%s\t%s\n", p.Host, p.Port, p.Protocol, p.Service)
		}
		w.Flush()
	}

	if len(added) == 0 {
		logger.Info("  No new ports")
	}
	fmt.Println()
}

func diffVulns(oldID, newID int64) {
	oldVulns, _ := database.GetVulnerabilities(oldID)
	newVulns, _ := database.GetVulnerabilities(newID)

	type vulnKey struct {
		Host       string
		TemplateID string
	}

	oldSet := make(map[vulnKey]bool)
	for _, v := range oldVulns {
		oldSet[vulnKey{v.Host, v.TemplateID}] = true
	}

	var added []database.Vulnerability
	for _, v := range newVulns {
		if !oldSet[vulnKey{v.Host, v.TemplateID}] {
			added = append(added, v)
		}
	}

	logger.Section("Vulnerabilities")
	logger.Info("Old: %d | New: %d | New findings: %d", len(oldVulns), len(newVulns), len(added))

	if len(added) > 0 {
		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  + SEVERITY\tHOST\tNAME\tTEMPLATE")
		for _, v := range added {
			severity := v.Severity
			switch severity {
			case "critical":
				severity = "🔴 CRITICAL"
			case "high":
				severity = "🟠 HIGH"
			case "medium":
				severity = "🟡 MEDIUM"
			case "low":
				severity = "🟢 LOW"
			}
			fmt.Fprintf(w, "  + %s\t%s\t%s\t%s\n", severity, v.Host, v.Name, v.TemplateID)
		}
		w.Flush()
	}

	if len(added) == 0 {
		logger.Info("  No new vulnerabilities")
	}
	fmt.Println()
}

func diffURLs(oldID, newID int64) {
	oldURLs, _ := database.GetURLs(oldID)
	newURLs, _ := database.GetURLs(newID)

	oldSet := make(map[string]bool)
	for _, u := range oldURLs {
		oldSet[u.URL] = true
	}

	newCount := 0
	for _, u := range newURLs {
		if !oldSet[u.URL] {
			newCount++
		}
	}

	logger.Section("URLs")
	logger.Info("Old: %d | New: %d | New URLs: %d", len(oldURLs), len(newURLs), newCount)
	if newCount == 0 {
		logger.Info("  No new URLs")
	}
}
