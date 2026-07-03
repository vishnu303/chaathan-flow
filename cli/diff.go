package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
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

// ─────────────────────────────────────────────────────────────
// Generic diff helper (F11)
// ─────────────────────────────────────────────────────────────

// diffResult holds the output of diffSets: items present in only the new
// set (added) and items present in only the old set (removed).
type diffResult[T any] struct {
	Added   []T
	Removed []T
}

// diffSets computes the added and removed items between two slices.
// The key function extracts a comparable identity from each element.
// This eliminates the 4× repeated set-building pattern that was in
// diffSubdomains, diffPorts, diffVulns, and diffURLs.
func diffSets[T any, K comparable](old, new []T, key func(T) K) diffResult[T] {
	oldSet := make(map[K]struct{}, len(old))
	for _, item := range old {
		oldSet[key(item)] = struct{}{}
	}
	newSet := make(map[K]struct{}, len(new))
	for _, item := range new {
		newSet[key(item)] = struct{}{}
	}

	var r diffResult[T]
	for _, item := range new {
		if _, exists := oldSet[key(item)]; !exists {
			r.Added = append(r.Added, item)
		}
	}
	for _, item := range old {
		if _, exists := newSet[key(item)]; !exists {
			r.Removed = append(r.Removed, item)
		}
	}
	return r
}

// ─────────────────────────────────────────────────────────────
// runDiff — main diff command handler
// ─────────────────────────────────────────────────────────────

func runDiff(cmd *cobra.Command, args []string) {
	oldID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}
	newID, ok := parseScanIDArg(args[1])
	if !ok {
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

	diffSubdomains(oldID, newID)
	diffPorts(oldID, newID)
	diffVulns(oldID, newID)
	diffURLs(oldID, newID)
}

// ─────────────────────────────────────────────────────────────
// Per-entity diff functions (now using diffSets)
// ─────────────────────────────────────────────────────────────

func diffSubdomains(oldID, newID int64) {
	oldSubs, err := database.GetSubdomains(oldID)
	if err != nil {
		logger.Warning("Failed to get subdomains for scan #%d: %v", oldID, err)
	}
	newSubs, err := database.GetSubdomains(newID)
	if err != nil {
		logger.Warning("Failed to get subdomains for scan #%d: %v", newID, err)
	}

	d := diffSets(oldSubs, newSubs, func(s database.Subdomain) string { return s.Domain })

	logger.Section("Subdomains")
	logger.Info("Old: %d | New: %d | Added: %d | Removed: %d", len(oldSubs), len(newSubs), len(d.Added), len(d.Removed))

	if len(d.Added) > 0 {
		fmt.Println()
		logger.Success("New subdomains:")
		for _, s := range d.Added {
			fmt.Printf("  + %s\n", s.Domain)
		}
	}

	if len(d.Removed) > 0 {
		fmt.Println()
		logger.Warning("Removed subdomains:")
		for _, s := range d.Removed {
			fmt.Printf("  - %s\n", s.Domain)
		}
	}

	if len(d.Added) == 0 && len(d.Removed) == 0 {
		logger.Info("  No changes")
	}
	fmt.Println()
}

func diffPorts(oldID, newID int64) {
	oldPorts, err := database.GetPorts(oldID)
	if err != nil {
		logger.Warning("Failed to get ports for scan #%d: %v", oldID, err)
	}
	newPorts, err := database.GetPorts(newID)
	if err != nil {
		logger.Warning("Failed to get ports for scan #%d: %v", newID, err)
	}

	type portKey struct {
		Host string
		Port int
	}
	d := diffSets(oldPorts, newPorts, func(p database.Port) portKey { return portKey{p.Host, p.Port} })

	logger.Section("Open Ports")
	logger.Info("Old: %d | New: %d | New ports: %d", len(oldPorts), len(newPorts), len(d.Added))

	if len(d.Added) > 0 {
		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  + HOST\tPORT\tPROTOCOL\tSERVICE")
		for _, p := range d.Added {
			fmt.Fprintf(w, "  + %s\t%d\t%s\t%s\n", p.Host, p.Port, p.Protocol, p.Service)
		}
		w.Flush()
	}

	if len(d.Added) == 0 {
		logger.Info("  No new ports")
	}
	fmt.Println()
}

func diffVulns(oldID, newID int64) {
	oldVulns, err := database.GetVulnerabilities(oldID)
	if err != nil {
		logger.Warning("Failed to get vulnerabilities for scan #%d: %v", oldID, err)
	}
	newVulns, err := database.GetVulnerabilities(newID)
	if err != nil {
		logger.Warning("Failed to get vulnerabilities for scan #%d: %v", newID, err)
	}

	type vulnKey struct {
		Host       string
		TemplateID string
	}
	d := diffSets(oldVulns, newVulns, func(v database.Vulnerability) vulnKey { return vulnKey{v.Host, v.TemplateID} })

	logger.Section("Vulnerabilities")
	logger.Info("Old: %d | New: %d | New findings: %d", len(oldVulns), len(newVulns), len(d.Added))

	if len(d.Added) > 0 {
		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  + SEVERITY\tHOST\tNAME\tTEMPLATE")
		for _, v := range d.Added {
			fmt.Fprintf(w, "  + %s\t%s\t%s\t%s\n", logger.EmojiSeverity(v.Severity), v.Host, v.Name, v.TemplateID)
		}
		w.Flush()
	}

	if len(d.Added) == 0 {
		logger.Info("  No new vulnerabilities")
	}
	fmt.Println()
}

func diffURLs(oldID, newID int64) {
	oldURLs, err := database.GetURLs(oldID)
	if err != nil {
		logger.Warning("Failed to get URLs for scan #%d: %v", oldID, err)
	}
	newURLs, err := database.GetURLs(newID)
	if err != nil {
		logger.Warning("Failed to get URLs for scan #%d: %v", newID, err)
	}

	d := diffSets(oldURLs, newURLs, func(u database.URL) string { return u.URL })

	logger.Section("URLs")
	logger.Info("Old: %d | New: %d | New URLs: %d", len(oldURLs), len(newURLs), len(d.Added))
	if len(d.Added) == 0 {
		logger.Info("  No new URLs")
	}
}
