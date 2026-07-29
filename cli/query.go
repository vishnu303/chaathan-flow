package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/tui"
	"github.com/vishnu303/chaathan/utils"
)

var queryCmd = &cobra.Command{
	Use:   "query [scan_id]",
	Short: "Query scan results",
	Long:  `Search and filter results from completed scans. Starts the interactive TUI console by default, or accepts subcommands for non-interactive text/JSON exports.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var presetScanID int64 = 0
		if len(args) > 0 {
			var ok bool
			presetScanID, ok = parseScanIDArg(args[0])
			if !ok {
				return
			}
		}

		if err := tui.StartQueryConsole(presetScanID); err != nil {
			logger.Error("Failed to start TUI query console: %v", err)
		}
	},
}

var querySubdomainsCmd = &cobra.Command{
	Use:   "subdomains [scan_id]",
	Short: "List subdomains from a scan",
	Args:  cobra.ExactArgs(1),
	Run:   runQuerySubdomains,
}

var queryPortsCmd = &cobra.Command{
	Use:   "ports [scan_id]",
	Short: "List open ports from a scan",
	Args:  cobra.ExactArgs(1),
	Run:   runQueryPorts,
}

var queryVulnsCmd = &cobra.Command{
	Use:   "vulns [scan_id]",
	Short: "List vulnerabilities from a scan",
	Args:  cobra.ExactArgs(1),
	Run:   runQueryVulns,
}

var queryUrlsCmd = &cobra.Command{
	Use:   "urls [scan_id]",
	Short: "List URLs from a scan",
	Args:  cobra.ExactArgs(1),
	Run:   runQueryUrls,
}

var queryEndpointsCmd = &cobra.Command{
	Use:   "endpoints [scan_id]",
	Short: "List endpoints from a scan",
	Args:  cobra.ExactArgs(1),
	Run:   runQueryEndpoints,
}

var queryROICmd = &cobra.Command{
	Use:   "roi [scan_id]",
	Short: "Rank URLs by likely testing ROI",
	Args:  cobra.ExactArgs(1),
	Run:   runQueryROI,
}

var (
	queryLiveOnly   bool
	querySeverity   string
	queryOutputJSON bool
	queryGrep       string
	queryLimit      int
	queryOutputFile string
	queryScope      bool
)

func init() {
	// Common flags
	querySubdomainsCmd.Flags().BoolVar(&queryLiveOnly, "live", false, "Show only live subdomains")
	querySubdomainsCmd.Flags().BoolVar(&queryOutputJSON, "json", false, "Output as JSON")
	querySubdomainsCmd.Flags().StringVar(&queryGrep, "grep", "", "Filter results by pattern")

	queryVulnsCmd.Flags().StringVar(&querySeverity, "severity", "", "Filter by severity (critical,high,medium,low,info)")
	queryVulnsCmd.Flags().BoolVar(&queryOutputJSON, "json", false, "Output as JSON")

	queryPortsCmd.Flags().BoolVar(&queryOutputJSON, "json", false, "Output as JSON")
	queryUrlsCmd.Flags().BoolVar(&queryOutputJSON, "json", false, "Output as JSON")
	queryEndpointsCmd.Flags().BoolVar(&queryOutputJSON, "json", false, "Output as JSON")
	queryROICmd.Flags().BoolVar(&queryOutputJSON, "json", false, "Output as JSON")
	queryROICmd.Flags().IntVar(&queryLimit, "limit", 20, "Maximum number of ranked URLs to show")
	queryROICmd.Flags().StringVar(&queryGrep, "grep", "", "Filter ROI targets by pattern")
	queryROICmd.Flags().StringVarP(&queryOutputFile, "output", "o", "", "Write ROI results to a file (best with --json)")
	queryROICmd.Flags().BoolVar(&queryScope, "scope", false, "Output as plain URLs only (scope file for downstream tools)")

	queryCmd.AddCommand(querySubdomainsCmd)
	queryCmd.AddCommand(queryPortsCmd)
	queryCmd.AddCommand(queryVulnsCmd)
	queryCmd.AddCommand(queryUrlsCmd)
	queryCmd.AddCommand(queryEndpointsCmd)
	queryCmd.AddCommand(queryROICmd)
	rootCmd.AddCommand(queryCmd)
}

func runQuerySubdomains(cmd *cobra.Command, args []string) {
	scanID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}

	var subs []database.Subdomain
	var err error

	if queryLiveOnly {
		subs, err = database.GetLiveSubdomains(scanID)
	} else {
		subs, err = database.GetSubdomains(scanID)
	}

	if err != nil {
		logger.Error("Failed to query subdomains: %v", err)
		return
	}

	// Apply grep filter
	if queryGrep != "" {
		var filtered []database.Subdomain
		for _, s := range subs {
			if strings.Contains(s.Domain, queryGrep) {
				filtered = append(filtered, s)
			}
		}
		subs = filtered
	}

	if queryOutputJSON {
		writeJSONOrPrint(subs, "")
		return
	}

	if len(subs) == 0 {
		logger.Info("No subdomains found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tLIVE\tIP\tSOURCE")
	for _, s := range subs {
		live := "-"
		if s.IsLive {
			live = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Domain, live, s.IPAddress, s.Source)
	}
	w.Flush()

	logger.Info("\nTotal: %d subdomains", len(subs))
}

func runQueryPorts(cmd *cobra.Command, args []string) {
	scanID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}

	ports, err := database.GetPorts(scanID)
	if err != nil {
		logger.Error("Failed to query ports: %v", err)
		return
	}

	if queryOutputJSON {
		writeJSONOrPrint(ports, "")
		return
	}

	if len(ports) == 0 {
		logger.Info("No open ports found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tPORT\tPROTOCOL\tSERVICE")
	for _, p := range ports {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", p.Host, p.Port, p.Protocol, p.Service)
	}
	w.Flush()

	logger.Info("\nTotal: %d open ports", len(ports))
}

func runQueryVulns(cmd *cobra.Command, args []string) {
	scanID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}

	var vulns []database.Vulnerability
	var err error

	if querySeverity != "" {
		vulns, err = database.GetVulnerabilitiesBySeverity(scanID, querySeverity)
	} else {
		vulns, err = database.GetVulnerabilities(scanID)
	}

	if err != nil {
		logger.Error("Failed to query vulnerabilities: %v", err)
		return
	}

	if queryOutputJSON {
		writeJSONOrPrint(vulns, "")
		return
	}

	if len(vulns) == 0 {
		logger.Info("No vulnerabilities found.")
		return
	}

	// Group by severity for display
	for _, v := range vulns {
		sevColor := logger.ColorSeverity(v.Severity)
		fmt.Printf("[%s] %s\n", sevColor, v.Name)
		fmt.Printf("  Host: %s\n", v.Host)
		if v.URL != "" {
			fmt.Printf("  URL: %s\n", v.URL)
		}
		if v.TemplateID != "" {
			fmt.Printf("  Template: %s\n", v.TemplateID)
		}
		fmt.Println()
	}

	// Summary
	counts, _ := database.CountVulnerabilities(scanID)
	logger.Section("Summary")
	for sev, count := range counts {
		fmt.Printf("  %s: %d\n", logger.ColorSeverity(sev), count)
	}
}

func runQueryUrls(cmd *cobra.Command, args []string) {
	scanID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}

	urls, err := database.GetURLs(scanID)
	if err != nil {
		logger.Error("Failed to query URLs: %v", err)
		return
	}

	if queryOutputJSON {
		writeJSONOrPrint(urls, "")
		return
	}

	if len(urls) == 0 {
		logger.Info("No URLs found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "URL\tSTATUS\tTITLE\tSOURCE")
	for _, u := range urls {
		title := u.Title
		if len(title) > 40 {
			title = title[:37] + "..."
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", utils.TruncateURL(u.URL, 60), u.StatusCode, title, u.Source)
	}
	w.Flush()

	logger.Info("\nTotal: %d URLs", len(urls))
}

func runQueryEndpoints(cmd *cobra.Command, args []string) {
	scanID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}

	endpoints, err := database.GetEndpoints(scanID)
	if err != nil {
		logger.Error("Failed to query endpoints: %v", err)
		return
	}

	if queryOutputJSON {
		writeJSONOrPrint(endpoints, "")
		return
	}

	if len(endpoints) == 0 {
		logger.Info("No endpoints found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ENDPOINT\tMETHOD\tSOURCE")
	for _, e := range endpoints {
		fmt.Fprintf(w, "%s\t%s\t%s\n", utils.TruncateURL(e.URL, 80), e.Method, e.Source)
	}
	w.Flush()

	logger.Info("\nTotal: %d endpoints", len(endpoints))
}

func runQueryROI(cmd *cobra.Command, args []string) {
	scanID, ok := parseScanIDArg(args[0])
	if !ok {
		return
	}

	targets, err := database.GetRankedURLs(scanID, 0)
	if err != nil {
		logger.Error("Failed to compute ROI targets: %v", err)
		return
	}

	if queryGrep != "" {
		var filtered []database.URLROI
		pattern := strings.ToLower(queryGrep)
		for _, t := range targets {
			if strings.Contains(strings.ToLower(t.URL), pattern) ||
				strings.Contains(strings.ToLower(t.Title), pattern) ||
				strings.Contains(strings.ToLower(strings.Join(t.InterestingTerms, " ")), pattern) {
				filtered = append(filtered, t)
			}
		}
		targets = filtered
	}

	if queryLimit > 0 && len(targets) > queryLimit {
		targets = targets[:queryLimit]
	}

	if len(targets) == 0 {
		logger.Info("No ROI-ranked URLs found.")
		return
	}

	if queryScope {
		// Scope mode: output raw URLs only, one per line
		var sb strings.Builder
		for _, t := range targets {
			sb.WriteString(t.URL)
			sb.WriteByte('\n')
		}
		if queryOutputFile != "" {
			if err := os.WriteFile(queryOutputFile, []byte(sb.String()), 0644); err != nil {
				logger.Error("Failed to write scope file: %v", err)
				return
			}
			logger.Success("Scope file saved: %s (%d URLs)", queryOutputFile, len(targets))
			return
		}
		fmt.Print(sb.String())
		return
	}

	if queryOutputJSON {
		writeJSONOrPrint(targets, queryOutputFile)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SCORE\tN-SCORE\tCONF\tSTATUS\tURL\tSURFACES")
	for _, t := range targets {
		surfaces := "-"
		if len(t.AttackSurfaces) > 0 {
			surfaces = strings.Join(t.AttackSurfaces, ",")
			if len(surfaces) > 30 {
				surfaces = surfaces[:27] + "..."
			}
		}
		fmt.Fprintf(w, "%d\t%d\t%s\t%d\t%s\t%s\n",
			t.Score,
			t.NormalizedScore,
			t.Confidence,
			t.StatusCode,
			utils.TruncateURL(t.URL, 65),
			surfaces,
		)
	}
	w.Flush()

	for _, t := range targets {
		logger.Section("ROI %d (N:%d %s) - %s", t.Score, t.NormalizedScore, t.Confidence, t.URL)
		if t.Title != "" {
			fmt.Printf("Title: %s\n", t.Title)
		}
		if len(t.AttackSurfaces) > 0 {
			fmt.Printf("Attack surfaces: %s\n", strings.Join(t.AttackSurfaces, ", "))
		}
		if len(t.Tech) > 0 {
			fmt.Printf("Tech: %s\n", strings.Join(t.Tech, ", "))
		}
		if len(t.Reasons) > 0 {
			fmt.Println("Why it ranked:")
			for _, reason := range t.Reasons {
				fmt.Printf("  - %s\n", reason)
			}
		}
		fmt.Println()
	}

	logger.Info("Showing %d ranked targets (max 3 per host)", len(targets))
}
