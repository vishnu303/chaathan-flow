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
	logger.TableHeader(w, "DOMAIN", "LIVE", "IP", "SOURCE")
	for _, s := range subs {
		live := logger.Dim + "-" + logger.Reset
		if s.IsLive {
			live = logger.BrightGreen + "yes" + logger.Reset
		}
		logger.TableRow(w, s.Domain, live, s.IPAddress, s.Source)
	}
	w.Flush()

	logger.Print("\n")
	logger.Result(len(subs), "subdomains")
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
	logger.TableHeader(w, "HOST", "PORT", "PROTOCOL", "SERVICE")
	for _, p := range ports {
		logger.TableRow(w, p.Host, fmt.Sprintf("%d", p.Port), p.Protocol, p.Service)
	}
	w.Flush()

	logger.Print("\n")
	logger.Result(len(ports), "open ports")
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

	// Group by severity for display (critical → info, then any others)
	sevOrder := []string{"critical", "high", "medium", "low", "info"}
	groups := make(map[string][]database.Vulnerability)
	for _, v := range vulns {
		groups[v.Severity] = append(groups[v.Severity], v)
	}
	ordered := make([]string, 0, len(groups))
	for _, sev := range sevOrder {
		if len(groups[sev]) > 0 {
			ordered = append(ordered, sev)
		}
	}
	known := make(map[string]bool, len(sevOrder))
	for _, sev := range sevOrder {
		known[sev] = true
	}
	for sev := range groups {
		if !known[sev] {
			ordered = append(ordered, sev)
		}
	}

	logger.Print("\n")
	for _, sev := range ordered {
		logger.Print("  %s%s%s %s(%d)%s\n",
			logger.SevColor(sev)+logger.Bold, strings.ToUpper(sev), logger.Reset,
			logger.Dim, len(groups[sev]), logger.Reset)
		for _, v := range groups[sev] {
			details := v.Host
			if v.URL != "" {
				details += " · " + v.URL
			}
			logger.Print("  %s●%s %s%s%s %s%s%s\n",
				logger.SevColor(sev), logger.Reset,
				logger.Bold, v.Name, logger.Reset,
				logger.Dim, details, logger.Reset)
		}
		logger.Print("\n")
	}

	// Summary
	counts, _ := database.CountVulnerabilities(scanID)
	logger.Section("Summary")
	printed := make(map[string]bool)
	for _, sev := range sevOrder {
		if counts[sev] > 0 {
			logger.ResultSev(sev, counts[sev], "%s", sev)
			printed[sev] = true
		}
	}
	for sev, count := range counts {
		if !printed[sev] && count > 0 {
			logger.ResultSev(sev, count, "%s", sev)
		}
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
	logger.TableHeader(w, "URL", "STATUS", "TITLE", "SOURCE")
	for _, u := range urls {
		title := u.Title
		if len(title) > 40 {
			title = title[:37] + "..."
		}
		logger.TableRow(w, utils.TruncateURL(u.URL, 60), fmt.Sprintf("%d", u.StatusCode), title, u.Source)
	}
	w.Flush()

	logger.Print("\n")
	logger.Result(len(urls), "URLs")
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
	logger.TableHeader(w, "ENDPOINT", "METHOD", "SOURCE")
	for _, e := range endpoints {
		logger.TableRow(w, utils.TruncateURL(e.URL, 80), e.Method, e.Source)
	}
	w.Flush()

	logger.Print("\n")
	logger.Result(len(endpoints), "endpoints")
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

	targets = filterROITargets(targets)

	if queryLimit > 0 && len(targets) > queryLimit {
		targets = targets[:queryLimit]
	}

	if len(targets) == 0 {
		logger.Info("No ROI-ranked URLs found.")
		return
	}

	if queryScope {
		printROIScope(targets)
		return
	}

	if queryOutputJSON {
		writeJSONOrPrint(targets, queryOutputFile)
		return
	}

	printROITable(targets)
	printROIDetails(targets)

	logger.Info("Showing %d ranked targets (max 3 per host)", len(targets))
}

// filterROITargets applies the --grep pattern filter to ROI targets
func filterROITargets(targets []database.URLROI) []database.URLROI {
	if queryGrep == "" {
		return targets
	}
	var filtered []database.URLROI
	pattern := strings.ToLower(queryGrep)
	for _, t := range targets {
		if strings.Contains(strings.ToLower(t.URL), pattern) ||
			strings.Contains(strings.ToLower(t.Title), pattern) ||
			strings.Contains(strings.ToLower(strings.Join(t.InterestingTerms, " ")), pattern) {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// printROIScope outputs raw URLs only, one per line (scope file mode)
func printROIScope(targets []database.URLROI) {
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
}

// printROITable renders the ROI summary table
func printROITable(targets []database.URLROI) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	logger.TableHeader(w, "SCORE", "N-SCORE", "CONF", "STATUS", "URL", "SURFACES")
	for _, t := range targets {
		surfaces := "-"
		if len(t.AttackSurfaces) > 0 {
			surfaces = strings.Join(t.AttackSurfaces, ",")
			if len(surfaces) > 30 {
				surfaces = surfaces[:27] + "..."
			}
		}
		nScore := fmt.Sprintf("%d", t.NormalizedScore)
		switch {
		case t.NormalizedScore >= 70:
			nScore = logger.BrightGreen + nScore + logger.Reset
		case t.NormalizedScore >= 40:
			nScore = logger.BrightYellow + nScore + logger.Reset
		}
		logger.TableRow(w,
			fmt.Sprintf("%d", t.Score),
			nScore,
			t.Confidence,
			fmt.Sprintf("%d", t.StatusCode),
			utils.TruncateURL(t.URL, 65),
			surfaces,
		)
	}
	w.Flush()
}

// printROIDetails renders the per-target detail sections
func printROIDetails(targets []database.URLROI) {
	for _, t := range targets {
		logger.Section("ROI %d (N:%d %s) - %s", t.Score, t.NormalizedScore, t.Confidence, t.URL)
		if t.Title != "" {
			logger.Print("  %sTitle:%s %s\n", logger.Dim, logger.Reset, t.Title)
		}
		if len(t.AttackSurfaces) > 0 {
			logger.Print("  %sAttack surfaces:%s %s\n", logger.Dim, logger.Reset, strings.Join(t.AttackSurfaces, ", "))
		}
		if len(t.Tech) > 0 {
			logger.Print("  %sTech:%s %s\n", logger.Dim, logger.Reset, strings.Join(t.Tech, ", "))
		}
		if len(t.Reasons) > 0 {
			logger.Print("  %sWhy it ranked:%s\n", logger.Dim, logger.Reset)
			for _, reason := range t.Reasons {
				logger.Print("    %s▸%s %s\n", logger.Dim, logger.Reset, reason)
			}
		}
		logger.Print("\n")
	}
}
