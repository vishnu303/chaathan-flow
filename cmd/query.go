package cmd

import (
	"chaathan/pkg/database"
	"chaathan/pkg/logger"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query scan results",
	Long:  `Search and filter results from completed scans.`,
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

var (
	queryLiveOnly   bool
	querySeverity   string
	queryOutputJSON bool
	queryGrep       string
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

	queryCmd.AddCommand(querySubdomainsCmd)
	queryCmd.AddCommand(queryPortsCmd)
	queryCmd.AddCommand(queryVulnsCmd)
	queryCmd.AddCommand(queryUrlsCmd)
	queryCmd.AddCommand(queryEndpointsCmd)
	rootCmd.AddCommand(queryCmd)
}

func runQuerySubdomains(cmd *cobra.Command, args []string) {
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

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
		data, _ := json.MarshalIndent(subs, "", "  ")
		fmt.Println(string(data))
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
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

	ports, err := database.GetPorts(scanID)
	if err != nil {
		logger.Error("Failed to query ports: %v", err)
		return
	}

	if queryOutputJSON {
		data, _ := json.MarshalIndent(ports, "", "  ")
		fmt.Println(string(data))
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
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

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
		data, _ := json.MarshalIndent(vulns, "", "  ")
		fmt.Println(string(data))
		return
	}

	if len(vulns) == 0 {
		logger.Info("No vulnerabilities found.")
		return
	}

	// Group by severity for display
	for _, v := range vulns {
		sevColor := colorSeverity(v.Severity)
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
		fmt.Printf("  %s: %d\n", colorSeverity(sev), count)
	}
}

func runQueryUrls(cmd *cobra.Command, args []string) {
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

	urls, err := database.GetURLs(scanID)
	if err != nil {
		logger.Error("Failed to query URLs: %v", err)
		return
	}

	if queryOutputJSON {
		data, _ := json.MarshalIndent(urls, "", "  ")
		fmt.Println(string(data))
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
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", truncateURL(u.URL, 60), u.StatusCode, title, u.Source)
	}
	w.Flush()

	logger.Info("\nTotal: %d URLs", len(urls))
}

func runQueryEndpoints(cmd *cobra.Command, args []string) {
	var scanID int64
	fmt.Sscanf(args[0], "%d", &scanID)

	endpoints, err := database.GetEndpoints(scanID)
	if err != nil {
		logger.Error("Failed to query endpoints: %v", err)
		return
	}

	if queryOutputJSON {
		data, _ := json.MarshalIndent(endpoints, "", "  ")
		fmt.Println(string(data))
		return
	}

	if len(endpoints) == 0 {
		logger.Info("No endpoints found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ENDPOINT\tMETHOD\tSOURCE")
	for _, e := range endpoints {
		fmt.Fprintf(w, "%s\t%s\t%s\n", truncateURL(e.URL, 80), e.Method, e.Source)
	}
	w.Flush()

	logger.Info("\nTotal: %d endpoints", len(endpoints))
}

func truncateURL(url string, max int) string {
	if len(url) <= max {
		return url
	}
	return url[:max-3] + "..."
}
