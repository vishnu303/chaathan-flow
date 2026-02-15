package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vishnu303/chaathan-flow/pkg/database"
	"github.com/vishnu303/chaathan-flow/pkg/logger"
	"github.com/vishnu303/chaathan-flow/pkg/notify"
	"github.com/vishnu303/chaathan-flow/pkg/report"
	"github.com/vishnu303/chaathan-flow/pkg/runner"
	"github.com/vishnu303/chaathan-flow/pkg/scan"
	"github.com/vishnu303/chaathan-flow/pkg/tools"
	"github.com/vishnu303/chaathan-flow/pkg/utils"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	targetDomain   string
	skipAmass      bool
	skipNuclei     bool
	wordlistPath   string
	githubToken    string
	resumeScanID   int64
	generateReport bool
)

var wildcardCmd = &cobra.Command{
	Use:   "wildcard",
	Short: "Run the Wildcard Reconnaissance Workflow",
	Long: `
Runs a full suite of subdomain enumeration and vulnerability scanning tools:

 1. Passive Enumeration (Subfinder, Assetfinder, Sublist3r) [Parallel]
 2. URL Discovery (Waybackurls, GAU) [Parallel]
 3. Active Enumeration (Amass) [Optional, can be slow]
 4. GitHub Subdomain Discovery [Requires GITHUB_TOKEN]
 5. Consolidation & DNS Resolution (DNSx)
 6. Live Web Probing (Httpx)
 7. Port Scanning (Naabu)
 8. Web Crawling (Katana, GoSpider) [Parallel]
 9. JavaScript Analysis (LinkFinder)
10. Wordlist Generation (CeWL) [Optional]
11. Directory Fuzzing (ffuf) [Optional, requires wordlist]
12. Vulnerability Scanning (Nuclei)

All results are stored in a SQLite database for querying and reporting.
`,
	Run: runWildcard,
}

func init() {
	wildcardCmd.Flags().StringVarP(&targetDomain, "domain", "d", "", "Target domain (required)")
	wildcardCmd.Flags().BoolVar(&skipAmass, "skip-amass", false, "Skip Amass (slow but thorough)")
	wildcardCmd.Flags().BoolVar(&skipNuclei, "skip-nuclei", false, "Skip Nuclei vulnerability scanning")
	wildcardCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Wordlist for directory fuzzing (enables ffuf)")
	wildcardCmd.Flags().StringVar(&githubToken, "github-token", "", "GitHub token for GitHub recon (or use GITHUB_TOKEN env)")
	wildcardCmd.Flags().Int64Var(&resumeScanID, "resume", 0, "Resume a previous scan by ID")
	wildcardCmd.Flags().BoolVar(&generateReport, "report", true, "Generate report after scan")
	wildcardCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(wildcardCmd)
}

func runWildcard(cmd *cobra.Command, args []string) {
	startTime := time.Now()

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Warning("Received interrupt signal. Stopping...")
		cancel()
	}()

	// Check for GitHub token in env if not provided via flag
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
		if Cfg != nil {
			token := Cfg.GetAPIKey("github")
			if token != "" {
				githubToken = token
			}
		}
	}

	logger.Info("Starting Wildcard Workflow for: %s", targetDomain)
	logger.Info("Mode: %s", Mode)

	// Setup output directory
	resultDir, err := CreateOutputDir(targetDomain)
	if err != nil {
		logger.Error("Error creating output dir: %v", err)
		return
	}

	// Create scan record in database
	configJSON, _ := json.Marshal(map[string]interface{}{
		"skip_amass":  skipAmass,
		"skip_nuclei": skipNuclei,
		"wordlist":    wordlistPath,
		"github":      githubToken != "",
	})

	dbScan, err := database.CreateScan(targetDomain, "wildcard", resultDir, string(configJSON))
	if err != nil {
		logger.Warning("Failed to create scan record: %v", err)
	}
	scanID := int64(0)
	if dbScan != nil {
		scanID = dbScan.ID
		logger.Info("Scan ID: %d", scanID)
	}

	// Initialize scan state manager
	home, _ := os.UserHomeDir()
	stateDir := filepath.Join(home, ".chaathan", "state")
	stateMgr := scan.NewManager(stateDir)

	scanState, _ := stateMgr.CreateState(scanID, targetDomain, "wildcard", resultDir, configJSON)

	// Setup runner and tools
	r := runner.New(Mode, Verbose)
	tb := tools.New(r)

	// Setup notifier
	var notifier *notify.Notifier
	if Cfg != nil && Cfg.Notifications.Enabled {
		notifier = notify.New(&Cfg.Notifications)
	}

	// =========================================================================
	// Step 1: Passive Enumeration (Parallel)
	// =========================================================================
	logger.Section("Step 1: Passive Subdomain Enumeration")
	stateMgr.MarkStepComplete(scanState, "passive_enum_start")

	var wg sync.WaitGroup
	passiveFiles := []string{
		filepath.Join(resultDir, "subfinder.txt"),
		filepath.Join(resultDir, "assetfinder.txt"),
		filepath.Join(resultDir, "sublist3r.txt"),
	}

	wg.Add(3)
	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Subfinder")
		if err := tb.RunSubfinder(ctx, targetDomain, passiveFiles[0]); err != nil {
			logger.Error("Subfinder failed: %v", err)
		} else {
			logger.SubStep("[Done] Subfinder")
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, passiveFiles[0], "subfinder")
				logger.Info("  Found %d subdomains", count)
			}
		}
	}()

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Assetfinder")
		if err := tb.RunAssetfinder(ctx, targetDomain, passiveFiles[1]); err != nil {
			logger.Error("Assetfinder failed: %v", err)
		} else {
			logger.SubStep("[Done] Assetfinder")
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, passiveFiles[1], "assetfinder")
				logger.Info("  Found %d subdomains", count)
			}
		}
	}()

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Sublist3r")
		if err := tb.RunSublist3r(ctx, targetDomain, passiveFiles[2]); err != nil {
			if Verbose {
				logger.Warning("Sublist3r failed: %v", err)
			}
		} else {
			logger.SubStep("[Done] Sublist3r")
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, passiveFiles[2], "sublist3r")
				logger.Info("  Found %d subdomains", count)
			}
		}
	}()

	wg.Wait()
	stateMgr.MarkStepComplete(scanState, "passive_enum")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 2: URL Discovery (Parallel - Waybackurls + GAU)
	// =========================================================================
	logger.Section("Step 2: Historical URL Discovery")

	waybackOut := filepath.Join(resultDir, "waybackurls.txt")
	gauOut := filepath.Join(resultDir, "gau.txt")

	wg.Add(2)
	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Waybackurls")
		if err := tb.RunWaybackurls(ctx, targetDomain, waybackOut); err != nil {
			if Verbose {
				logger.Warning("Waybackurls failed: %v", err)
			}
		} else {
			logger.SubStep("[Done] Waybackurls")
			if scanID > 0 {
				count, _ := utils.ParseURLsFile(scanID, waybackOut, "waybackurls")
				logger.Info("  Found %d URLs", count)
			}
		}
	}()

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] GAU")
		if err := tb.RunGau(ctx, targetDomain, gauOut); err != nil {
			if Verbose {
				logger.Warning("GAU failed: %v", err)
			}
		} else {
			logger.SubStep("[Done] GAU")
		}
	}()

	wg.Wait()
	stateMgr.MarkStepComplete(scanState, "url_discovery")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 3: Active Enumeration (Amass - Optional)
	// =========================================================================
	amassOut := filepath.Join(resultDir, "amass.txt")
	if !skipAmass {
		logger.Section("Step 3: Active Subdomain Enumeration (Amass)")
		logger.SubStep("Running Amass (this may take a while)...")
		if err := tb.RunAmass(ctx, targetDomain, amassOut); err != nil {
			logger.Error("Amass failed: %v", err)
			stateMgr.MarkStepFailed(scanState, "active_enum", err)
		} else {
			passiveFiles = append(passiveFiles, amassOut)
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, amassOut, "amass")
				logger.Info("  Found %d subdomains", count)
			}
			stateMgr.MarkStepComplete(scanState, "active_enum")
		}
	} else {
		logger.Section("Step 3: Skipping Amass (--skip-amass)")
		stateMgr.MarkStepComplete(scanState, "active_enum")
	}

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 4: GitHub Subdomain Discovery (Optional)
	// =========================================================================
	if githubToken != "" {
		logger.Section("Step 4: GitHub Subdomain Discovery")
		githubSubsOut := filepath.Join(resultDir, "github_subdomains.txt")
		logger.SubStep("Running github-subdomains...")
		if err := tb.RunGithubSubdomains(ctx, targetDomain, githubToken, githubSubsOut); err != nil {
			logger.Warning("GitHub subdomains failed: %v", err)
		} else {
			passiveFiles = append(passiveFiles, githubSubsOut)
			if scanID > 0 {
				count, _ := utils.ParseSubdomainsFile(scanID, githubSubsOut, "github")
				logger.Info("  Found %d subdomains", count)
			}
			logger.SubStep("[Done] GitHub Subdomains")
		}
	} else {
		logger.Section("Step 4: Skipping GitHub Recon (no token provided)")
		logger.Warning("Set GITHUB_TOKEN env var or use --github-token for GitHub recon")
	}
	stateMgr.MarkStepComplete(scanState, "github_recon")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 5: Consolidation & DNS Resolution
	// =========================================================================
	logger.Section("Step 5: Consolidating Subdomains")
	consolidatedSubs := filepath.Join(resultDir, "all_subdomains.txt")
	if err := utils.MergeAndDeduplicate(passiveFiles, consolidatedSubs); err != nil {
		logger.Error("Failed to consolidate files: %v", err)
		finalizeScan(scanID, "failed", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}
	logger.Success("Consolidated list saved to %s", consolidatedSubs)

	// DNS Resolution
	logger.SubStep("Running DNSx for resolution...")
	dnsxOut := filepath.Join(resultDir, "dnsx_resolved.json")
	if err := tb.RunDnsx(ctx, consolidatedSubs, dnsxOut); err != nil {
		logger.Error("DNSx failed: %v", err)
	}
	stateMgr.MarkStepComplete(scanState, "consolidation")
	stateMgr.MarkStepComplete(scanState, "dns_resolution")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 6: Live Web Probing (Httpx)
	// =========================================================================
	logger.Section("Step 6: Live Web Server Probing")
	httpxOut := filepath.Join(resultDir, "httpx_live.json")
	logger.SubStep("Running Httpx...")
	if err := tb.RunHttpx(ctx, consolidatedSubs, httpxOut); err != nil {
		logger.Error("Httpx failed: %v", err)
	} else {
		if scanID > 0 {
			count, _ := utils.ParseHttpxOutput(scanID, httpxOut)
			logger.Info("  Found %d live hosts", count)
		}
	}
	stateMgr.MarkStepComplete(scanState, "http_probing")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 7: Port Scanning (Naabu)
	// =========================================================================
	logger.Section("Step 7: Port Scanning")
	naabuOut := filepath.Join(resultDir, "naabu_ports.txt")
	logger.SubStep("Running Naabu...")
	if err := tb.RunNaabu(ctx, targetDomain, naabuOut); err != nil {
		logger.Error("Naabu failed: %v", err)
	} else {
		if scanID > 0 {
			count, _ := utils.ParseNaabuOutput(scanID, naabuOut)
			logger.Info("  Found %d open ports", count)
		}
	}
	stateMgr.MarkStepComplete(scanState, "port_scanning")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 8: Web Crawling (Parallel - Katana + GoSpider)
	// =========================================================================
	logger.Section("Step 8: Web Crawling")
	katanaOut := filepath.Join(resultDir, "katana_crawl.txt")
	gospiderOut := filepath.Join(resultDir, "gospider_crawl")
	targetURL := fmt.Sprintf("https://%s", targetDomain)

	wg.Add(2)
	go func() {
		defer wg.Done()
		logger.SubStep("[Start] Katana")
		if err := tb.RunKatana(ctx, targetURL, katanaOut); err != nil {
			logger.Warning("Katana failed: %v", err)
		} else {
			logger.SubStep("[Done] Katana")
			if scanID > 0 {
				count, _ := utils.ParseEndpointsFile(scanID, katanaOut, "katana")
				logger.Info("  Found %d endpoints", count)
			}
		}
	}()

	go func() {
		defer wg.Done()
		logger.SubStep("[Start] GoSpider")
		if err := tb.RunGoSpider(ctx, targetURL, gospiderOut); err != nil {
			logger.Warning("GoSpider failed: %v", err)
		} else {
			logger.SubStep("[Done] GoSpider")
		}
	}()

	wg.Wait()
	stateMgr.MarkStepComplete(scanState, "web_crawling")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 9: JavaScript Analysis (LinkFinder)
	// =========================================================================
	logger.Section("Step 9: JavaScript Endpoint Discovery")
	linkfinderOut := filepath.Join(resultDir, "linkfinder_endpoints.txt")
	logger.SubStep("Running LinkFinder on target...")
	if err := tb.RunLinkfinder(ctx, targetURL, linkfinderOut); err != nil {
		if Verbose {
			logger.Warning("LinkFinder failed: %v", err)
		}
	} else {
		logger.SubStep("[Done] LinkFinder")
		if scanID > 0 {
			count, _ := utils.ParseEndpointsFile(scanID, linkfinderOut, "linkfinder")
			logger.Info("  Found %d endpoints", count)
		}
	}
	stateMgr.MarkStepComplete(scanState, "js_analysis")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 10: Custom Wordlist Generation (CeWL)
	// =========================================================================
	logger.Section("Step 10: Custom Wordlist Generation")
	cewlOut := filepath.Join(resultDir, "cewl_wordlist.txt")
	logger.SubStep("Running CeWL to generate custom wordlist...")
	if err := tb.RunCewl(ctx, targetURL, cewlOut); err != nil {
		if Verbose {
			logger.Warning("CeWL failed: %v", err)
		}
	} else {
		logger.SubStep("[Done] CeWL - Wordlist: %s", cewlOut)
	}
	stateMgr.MarkStepComplete(scanState, "wordlist_gen")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 11: Directory Fuzzing (ffuf) - Optional
	// =========================================================================
	if wordlistPath != "" {
		logger.Section("Step 11: Directory Fuzzing (ffuf)")
		ffufOut := filepath.Join(resultDir, "ffuf_results.json")
		logger.SubStep("Running ffuf with wordlist: %s", wordlistPath)
		if err := tb.RunFfufWithFUZZ(ctx, targetURL, wordlistPath, ffufOut); err != nil {
			logger.Warning("ffuf failed: %v", err)
		} else {
			logger.SubStep("[Done] ffuf - Results: %s", ffufOut)
		}
	} else {
		logger.Section("Step 11: Skipping ffuf (no wordlist provided)")
		logger.Info("Use --wordlist to enable directory fuzzing")
		if _, err := os.Stat(cewlOut); err == nil {
			logger.Info("Tip: You can use the generated CeWL wordlist: %s", cewlOut)
		}
	}
	stateMgr.MarkStepComplete(scanState, "dir_fuzzing")

	if ctx.Err() != nil {
		finalizeScan(scanID, "cancelled", stateMgr, scanState, notifier, startTime, resultDir)
		return
	}

	// =========================================================================
	// Step 12: Vulnerability Scanning (Nuclei)
	// =========================================================================
	if !skipNuclei {
		logger.Section("Step 12: Vulnerability Scanning (Nuclei)")
		nucleiOut := filepath.Join(resultDir, "nuclei_vulns.json")
		logger.SubStep("Running Nuclei on discovered subdomains...")
		if err := tb.RunNuclei(ctx, consolidatedSubs, nucleiOut); err != nil {
			logger.Error("Nuclei failed: %v", err)
		} else {
			if scanID > 0 {
				count, _ := utils.ParseNucleiOutput(scanID, nucleiOut)
				logger.Info("  Found %d vulnerabilities", count)

				// Send notifications for critical/high findings
				if notifier != nil && count > 0 {
					vulns, _ := database.GetVulnerabilities(scanID)
					for _, v := range vulns {
						if v.Severity == "critical" || v.Severity == "high" {
							notifier.SendFinding(notify.Finding{
								Target:      targetDomain,
								Type:        "vulnerability",
								Name:        v.Name,
								Severity:    v.Severity,
								Description: v.Description,
								URL:         v.URL,
								TemplateID:  v.TemplateID,
								Timestamp:   time.Now(),
							})
						}
					}
				}
			}
		}
	} else {
		logger.Section("Step 12: Skipping Nuclei (--skip-nuclei)")
	}
	stateMgr.MarkStepComplete(scanState, "vuln_scanning")

	// =========================================================================
	// Finalize
	// =========================================================================
	finalizeScan(scanID, "completed", stateMgr, scanState, notifier, startTime, resultDir)
}

func finalizeScan(scanID int64, status string, stateMgr *scan.Manager, state *scan.State, notifier *notify.Notifier, startTime time.Time, resultDir string) {
	duration := time.Since(startTime)

	// Update database
	if scanID > 0 {
		database.UpdateScanStatus(scanID, status)
	}

	// Clean up state file for completed scans
	if status == "completed" && stateMgr != nil && state != nil {
		stateMgr.DeleteState(state.ScanID)
	}

	// Print summary
	logger.Section("Workflow %s", status)
	logger.Info("Duration: %s", duration.Round(time.Second))
	logger.Success("Results saved in: %s", resultDir)

	// Print stats and export results
	if scanID > 0 {
		stats, err := database.GetScanStats(scanID)
		if err == nil {
			logger.Info("\nStatistics:")
			logger.Info("  Subdomains: %d (Live: %d)", stats.TotalSubdomains, stats.LiveSubdomains)
			logger.Info("  Open Ports: %d", stats.TotalPorts)
			logger.Info("  URLs: %d", stats.TotalURLs)
			logger.Info("  Endpoints: %d", stats.TotalEndpoints)

			if len(stats.Vulnerabilities) > 0 {
				logger.Info("  Vulnerabilities:")
				for sev, count := range stats.Vulnerabilities {
					logger.Info("    %s: %d", sev, count)
				}
			}

			// Send scan complete notification
			if notifier != nil {
				notifier.SendScanComplete(notify.ScanComplete{
					Target:   targetDomain,
					ScanID:   scanID,
					Duration: duration,
					Stats: map[string]int{
						"subdomains": stats.TotalSubdomains,
						"ports":      stats.TotalPorts,
						"vulns":      len(stats.Vulnerabilities),
					},
				})
			}
		}

		// Export all results to text files
		if status == "completed" || status == "cancelled" {
			logger.Info("\nExporting results to text files...")
			if err := utils.ExportResults(scanID, resultDir); err != nil {
				logger.Warning("Failed to export some results: %v", err)
			} else {
				logger.Success("Results exported to text files")
			}

			// Create summary file
			if err := utils.ExportSummary(scanID, resultDir, targetDomain); err != nil {
				logger.Warning("Failed to create summary: %v", err)
			}
		}

		// Generate report
		if generateReport && status == "completed" {
			logger.Info("\nGenerating report...")
			rpt, err := report.Generate(scanID)
			if err == nil {
				home, _ := os.UserHomeDir()
				reportPath := filepath.Join(home, ".chaathan", "reports", fmt.Sprintf("scan_%d.md", scanID))
				if err := rpt.Export(report.FormatMarkdown, reportPath); err == nil {
					logger.Success("Report saved: %s", reportPath)
				}

				// Also save report in result directory
				localReportPath := filepath.Join(resultDir, "REPORT.md")
				if err := rpt.Export(report.FormatMarkdown, localReportPath); err == nil {
					logger.Success("Report also saved: %s", localReportPath)
				}
			}
		}
	}

	// Usage hints
	if scanID > 0 {
		logger.Info("\nNext steps:")
		logger.Info("  chaathan scans show %d       # View scan details", scanID)
		logger.Info("  chaathan query vulns %d      # List vulnerabilities", scanID)
		logger.Info("  chaathan report generate %d  # Generate full report", scanID)
	}
}
