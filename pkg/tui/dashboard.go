package tui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/scan"
)

// Catppuccin color theme constants
const (
	ColorBorder   = "#585b70" // High-contrast grey
	ColorActive   = "#cba6f7" // Mauve active highlight
	ColorSubtle   = "#a6adc8" // Subtext muted grey
	ColorLavender = "#b4befe" // Purple
	ColorSapphire = "#74c7ec" // Sky blue
	ColorGreen    = "#a6e3a1" // Green
	ColorRed      = "#f38ba8" // Red
	ColorYellow   = "#f9e2af" // Yellow
	ColorBlue     = "#89b4fa" // Blue
	ColorOrange   = "#fab387" // Orange
)

// ResumeSignal is returned when the user triggers a scan resume action in the TUI.
type ResumeSignal struct {
	ScanID int64
}

func (r ResumeSignal) Error() string {
	return fmt.Sprintf("resume scan: %d", r.ScanID)
}

// dashboard holds the tview components and state for the status dashboard.
type dashboard struct {
	app        *tview.Application
	pages      *tview.Pages
	topStats   *tview.TextView
	leftList   *tview.List
	middleText *tview.TextView
	rightText  *tview.TextView

	// scansList mirrors the fetched scan rows to resolve list indices.
	scansList []database.Scan

	resumeScanID int64
}

// StartDashboard boots up the interactive tview dashboard.
func StartDashboard() error {
	// Configure global tview styles to use terminal transparent background
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDefault
	tview.Styles.ContrastBackgroundColor = tcell.ColorDefault
	tview.Styles.MoreContrastBackgroundColor = tcell.ColorDefault
	tview.Styles.BorderColor = tcell.GetColor(ColorActive)
	tview.Styles.GraphicsColor = tcell.GetColor(ColorActive)
	tview.Styles.TitleColor = tcell.GetColor(ColorSapphire)

	d := &dashboard{app: tview.NewApplication()}

	// 1. Header View
	headerText := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	headerText.SetText(fmt.Sprintf(
		" [%s::b]CHAATHAN PENTESTING ORCHESTRATOR[-] [%s::i]v1.0.0 • Professional Recon Console[-]",
		ColorActive, ColorSapphire,
	))

	// 2. Global Metrics Bar
	d.topStats = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)

	// 3. Left Column: Scan Runs List
	d.leftList = tview.NewList().
		ShowSecondaryText(true)
	dashboardBorderStyle(d.leftList.Box, "SCAN RUNS")
	d.leftList.SetSelectedTextColor(tcell.GetColor(ColorActive)).
		SetSelectedBackgroundColor(tcell.GetColor("#313244"))

	// 4. Middle Column: Details & Open Ports
	d.middleText = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true)
	dashboardBorderStyle(d.middleText.Box, "PROPERTIES & OPEN PORTS")

	// 5. Right Column: Scope Metrics & Vulnerabilities
	d.rightText = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true)
	dashboardBorderStyle(d.rightText.Box, "FINDINGS & VULNERABILITIES")

	// 6. Footer Help Bar
	footerHelp := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	footerHelp.SetText(fmt.Sprintf(
		" [%s]Keys:[-] Up/Down: Navigate  |  [%s]Ctrl+R/F5[-] Refresh  |  [%s]R[-] Resume  |  [%s]D[-] Delete  |  [%s]Q/Ctrl+C[-] Exit",
		ColorActive, ColorActive, ColorActive, ColorActive, ColorActive,
	))

	d.pages = buildDashboardLayout(headerText, d.topStats, d.leftList, d.middleText, d.rightText, footerHelp)

	// Update details pane when a scan is selected
	d.leftList.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		if index < 0 || index >= len(d.scansList) {
			return
		}
		d.showScanDetails(d.scansList[index])
	})

	// Setup input captures (Global hotkeys)
	d.app.SetInputCapture(d.dashboardKeys)

	// Initial data reload
	d.reloadData()

	// Draw full screen layout container
	if err := d.app.SetRoot(d.pages, true).EnableMouse(true).Run(); err != nil {
		return err
	}
	if d.resumeScanID > 0 {
		return ResumeSignal{ScanID: d.resumeScanID}
	}
	return nil
}

// dashboardBorderStyle applies the shared border/title styling to a dashboard pane.
func dashboardBorderStyle(box *tview.Box, title string) {
	box.SetBorder(true).
		SetTitle(" " + title + " ").
		SetTitleColor(tcell.GetColor(ColorSapphire)).
		SetBorderColor(tcell.GetColor(ColorActive))
}

// buildDashboardLayout assembles the 3-pane dashboard screen layout.
func buildDashboardLayout(headerText, topStats *tview.TextView, leftList *tview.List, middleText, rightText *tview.TextView, footerHelp *tview.TextView) *tview.Pages {
	// 3-pane horizontal flex column layout
	mainFlex := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(leftList, 32, 1, true).
		AddItem(middleText, 42, 1, false).
		AddItem(rightText, 0, 1, false)

	// Screen layout vertical rows
	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(headerText, 1, 0, false).
		AddItem(topStats, 3, 0, false).
		AddItem(mainFlex, 0, 1, true).
		AddItem(footerHelp, 1, 0, false)

	return tview.NewPages().AddPage("main", layout, true, true)
}

// reloadData refreshes the global stats bar and scan list from the database.
func (d *dashboard) reloadData() {
	go func() {
		totalScans, _ := database.GetTotalScansCount()
		totalSubs, _ := database.GetTotalSubdomainsCount()
		totalPorts, _ := database.GetTotalPortsCount()
		totalVulns, _ := database.GetTotalVulnerabilitiesCount()
		scans, err := database.GetRecentScans(15)

		d.app.QueueUpdateDraw(func() {
			statsText := fmt.Sprintf(
				" GLOBAL STATS: [%s]Scans ran:[-] [#cdd6f4]%d[-]    [%s]Domains found:[-] [#cdd6f4]%d[-]    [%s]Ports open:[-] [#cdd6f4]%d[-]    [%s]Vulnerabilities:[-] [#cdd6f4]%d[-]",
				ColorBlue, totalScans, ColorBlue, totalSubs, ColorBlue, totalPorts, ColorBlue, totalVulns,
			)
			d.topStats.SetText(statsText)

			if err != nil {
				d.middleText.SetText(fmt.Sprintf(" [red]Database error: %v[-]", err))
				return
			}
			d.scansList = scans

			d.leftList.Clear()
			if len(d.scansList) == 0 {
				d.leftList.AddItem("No scans recorded.", "Run a scan first.", 0, nil)
				d.middleText.SetText(" Select a scan run to view properties.")
				d.rightText.SetText(" Select a scan to inspect findings.")
				return
			}

			for _, s := range d.scansList {
				statusSymbol, statusColor := dashboardStatusBadge(s.Status)

				age := time.Since(s.StartedAt).Round(time.Minute)
				ageStr := fmt.Sprintf("%dm ago", int(age.Minutes()))
				if age.Hours() >= 24 {
					ageStr = fmt.Sprintf("%.0fd ago", age.Hours()/24)
				} else if age.Hours() >= 1 {
					ageStr = fmt.Sprintf("%.0fh ago", age.Hours())
				}

				rowText := fmt.Sprintf("[%s]%s[-] #%d %s", statusColor, statusSymbol, s.ID, s.Target)
				d.leftList.AddItem(rowText, "Started "+ageStr, 0, nil)
			}

			if d.leftList.GetItemCount() > 0 {
				d.leftList.SetCurrentItem(0)
			}
		})
	}()
}

// dashboardStatusBadge maps a scan status to its list symbol and color.
func dashboardStatusBadge(status string) (string, string) {
	switch status {
	case "completed":
		return "[+]", ColorGreen
	case "failed":
		return "[-]", ColorRed
	case "running":
		return "[*]", ColorYellow
	case "cancelled":
		return "[ ]", ColorBlue
	default:
		return "[ ]", ""
	}
}

// showScanDetails fetches details for the selected scan and renders both panes.
func (d *dashboard) showScanDetails(s database.Scan) {
	d.middleText.SetText("  Loading details...")
	d.rightText.SetText("  Loading findings...")

	go func(sID int64, sType string, sStatus string, sTarget string, sStartedAt time.Time, sCompletedAt *time.Time, sResultDir string) {
		ports, errPorts := database.GetPorts(sID)
		stats, errStats := database.GetScanStats(sID)
		techs := getTopTechnologies(sID)
		vulns, errVulns := database.GetVulnerabilities(sID)
		runtimeProgressText := dashboardRuntimeProgress(sID, sType, sStatus)

		d.app.QueueUpdateDraw(func() {
			// Verify selection hasn't changed
			currIdx := d.leftList.GetCurrentItem()
			if currIdx < 0 || currIdx >= len(d.scansList) || d.scansList[currIdx].ID != sID {
				return
			}
			d.middleText.SetText(buildDashboardDetails(sType, sStatus, sTarget, sStartedAt, sCompletedAt, sResultDir, runtimeProgressText, ports, errPorts))
			d.rightText.SetText(buildDashboardFindings(stats, errStats, techs, vulns, errVulns))
		})
	}(s.ID, s.Type, s.Status, s.Target, s.StartedAt, s.CompletedAt, s.ResultDir)
}

// dashboardRuntimeProgress renders the live step progress block for running scans.
func dashboardRuntimeProgress(sID int64, sType string, sStatus string) string {
	if sStatus != "running" {
		return ""
	}
	stateMgr := scan.NewManager(paths.StateDir())
	state, err := stateMgr.LoadState(sID)
	if err != nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  [%s::b]RUNTIME PROGRESS[-]\n", ColorYellow))
	completed := len(state.CompletedSteps)
	total := state.TotalSteps
	if total == 0 {
		total = 1
	}
	pct := float64(completed) / float64(total) * 100

	sb.WriteString(fmt.Sprintf("  [%s]%.0f%%[-] Current: %d/%d steps\n", ColorYellow, pct, completed, total))
	steps := pickStepsForType(sType)
	if state.CurrentStep < len(steps) {
		sb.WriteString(fmt.Sprintf("  Current: %s\n\n", steps[state.CurrentStep].Description))
	} else {
		sb.WriteString("  Current: Finalizing...\n\n")
	}
	return sb.String()
}

// buildDashboardDetails renders the middle pane (scan properties and open ports).
func buildDashboardDetails(sType string, sStatus string, sTarget string, sStartedAt time.Time, sCompletedAt *time.Time, sResultDir string, runtimeProgressText string, ports []database.Port, errPorts error) string {
	var midSB strings.Builder
	statusColor := ColorBlue
	switch sStatus {
	case "completed":
		statusColor = ColorGreen
	case "failed":
		statusColor = ColorRed
	case "running":
		statusColor = ColorYellow
	}
	statusBadge := fmt.Sprintf("[%s::b] %s [-]", statusColor, strings.ToUpper(sStatus))

	midSB.WriteString(fmt.Sprintf("  [%s::b]Target: %s[-]\n\n", ColorLavender, sTarget))
	midSB.WriteString(fmt.Sprintf("  %-12s %s\n", "Type:", strings.ToUpper(sType)))
	midSB.WriteString(fmt.Sprintf("  %-12s %s\n", "Status:", statusBadge))
	midSB.WriteString(fmt.Sprintf("  %-12s %s\n", "Started:", sStartedAt.Format("15:04:05")))

	var durStr string
	switch {
	case sCompletedAt != nil:
		durStr = sCompletedAt.Sub(sStartedAt).Round(time.Second).String()
	case sStatus != "running":
		durStr = "Unknown"
	default:
		durStr = time.Since(sStartedAt).Round(time.Second).String()
	}
	midSB.WriteString(fmt.Sprintf("  %-12s %s\n", "Duration:", durStr))
	midSB.WriteString(fmt.Sprintf("  [%s]Folder:[-] %s\n\n", ColorSubtle, sResultDir))

	if runtimeProgressText != "" {
		midSB.WriteString(runtimeProgressText)
	}

	midSB.WriteString(fmt.Sprintf("  [%s::b]DISCOVERED OPEN PORTS[-]\n", ColorSapphire))
	if errPorts == nil && len(ports) > 0 {
		midSB.WriteString(fmt.Sprintf("  [%s]Host                Port/Proto  Service[-]\n", ColorSubtle))
		displayLimit := 8
		if len(ports) < displayLimit {
			displayLimit = len(ports)
		}
		for i := 0; i < displayLimit; i++ {
			p := ports[i]
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			portStr := fmt.Sprintf("%d/%s", p.Port, proto)
			srv := p.Service
			if srv == "" {
				srv = "unknown"
			}
			midSB.WriteString(fmt.Sprintf("  %-19s %-11s %s\n", truncateText(p.Host, 18), portStr, truncateText(srv, 8)))
		}
		if len(ports) > displayLimit {
			midSB.WriteString(fmt.Sprintf("  [%s::i]...and %d more ports[-]\n", ColorSubtle, len(ports)-displayLimit))
		}
	} else {
		midSB.WriteString(fmt.Sprintf("  [%s]No open ports discovered.[-]\n", ColorSubtle))
	}
	return midSB.String()
}

// buildDashboardFindings renders the right pane (scope counts, techs, vulnerabilities).
func buildDashboardFindings(stats *database.ScanStats, errStats error, techs []string, vulns []database.Vulnerability, errVulns error) string {
	var rightSB strings.Builder
	rightSB.WriteString(fmt.Sprintf("  [%s::b]SCOPE COUNTS[-]\n", ColorSapphire))
	if errStats == nil && stats != nil {
		colSub := fmt.Sprintf("%d", stats.TotalSubdomains)
		colLive := fmt.Sprintf("%d", stats.LiveSubdomains)
		rightSB.WriteString(fmt.Sprintf("  %-14s [%s]%s[-]\n", "Subdomains:", ColorSapphire, colSub))
		rightSB.WriteString(fmt.Sprintf("  %-14s [%s]%s[-]\n", "Live Hosts:", ColorSapphire, colLive))
		rightSB.WriteString(fmt.Sprintf("  %-14s [%s]%d[-]\n", "URLs Crawled:", ColorSapphire, stats.TotalURLs))
		rightSB.WriteString(fmt.Sprintf("  %-14s [%s]%d[-]\n\n", "Endpoints:", ColorSapphire, stats.TotalEndpoints))
	} else {
		rightSB.WriteString(fmt.Sprintf("  [%s]No counters compiled.[-]\n\n", ColorSubtle))
	}

	if len(techs) > 0 {
		rightSB.WriteString(fmt.Sprintf("  [%s::b]TOP TECHNOLOGIES DETECTED[-]\n", ColorSapphire))
		for _, t := range techs {
			rightSB.WriteString(fmt.Sprintf("  • %s\n", t))
		}
		rightSB.WriteString("\n")
	}

	rightSB.WriteString(fmt.Sprintf("  [%s::b]VULNERABILITY DISCOVERIES[-]\n", ColorActive))
	if errVulns == nil && len(vulns) > 0 {
		displayLimit := 5
		if len(vulns) < displayLimit {
			displayLimit = len(vulns)
		}
		for i := 0; i < displayLimit; i++ {
			v := vulns[i]
			badge := dashboardSeverityBadge(v.Severity)

			vTitle := truncateText(v.Name, 26)
			vHost := truncateText(v.Host, 14)
			rightSB.WriteString(fmt.Sprintf("  %s %s [%s]%s[-]\n", badge, vHost, ColorSubtle, vTitle))
			if v.URL != "" {
				rightSB.WriteString(fmt.Sprintf("    [%s]↳ URL: %s[-]\n", ColorSubtle, truncateText(v.URL, 80)))
			}
		}
		if len(vulns) > displayLimit {
			rightSB.WriteString(fmt.Sprintf("  [%s::i]...and %d more vulnerabilities[-]\n", ColorSubtle, len(vulns)-displayLimit))
		}
	} else {
		rightSB.WriteString(fmt.Sprintf("\n  [%s]Clean Scan - No vulnerabilities found.[-]\n", ColorGreen))
	}
	return rightSB.String()
}

// dashboardSeverityBadge maps a vulnerability severity to its colored badge.
func dashboardSeverityBadge(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return fmt.Sprintf("[%s][CRIT][-]", ColorRed)
	case "high":
		return fmt.Sprintf("[%s][HIGH][-]", ColorOrange)
	case "medium":
		return fmt.Sprintf("[%s][MED ][-]", ColorYellow)
	case "low":
		return fmt.Sprintf("[%s][LOW ][-]", ColorGreen)
	default:
		return fmt.Sprintf("[%s][INFO][-]", ColorBlue)
	}
}

// dashboardKeys handles the global dashboard hotkeys.
func (d *dashboard) dashboardKeys(event *tcell.EventKey) *tcell.EventKey {
	if d.pages.HasPage("delete_confirm") {
		return event
	}

	switch event.Rune() {
	case 'q', 'Q':
		d.app.Stop()
		return nil
	case 'd', 'D':
		idx := d.leftList.GetCurrentItem()
		if idx >= 0 && idx < len(d.scansList) {
			d.showDeleteConfirm(d.scansList[idx])
		}
		return nil
	case 'r', 'R':
		idx := d.leftList.GetCurrentItem()
		if idx >= 0 && idx < len(d.scansList) {
			d.resumeScanID = d.scansList[idx].ID
			d.app.Stop()
		}
		return nil
	}

	if event.Key() == tcell.KeyCtrlR || event.Key() == tcell.KeyF5 {
		d.reloadData()
		return nil
	}

	// Also support Escape and Ctrl+C to quit
	if event.Key() == tcell.KeyCtrlC || event.Key() == tcell.KeyEscape {
		d.app.Stop()
		return nil
	}
	return event
}

// showDeleteConfirm opens the scan deletion confirmation modal.
func (d *dashboard) showDeleteConfirm(s database.Scan) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Are you sure you want to delete scan #%d for %s?\nThis action cannot be undone.", s.ID, s.Target)).
		AddButtons([]string{"Yes", "No"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Yes" {
				if err := database.DeleteScan(s.ID); err == nil {
					d.reloadData()
				} else {
					logger.FileDebug("failed to delete scan %d: %v", s.ID, err)
					errorModal := tview.NewModal().
						SetText(fmt.Sprintf("Failed to delete scan #%d: %v", s.ID, err)).
						AddButtons([]string{"OK"}).
						SetDoneFunc(func(bIdx int, bLabel string) {
							d.pages.RemovePage("delete_error")
							d.app.SetFocus(d.leftList)
						})
					d.pages.AddPage("delete_error", errorModal, true, true)
					return
				}
			}
			d.pages.RemovePage("delete_confirm")
			d.app.SetFocus(d.leftList)
		})
	d.pages.AddPage("delete_confirm", modal, true, true)
}

func getTopTechnologies(scanID int64) []string {
	urls, err := database.GetURLs(scanID)
	if err != nil || len(urls) == 0 {
		return nil
	}
	techCounts := make(map[string]int)
	for _, u := range urls {
		if u.Tech == "" {
			continue
		}
		var techs []string
		if err := json.Unmarshal([]byte(u.Tech), &techs); err == nil {
			for _, t := range techs {
				techCounts[t]++
			}
		} else {
			for _, t := range strings.Split(u.Tech, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					techCounts[t]++
				}
			}
		}
	}
	type techCount struct {
		name  string
		count int
	}
	var list []techCount
	for k, v := range techCounts {
		list = append(list, techCount{k, v})
	}

	// Sort descending using sort.Slice (L3)
	sort.Slice(list, func(i, j int) bool {
		return list[i].count > list[j].count
	})

	var result []string
	limit := 4
	if len(list) < limit {
		limit = len(list)
	}
	for i := 0; i < limit; i++ {
		result = append(result, fmt.Sprintf("%s (%d)", list[i].name, list[i].count))
	}
	return result
}

func truncateText(str string, limit int) string {
	runes := []rune(str)
	if len(runes) <= limit {
		return str
	}
	if limit <= 3 {
		return string(runes[:limit])
	}
	return string(runes[:limit-3]) + "..."
}

func pickStepsForType(scanType string) []scan.Step {
	if scanType == "company" {
		return scan.CompanySteps
	}
	return scan.WildcardSteps
}
