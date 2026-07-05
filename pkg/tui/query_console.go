package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
)

// QueryConsole state and components structure
type QueryConsole struct {
	App         *tview.Application
	Pages       *tview.Pages
	ScanList    *tview.List
	TabsText    *tview.TextView
	Tables      [6]*tview.Table
	FilterInput *tview.InputField
	FooterText  *tview.TextView

	ActiveTab  int
	ScanID     int64
	FilterText string

	// Master raw data loaded from database
	subdomains []database.Subdomain
	ports      []database.Port
	vulns      []database.Vulnerability
	urls       []database.URL
	endpoints  []database.Endpoint
	roi        []database.URLROI

	// Total counts before truncation
	subdomainsTotalCount int
	portsTotalCount      int
	vulnsTotalCount      int
	urlsTotalCount       int
	endpointsTotalCount  int
	roiTotalCount        int

	// Cache for technology strings
	techCache map[string]string

	// Debounce timer for filtering
	filterTimer *time.Timer

	// Filtered data displayed in current tables
	filteredSubdomains []database.Subdomain
	filteredPorts      []database.Port
	filteredVulns      []database.Vulnerability
	filteredURLs       []database.URL
	filteredEndpoints  []database.Endpoint
	filteredROI        []database.URLROI

	// Reference list of loaded scans
	scans []database.Scan
}

// StartQueryConsole launches the interactive TUI console
func StartQueryConsole(presetScanID int64) error {
	// Configure global transparent theme with Catppuccin color borders
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDefault
	tview.Styles.ContrastBackgroundColor = tcell.ColorDefault
	tview.Styles.MoreContrastBackgroundColor = tcell.ColorDefault
	tview.Styles.BorderColor = tcell.GetColor(ColorBorder)
	tview.Styles.GraphicsColor = tcell.GetColor(ColorActive)
	tview.Styles.TitleColor = tcell.GetColor(ColorSapphire)

	q := &QueryConsole{
		App:       tview.NewApplication(),
		ActiveTab: 0,
		ScanID:    presetScanID,
	}

	// 1. Header Text
	header := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	header.SetText(fmt.Sprintf(
		" [%s::b]CHAATHAN RECON CONSOLE[-] [%s::i]• Unified Query & Findings Explorer[-]",
		ColorActive, ColorSapphire,
	))

	// 2. Scan Selector Sidebar (Left)
	q.ScanList = tview.NewList().
		ShowSecondaryText(true)
	q.ScanList.SetBorder(true).
		SetTitle(" SCANS HISTORY ").
		SetTitleColor(tcell.GetColor(ColorSapphire)).
		SetBorderColor(tcell.GetColor(ColorBorder))
	q.ScanList.SetSelectedTextColor(tcell.GetColor(ColorActive)).
		SetSelectedBackgroundColor(tcell.GetColor("#313244"))

	// 3. Category Tabs Bar
	q.TabsText = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	q.drawTabs()

	// 4. Tables and Pages Container
	q.Pages = tview.NewPages()
	tabPages := []string{"subdomains", "ports", "vulns", "urls", "endpoints", "roi"}

	for i := 0; i < 6; i++ {
		table := tview.NewTable().
			SetBorders(false).
			SetSelectable(true, false).
			SetFixed(1, 0)
		
		table.SetBorder(true).
			SetTitleColor(tcell.GetColor(ColorSapphire)).
			SetBorderColor(tcell.GetColor(ColorBorder))
		
		// Style selection row
		selectedStyle := tcell.StyleDefault.
			Foreground(tcell.GetColor(ColorActive)).
			Background(tcell.GetColor("#313244"))
		table.SetSelectedStyle(selectedStyle)

		// Set table titles matching their categories
		titles := []string{" SUBDOMAINS FINDINGS ", " OPEN PORTS ", " DISCOVERED VULNERABILITIES ", " CRAWLED URLS ", " API ENDPOINTS ", " TESTING ROI TARGETS "}
		table.SetTitle(titles[i])

		q.Tables[i] = table
		q.Pages.AddPage(tabPages[i], table, true, i == 0)

		// Capture Enter key to open selection details popup
		idx := i
		table.SetSelectedFunc(func(row, column int) {
			if row <= 0 {
				return // Header selected
			}
			q.showDetailsPopup(idx, row-1)
		})
	}

	// 5. Search / Filter Input
	q.FilterInput = tview.NewInputField().
		SetLabel(" Filter query: ").
		SetFieldWidth(0).
		SetFieldBackgroundColor(tcell.ColorDefault)
	q.FilterInput.SetBorder(true).
		SetTitle(" REAL-TIME FILTER ").
		SetTitleColor(tcell.GetColor(ColorSapphire)).
		SetBorderColor(tcell.GetColor(ColorBorder))

	q.FilterInput.SetChangedFunc(func(text string) {
		q.FilterText = text

		if q.filterTimer != nil {
			q.filterTimer.Stop()
		}

		q.filterTimer = time.AfterFunc(60*time.Millisecond, func() {
			q.App.QueueUpdateDraw(func() {
				q.populateTable(q.ActiveTab)
			})
		})
	})

	// 6. Footer Help Bar
	q.FooterText = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	q.FooterText.SetText(fmt.Sprintf(
		" [%s]Tab[-] Focus Panel  |  [%s]1-6[-] Switch Tabs  |  [%s]/[-] Search  |  [%s]Esc[-] Unfocus  |  [%s]R[-] Reload  |  [%s]Q/Ctrl+C[-] Exit",
		ColorActive, ColorActive, ColorActive, ColorActive, ColorActive, ColorActive,
	))

	// Layout Flex columns and rows
	rightFlex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(q.TabsText, 1, 0, false).
		AddItem(q.Pages, 0, 1, true).
		AddItem(q.FilterInput, 3, 0, false)

	mainFlex := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(q.ScanList, 30, 1, true).
		AddItem(rightFlex, 0, 2, false)

	rootLayout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(header, 1, 0, false).
		AddItem(mainFlex, 0, 1, true).
		AddItem(q.FooterText, 1, 0, false)

	// Sidebar scan list selection triggers data loading
	q.ScanList.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		if index < 0 || index >= len(q.scans) {
			return
		}
		q.loadScanData(q.scans[index].ID)
	})

	// Set focus change handlers to paint borders dynamically
	q.ScanList.SetFocusFunc(func() { q.updateBorderColors() })
	q.FilterInput.SetFocusFunc(func() { q.updateBorderColors() })
	for i := 0; i < 6; i++ {
		q.Tables[i].SetFocusFunc(func() { q.updateBorderColors() })
	}

	// Global Key Captures for fast navigation
	q.App.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if q.Pages.HasPage("detail_modal") {
			return event // Let detail modal capture inputs
		}

		switch event.Key() {
		case tcell.KeyCtrlC:
			q.App.Stop()
			return nil
		case tcell.KeyTab:
			q.cycleFocus(false)
			return nil
		case tcell.KeyBacktab:
			q.cycleFocus(true)
			return nil
		case tcell.KeyEscape:
			if q.FilterInput.HasFocus() {
				q.FilterInput.SetText("")
				q.FilterText = ""
				q.populateTable(q.ActiveTab)
				q.App.SetFocus(q.Tables[q.ActiveTab])
				q.updateBorderColors()
				return nil
			}
		}

		switch event.Rune() {
		case 'q', 'Q':
			if !q.FilterInput.HasFocus() {
				q.App.Stop()
				return nil
			}
		case 'r', 'R':
			if !q.FilterInput.HasFocus() {
				q.loadScanData(q.ScanID)
				return nil
			}
		case '/':
			if !q.FilterInput.HasFocus() {
				q.App.SetFocus(q.FilterInput)
				q.updateBorderColors()
				return nil
			}
		case '1', '2', '3', '4', '5', '6':
			if !q.FilterInput.HasFocus() {
				tabIdx := int(event.Rune() - '1')
				q.switchTab(tabIdx)
				return nil
			}
		}

		return event
	})

	// Load scans from database
	scans, err := database.GetRecentScans(50)
	if err != nil {
		return fmt.Errorf("failed to fetch scans: %w", err)
	}
	q.scans = scans

	if len(q.scans) == 0 {
		q.ScanList.AddItem("No scans found.", "Run a scan target first.", 0, nil)
	} else {
		presetIdx := 0
		for idx, s := range q.scans {
			statusSymbol := "[ ]"
			switch s.Status {
			case "completed":
				statusSymbol = "[+]"
			case "failed":
				statusSymbol = "[-]"
			case "running":
				statusSymbol = "[*]"
			}

			if s.ID == presetScanID {
				presetIdx = idx
			}

			dateStr := s.StartedAt.Format("2006-01-02 15:04")
			q.ScanList.AddItem(fmt.Sprintf("%s #%d %s", statusSymbol, s.ID, s.Target), dateStr, 0, nil)
		}

		// Trigger initial load
		q.ScanList.SetCurrentItem(presetIdx)
		q.loadScanData(q.scans[presetIdx].ID)
	}

	q.updateBorderColors()

	if err := q.App.SetRoot(rootLayout, true).EnableMouse(true).Run(); err != nil {
		return err
	}
	return nil
}

// updateBorderColors sets high-contrast highlights for focused widgets
func (q *QueryConsole) updateBorderColors() {
	if q.ScanList.HasFocus() {
		q.ScanList.SetBorderColor(tcell.GetColor(ColorActive))
	} else {
		q.ScanList.SetBorderColor(tcell.GetColor(ColorBorder))
	}

	activeTable := q.Tables[q.ActiveTab]
	if activeTable.HasFocus() {
		activeTable.SetBorderColor(tcell.GetColor(ColorActive))
	} else {
		activeTable.SetBorderColor(tcell.GetColor(ColorBorder))
	}

	if q.FilterInput.HasFocus() {
		q.FilterInput.SetBorderColor(tcell.GetColor(ColorActive))
	} else {
		q.FilterInput.SetBorderColor(tcell.GetColor(ColorBorder))
	}
}

// cycleFocus shifts key input focus between panels sequentially
func (q *QueryConsole) cycleFocus(reverse bool) {
	elements := []tview.Primitive{q.ScanList, q.Tables[q.ActiveTab], q.FilterInput}
	currentIdx := -1
	for i, el := range elements {
		if el.HasFocus() {
			currentIdx = i
			break
		}
	}

	nextIdx := 0
	if currentIdx != -1 {
		if reverse {
			nextIdx = (currentIdx - 1 + len(elements)) % len(elements)
		} else {
			nextIdx = (currentIdx + 1) % len(elements)
		}
	}

	q.App.SetFocus(elements[nextIdx])
	q.updateBorderColors()
}

// drawTabs renders tab labels with styling markers
func (q *QueryConsole) drawTabs() {
	tabNames := []string{"SUBDOMAINS", "PORTS", "VULNERABILITIES", "URLS", "ENDPOINTS", "ROI TARGETS"}
	var parts []string
	for i, name := range tabNames {
		if i == q.ActiveTab {
			parts = append(parts, fmt.Sprintf("[%s::b]● %s[-]", ColorActive, name))
		} else {
			parts = append(parts, fmt.Sprintf("[%s]○ %s[-]", ColorSubtle, name))
		}
	}
	q.TabsText.SetText("  " + strings.Join(parts, "   |   "))
}

// switchTab shifts active findings page and updates rendering
func (q *QueryConsole) switchTab(tabIdx int) {
	if tabIdx < 0 || tabIdx >= 6 {
		return
	}
	q.ActiveTab = tabIdx
	q.drawTabs()

	tabPages := []string{"subdomains", "ports", "vulns", "urls", "endpoints", "roi"}
	q.Pages.SwitchToPage(tabPages[tabIdx])
	q.populateTable(tabIdx)

	// Preserve active control focus when changing tabs
	for _, t := range q.Tables {
		if t.HasFocus() {
			q.App.SetFocus(q.Tables[tabIdx])
			break
		}
	}
	q.updateBorderColors()
}

// loadScanData queries findings for selected scan in memory
func (q *QueryConsole) loadScanData(scanID int64) {
	q.ScanID = scanID

	var err error
	rawSubs, err := database.GetLiveSubdomains(scanID)
	if err != nil {
		logger.FileDebug("GetLiveSubdomains error: %v", err)
	}
	rawPorts, err := database.GetPorts(scanID)
	if err != nil {
		logger.FileDebug("GetPorts error: %v", err)
	}
	rawVulns, err := database.GetVulnerabilities(scanID)
	if err != nil {
		logger.FileDebug("GetVulnerabilities error: %v", err)
	}
	rawUrls, err := database.GetURLs(scanID)
	if err != nil {
		logger.FileDebug("GetURLs error: %v", err)
	}
	rawEndpoints, err := database.GetEndpoints(scanID)
	if err != nil {
		logger.FileDebug("GetEndpoints error: %v", err)
	}
	rawRoi, err := database.GetRankedURLs(scanID, 5000)
	if err != nil {
		logger.FileDebug("GetRankedURLs error: %v", err)
	}

	// Store total counts
	q.subdomainsTotalCount = len(rawSubs)
	q.portsTotalCount = len(rawPorts)
	q.vulnsTotalCount = len(rawVulns)
	q.urlsTotalCount = len(rawUrls)
	q.endpointsTotalCount = len(rawEndpoints)
	q.roiTotalCount = len(rawRoi)

	// Truncate to 5000 rows max in memory for TUI
	if len(rawSubs) > 5000 {
		rawSubs = rawSubs[:5000]
	}
	if len(rawPorts) > 5000 {
		rawPorts = rawPorts[:5000]
	}
	if len(rawVulns) > 5000 {
		rawVulns = rawVulns[:5000]
	}
	if len(rawUrls) > 5000 {
		rawUrls = rawUrls[:5000]
	}
	if len(rawEndpoints) > 5000 {
		rawEndpoints = rawEndpoints[:5000]
	}

	q.subdomains = rawSubs
	q.ports = rawPorts
	q.vulns = rawVulns
	q.urls = rawUrls
	q.endpoints = rawEndpoints
	q.roi = rawRoi

	// Build tech stack cache (L4)
	q.techCache = make(map[string]string)
	for _, u := range rawUrls {
		var techStr string
		var techs []string
		if err := json.Unmarshal([]byte(u.Tech), &techs); err == nil {
			techStr = strings.Join(techs, ", ")
		} else {
			techStr = u.Tech
		}
		q.techCache[u.URL] = techStr
	}

	q.FilterInput.SetText("")
	q.FilterText = ""

	for i := 0; i < 6; i++ {
		q.populateTable(i)
	}
}

// populateTable performs string search filtering and renders columns
func (q *QueryConsole) populateTable(tabIndex int) {
	table := q.Tables[tabIndex]
	table.Clear()

	filter := strings.ToLower(q.FilterText)
	rowIdx := 1

	switch tabIndex {
	case 0: // Subdomains
		q.filteredSubdomains = nil
		headers := []string{"DOMAIN", "LIVE", "IP ADDRESS", "SOURCE"}
		for col, h := range headers {
			cell := tview.NewTableCell(" " + h + " ").
				SetTextColor(tcell.GetColor(ColorSapphire)).
				SetSelectable(false)
			if col == 0 {
				cell.SetExpansion(1)
			}
			table.SetCell(0, col, cell)
		}

		rowIdx = 1
		for _, s := range q.subdomains {
			if filter != "" && !strings.Contains(strings.ToLower(s.Domain), filter) &&
				!strings.Contains(strings.ToLower(s.IPAddress), filter) &&
				!strings.Contains(strings.ToLower(s.Source), filter) {
				continue
			}
			q.filteredSubdomains = append(q.filteredSubdomains, s)

			liveText := "no"
			liveColor := tcell.GetColor(ColorSubtle)
			if s.IsLive {
				liveText = "yes"
				liveColor = tcell.GetColor(ColorGreen)
			}

			table.SetCell(rowIdx, 0, tview.NewTableCell(" "+s.Domain).SetTextColor(tcell.ColorWhite))
			table.SetCell(rowIdx, 1, tview.NewTableCell(" "+liveText).SetTextColor(liveColor).SetAlign(tview.AlignCenter))
			table.SetCell(rowIdx, 2, tview.NewTableCell(" "+s.IPAddress).SetTextColor(tcell.GetColor(ColorLavender)))
			table.SetCell(rowIdx, 3, tview.NewTableCell(" "+s.Source).SetTextColor(tcell.GetColor(ColorSubtle)))
			rowIdx++
		}

	case 1: // Ports
		q.filteredPorts = nil
		headers := []string{"HOST", "PORT", "PROTOCOL", "SERVICE"}
		for col, h := range headers {
			cell := tview.NewTableCell(" " + h + " ").
				SetTextColor(tcell.GetColor(ColorSapphire)).
				SetSelectable(false)
			if col == 0 {
				cell.SetExpansion(1)
			}
			table.SetCell(0, col, cell)
		}

		rowIdx = 1
		for _, p := range q.ports {
			portStr := fmt.Sprintf("%d", p.Port)
			if filter != "" && !strings.Contains(strings.ToLower(p.Host), filter) &&
				!strings.Contains(strings.ToLower(portStr), filter) &&
				!strings.Contains(strings.ToLower(p.Protocol), filter) &&
				!strings.Contains(strings.ToLower(p.Service), filter) {
				continue
			}
			q.filteredPorts = append(q.filteredPorts, p)

			table.SetCell(rowIdx, 0, tview.NewTableCell(" "+p.Host).SetTextColor(tcell.ColorWhite))
			table.SetCell(rowIdx, 1, tview.NewTableCell(" "+portStr).SetTextColor(tcell.GetColor(ColorYellow)).SetAlign(tview.AlignRight))
			table.SetCell(rowIdx, 2, tview.NewTableCell(" "+p.Protocol).SetTextColor(tcell.GetColor(ColorBlue)).SetAlign(tview.AlignCenter))
			table.SetCell(rowIdx, 3, tview.NewTableCell(" "+p.Service).SetTextColor(tcell.GetColor(ColorGreen)))
			rowIdx++
		}

	case 2: // Vulnerabilities
		q.filteredVulns = nil
		headers := []string{"SEVERITY", "HOST", "VULNERABILITY NAME", "TEMPLATE"}
		for col, h := range headers {
			cell := tview.NewTableCell(" " + h + " ").
				SetTextColor(tcell.GetColor(ColorSapphire)).
				SetSelectable(false)
			if col == 2 {
				cell.SetExpansion(1)
			}
			table.SetCell(0, col, cell)
		}

		rowIdx = 1
		for _, v := range q.vulns {
			if filter != "" && !strings.Contains(strings.ToLower(v.Severity), filter) &&
				!strings.Contains(strings.ToLower(v.Host), filter) &&
				!strings.Contains(strings.ToLower(v.Name), filter) &&
				!strings.Contains(strings.ToLower(v.URL), filter) {
				continue
			}
			q.filteredVulns = append(q.filteredVulns, v)

			var badge string
			var badgeColor tcell.Color
			switch strings.ToLower(v.Severity) {
			case "critical":
				badge = "CRIT"
				badgeColor = tcell.GetColor(ColorRed)
			case "high":
				badge = "HIGH"
				badgeColor = tcell.GetColor(ColorOrange)
			case "medium":
				badge = "MED"
				badgeColor = tcell.GetColor(ColorYellow)
			case "low":
				badge = "LOW"
				badgeColor = tcell.GetColor(ColorGreen)
			default:
				badge = "INFO"
				badgeColor = tcell.GetColor(ColorBlue)
			}

			table.SetCell(rowIdx, 0, tview.NewTableCell(fmt.Sprintf(" [%s] ", badge)).SetTextColor(badgeColor).SetAlign(tview.AlignCenter))
			table.SetCell(rowIdx, 1, tview.NewTableCell(" "+v.Host).SetTextColor(tcell.GetColor(ColorLavender)))
			table.SetCell(rowIdx, 2, tview.NewTableCell(" "+v.Name).SetTextColor(tcell.ColorWhite))
			table.SetCell(rowIdx, 3, tview.NewTableCell(" "+v.TemplateID).SetTextColor(tcell.GetColor(ColorSubtle)))
			rowIdx++
		}

	case 3: // URLs
		q.filteredURLs = nil
		headers := []string{"STATUS", "SOURCE", "URL", "TITLE", "TECH"}
		for col, h := range headers {
			cell := tview.NewTableCell(" " + h + " ").
				SetTextColor(tcell.GetColor(ColorSapphire)).
				SetSelectable(false)
			if col == 2 {
				cell.SetExpansion(1)
			}
			table.SetCell(0, col, cell)
		}

		rowIdx = 1
		for _, u := range q.urls {
			statusStr := fmt.Sprintf("%d", u.StatusCode)
			if filter != "" && !strings.Contains(statusStr, filter) &&
				!strings.Contains(strings.ToLower(u.Source), filter) &&
				!strings.Contains(strings.ToLower(u.URL), filter) &&
				!strings.Contains(strings.ToLower(u.Title), filter) &&
				!strings.Contains(strings.ToLower(u.Tech), filter) {
				continue
			}
			q.filteredURLs = append(q.filteredURLs, u)

			statusColor := tcell.GetColor(ColorSubtle)
			if u.StatusCode >= 200 && u.StatusCode < 300 {
				statusColor = tcell.GetColor(ColorGreen)
			} else if u.StatusCode >= 300 && u.StatusCode < 400 {
				statusColor = tcell.GetColor(ColorYellow)
			} else if u.StatusCode >= 400 {
				statusColor = tcell.GetColor(ColorRed)
			}

			table.SetCell(rowIdx, 0, tview.NewTableCell(" "+statusStr).SetTextColor(statusColor).SetAlign(tview.AlignCenter))
			table.SetCell(rowIdx, 1, tview.NewTableCell(" "+u.Source).SetTextColor(tcell.GetColor(ColorLavender)))
			table.SetCell(rowIdx, 2, tview.NewTableCell(" "+u.URL).SetTextColor(tcell.ColorWhite))
			table.SetCell(rowIdx, 3, tview.NewTableCell(" "+u.Title).SetTextColor(tcell.GetColor(ColorBlue)))

			techStr := q.techCache[u.URL]
			table.SetCell(rowIdx, 4, tview.NewTableCell(" "+techStr).SetTextColor(tcell.GetColor(ColorGreen)))
			rowIdx++
		}

	case 4: // Endpoints
		q.filteredEndpoints = nil
		headers := []string{"METHOD", "SOURCE", "URL"}
		for col, h := range headers {
			cell := tview.NewTableCell(" " + h + " ").
				SetTextColor(tcell.GetColor(ColorSapphire)).
				SetSelectable(false)
			if col == 2 {
				cell.SetExpansion(1)
			}
			table.SetCell(0, col, cell)
		}

		rowIdx = 1
		for _, e := range q.endpoints {
			if filter != "" && !strings.Contains(strings.ToLower(e.Method), filter) &&
				!strings.Contains(strings.ToLower(e.Source), filter) &&
				!strings.Contains(strings.ToLower(e.URL), filter) {
				continue
			}
			q.filteredEndpoints = append(q.filteredEndpoints, e)

			methodColor := tcell.GetColor(ColorSubtle)
			switch strings.ToUpper(e.Method) {
			case "GET":
				methodColor = tcell.GetColor(ColorGreen)
			case "POST":
				methodColor = tcell.GetColor(ColorYellow)
			case "PUT", "DELETE":
				methodColor = tcell.GetColor(ColorRed)
			}

			table.SetCell(rowIdx, 0, tview.NewTableCell(" "+e.Method).SetTextColor(methodColor).SetAlign(tview.AlignCenter))
			table.SetCell(rowIdx, 1, tview.NewTableCell(" "+e.Source).SetTextColor(tcell.GetColor(ColorLavender)))
			table.SetCell(rowIdx, 2, tview.NewTableCell(" "+e.URL).SetTextColor(tcell.ColorWhite))
			rowIdx++
		}

	case 5: // ROI Targets
		q.filteredROI = nil
		headers := []string{"SCORE", "CONF", "STATUS", "URL", "ATTACK SURFACES"}
		for col, h := range headers {
			cell := tview.NewTableCell(" " + h + " ").
				SetTextColor(tcell.GetColor(ColorSapphire)).
				SetSelectable(false)
			if col == 3 {
				cell.SetExpansion(1)
			}
			table.SetCell(0, col, cell)
		}

		rowIdx = 1
		for _, r := range q.roi {
			scoreStr := fmt.Sprintf("%d", r.Score)
			statusStr := fmt.Sprintf("%d", r.StatusCode)
			surfaces := strings.Join(r.AttackSurfaces, ", ")
			reasons := strings.Join(r.Reasons, " ")

			if filter != "" && !strings.Contains(scoreStr, filter) &&
				!strings.Contains(strings.ToLower(r.Confidence), filter) &&
				!strings.Contains(statusStr, filter) &&
				!strings.Contains(strings.ToLower(r.URL), filter) &&
				!strings.Contains(strings.ToLower(surfaces), filter) &&
				!strings.Contains(strings.ToLower(reasons), filter) {
				continue
			}
			q.filteredROI = append(q.filteredROI, r)

			scoreColor := tcell.GetColor(ColorGreen)
			if r.Score >= 80 {
				scoreColor = tcell.GetColor(ColorRed)
			} else if r.Score >= 40 {
				scoreColor = tcell.GetColor(ColorOrange)
			} else if r.Score >= 20 {
				scoreColor = tcell.GetColor(ColorYellow)
			}

			confColor := tcell.GetColor(ColorSubtle)
			switch strings.ToLower(r.Confidence) {
			case "high":
				confColor = tcell.GetColor(ColorGreen)
			case "medium":
				confColor = tcell.GetColor(ColorYellow)
			}

			statusColor := tcell.GetColor(ColorSubtle)
			if r.StatusCode >= 200 && r.StatusCode < 300 {
				statusColor = tcell.GetColor(ColorGreen)
			} else if r.StatusCode >= 300 && r.StatusCode < 400 {
				statusColor = tcell.GetColor(ColorYellow)
			} else if r.StatusCode >= 400 {
				statusColor = tcell.GetColor(ColorRed)
			}

			table.SetCell(rowIdx, 0, tview.NewTableCell(" "+scoreStr).SetTextColor(scoreColor).SetAlign(tview.AlignRight))
			table.SetCell(rowIdx, 1, tview.NewTableCell(" "+r.Confidence).SetTextColor(confColor).SetAlign(tview.AlignCenter))
			table.SetCell(rowIdx, 2, tview.NewTableCell(" "+statusStr).SetTextColor(statusColor).SetAlign(tview.AlignCenter))
			table.SetCell(rowIdx, 3, tview.NewTableCell(" "+r.URL).SetTextColor(tcell.ColorWhite))
			table.SetCell(rowIdx, 4, tview.NewTableCell(" "+surfaces).SetTextColor(tcell.GetColor(ColorGreen)))
		}
	}

	if rowIdx > 1 {
		table.Select(1, 0)
	} else {
		table.Select(0, 0)
	}
	table.ScrollToBeginning()

	// Update footer text with truncation warnings (M2)
	var footerMsg string
	var total, shown int

	switch tabIndex {
	case 0:
		total = q.subdomainsTotalCount
		shown = len(q.subdomains)
	case 1:
		total = q.portsTotalCount
		shown = len(q.ports)
	case 2:
		total = q.vulnsTotalCount
		shown = len(q.vulns)
	case 3:
		total = q.urlsTotalCount
		shown = len(q.urls)
	case 4:
		total = q.endpointsTotalCount
		shown = len(q.endpoints)
	case 5:
		total = q.roiTotalCount
		shown = len(q.roi)
	}

	isTruncated := total > shown
	helpKeys := fmt.Sprintf(
		" [%s]Tab[-] Focus Panel  |  [%s]1-6[-] Switch Tabs  |  [%s]/[-] Search  |  [%s]Esc[-] Unfocus  |  [%s]R[-] Reload  |  [%s]Q/Ctrl+C[-] Exit",
		ColorActive, ColorActive, ColorActive, ColorActive, ColorActive, ColorActive,
	)

	if isTruncated {
		footerMsg = fmt.Sprintf("%s  |  [#f38ba8::b]⚠️ WARNING: Truncated - showing first %d of %d items[-]", helpKeys, shown, total)
	} else {
		footerMsg = helpKeys
	}
	q.FooterText.SetText(footerMsg)
}

// showDetailsPopup opens detailed overlay modal cards
func (q *QueryConsole) showDetailsPopup(tabIndex int, dataIndex int) {
	var title string
	var sb strings.Builder

	switch tabIndex {
	case 0:
		if dataIndex < 0 || dataIndex >= len(q.filteredSubdomains) {
			return
		}
		s := q.filteredSubdomains[dataIndex]
		title = " SUBDOMAIN DETAILS "
		sb.WriteString(fmt.Sprintf("[%s::b]Domain Context:[-]\n\n", ColorLavender))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Hostname:", s.Domain))
		sb.WriteString(fmt.Sprintf("  %-16s %t\n", "Resolving (Live):", s.IsLive))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "IP Address:", s.IPAddress))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Discovery Tool:", s.Source))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Recorded At:", s.CreatedAt.Format("2006-01-02 15:04:05")))

	case 1:
		if dataIndex < 0 || dataIndex >= len(q.filteredPorts) {
			return
		}
		p := q.filteredPorts[dataIndex]
		title = " PORT DETAILS "
		sb.WriteString(fmt.Sprintf("[%s::b]Open Port Context:[-]\n\n", ColorLavender))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "IP/Host:", p.Host))
		sb.WriteString(fmt.Sprintf("  %-16s %d/%s\n", "Port Service:", p.Port, p.Protocol))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Declared Protocol:", p.Service))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Recorded At:", p.CreatedAt.Format("2006-01-02 15:04:05")))

	case 2:
		if dataIndex < 0 || dataIndex >= len(q.filteredVulns) {
			return
		}
		v := q.filteredVulns[dataIndex]
		title = " VULNERABILITY DETAILS "
		sb.WriteString(fmt.Sprintf("[%s::b]Discovery Finding:[-]\n\n", ColorRed))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Target Name:", v.Name))
		sb.WriteString(fmt.Sprintf("  %-16s [%s::b]%s[-]\n", "Severity Rating:", ColorRed, strings.ToUpper(v.Severity)))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Target IP/Host:", v.Host))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Trigger URL:", v.URL))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Nuclei Template:", v.TemplateID))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n\n", "Trigger Time:", v.CreatedAt.Format("2006-01-02 15:04:05")))

		if v.Description != "" {
			sb.WriteString(fmt.Sprintf("[%s::b]Description:[-]\n  %s\n\n", ColorSapphire, v.Description))
		}
		if v.Matcher != "" {
			sb.WriteString(fmt.Sprintf("[%s::b]Trigger Matcher:[-]\n  %s\n\n", ColorSapphire, v.Matcher))
		}
		if v.Evidence != "" {
			sb.WriteString(fmt.Sprintf("[%s::b]Matcher Evidence / Response Extract:[-]\n  %s\n", ColorSapphire, v.Evidence))
		}

	case 3:
		if dataIndex < 0 || dataIndex >= len(q.filteredURLs) {
			return
		}
		u := q.filteredURLs[dataIndex]
		title = " URL DETAILS "
		sb.WriteString(fmt.Sprintf("[%s::b]Web Resource details:[-]\n\n", ColorLavender))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Complete URL:", u.URL))
		sb.WriteString(fmt.Sprintf("  %-16s %d\n", "HTTP Response:", u.StatusCode))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Content Type:", u.ContentType))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Page Title:", u.Title))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Scraped Sources:", u.Source))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n\n", "Scraped At:", u.CreatedAt.Format("2006-01-02 15:04:05")))

		var techs []string
		if err := json.Unmarshal([]byte(u.Tech), &techs); err == nil && len(techs) > 0 {
			sb.WriteString(fmt.Sprintf("[%s::b]Fingerprinted Stack:[-]\n", ColorSapphire))
			for _, t := range techs {
				sb.WriteString(fmt.Sprintf("  • %s\n", t))
			}
		} else if u.Tech != "" {
			sb.WriteString(fmt.Sprintf("[%s::b]Fingerprinted Stack:[-]\n  %s\n", ColorSapphire, u.Tech))
		}

	case 4:
		if dataIndex < 0 || dataIndex >= len(q.filteredEndpoints) {
			return
		}
		e := q.filteredEndpoints[dataIndex]
		title = " API ENDPOINT DETAILS "
		sb.WriteString(fmt.Sprintf("[%s::b]Endpoint Context:[-]\n\n", ColorLavender))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Discovered URL:", e.URL))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "HTTP Method:", e.Method))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Parser Source:", e.Source))
		sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Recorded At:", e.CreatedAt.Format("2006-01-02 15:04:05")))

	case 5:
		if dataIndex < 0 || dataIndex >= len(q.filteredROI) {
			return
		}
		r := q.filteredROI[dataIndex]
		title = " ROI RATING DETAILS "
		sb.WriteString(fmt.Sprintf("[%s::b]ROI Target Ranking:[-]\n\n", ColorLavender))
		sb.WriteString(fmt.Sprintf("  %-18s %s\n", "Target URL:", r.URL))
		sb.WriteString(fmt.Sprintf("  %-18s %d\n", "Raw ROI Score:", r.Score))
		sb.WriteString(fmt.Sprintf("  %-18s %d/100\n", "Normalized Score:", r.NormalizedScore))
		sb.WriteString(fmt.Sprintf("  %-18s %s\n", "Confidence Tier:", r.Confidence))
		sb.WriteString(fmt.Sprintf("  %-18s %d\n", "HTTP Response:", r.StatusCode))
		if len(r.Tech) > 0 {
			sb.WriteString(fmt.Sprintf("  %-18s %s\n", "Tech Stack:", strings.Join(r.Tech, ", ")))
		}
		if len(r.AttackSurfaces) > 0 {
			sb.WriteString(fmt.Sprintf("  %-18s %s\n", "Attack Surfaces:", strings.Join(r.AttackSurfaces, ", ")))
		}
		sb.WriteString("\n")

		if len(r.Reasons) > 0 {
			sb.WriteString(fmt.Sprintf("[%s::b]ROI Point Rationale:[-]\n", ColorSapphire))
			for _, reason := range r.Reasons {
				sb.WriteString(fmt.Sprintf("  %s\n", reason))
			}
		}
	}

	// Create styled popup TextView
	view := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true).
		SetText(sb.String())

	view.SetBorder(true).
		SetTitle(title).
		SetTitleColor(tcell.GetColor(ColorSapphire)).
		SetBorderColor(tcell.GetColor(ColorActive))

	view.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape || event.Key() == tcell.KeyEnter {
			q.Pages.RemovePage("detail_modal")
			return nil
		}
		return event
	})

	// Align to center overlay flex container
	modal := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().
			SetDirection(tview.FlexColumn).
			AddItem(nil, 0, 1, false).
			AddItem(view, 80, 1, true).
			AddItem(nil, 0, 1, false), 20, 1, true).
		AddItem(nil, 0, 1, false)

	q.Pages.AddPage("detail_modal", modal, true, true)
}
