package tui

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
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
	HeaderText  *tview.TextView

	ActiveTab  int
	ScanID     int64
	FilterText string

	showLiveOnly       bool
	vulnSeverityFilter string
	currentPage        [6]int
	pageSize           int
	liveSubdomains     map[string]bool

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
		App:          tview.NewApplication(),
		ActiveTab:    0,
		ScanID:       presetScanID,
		showLiveOnly: true,
		pageSize:     100,
	}

	q.initViews()
	q.setupLayoutAndEvents()

	if err := q.loadScansHistory(presetScanID); err != nil {
		return err
	}

	q.updateBorderColors()

	if err := q.App.SetRoot(q.buildRootLayout(), true).EnableMouse(true).Run(); err != nil {
		return err
	}
	return nil
}

// initViews initializes TUI layout components
func (q *QueryConsole) initViews() {
	// 1. Header Text
	q.HeaderText = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	q.HeaderText.SetText(fmt.Sprintf(
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
	titles := []string{" SUBDOMAINS FINDINGS ", " OPEN PORTS ", " DISCOVERED VULNERABILITIES ", " CRAWLED URLS ", " API ENDPOINTS ", " TESTING ROI TARGETS "}

	for i := 0; i < 6; i++ {
		table := tview.NewTable().
			SetBorders(false).
			SetSelectable(true, false).
			SetFixed(1, 0)
		
		table.SetBorder(true).
			SetTitleColor(tcell.GetColor(ColorSapphire)).
			SetBorderColor(tcell.GetColor(ColorBorder))
		table.SetTitle(titles[i])
		
		// Style selection row
		selectedStyle := tcell.StyleDefault.
			Foreground(tcell.GetColor(ColorActive)).
			Background(tcell.GetColor("#313244"))
		table.SetSelectedStyle(selectedStyle)

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
				q.currentPage[q.ActiveTab] = 0
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
}

// setupLayoutAndEvents wires handlers and input mappings
func (q *QueryConsole) setupLayoutAndEvents() {
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
		case tcell.KeyCtrlF:
			if !q.FilterInput.HasFocus() {
				q.nextPage()
				return nil
			}
		case tcell.KeyCtrlB:
			if !q.FilterInput.HasFocus() {
				q.prevPage()
				return nil
			}
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
		case '[':
			if !q.FilterInput.HasFocus() {
				prevTab := (q.ActiveTab - 1 + 6) % 6
				q.switchTab(prevTab)
				return nil
			}
		case ']':
			if !q.FilterInput.HasFocus() {
				nextTab := (q.ActiveTab + 1) % 6
				q.switchTab(nextTab)
				return nil
			}
		case '.':
			if !q.FilterInput.HasFocus() {
				q.nextPage()
				return nil
			}
		case ',':
			if !q.FilterInput.HasFocus() {
				q.prevPage()
				return nil
			}
		case 'l', 'L':
			if !q.FilterInput.HasFocus() {
				q.showLiveOnly = !q.showLiveOnly
				q.currentPage[q.ActiveTab] = 0
				q.populateTable(q.ActiveTab)
				return nil
			}
		case 's', 'S':
			if !q.FilterInput.HasFocus() && q.ActiveTab == 2 {
				var nextSev string
				switch q.vulnSeverityFilter {
				case "":
					nextSev = "critical"
				case "critical":
					nextSev = "high"
				case "high":
					nextSev = "medium"
				case "medium":
					nextSev = "low"
				case "low":
					nextSev = "info"
				case "info":
					nextSev = ""
				}
				q.vulnSeverityFilter = nextSev
				q.currentPage[2] = 0
				q.populateTable(2)
				return nil
			}
		}

		return event
	})
}

// loadScansHistory queries database for the scan runs history list
func (q *QueryConsole) loadScansHistory(presetScanID int64) error {
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
	return nil
}

// buildRootLayout assembles layouts in nested flex columns and rows
func (q *QueryConsole) buildRootLayout() *tview.Flex {
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
		AddItem(q.HeaderText, 1, 0, false).
		AddItem(mainFlex, 0, 1, true).
		AddItem(q.FooterText, 1, 0, false)

	return rootLayout
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
	if q.TabsText == nil {
		return
	}
	tabNames := []string{"SUBDOMAINS", "PORTS", "VULNERABILITIES", "URLS", "ENDPOINTS", "ROI TARGETS"}
	counts := []int{
		q.subdomainsTotalCount,
		q.portsTotalCount,
		q.vulnsTotalCount,
		q.urlsTotalCount,
		q.endpointsTotalCount,
		q.roiTotalCount,
	}
	var parts []string
	for i, name := range tabNames {
		countStr := ""
		if len(q.scans) > 0 {
			countStr = fmt.Sprintf(" (%d)", counts[i])
		}
		if i == q.ActiveTab {
			parts = append(parts, fmt.Sprintf("[%s::b]● %s%s[-]", ColorActive, name, countStr))
		} else {
			parts = append(parts, fmt.Sprintf("[%s]○ %s%s[-]", ColorSubtle, name, countStr))
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
	q.loadActiveTab(tabIdx)

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

	// Reset page indices and filters
	q.currentPage = [6]int{}
	q.vulnSeverityFilter = ""
	q.showLiveOnly = true

	// Clear filter input UI safely without triggering extra draws
	q.FilterText = ""
	if q.FilterInput != nil {
		q.FilterInput.SetText("")
	}

	// Release all loaded slices from the old scan
	for idx := 0; idx < 6; idx++ {
		q.releaseTabMemory(idx)
	}

	// Load live subdomains map for filtering other tabs
	q.loadLiveSubdomainsMap(scanID)

	// Load counts (also sets header text and calls drawTabs)
	q.loadScanCounts(scanID)

	// Lazy load active tab data (which will call populateTable)
	q.loadActiveTab(q.ActiveTab)
}

// populateTable performs string search filtering and renders columns
func (q *QueryConsole) populateTable(tabIndex int) {
	table := q.Tables[tabIndex]
	table.Clear()

	filter := strings.ToLower(q.FilterText)

	// Phase 1: Filter data
	q.filterDataForTab(tabIndex, filter)

	// Phase 2: Pagination calculations
	count := q.getFilteredCount(tabIndex)
	pageSize := q.pageSize
	if pageSize <= 0 {
		pageSize = 100
	}
	totalPages := 0
	if count > 0 {
		totalPages = (count + pageSize - 1) / pageSize
	}
	if q.currentPage[tabIndex] >= totalPages {
		q.currentPage[tabIndex] = totalPages - 1
	}
	if q.currentPage[tabIndex] < 0 {
		q.currentPage[tabIndex] = 0
	}

	start := q.currentPage[tabIndex] * pageSize
	end := start + pageSize
	if end > count {
		end = count
	}

	// Phase 3: Render tab columns
	q.renderTabTable(tabIndex, table, filter, start, end, count, totalPages)

	// Phase 4: Selection and Scroll Settings
	if end > start {
		table.Select(1, 0)
	} else {
		table.Select(0, 0)
	}
	table.ScrollToBeginning()

	q.updateFooter(tabIndex)
}

// filterDataForTab delegates filtering to specific category helpers
func (q *QueryConsole) filterDataForTab(tabIndex int, filter string) {
	switch tabIndex {
	case 0:
		q.filterSubdomains(filter)
	case 1:
		q.filterPorts(filter)
	case 2:
		q.filterVulns(filter)
	case 3:
		q.filterURLs(filter)
	case 4:
		q.filterEndpoints(filter)
	case 5:
		q.filterROI(filter)
	}
}

func (q *QueryConsole) filterSubdomains(filter string) {
	q.filteredSubdomains = nil
	for _, s := range q.subdomains {
		if q.showLiveOnly && !s.IsLive {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(s.Domain), filter) &&
			!strings.Contains(strings.ToLower(s.IPAddress), filter) &&
			!strings.Contains(strings.ToLower(s.Source), filter) {
			continue
		}
		q.filteredSubdomains = append(q.filteredSubdomains, s)
	}
}

func (q *QueryConsole) filterPorts(filter string) {
	q.filteredPorts = nil
	for _, p := range q.ports {
		if q.showLiveOnly && !q.isHostLive(p.Host) {
			continue
		}
		portStr := fmt.Sprintf("%d", p.Port)
		if filter != "" && !strings.Contains(strings.ToLower(p.Host), filter) &&
			!strings.Contains(strings.ToLower(portStr), filter) &&
			!strings.Contains(strings.ToLower(p.Protocol), filter) &&
			!strings.Contains(strings.ToLower(p.Service), filter) {
			continue
		}
		q.filteredPorts = append(q.filteredPorts, p)
	}
}

func (q *QueryConsole) filterVulns(filter string) {
	q.filteredVulns = nil
	for _, v := range q.vulns {
		if q.showLiveOnly && !q.isHostLive(v.Host) {
			continue
		}
		if q.vulnSeverityFilter != "" && strings.ToLower(v.Severity) != q.vulnSeverityFilter {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(v.Severity), filter) &&
			!strings.Contains(strings.ToLower(v.Host), filter) &&
			!strings.Contains(strings.ToLower(v.Name), filter) &&
			!strings.Contains(strings.ToLower(v.URL), filter) {
			continue
		}
		q.filteredVulns = append(q.filteredVulns, v)
	}
}

func (q *QueryConsole) filterURLs(filter string) {
	q.filteredURLs = nil
	for _, u := range q.urls {
		if q.showLiveOnly && (u.StatusCode <= 0 || !q.isHostLive(u.Host)) {
			continue
		}
		statusStr := fmt.Sprintf("%d", u.StatusCode)
		if filter != "" && !strings.Contains(statusStr, filter) &&
			!strings.Contains(strings.ToLower(u.Source), filter) &&
			!strings.Contains(strings.ToLower(u.URL), filter) &&
			!strings.Contains(strings.ToLower(u.Title), filter) &&
			!strings.Contains(strings.ToLower(u.Tech), filter) {
			continue
		}
		q.filteredURLs = append(q.filteredURLs, u)
	}
}

func (q *QueryConsole) filterEndpoints(filter string) {
	q.filteredEndpoints = nil
	for _, e := range q.endpoints {
		if q.showLiveOnly && !q.isHostLive(e.Host) {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(e.Method), filter) &&
			!strings.Contains(strings.ToLower(e.Source), filter) &&
			!strings.Contains(strings.ToLower(e.URL), filter) {
			continue
		}
		q.filteredEndpoints = append(q.filteredEndpoints, e)
	}
}

func (q *QueryConsole) filterROI(filter string) {
	q.filteredROI = nil
	for _, r := range q.roi {
		if q.showLiveOnly && (r.StatusCode <= 0 || !q.isHostLive(r.Host)) {
			continue
		}
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
	}
}

// renderTabTable delegates rendering logic to specific tab helpers
func (q *QueryConsole) renderTabTable(tabIdx int, table *tview.Table, filter string, start, end, count, totalPages int) {
	switch tabIdx {
	case 0:
		q.renderSubdomainsTable(table, filter, start, end, count, totalPages)
	case 1:
		q.renderPortsTable(table, filter, start, end, count, totalPages)
	case 2:
		q.renderVulnsTable(table, filter, start, end, count, totalPages)
	case 3:
		q.renderURLsTable(table, filter, start, end, count, totalPages)
	case 4:
		q.renderEndpointsTable(table, filter, start, end, count, totalPages)
	case 5:
		q.renderROITable(table, filter, start, end, count, totalPages)
	}
}

// formatTitle returns a structured standard title for findings tables
func (q *QueryConsole) formatTitle(baseTitle string, tabIdx int, count, totalPages, start, end int, extra string) string {
	if count == 0 {
		if extra != "" {
			return fmt.Sprintf(" %s (0 items, %s) ", baseTitle, extra)
		}
		return fmt.Sprintf(" %s (0 items) ", baseTitle)
	}
	extraStr := ""
	if extra != "" {
		extraStr = ", " + extra
	}
	return fmt.Sprintf(" %s (Page %d/%d, showing %d-%d of %d%s) ", baseTitle, q.currentPage[tabIdx]+1, totalPages, start+1, end, count, extraStr)
}

// setTableHeader sets structured header cells for tables
func (q *QueryConsole) setTableHeader(table *tview.Table, headers []string, expansionCol int) {
	for col, h := range headers {
		cell := tview.NewTableCell(" " + h + " ").
			SetTextColor(tcell.GetColor(ColorSapphire)).
			SetSelectable(false)
		if col == expansionCol {
			cell.SetExpansion(1)
		}
		table.SetCell(0, col, cell)
	}
}

func (q *QueryConsole) renderSubdomainsTable(table *tview.Table, filter string, start, end, count, totalPages int) {
	q.setTableHeader(table, []string{"DOMAIN", "LIVE", "IP ADDRESS", "SOURCE"}, 0)

	extra := "All"
	if q.showLiveOnly {
		extra = "Live Only"
	}
	if filter != "" {
		extra += ", Filtered"
	}
	table.SetTitle(q.formatTitle("SUBDOMAINS FINDINGS", 0, count, totalPages, start, end, extra))

	if count == 0 {
		return
	}

	rowIdx := 1
	sliced := q.filteredSubdomains[start:end]
	for _, s := range sliced {
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
}

func (q *QueryConsole) renderPortsTable(table *tview.Table, filter string, start, end, count, totalPages int) {
	q.setTableHeader(table, []string{"HOST", "PORT", "PROTOCOL", "SERVICE"}, 0)

	extra := ""
	if filter != "" {
		extra = "Filtered"
	}
	table.SetTitle(q.formatTitle("OPEN PORTS", 1, count, totalPages, start, end, extra))

	if count == 0 {
		return
	}

	rowIdx := 1
	sliced := q.filteredPorts[start:end]
	for _, p := range sliced {
		portStr := fmt.Sprintf("%d", p.Port)
		table.SetCell(rowIdx, 0, tview.NewTableCell(" "+p.Host).SetTextColor(tcell.ColorWhite))
		table.SetCell(rowIdx, 1, tview.NewTableCell(" "+portStr).SetTextColor(tcell.GetColor(ColorYellow)).SetAlign(tview.AlignRight))
		table.SetCell(rowIdx, 2, tview.NewTableCell(" "+p.Protocol).SetTextColor(tcell.GetColor(ColorBlue)).SetAlign(tview.AlignCenter))
		table.SetCell(rowIdx, 3, tview.NewTableCell(" "+p.Service).SetTextColor(tcell.GetColor(ColorGreen)))
		rowIdx++
	}
}

func (q *QueryConsole) renderVulnsTable(table *tview.Table, filter string, start, end, count, totalPages int) {
	q.setTableHeader(table, []string{"SEVERITY", "HOST", "VULNERABILITY NAME", "TEMPLATE"}, 2)

	extra := "All Severities"
	if q.vulnSeverityFilter != "" {
		extra = strings.ToUpper(q.vulnSeverityFilter)
	}
	if filter != "" {
		extra += ", Filtered"
	}
	table.SetTitle(q.formatTitle("DISCOVERED VULNERABILITIES", 2, count, totalPages, start, end, extra))

	if count == 0 {
		return
	}

	rowIdx := 1
	sliced := q.filteredVulns[start:end]
	for _, v := range sliced {
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
}

func (q *QueryConsole) renderURLsTable(table *tview.Table, filter string, start, end, count, totalPages int) {
	q.setTableHeader(table, []string{"STATUS", "SOURCE", "URL", "TITLE", "TECH"}, 2)

	extra := ""
	if filter != "" {
		extra = "Filtered"
	}
	table.SetTitle(q.formatTitle("CRAWLED URLS", 3, count, totalPages, start, end, extra))

	if count == 0 {
		return
	}

	rowIdx := 1
	sliced := q.filteredURLs[start:end]
	for _, u := range sliced {
		statusStr := fmt.Sprintf("%d", u.StatusCode)
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

		var techStr string
		if u.Tech != "" {
			var techs []string
			if err := json.Unmarshal([]byte(u.Tech), &techs); err == nil {
				techStr = strings.Join(techs, ", ")
			} else {
				techStr = u.Tech
			}
		}
		table.SetCell(rowIdx, 4, tview.NewTableCell(" "+techStr).SetTextColor(tcell.GetColor(ColorGreen)))
		rowIdx++
	}
}

func (q *QueryConsole) renderEndpointsTable(table *tview.Table, filter string, start, end, count, totalPages int) {
	q.setTableHeader(table, []string{"METHOD", "SOURCE", "URL"}, 2)

	extra := ""
	if filter != "" {
		extra = "Filtered"
	}
	table.SetTitle(q.formatTitle("API ENDPOINTS", 4, count, totalPages, start, end, extra))

	if count == 0 {
		return
	}

	rowIdx := 1
	sliced := q.filteredEndpoints[start:end]
	for _, e := range sliced {
		methodColor := tcell.GetColor(ColorSubtle)
		method := e.Method
		if method == "" {
			method = "GET"
		}
		switch strings.ToUpper(method) {
		case "GET":
			methodColor = tcell.GetColor(ColorGreen)
		case "POST":
			methodColor = tcell.GetColor(ColorYellow)
		case "PUT", "DELETE":
			methodColor = tcell.GetColor(ColorRed)
		}

		table.SetCell(rowIdx, 0, tview.NewTableCell(" "+method).SetTextColor(methodColor).SetAlign(tview.AlignCenter))
		table.SetCell(rowIdx, 1, tview.NewTableCell(" "+e.Source).SetTextColor(tcell.GetColor(ColorLavender)))
		table.SetCell(rowIdx, 2, tview.NewTableCell(" "+e.URL).SetTextColor(tcell.ColorWhite))
		rowIdx++
	}
}

func (q *QueryConsole) renderROITable(table *tview.Table, filter string, start, end, count, totalPages int) {
	q.setTableHeader(table, []string{"SCORE", "CONF", "STATUS", "URL", "ATTACK SURFACES"}, 3)

	extra := ""
	if filter != "" {
		extra = "Filtered"
	}
	table.SetTitle(q.formatTitle("TESTING ROI TARGETS", 5, count, totalPages, start, end, extra))

	if count == 0 {
		return
	}

	rowIdx := 1
	sliced := q.filteredROI[start:end]
	for _, r := range sliced {
		scoreStr := fmt.Sprintf("%d", r.Score)
		statusStr := fmt.Sprintf("%d", r.StatusCode)
		surfaces := strings.Join(r.AttackSurfaces, ", ")

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
		rowIdx++
	}
}

// updateFooter writes contextual instructions and matching statistics to the footer widget
func (q *QueryConsole) updateFooter(tabIndex int) {
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
		" [%s]Tab[-] Focus Panel  |  [%s]1-6/[/]/[-] Tabs  |  [%s]/[-] Filter  |  [%s][,] [.][-] Page  |  [%s]R[-] Reload  |  [%s]Q/Ctrl+C[-] Exit",
		ColorActive, ColorActive, ColorActive, ColorActive, ColorActive, ColorActive,
	)

	statusStr := "Off"
	if q.showLiveOnly {
		statusStr = "On"
	}
	helpKeys += fmt.Sprintf("  |  [%s]L[-] Live Only: %s", ColorActive, statusStr)

	if tabIndex == 2 {
		vulnStatusStr := "All"
		if q.vulnSeverityFilter != "" {
			vulnStatusStr = strings.ToUpper(q.vulnSeverityFilter)
		}
		helpKeys += fmt.Sprintf("  |  [%s]S[-] Severity: %s", ColorActive, vulnStatusStr)
	}

	var footerMsg string
	if isTruncated {
		footerMsg = fmt.Sprintf("%s  |  [#f38ba8::b]⚠️ WARNING: Truncated - showing first %d of %d items[-]", helpKeys, shown, total)
	} else {
		footerMsg = helpKeys
	}
	q.FooterText.SetText(footerMsg)
}

// showDetailsPopup opens detailed overlay modal cards
func (q *QueryConsole) showDetailsPopup(tabIndex int, dataIndex int) {
	var title, text string
	
	pageSize := q.pageSize
	if pageSize <= 0 {
		pageSize = 100
	}

	switch tabIndex {
	case 0:
		title, text = q.getSubdomainDetailsText(dataIndex, pageSize)
	case 1:
		title, text = q.getPortDetailsText(dataIndex, pageSize)
	case 2:
		title, text = q.getVulnDetailsText(dataIndex, pageSize)
	case 3:
		title, text = q.getURLDetailsText(dataIndex, pageSize)
	case 4:
		title, text = q.getEndpointDetailsText(dataIndex, pageSize)
	case 5:
		title, text = q.getROIDetailsText(dataIndex, pageSize)
	}

	if title == "" || text == "" {
		return
	}

	var sb strings.Builder
	sb.WriteString(text)
	sb.WriteString(fmt.Sprintf("\n\n[%s]────────────────────────────────────────────────────────────────────────────────[-]\n", ColorBorder))
	sb.WriteString(fmt.Sprintf(" [%s]Close:[-] [ESC/ENTER]  |  [%s]Scroll:[-] [Up/Down, PgUp/PgDn]", ColorActive, ColorActive))

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

	// Align to center overlay flex container (width 80, height 22)
	modal := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().
			SetDirection(tview.FlexColumn).
			AddItem(nil, 0, 1, false).
			AddItem(view, 80, 1, true).
			AddItem(nil, 0, 1, false), 22, 1, true).
		AddItem(nil, 0, 1, false)

	q.Pages.AddPage("detail_modal", modal, true, true)
}

func (q *QueryConsole) getSubdomainDetailsText(dataIndex, pageSize int) (string, string) {
	actualIndex := q.currentPage[0]*pageSize + dataIndex
	if actualIndex < 0 || actualIndex >= len(q.filteredSubdomains) {
		return "", ""
	}
	s := q.filteredSubdomains[actualIndex]
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s::b]Domain Context:[-]\n\n", ColorLavender))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Hostname:", s.Domain))
	sb.WriteString(fmt.Sprintf("  %-16s %t\n", "Resolving (Live):", s.IsLive))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "IP Address:", s.IPAddress))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Discovery Tool:", s.Source))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Recorded At:", s.CreatedAt.Format("2006-01-02 15:04:05")))
	return " SUBDOMAIN DETAILS ", sb.String()
}

func (q *QueryConsole) getPortDetailsText(dataIndex, pageSize int) (string, string) {
	actualIndex := q.currentPage[1]*pageSize + dataIndex
	if actualIndex < 0 || actualIndex >= len(q.filteredPorts) {
		return "", ""
	}
	p := q.filteredPorts[actualIndex]
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s::b]Open Port Context:[-]\n\n", ColorLavender))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "IP/Host:", p.Host))
	sb.WriteString(fmt.Sprintf("  %-16s %d/%s\n", "Port Service:", p.Port, p.Protocol))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Declared Protocol:", p.Service))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Recorded At:", p.CreatedAt.Format("2006-01-02 15:04:05")))
	return " PORT DETAILS ", sb.String()
}

func (q *QueryConsole) getVulnDetailsText(dataIndex, pageSize int) (string, string) {
	actualIndex := q.currentPage[2]*pageSize + dataIndex
	if actualIndex < 0 || actualIndex >= len(q.filteredVulns) {
		return "", ""
	}
	v := q.filteredVulns[actualIndex]
	var sb strings.Builder
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
	return " VULNERABILITY DETAILS ", sb.String()
}

func (q *QueryConsole) getURLDetailsText(dataIndex, pageSize int) (string, string) {
	actualIndex := q.currentPage[3]*pageSize + dataIndex
	if actualIndex < 0 || actualIndex >= len(q.filteredURLs) {
		return "", ""
	}
	u := q.filteredURLs[actualIndex]
	var sb strings.Builder
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
	return " URL DETAILS ", sb.String()
}

func (q *QueryConsole) getEndpointDetailsText(dataIndex, pageSize int) (string, string) {
	actualIndex := q.currentPage[4]*pageSize + dataIndex
	if actualIndex < 0 || actualIndex >= len(q.filteredEndpoints) {
		return "", ""
	}
	e := q.filteredEndpoints[actualIndex]
	method := e.Method
	if method == "" {
		method = "GET (Default)"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s::b]Endpoint Context:[-]\n\n", ColorLavender))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Discovered URL:", e.URL))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "HTTP Method:", method))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Parser Source:", e.Source))
	sb.WriteString(fmt.Sprintf("  %-16s %s\n", "Recorded At:", e.CreatedAt.Format("2006-01-02 15:04:05")))
	return " API ENDPOINT DETAILS ", sb.String()
}

func (q *QueryConsole) getROIDetailsText(dataIndex, pageSize int) (string, string) {
	actualIndex := q.currentPage[5]*pageSize + dataIndex
	if actualIndex < 0 || actualIndex >= len(q.filteredROI) {
		return "", ""
	}
	r := q.filteredROI[actualIndex]
	var sb strings.Builder
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
	return " ROI RATING DETAILS ", sb.String()
}

// loadScanCounts loads counts of findings and updates category headers
func (q *QueryConsole) loadScanCounts(scanID int64) {
	stats, err := database.GetScanStats(scanID)
	if err != nil {
		logger.FileDebug("GetScanStats error: %v", err)
		return
	}

	q.subdomainsTotalCount = stats.TotalSubdomains
	q.portsTotalCount = stats.TotalPorts
	
	vulnTotal := 0
	if stats.Vulnerabilities != nil {
		for _, count := range stats.Vulnerabilities {
			vulnTotal += count
		}
	}
	q.vulnsTotalCount = vulnTotal
	q.urlsTotalCount = stats.TotalURLs
	q.endpointsTotalCount = stats.TotalEndpoints
	q.roiTotalCount = stats.TotalURLs

	var currentScan *database.Scan
	for _, s := range q.scans {
		if s.ID == scanID {
			currentScan = &s
			break
		}
	}

	if q.HeaderText != nil && currentScan != nil {
		statusSymbol := "[+]"
		statusColor := ColorGreen
		switch currentScan.Status {
		case "failed":
			statusSymbol = "[-]"
			statusColor = ColorRed
		case "running":
			statusSymbol = "[*]"
			statusColor = ColorYellow
		case "cancelled":
			statusSymbol = "[ ]"
			statusColor = ColorBlue
		}
		
		q.HeaderText.SetText(fmt.Sprintf(
			" [%s::b]CHAATHAN RECON CONSOLE[-]  |  Active Scan: [#ffffff::b]%s[-] (ID: #%d)  |  Status: [%s]%s %s[-]",
			ColorActive, currentScan.Target, currentScan.ID, statusColor, statusSymbol, strings.ToUpper(currentScan.Status),
		))
	}

	q.drawTabs()
}

// loadActiveTab queries database for only the active tab's findings (optimized caching)
func (q *QueryConsole) loadActiveTab(tabIdx int) {
	maxRows := 50000
	var err error

	switch tabIdx {
	case 0:
		if q.subdomains == nil {
			var rawSubs []database.Subdomain
			rawSubs, err = database.GetSubdomains(q.ScanID)
			if err == nil {
				if len(rawSubs) > maxRows {
					rawSubs = rawSubs[:maxRows]
				}
				q.subdomains = rawSubs
			} else {
				logger.FileDebug("GetSubdomains error: %v", err)
			}
		}

	case 1:
		if q.ports == nil {
			var rawPorts []database.Port
			rawPorts, err = database.GetPorts(q.ScanID)
			if err == nil {
				if len(rawPorts) > maxRows {
					rawPorts = rawPorts[:maxRows]
				}
				q.ports = rawPorts
			} else {
				logger.FileDebug("GetPorts error: %v", err)
			}
		}

	case 2:
		if q.vulns == nil {
			var rawVulns []database.Vulnerability
			rawVulns, err = database.GetVulnerabilities(q.ScanID)
			if err == nil {
				if len(rawVulns) > maxRows {
					rawVulns = rawVulns[:maxRows]
				}
				q.vulns = rawVulns
			} else {
				logger.FileDebug("GetVulnerabilities error: %v", err)
			}
		}

	case 3:
		if q.urls == nil {
			var rawUrls []database.URL
			rawUrls, err = database.GetURLs(q.ScanID)
			if err == nil {
				if len(rawUrls) > maxRows {
					rawUrls = rawUrls[:maxRows]
				}
				q.urls = rawUrls
			} else {
				logger.FileDebug("GetURLs error: %v", err)
			}
		}

	case 4:
		if q.endpoints == nil {
			var rawEndpoints []database.Endpoint
			rawEndpoints, err = database.GetEndpoints(q.ScanID)
			if err == nil {
				if len(rawEndpoints) > maxRows {
					rawEndpoints = rawEndpoints[:maxRows]
				}
				q.endpoints = rawEndpoints
			} else {
				logger.FileDebug("GetEndpoints error: %v", err)
			}
		}

	case 5:
		if q.roi == nil {
			var rawRoi []database.URLROI
			rawRoi, err = database.GetRankedURLs(q.ScanID, maxRows)
			if err == nil {
				q.roi = rawRoi
			} else {
				logger.FileDebug("GetRankedURLs error: %v", err)
			}
		}
	}

	q.populateTable(tabIdx)
}

// releaseTabMemory sets inactive tab slices to nil to reclaim memory via GC
func (q *QueryConsole) releaseTabMemory(tabIdx int) {
	switch tabIdx {
	case 0:
		q.subdomains = nil
		q.filteredSubdomains = nil
	case 1:
		q.ports = nil
		q.filteredPorts = nil
	case 2:
		q.vulns = nil
		q.filteredVulns = nil
	case 3:
		q.urls = nil
		q.filteredURLs = nil
		q.techCache = nil
	case 4:
		q.endpoints = nil
		q.filteredEndpoints = nil
	case 5:
		q.roi = nil
		q.filteredROI = nil
	}
}

func (q *QueryConsole) getFilteredCount(tabIdx int) int {
	switch tabIdx {
	case 0:
		return len(q.filteredSubdomains)
	case 1:
		return len(q.filteredPorts)
	case 2:
		return len(q.filteredVulns)
	case 3:
		return len(q.filteredURLs)
	case 4:
		return len(q.filteredEndpoints)
	case 5:
		return len(q.filteredROI)
	}
	return 0
}

func (q *QueryConsole) nextPage() {
	count := q.getFilteredCount(q.ActiveTab)
	if count == 0 {
		return
	}
	pageSize := q.pageSize
	if pageSize <= 0 {
		pageSize = 100
	}
	totalPages := (count + pageSize - 1) / pageSize
	if q.currentPage[q.ActiveTab] < totalPages-1 {
		q.currentPage[q.ActiveTab]++
		q.populateTable(q.ActiveTab)
	}
}

func (q *QueryConsole) prevPage() {
	if q.currentPage[q.ActiveTab] > 0 {
		q.currentPage[q.ActiveTab]--
		q.populateTable(q.ActiveTab)
	}
}

func (q *QueryConsole) isHostLive(host string) bool {
	if q.liveSubdomains == nil {
		return true // fallback if not loaded
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err == nil {
			host = parsed.Hostname()
		}
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	return q.liveSubdomains[host]
}

func (q *QueryConsole) loadLiveSubdomainsMap(scanID int64) {
	q.liveSubdomains = make(map[string]bool)

	if database.DB == nil {
		return
	}

	// 1. Get DNS-live subdomains and their IPs from subdomains table
	rows, err := database.DB.Query("SELECT domain, ip_address FROM subdomains WHERE scan_id = ? AND is_live = TRUE", scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var domain, ip string
			if err := rows.Scan(&domain, &ip); err == nil {
				domain = strings.ToLower(strings.TrimSpace(domain))
				if domain != "" {
					q.liveSubdomains[domain] = true
				}
				ip = strings.ToLower(strings.TrimSpace(ip))
				if ip != "" {
					// Split by comma in case multiple IPs are stored
					for _, part := range strings.Split(ip, ",") {
						part = strings.TrimSpace(part)
						if part != "" {
							q.liveSubdomains[part] = true
						}
					}
				}
			}
		}
	} else {
		logger.FileDebug("Failed to query live subdomains/IPs: %v", err)
	}

	// 2. Get HTTP-live hosts from urls table (status_code > 0)
	rows2, err := database.DB.Query("SELECT DISTINCT host FROM urls WHERE scan_id = ? AND status_code > 0 AND host IS NOT NULL AND host != ''", scanID)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var h string
			if err := rows2.Scan(&h); err == nil {
				q.liveSubdomains[strings.ToLower(strings.TrimSpace(h))] = true
			}
		}
	} else {
		logger.FileDebug("Failed to get live hosts from urls: %v", err)
	}
}
