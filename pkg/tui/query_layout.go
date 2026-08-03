package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

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
	q.setupScanListHandlers()
	q.setupFocusHandlers()

	// Global Key Captures for fast navigation
	q.App.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if q.Pages.HasPage("detail_modal") {
			return event // Let detail modal capture inputs
		}
		if event = q.handleSpecialKey(event); event == nil {
			return nil
		}
		return q.handleRuneKey(event)
	})
}

// setupScanListHandlers wires sidebar scan selection to data loading
func (q *QueryConsole) setupScanListHandlers() {
	// Sidebar scan list selection triggers data loading
	q.ScanList.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		if index < 0 || index >= len(q.scans) {
			return
		}
		q.loadScanData(q.scans[index].ID)
	})
}

// setupFocusHandlers paints widget borders dynamically on focus change
func (q *QueryConsole) setupFocusHandlers() {
	q.ScanList.SetFocusFunc(func() { q.updateBorderColors() })
	q.FilterInput.SetFocusFunc(func() { q.updateBorderColors() })
	for i := 0; i < 6; i++ {
		q.Tables[i].SetFocusFunc(func() { q.updateBorderColors() })
	}
}

// handleSpecialKey handles non-rune navigation keys; returns nil when consumed
func (q *QueryConsole) handleSpecialKey(event *tcell.EventKey) *tcell.EventKey {
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
			q.clearFilterAndRefocusTable()
			return nil
		}
	}
	return event
}

// clearFilterAndRefocusTable resets the filter input and returns focus to the active table
func (q *QueryConsole) clearFilterAndRefocusTable() {
	q.FilterInput.SetText("")
	q.FilterText = ""
	q.populateTable(q.ActiveTab)
	q.App.SetFocus(q.Tables[q.ActiveTab])
	q.updateBorderColors()
}

// handleRuneKey handles rune shortcuts; returns nil when the key is consumed
func (q *QueryConsole) handleRuneKey(event *tcell.EventKey) *tcell.EventKey {
	if q.FilterInput.HasFocus() {
		return event
	}

	switch event.Rune() {
	case 'q', 'Q':
		q.App.Stop()
		return nil
	case 'r', 'R':
		q.loadScanData(q.ScanID)
		return nil
	case '/':
		q.App.SetFocus(q.FilterInput)
		q.updateBorderColors()
		return nil
	case '1', '2', '3', '4', '5', '6':
		q.switchTab(int(event.Rune() - '1'))
		return nil
	case '[':
		q.switchTab((q.ActiveTab - 1 + 6) % 6)
		return nil
	case ']':
		q.switchTab((q.ActiveTab + 1) % 6)
		return nil
	case '.':
		q.nextPage()
		return nil
	case ',':
		q.prevPage()
		return nil
	case 'l', 'L':
		q.toggleLiveOnly()
		return nil
	case 's', 'S':
		if q.ActiveTab == 2 {
			q.cycleSeverityFilter()
			return nil
		}
	}
	return event
}

// toggleLiveOnly flips live-only filtering and refreshes the active tab
func (q *QueryConsole) toggleLiveOnly() {
	q.showLiveOnly = !q.showLiveOnly
	q.currentPage[q.ActiveTab] = 0
	q.populateTable(q.ActiveTab)
}

// cycleSeverityFilter advances the vulnerability severity filter and refreshes the vulns tab
func (q *QueryConsole) cycleSeverityFilter() {
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
}

// loadScansHistory queries database for the scan runs history list

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
