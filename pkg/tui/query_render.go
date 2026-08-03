package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

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
