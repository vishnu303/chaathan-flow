package tui

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
)

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
	switch tabIdx {
	case 0:
		q.loadSubdomainsCache()
	case 1:
		q.loadPortsCache()
	case 2:
		q.loadVulnsCache()
	case 3:
		q.loadURLsCache()
	case 4:
		q.loadEndpointsCache()
	case 5:
		q.loadROICache()
	}

	q.populateTable(tabIdx)
}

// loadSubdomainsCache lazily loads subdomain rows for the current scan
func (q *QueryConsole) loadSubdomainsCache() {
	const maxRows = 50000
	if q.subdomains != nil {
		return
	}
	rawSubs, err := database.GetSubdomains(q.ScanID)
	if err != nil {
		logger.FileDebug("GetSubdomains error: %v", err)
		return
	}
	if len(rawSubs) > maxRows {
		rawSubs = rawSubs[:maxRows]
	}
	q.subdomains = rawSubs
}

// loadPortsCache lazily loads open port rows for the current scan
func (q *QueryConsole) loadPortsCache() {
	const maxRows = 50000
	if q.ports != nil {
		return
	}
	rawPorts, err := database.GetPorts(q.ScanID)
	if err != nil {
		logger.FileDebug("GetPorts error: %v", err)
		return
	}
	if len(rawPorts) > maxRows {
		rawPorts = rawPorts[:maxRows]
	}
	q.ports = rawPorts
}

// loadVulnsCache lazily loads vulnerability rows for the current scan
func (q *QueryConsole) loadVulnsCache() {
	const maxRows = 50000
	if q.vulns != nil {
		return
	}
	rawVulns, err := database.GetVulnerabilities(q.ScanID)
	if err != nil {
		logger.FileDebug("GetVulnerabilities error: %v", err)
		return
	}
	if len(rawVulns) > maxRows {
		rawVulns = rawVulns[:maxRows]
	}
	q.vulns = rawVulns
}

// loadURLsCache lazily loads crawled URL rows for the current scan
func (q *QueryConsole) loadURLsCache() {
	const maxRows = 50000
	if q.urls != nil {
		return
	}
	rawUrls, err := database.GetURLs(q.ScanID)
	if err != nil {
		logger.FileDebug("GetURLs error: %v", err)
		return
	}
	if len(rawUrls) > maxRows {
		rawUrls = rawUrls[:maxRows]
	}
	q.urls = rawUrls
}

// loadEndpointsCache lazily loads endpoint rows for the current scan
func (q *QueryConsole) loadEndpointsCache() {
	const maxRows = 50000
	if q.endpoints != nil {
		return
	}
	rawEndpoints, err := database.GetEndpoints(q.ScanID)
	if err != nil {
		logger.FileDebug("GetEndpoints error: %v", err)
		return
	}
	if len(rawEndpoints) > maxRows {
		rawEndpoints = rawEndpoints[:maxRows]
	}
	q.endpoints = rawEndpoints
}

// loadROICache lazily loads ranked ROI URL rows for the current scan
func (q *QueryConsole) loadROICache() {
	const maxRows = 50000
	if q.roi != nil {
		return
	}
	rawRoi, err := database.GetRankedURLs(q.ScanID, maxRows)
	if err != nil {
		logger.FileDebug("GetRankedURLs error: %v", err)
		return
	}
	q.roi = rawRoi
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
