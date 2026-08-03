package tui

import (
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/vishnu303/chaathan/pkg/database"
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
