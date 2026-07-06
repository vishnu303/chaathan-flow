package tui

import (
	"github.com/vishnu303/chaathan/pkg/database"
)

var TruncateText = truncateText
var PickStepsForType = pickStepsForType
var GetTopTechnologies = getTopTechnologies

func (q *QueryConsole) LoadScanData(scanID int64) {
	q.loadScanData(scanID)
}

func (q *QueryConsole) GetSubdomainsTotalCount() int {
	return q.subdomainsTotalCount
}

func (q *QueryConsole) GetSubdomains() []database.Subdomain {
	return q.subdomains
}

func (q *QueryConsole) GetTechCacheValue(url string) string {
	if q.techCache == nil {
		return ""
	}
	return q.techCache[url]
}
