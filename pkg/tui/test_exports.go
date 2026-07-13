package tui

import (
	"encoding/json"
	"strings"

	"github.com/vishnu303/chaathan/pkg/database"
)

var TruncateText = truncateText
var PickStepsForType = pickStepsForType
var GetTopTechnologies = getTopTechnologies

func (q *QueryConsole) LoadScanData(scanID int64) {
	q.loadScanData(scanID)
}

func (q *QueryConsole) LoadActiveTab(tabIdx int) {
	q.loadActiveTab(tabIdx)
}

func (q *QueryConsole) GetSubdomainsTotalCount() int {
	return q.subdomainsTotalCount
}

func (q *QueryConsole) GetSubdomains() []database.Subdomain {
	return q.subdomains
}

func (q *QueryConsole) GetTechCacheValue(targetURL string) string {
	for _, u := range q.urls {
		if u.URL == targetURL {
			if u.Tech == "" {
				return ""
			}
			var techs []string
			if err := json.Unmarshal([]byte(u.Tech), &techs); err == nil {
				return strings.Join(techs, ", ")
			}
			return u.Tech
		}
	}
	return ""
}
