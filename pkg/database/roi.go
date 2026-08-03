package database

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
)

// URLROI represents a ranked target with score context.
type URLROI struct {
	URL              string         `json:"url"`
	Host             string         `json:"host"`
	StatusCode       int            `json:"status_code,omitempty"`
	Title            string         `json:"title,omitempty"`
	ContentType      string         `json:"content_type,omitempty"`
	Source           string         `json:"source,omitempty"`
	Tech             []string       `json:"tech,omitempty"`
	Score            int            `json:"score"`
	NormalizedScore  int            `json:"normalized_score"`
	Confidence       string         `json:"confidence"`
	SignalCount      int            `json:"signal_count"`
	AttackSurfaces   []string       `json:"attack_surfaces,omitempty"`
	Reasons          []string       `json:"reasons"`
	EndpointCount    int            `json:"endpoint_count"`
	KatanaCount      int            `json:"katana_count"`
	GoSpiderCount    int            `json:"gospider_count"`
	LinkFinderCount  int            `json:"linkfinder_count"`
	FfufCount        int            `json:"ffuf_count"`
	OpenPortCount    int            `json:"open_port_count"`
	ExactVulnCounts  map[string]int `json:"exact_vuln_counts,omitempty"`
	HostVulnCounts   map[string]int `json:"host_vuln_counts,omitempty"`
	IsParameterized  bool           `json:"is_parameterized"`
	InterestingTerms []string       `json:"interesting_terms,omitempty"`
}

type endpointStats struct {
	Total    int
	BySource map[string]int
}

type mergedMetadata struct {
	HasHostData         bool
	HasURLData          bool
	HasCSP              bool
	HasCacheHeaders     bool
	LoginSurface        bool
	SSLExpired          bool
	SSLSelfSigned       bool
	SSLMismatch         bool
	WeakTLS             bool
	ResponseBytes       int
	HasJSSecrets        bool
	FormCount           int
	HasFileUpload       bool
	HiddenInputCount    int
	HostHeadersJSON     string
	URLHeadersJSON      string
	CORSWildcard        bool
	HasInsecureCookies  bool
	HasSessionCookie    bool
	HasDangerousMethods bool
	ParamCount          int
}

// roiData holds every dataset GetRankedURLs needs to score URLs.
type roiData struct {
	urls         []URL
	endpoints    []Endpoint
	vulns        []Vulnerability
	ports        []Port
	hostMetadata []HostMetadata
	urlMetadata  []URLMetadata
	gfMatches    map[string][]GFMatchResult
}

// roiIndex holds lookup tables built from roiData for O(1) access during scoring.
type roiIndex struct {
	hostMetadata    map[string]HostMetadata
	urlMetadata     map[string]URLMetadata
	endpointsByHost map[string]*endpointStats
	exactVulnsByURL map[string]map[string]int
	hostVulnsByHost map[string]map[string]int
	portsByHost     map[string]int
}

// TODO(roi-scaling): GetRankedURLs loads the full scan into memory;
// for >100k-URL scans this should be rewritten to stream via rows.Next() and score incrementally.
// GetRankedURLs computes ROI scores from persisted scan data without requiring
// extra storage, so existing scans can be ranked immediately.
func GetRankedURLs(scanID int64, limit int) ([]URLROI, error) {
	if DB == nil {
		return nil, ErrDBNotInitialized
	}

	data, err := loadROIData(scanID)
	if err != nil {
		return nil, err
	}

	idx := buildROIIndex(data)

	results := make([]URLROI, 0, len(data.urls))
	for _, u := range data.urls {
		results = append(results, scoreURL(u, idx, data.gfMatches))
	}

	return dedupeAndRank(results, limit), nil
}

// loadROIData fetches every dataset needed for ROI scoring.
func loadROIData(scanID int64) (*roiData, error) {
	urls, err := GetURLs(scanID)
	if err != nil {
		return nil, err
	}

	endpoints, err := GetEndpoints(scanID)
	if err != nil {
		return nil, err
	}

	vulns, err := GetVulnerabilities(scanID)
	if err != nil {
		return nil, err
	}

	ports, err := GetPorts(scanID)
	if err != nil {
		return nil, err
	}

	hostMetadata, err := GetHostMetadata(scanID)
	if err != nil {
		return nil, err
	}

	urlMetadata, err := GetURLMetadata(scanID)
	if err != nil {
		return nil, err
	}

	gfMatches, err := GetGFMatchesByScan(scanID)
	if err != nil {
		return nil, err
	}

	return &roiData{
		urls:         urls,
		endpoints:    endpoints,
		vulns:        vulns,
		ports:        ports,
		hostMetadata: hostMetadata,
		urlMetadata:  urlMetadata,
		gfMatches:    gfMatches,
	}, nil
}

// buildROIIndex builds lookup tables keyed by host or normalized URL.
func buildROIIndex(data *roiData) *roiIndex {
	hostMetadataMap := make(map[string]HostMetadata, len(data.hostMetadata))
	for _, meta := range data.hostMetadata {
		hostMetadataMap[strings.ToLower(strings.TrimSpace(meta.Host))] = meta
	}

	urlMetadataMap := make(map[string]URLMetadata, len(data.urlMetadata))
	for _, meta := range data.urlMetadata {
		urlMetadataMap[normalizeComparableURL(meta.URL)] = meta
	}

	endpointsByHost := make(map[string]*endpointStats)
	for _, ep := range data.endpoints {
		host := extractHost(ep.URL)
		if host == "" {
			continue
		}
		stats := endpointsByHost[host]
		if stats == nil {
			stats = &endpointStats{BySource: make(map[string]int)}
			endpointsByHost[host] = stats
		}
		stats.Total++
		stats.BySource[strings.ToLower(strings.TrimSpace(ep.Source))]++
	}

	exactVulnsByURL := make(map[string]map[string]int)
	hostVulnsByHost := make(map[string]map[string]int)
	for _, vuln := range data.vulns {
		sev := normalizeSeverity(vuln.Severity)
		if sev == "" {
			sev = "info"
		}

		if vuln.URL != "" {
			normURL := normalizeComparableURL(vuln.URL)
			if normURL != "" {
				if exactVulnsByURL[normURL] == nil {
					exactVulnsByURL[normURL] = make(map[string]int)
				}
				exactVulnsByURL[normURL][sev]++
			}
		}

		host := extractHost(vuln.URL)
		if host == "" {
			host = extractHost(vuln.Host)
		}
		if host != "" {
			if hostVulnsByHost[host] == nil {
				hostVulnsByHost[host] = make(map[string]int)
			}
			hostVulnsByHost[host][sev]++
		}
	}

	portsByHost := make(map[string]int)
	for _, p := range data.ports {
		host := strings.ToLower(strings.TrimSpace(p.Host))
		if host == "" {
			continue
		}
		portsByHost[host]++
	}

	return &roiIndex{
		hostMetadata:    hostMetadataMap,
		urlMetadata:     urlMetadataMap,
		endpointsByHost: endpointsByHost,
		exactVulnsByURL: exactVulnsByURL,
		hostVulnsByHost: hostVulnsByHost,
		portsByHost:     portsByHost,
	}
}

// scoreURL computes the ROI score, reasons, and confidence for a single URL.
func scoreURL(u URL, idx *roiIndex, gfMatches map[string][]GFMatchResult) URLROI {
	host := extractHost(u.URL)
	techs := parseTechList(u.Tech)
	endpointData := idx.endpointsByHost[host]
	exactCounts := cloneStringIntMap(idx.exactVulnsByURL[normalizeComparableURL(u.URL)])
	hostCounts := subtractSeverityMaps(idx.hostVulnsByHost[host], exactCounts)
	meta := mergeMetadata(idx.urlMetadata[normalizeComparableURL(u.URL)], idx.hostMetadata[host])

	roi := URLROI{
		URL:             u.URL,
		Host:            host,
		StatusCode:      u.StatusCode,
		Title:           u.Title,
		ContentType:     u.ContentType,
		Source:          u.Source,
		Tech:            techs,
		Score:           0,
		Reasons:         nil,
		ExactVulnCounts: exactCounts,
		HostVulnCounts:  hostCounts,
	}

	addPoints := func(points int, reason string) {
		if points <= 0 {
			return
		}
		roi.Score += points
		roi.Reasons = append(roi.Reasons, fmt.Sprintf("+%d %s", points, reason))
	}

	// signalCategories tracks which broad categories contributed to the score.
	// Used for confidence computation.
	signalCategories := make(map[string]bool)

	scoreStatusCode(u.StatusCode, addPoints, signalCategories)
	scoreTech(techs, addPoints, signalCategories)
	scoreEndpoints(&roi, endpointData, addPoints, signalCategories)
	scorePorts(&roi, idx.portsByHost[host], addPoints, signalCategories)
	scoreVulns(exactCounts, hostCounts, addPoints, signalCategories)
	scoreParameters(&roi, u.URL, addPoints)
	scoreKeywords(&roi, u.URL+" "+u.Title, addPoints)
	scoreSources(u.Source, addPoints)
	if strings.Contains(strings.ToLower(u.ContentType), "json") {
		addPoints(8, "JSON response surface")
	}
	scoreMetadata(meta, addPoints, signalCategories)
	scoreSubdomainDepth(host, addPoints)

	// Phase 3.3: HeadersJSON Parsing
	for _, sig := range scoreHeaders(meta.URLHeadersJSON, meta.HostHeadersJSON) {
		if sig.points > 0 {
			addPoints(sig.points, sig.reason)
		}
	}

	scoreNonStandardPort(u.URL, addPoints)
	scoreGFMatches(gfMatches[u.URL], addPoints, signalCategories)
	scoreResponseBytes(meta, &roi, addPoints)
	applyPenalties(&roi, u)

	// Floor: don't let score go negative
	if roi.Score < 0 {
		roi.Score = 0
	}

	// Compute confidence and attack surfaces from the signals collected
	roi.SignalCount = len(signalCategories)
	roi.Confidence = computeConfidence(signalCategories)
	roi.AttackSurfaces = computeAttackSurfaces(&roi, meta, gfMatches[u.URL])

	return roi
}

// pointAdder adds positive points with a reason to a URL's ROI score.
type pointAdder func(points int, reason string)

func scoreStatusCode(statusCode int, addPoints pointAdder, signalCategories map[string]bool) {
	switch {
	case statusCode == 200:
		addPoints(40, "200 OK live application")
	case statusCode == 401 || statusCode == 403:
		addPoints(35, fmt.Sprintf("%d protected surface", statusCode))
	case statusCode >= 300 && statusCode < 400:
		addPoints(15, "redirecting surface")
	case statusCode >= 500 && statusCode < 600:
		addPoints(25, "server error behavior")
	case statusCode > 0:
		addPoints(8, fmt.Sprintf("responds with status %d", statusCode))
	default:
		return
	}
	signalCategories["status"] = true
}

// scoreTech implements Phase 3.1: Tech Detection Tiering.
func scoreTech(techs []string, addPoints pointAdder, signalCategories map[string]bool) {
	if len(techs) == 0 {
		return
	}
	totalTechPoints := 0
	var highValueMatches []string
	for _, t := range techs {
		if pts, ok := highValueTech[strings.ToLower(t)]; ok {
			totalTechPoints += pts
			highValueMatches = append(highValueMatches, t)
		} else {
			totalTechPoints += 2
		}
	}
	capped := min(40, totalTechPoints)
	if len(highValueMatches) > 0 {
		addPoints(capped, fmt.Sprintf("%d techs (%s)", len(techs), strings.Join(highValueMatches, ", ")))
	} else {
		addPoints(capped, fmt.Sprintf("%d technologies detected", len(techs)))
	}
	signalCategories["tech"] = true
}

func scoreEndpoints(roi *URLROI, endpointData *endpointStats, addPoints pointAdder, signalCategories map[string]bool) {
	if endpointData == nil {
		return
	}
	signalCategories["endpoints"] = true
	roi.EndpointCount = endpointData.Total
	roi.KatanaCount = endpointData.BySource["katana"]
	roi.GoSpiderCount = endpointData.BySource["gospider"]
	roi.LinkFinderCount = endpointData.BySource["golinkfinder"]
	roi.FfufCount = endpointData.BySource["ffuf"]

	addPoints(min(20, endpointData.Total), fmt.Sprintf("%d discovered endpoints on host", endpointData.Total))
	if roi.FfufCount > 0 {
		addPoints(min(16, roi.FfufCount*4), fmt.Sprintf("%d ffuf hits", roi.FfufCount))
	}
	if roi.LinkFinderCount > 0 {
		addPoints(min(12, roi.LinkFinderCount*3), fmt.Sprintf("%d JS-extracted endpoints", roi.LinkFinderCount))
	}
	crawlCount := roi.KatanaCount + roi.GoSpiderCount
	if crawlCount > 0 {
		addPoints(min(14, crawlCount*2), fmt.Sprintf("%d crawler-discovered endpoints", crawlCount))
	}
}

func scorePorts(roi *URLROI, portCount int, addPoints pointAdder, signalCategories map[string]bool) {
	roi.OpenPortCount = portCount
	if portCount > 0 {
		addPoints(min(10, portCount*2), fmt.Sprintf("%d open ports on host", portCount))
		signalCategories["ports"] = true
	}
}

func scoreVulns(exactCounts, hostCounts map[string]int, addPoints pointAdder, signalCategories map[string]bool) {
	exactPoints, exactSummary := severityScore(exactCounts, true)
	if exactPoints > 0 {
		addPoints(exactPoints, "exact URL vulnerabilities: "+exactSummary)
		signalCategories["vulns"] = true
	}

	hostPoints, hostSummary := severityScore(hostCounts, false)
	if hostPoints > 0 {
		addPoints(hostPoints, "host vulnerabilities: "+hostSummary)
		signalCategories["vulns"] = true
	}
}

func scoreParameters(roi *URLROI, rawURL string, addPoints pointAdder) {
	if !strings.Contains(rawURL, "?") || !strings.Contains(rawURL, "=") {
		return
	}
	roi.IsParameterized = true
	paramCount := countURLParams(rawURL)
	addPoints(min(30, paramCount*8), fmt.Sprintf("%d URL parameters", paramCount))
	sensitiveCount := countSensitiveParams(rawURL)
	if sensitiveCount > 0 {
		addPoints(min(20, sensitiveCount*10), fmt.Sprintf("%d sensitive param names", sensitiveCount))
	}
}

func scoreKeywords(roi *URLROI, text string, addPoints pointAdder) {
	keywords := extractInterestingKeywords(text)
	if len(keywords) > 0 {
		roi.InterestingTerms = keywords
		addPoints(min(18, len(keywords)*4), "interesting keywords: "+strings.Join(keywords, ", "))
	}
}

// scoreSources implements Phase 4.5: multi-source URL confirmation.
func scoreSources(source string, addPoints pointAdder) {
	if !strings.Contains(source, ",") {
		if isHistoricalSource(source) {
			addPoints(4, fmt.Sprintf("discovered via historical source %s", source))
		}
		if isCrawlerSource(source) {
			addPoints(5, fmt.Sprintf("discovered via crawler %s", source))
		}
		return
	}

	sources := strings.Split(source, ",")
	hasHistorical := false
	hasCrawler := false
	hasHTTPX := false
	for _, s := range sources {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "waybackurls" || s == "gau" {
			hasHistorical = true
		}
		if s == "katana" || s == "gospider" {
			hasCrawler = true
		}
		if s == "httpx" {
			hasHTTPX = true
		}
	}
	switch {
	case hasHistorical && hasCrawler:
		addPoints(10, "confirmed by both historical + active crawler")
	case hasHistorical && hasHTTPX:
		addPoints(8, "historical URL confirmed live by httpx")
	case len(sources) >= 2:
		addPoints(5, fmt.Sprintf("discovered by %d sources", len(sources)))
	}
}

// scoreMetadata scores collected host/URL metadata signals
// (Phases 4.1–4.4: CORS, cookies, methods, hidden params).
func scoreMetadata(meta mergedMetadata, addPoints pointAdder, signalCategories map[string]bool) {
	if !meta.HasHostData && !meta.HasURLData {
		return
	}
	signalCategories["metadata"] = true
	if !meta.HasCSP {
		if meta.HasURLData {
			addPoints(10, "selected URL metadata shows missing CSP")
		} else {
			addPoints(8, "host metadata shows missing CSP")
		}
	}
	if meta.HasCacheHeaders {
		addPoints(6, "cache-related headers exposed")
	}
	if meta.LoginSurface {
		addPoints(12, "authentication or login surface detected")
	}
	scoreTLSMetadata(meta, addPoints)
	if meta.HasJSSecrets {
		addPoints(25, "host has exposed secrets in JavaScript")
	}
	if meta.FormCount > 0 {
		addPoints(min(15, meta.FormCount*5), fmt.Sprintf("%d HTML forms (input surfaces)", meta.FormCount))
	}
	if meta.HasFileUpload {
		addPoints(20, "file upload form detected")
	}
	if meta.HiddenInputCount > 3 {
		addPoints(8, fmt.Sprintf("%d hidden inputs (potential IDOR/CSRF)", meta.HiddenInputCount))
	}

	// Phase 4.1: CORS Misconfiguration
	if meta.CORSWildcard {
		addPoints(10, "CORS allows wildcard origin (*)")
	}

	// Phase 4.2: Cookie Security Flags
	if meta.HasSessionCookie && meta.HasInsecureCookies {
		addPoints(15, "session cookie without Secure/HttpOnly flags")
	} else if meta.HasInsecureCookies {
		addPoints(6, "cookies missing security flags")
	}

	// Phase 4.3: Dangerous HTTP Methods
	if meta.HasDangerousMethods {
		addPoints(15, "dangerous HTTP methods (PUT/DELETE) allowed")
	}

	// Phase 4.4: Hidden Parameters
	if meta.ParamCount > 0 {
		addPoints(min(25, meta.ParamCount*5), fmt.Sprintf("%d hidden params discovered by x8", meta.ParamCount))
	}
}

// scoreTLSMetadata scores SSL/TLS certificate issues.
func scoreTLSMetadata(meta mergedMetadata, addPoints pointAdder) {
	if meta.SSLExpired {
		addPoints(14, "expired SSL certificate")
	}
	if meta.SSLSelfSigned {
		addPoints(10, "self-signed SSL certificate")
	}
	if meta.SSLMismatch {
		addPoints(12, "SSL hostname mismatch")
	}
	if meta.WeakTLS {
		addPoints(10, "weak TLS version detected")
	}
}

// scoreSubdomainDepth implements Phase 3.2: Subdomain Depth & Naming Signal.
func scoreSubdomainDepth(host string, addPoints pointAdder) {
	if host == "" {
		return
	}
	subdomainDepth := strings.Count(host, ".") - 1 // e.g., a.b.example.com = depth 2
	if subdomainDepth >= 3 {
		addPoints(10, fmt.Sprintf("deep subdomain (depth %d, likely internal)", subdomainDepth))
	}
	if revealingPrefix := matchRevealingPrefix(host); revealingPrefix != "" {
		addPoints(12, fmt.Sprintf("revealing subdomain name: %s", revealingPrefix))
	}
}

func scoreNonStandardPort(rawURL string, addPoints pointAdder) {
	parsed, parseErr := url.Parse(rawURL)
	if parseErr != nil || parsed.Port() == "" {
		return
	}
	port := parsed.Port()
	if port == "80" || port == "443" {
		return
	}
	addPoints(12, fmt.Sprintf("non-standard port :%s", port))
	if isDevPort(port) {
		addPoints(8, fmt.Sprintf("known dev/admin port :%s", port))
	}
}

// gfPatternPoints maps gf pattern names to base points; confirmed matches
// get a boost on top.
var gfPatternPoints = map[string]int{
	"rce":         30,
	"rce-2":       30,
	"sqli":        25,
	"sqli-error":  25,
	"ssrf":        25,
	"ssti":        25,
	"lfi":         20,
	"idor":        20,
	"xss":         15,
	"redirect":    12,
	"debug_logic": 10,
}

// gfPatternLabels describes known gf patterns in reasons.
var gfPatternLabels = map[string]string{
	"rce":         "RCE pattern",
	"rce-2":       "RCE pattern",
	"sqli":        "SQLi pattern",
	"sqli-error":  "SQLi pattern",
	"ssrf":        "SSRF pattern",
	"ssti":        "SSTI pattern",
	"lfi":         "LFI pattern",
	"idor":        "IDOR pattern",
	"xss":         "XSS pattern",
	"redirect":    "open redirect pattern",
	"debug_logic": "debug logic pattern",
}

func scoreGFMatches(matches []GFMatchResult, addPoints pointAdder, signalCategories map[string]bool) {
	if len(matches) == 0 {
		return
	}
	signalCategories["gf_matches"] = true
	for _, m := range matches {
		// Confirmed secrets get a significant boost
		confirmedBoost := 0
		if m.Status == "confirmed" {
			confirmedBoost = 20
		}
		base, known := gfPatternPoints[m.Pattern]
		if !known {
			addPoints(8+confirmedBoost, fmt.Sprintf("gf matched: %s pattern", m.Pattern))
			continue
		}
		addPoints(base+confirmedBoost, "gf matched: "+gfPatternLabels[m.Pattern])
	}
}

// scoreResponseBytes scores response size (only when metadata was collected).
func scoreResponseBytes(meta mergedMetadata, roi *URLROI, addPoints pointAdder) {
	if (!meta.HasHostData && !meta.HasURLData) || meta.ResponseBytes <= 0 {
		return
	}
	switch {
	case meta.ResponseBytes > 100000:
		addPoints(12, "large response body (rich application)")
	case meta.ResponseBytes > 30000:
		addPoints(8, "substantial response body")
	case meta.ResponseBytes > 5000:
		addPoints(4, "moderate response body")
	case meta.ResponseBytes < 500:
		roi.Score -= 10
		roi.Reasons = append(roi.Reasons, "-10 tiny response (likely default/error page)")
	}
}

// applyPenalties subtracts points for low-value or noisy URLs.
func applyPenalties(roi *URLROI, u URL) {
	// Penalty: default/parked pages
	if isDefaultPage(u.Title) {
		roi.Score -= 30
		roi.Reasons = append(roi.Reasons, "-30 default/parked page: "+u.Title)
	}

	// Penalty: WAF/CDN block pages
	if isWAFBlock(u.StatusCode, u.Title) {
		roi.Score -= 15
		roi.Reasons = append(roi.Reasons, "-15 likely WAF/CDN block page")
	}

	// Penalty: static asset URLs
	if isStaticAsset(u.URL) {
		roi.Score -= 20
		roi.Reasons = append(roi.Reasons, "-20 static asset URL")
	}

	// Penalty: extremely long URLs (tracking/analytics noise)
	if len(u.URL) > 500 {
		roi.Score -= 10
		roi.Reasons = append(roi.Reasons, "-10 extremely long URL (likely noise)")
	}
}

// dedupeAndRank sorts results by score, diversifies by host, normalizes scores
// to a 0–100 scale, and applies the result limit.
func dedupeAndRank(results []URLROI, limit int) []URLROI {
	slices.SortFunc(results, func(a, b URLROI) int {
		if a.Score != b.Score {
			return cmp.Compare(b.Score, a.Score)
		}
		if a.EndpointCount != b.EndpointCount {
			return cmp.Compare(b.EndpointCount, a.EndpointCount)
		}
		return cmp.Compare(a.URL, b.URL)
	})

	// Phase 5.1: Host deduplication — max 3 per host before other hosts
	results = diversifyResults(results, 3)

	// Phase 5.2: Score normalization — 0–100 scale
	normalizeScores(results)

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	return results
}

func parseTechList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var techs []string
	if err := json.Unmarshal([]byte(raw), &techs); err == nil {
		return dedupeStrings(techs)
	}

	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			techs = append(techs, p)
		}
	}
	return dedupeStrings(techs)
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	return out
}

func extractHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	return strings.TrimSpace(host)
}

func normalizeComparableURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return strings.TrimRight(strings.ToLower(raw), "/")
	}
	parsed.Fragment = ""
	parsed.User = nil // Strip embedded credentials to prevent leakage into reports
	s := strings.ToLower(parsed.String())
	return strings.TrimRight(s, "/")
}

func normalizeSeverity(sev string) string {
	return strings.ToLower(strings.TrimSpace(sev))
}

func cloneStringIntMap(in map[string]int) map[string]int {
	if len(in) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func subtractSeverityMaps(total, exact map[string]int) map[string]int {
	if len(total) == 0 {
		return map[string]int{}
	}
	out := cloneStringIntMap(total)
	for sev, count := range exact {
		out[sev] -= count
		if out[sev] < 0 {
			out[sev] = 0
		}
	}
	return out
}

func severityScore(counts map[string]int, exact bool) (int, string) {
	if len(counts) == 0 {
		return 0, ""
	}

	weights := map[string]int{
		"critical": 100,
		"high":     60,
		"medium":   35,
		"low":      15,
		"info":     5,
	}
	if !exact {
		weights = map[string]int{
			"critical": 45,
			"high":     28,
			"medium":   16,
			"low":      8,
			"info":     3,
		}
	}

	order := []string{"critical", "high", "medium", "low", "info"}
	total := 0
	var parts []string
	for _, sev := range order {
		count := counts[sev]
		if count <= 0 {
			continue
		}
		total += count * weights[sev]
		parts = append(parts, fmt.Sprintf("%d %s", count, sev))
	}

	// Cap vulnerability score contribution to prevent domination
	maxPoints := 150
	if !exact {
		maxPoints = 80
	}
	if total > maxPoints {
		total = maxPoints
	}
	return total, strings.Join(parts, ", ")
}

func extractInterestingKeywords(text string) []string {
	keywords := []string{
		"admin", "login", "signin", "auth", "oauth", "callback", "redirect",
		"token", "api", "graphql", "internal", "debug", "staging", "dev",
		"upload", "webhook", "config",
	}

	text = strings.ToLower(text)
	var matches []string
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			matches = append(matches, keyword)
		}
	}
	return dedupeStrings(matches)
}

func isHistoricalSource(source string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	return source == "waybackurls" || source == "gau"
}

func isCrawlerSource(source string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	return source == "katana" || source == "gospider"
}

// highValueTech maps technology names (lowercase) to their pentesting value.
// CMS platforms with CVE histories, CI/CD tools with common misconfigurations,
// and data tools with default credential issues score highest.
var highValueTech = map[string]int{
	// CMS (CVE-rich)
	"wordpress": 15, "drupal": 15, "joomla": 14, "magento": 14,
	// CI/CD & DevOps (usually misconfigured)
	"jenkins": 20, "gitlab": 18, "bamboo": 16, "teamcity": 16,
	// Data/Monitoring (default creds)
	"grafana": 14, "kibana": 14, "elasticsearch": 15,
	"solr": 15, "phpmyadmin": 18, "adminer": 16,
	// App servers (known exploits)
	"tomcat": 12, "weblogic": 16, "jboss": 16,
	// Frameworks
	"spring boot": 12, "laravel": 8, "django": 8, "flask": 8,
	// Legacy
	"coldfusion": 18, "asp.net": 8, "php": 6,
}

// revealingPrefixes are subdomain name components that suggest internal,
// staging, or admin infrastructure — high-value recon targets.
var revealingPrefixes = []string{
	"staging", "dev", "test", "uat", "qa", "internal", "admin",
	"jenkins", "ci", "git", "backup", "old", "legacy", "beta", "sandbox",
	"preprod", "pre-prod", "stg", "demo", "debug", "mgmt", "manage",
	"monitor", "grafana", "kibana", "jira", "confluence", "vpn",
}

type headerSignal struct {
	points int
	reason string
}

func mergeMetadata(urlMeta URLMetadata, hostMeta HostMetadata) mergedMetadata {
	responseBytes := urlMeta.ResponseBytes
	if responseBytes == 0 {
		responseBytes = hostMeta.ResponseBytes
	}
	return mergedMetadata{
		HasHostData:         hostMeta.Host != "",
		HasURLData:          urlMeta.URL != "",
		HasCSP:              urlMeta.HasCSP || hostMeta.HasCSP,
		HasCacheHeaders:     urlMeta.HasCacheHeaders || hostMeta.HasCacheHeaders,
		LoginSurface:        urlMeta.LoginSurface || hostMeta.LoginSurface,
		SSLExpired:          hostMeta.SSLExpired,
		SSLSelfSigned:       hostMeta.SSLSelfSigned,
		SSLMismatch:         hostMeta.SSLMismatch,
		WeakTLS:             hostMeta.WeakTLS,
		ResponseBytes:       responseBytes,
		HasJSSecrets:        hostMeta.HasJSSecrets,
		FormCount:           urlMeta.FormCount,
		HasFileUpload:       urlMeta.HasFileUpload,
		HiddenInputCount:    urlMeta.HiddenInputCount,
		HostHeadersJSON:     hostMeta.HeadersJSON,
		URLHeadersJSON:      urlMeta.HeadersJSON,
		CORSWildcard:        hostMeta.CORSWildcard,
		HasInsecureCookies:  hostMeta.HasInsecureCookies,
		HasSessionCookie:    hostMeta.HasSessionCookie,
		HasDangerousMethods: hostMeta.HasDangerousMethods,
		ParamCount:          urlMeta.ParamCount,
	}
}

func countURLParams(rawURL string) int {
	idx := strings.Index(rawURL, "?")
	if idx < 0 {
		return 0
	}
	query := rawURL[idx+1:]
	if frag := strings.Index(query, "#"); frag >= 0 {
		query = query[:frag]
	}
	count := 0
	for _, pair := range strings.Split(query, "&") {
		if strings.Contains(pair, "=") {
			count++
		}
	}
	return count
}

func countSensitiveParams(rawURL string) int {
	sensitiveNames := map[string]bool{
		"id": true, "user": true, "uid": true, "userid": true, "user_id": true,
		"file": true, "path": true, "dir": true, "page": true, "url": true, "uri": true,
		"redirect": true, "next": true, "return": true, "callback": true, "rurl": true,
		"token": true, "key": true, "secret": true, "password": true, "pass": true, "pwd": true,
		"admin": true, "role": true, "action": true, "cmd": true, "exec": true, "command": true,
		"query": true, "search": true, "q": true, "s": true,
		"email": true, "mail": true, "account": true,
		"name": true, "username": true, "login": true,
		"upload": true, "download": true, "export": true, "import": true,
	}
	idx := strings.Index(rawURL, "?")
	if idx < 0 {
		return 0
	}
	query := strings.ToLower(rawURL[idx+1:])
	if frag := strings.Index(query, "#"); frag >= 0 {
		query = query[:frag]
	}
	count := 0
	for _, pair := range strings.Split(query, "&") {
		eqIdx := strings.Index(pair, "=")
		if eqIdx < 0 {
			continue
		}
		paramName := pair[:eqIdx]
		if sensitiveNames[paramName] {
			count++
		}
	}
	return count
}

// devPorts are port numbers commonly used for development, admin panels,
// and internal services.
var devPorts = map[string]bool{
	"8080": true, "8443": true, "9090": true, "3000": true,
	"4443": true, "8888": true, "9200": true, "5601": true,
	"8000": true, "8081": true, "1337": true, "4200": true,
	"3001": true, "5000": true, "9000": true, "7070": true,
	"9443": true, "8008": true, "8181": true, "2083": true,
}

func isDevPort(port string) bool {
	return devPorts[port]
}

func isDefaultPage(title string) bool {
	if title == "" {
		return false
	}
	indicators := []string{
		"coming soon", "under construction", "domain for sale",
		"parked domain", "buy this domain", "website is under",
		"default web page", "apache2 default page", "welcome to nginx",
		"it works!", "iis windows server", "congratulations",
		"test page", "placeholder", "index of /",
		"domain parking", "future home", "site not found",
		"page not found", "404 not found", "default page",
	}
	lower := strings.ToLower(title)
	for _, indicator := range indicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

func isWAFBlock(statusCode int, title string) bool {
	if statusCode != 403 && statusCode != 503 {
		return false
	}
	lower := strings.ToLower(title)
	wafIndicators := []string{
		"cloudflare", "access denied", "forbidden",
		"blocked", "firewall", "security check",
		"ddos protection", "captcha", "please wait",
		"attention required", "akamai", "incapsula",
		"sucuri", "imperva",
	}
	for _, indicator := range wafIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

func isStaticAsset(rawURL string) bool {
	path := strings.ToLower(rawURL)
	if qIdx := strings.Index(path, "?"); qIdx >= 0 {
		path = path[:qIdx]
	}
	staticExtensions := []string{
		".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
		".pdf", ".zip", ".tar", ".gz", ".bmp", ".webp", ".avif",
		".mov", ".avi", ".flv", ".wmv", ".wav", ".ogg",
		".map", // source maps are auto-generated, not attack surface
	}
	for _, ext := range staticExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// matchRevealingPrefix checks if the hostname starts with or contains a
// revealing prefix that suggests internal/staging/admin infrastructure.
func matchRevealingPrefix(host string) string {
	lower := strings.ToLower(host)
	parts := strings.Split(lower, ".")
	if len(parts) < 2 {
		return ""
	}
	for _, prefix := range revealingPrefixes {
		// Check the leftmost label first (most common: dev.example.com)
		if parts[0] == prefix {
			return prefix
		}
		// Also check as substring of leftmost label (e.g., staging-api.example.com)
		if strings.Contains(parts[0], prefix) && parts[0] != prefix {
			return prefix
		}
	}
	return ""
}

// scoreHeaders parses stored JSON headers and returns security scoring signals.
// It checks URL-level headers first, falling back to host-level headers.
func scoreHeaders(urlHeadersJSON, hostHeadersJSON string) []headerSignal {
	headers := parseHeadersJSON(urlHeadersJSON)
	if len(headers) == 0 {
		headers = parseHeadersJSON(hostHeadersJSON)
	}
	if len(headers) == 0 {
		return nil
	}

	var signals []headerSignal

	// Missing security headers
	if _, ok := headers["x-frame-options"]; !ok {
		signals = append(signals, headerSignal{4, "missing X-Frame-Options header"})
	}
	if _, ok := headers["x-content-type-options"]; !ok {
		signals = append(signals, headerSignal{3, "missing X-Content-Type-Options header"})
	}
	if _, ok := headers["strict-transport-security"]; !ok {
		signals = append(signals, headerSignal{5, "missing Strict-Transport-Security header"})
	}

	// Information leakage headers
	if server, ok := headers["server"]; ok {
		if containsVersionNumber(server) {
			signals = append(signals, headerSignal{6, fmt.Sprintf("Server header leaks version: %s", server)})
		}
	}
	if poweredBy, ok := headers["x-powered-by"]; ok {
		signals = append(signals, headerSignal{8, fmt.Sprintf("X-Powered-By exposes stack: %s", poweredBy)})
	}
	if _, ok := headers["x-debug"]; ok {
		signals = append(signals, headerSignal{15, "X-Debug header present (debug mode)"})
	}
	if _, ok := headers["x-debug-token"]; ok {
		signals = append(signals, headerSignal{15, "X-Debug-Token header present (debug mode)"})
	}
	if _, ok := headers["x-debug-token-link"]; ok {
		signals = append(signals, headerSignal{12, "X-Debug-Token-Link header present"})
	}

	return signals
}

// parseHeadersJSON parses the stored headers JSON into a lowercase key map.
// Uses interface{} unmarshal to handle both flat string values and array values
// in a single pass.
func parseHeadersJSON(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil
	}
	if len(parsed) == 0 {
		return nil
	}

	normalized := make(map[string]string, len(parsed))
	for k, v := range parsed {
		key := strings.ToLower(strings.TrimSpace(k))
		switch val := v.(type) {
		case string:
			normalized[key] = val
		case []interface{}:
			if len(val) > 0 {
				if s, ok := val[0].(string); ok {
					normalized[key] = s
				}
			}
		}
	}
	return normalized
}

// containsVersionNumber checks if a header value contains a version string
// like "Apache/2.4.49" or "nginx/1.21.0".
func containsVersionNumber(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '/' {
			// Check if followed by a digit (version number)
			if i+1 < len(value) && value[i+1] >= '0' && value[i+1] <= '9' {
				return true
			}
		}
	}
	return false
}

// diversifyResults reorders results so no single host dominates the top
// positions. After the first maxPerHost URLs from any host appear, remaining
// URLs for that host are deferred until all other hosts have had their turn.
func diversifyResults(results []URLROI, maxPerHost int) []URLROI {
	if len(results) == 0 || maxPerHost <= 0 {
		return results
	}

	hostCount := make(map[string]int)
	var primary, deferred []URLROI

	for _, r := range results {
		hostCount[r.Host]++
		if hostCount[r.Host] <= maxPerHost {
			primary = append(primary, r)
		} else {
			deferred = append(deferred, r)
		}
	}

	return append(primary, deferred...)
}

// normalizeScores maps raw scores to a 0–100 scale based on the highest
// score in the result set. If max is 0, all scores normalize to 0.
func normalizeScores(results []URLROI) {
	if len(results) == 0 {
		return
	}

	maxScore := 0
	for _, r := range results {
		if r.Score > maxScore {
			maxScore = r.Score
		}
	}

	if maxScore == 0 {
		return
	}

	for i := range results {
		results[i].NormalizedScore = (results[i].Score * 100) / maxScore
	}
}

// computeConfidence returns "high", "medium", or "low" based on how many
// distinct signal categories contributed to scoring. Categories are:
// status, tech, vulns, ports, metadata, gf_matches.
func computeConfidence(categories map[string]bool) string {
	count := len(categories)
	switch {
	case count >= 4:
		return "high"
	case count >= 2:
		return "medium"
	default:
		return "low"
	}
}

// computeAttackSurfaces tags a URL with the attack types it's most suitable
// for, based on already-computed signals. This helps pentesters quickly triage
// which tools to point at each target.
func computeAttackSurfaces(roi *URLROI, meta mergedMetadata, gfPatterns []GFMatchResult) []string {
	seen := make(map[string]bool)
	add := func(tag string) {
		if !seen[tag] {
			seen[tag] = true
		}
	}

	// Injection surfaces
	for _, m := range gfPatterns {
		switch m.Pattern {
		case "sqli", "sqli-error", "rce", "rce-2", "ssti", "lfi":
			add("injection")
		case "xss":
			add("xss")
		case "ssrf":
			add("ssrf")
		case "redirect":
			add("redirect")
		case "idor":
			add("idor")
		}
	}
	if roi.IsParameterized {
		add("injection")
	}

	// Authentication surface
	if meta.LoginSurface || meta.HasSessionCookie {
		add("authentication")
	}
	if meta.HasInsecureCookies {
		add("authentication")
	}

	// File upload
	if meta.HasFileUpload {
		add("file-upload")
	}

	// Hidden content / discovery
	if roi.FfufCount > 0 || meta.ParamCount > 0 || meta.HiddenInputCount > 3 {
		add("hidden-content")
	}

	// Misconfig surfaces
	if meta.CORSWildcard || meta.HasDangerousMethods {
		add("misconfiguration")
	}

	// XSS via forms without CSP
	if meta.FormCount > 0 && !meta.HasCSP {
		add("xss")
	}

	return slices.Sorted(maps.Keys(seen))
}
