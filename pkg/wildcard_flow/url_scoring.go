package wildcard_flow

import (
	"bufio"
	"cmp"
	"container/heap"
	"fmt"
	neturl "net/url"
	"os"
	"slices"
	"strings"

	"github.com/vishnu303/chaathan/utils"
)

// collectROIMetadataTargetsFromFile selects high-value URLs from inputFile,
// capped at perHostLimit per host and totalLimit overall.
func collectROIMetadataTargetsFromFile(inputFile, outputFile string, perHostLimit, totalLimit int) int {
	file, err := os.Open(inputFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	seen := make(map[string]bool)
	perHost := make(map[string]int)
	count := 0
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] || !isHighValueURL(line) {
			continue
		}
		host := hostFromRawURL(line)
		if host == "" {
			continue
		}
		if perHostLimit > 0 && perHost[host] >= perHostLimit {
			continue
		}
		seen[line] = true
		perHost[host]++
		fmt.Fprintln(f, line)
		count++
		if totalLimit > 0 && count >= totalLimit {
			break
		}
	}
	return count
}

// writeEmptyFile truncates or creates a file so retry paths do not reuse stale output.

// isHighValueURL returns true for parameterised URLs or those containing
// known sensitive path markers (admin panels, APIs, auth endpoints, etc.).
func isHighValueURL(raw string) bool {
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "?") && strings.Contains(lower, "=") {
		return true
	}
	for _, marker := range getHighValueMarkers() {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// hostFromRawURL extracts the lowercase hostname from a raw URL string.
func hostFromRawURL(raw string) string {
	parsed, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// extractUncoverHosts reads an uncover JSONL output file and writes unique
// hostnames (one per line) to outputFile. Returns the number written.
// This converts Uncover's JSON format into a plain-text list that can be
// merged into all_subdomains.txt by stepDNSConsolidation (Step 6).

// junkDomainSuffixes are 3rd-party domains that should never be scanned.
func getJunkDomains() []string {
	return utils.JunkDomains()
}

// staticExtensions are file extensions that can't have injection points.
func getStaticExtensions() map[string]bool {
	exts := utils.StaticExtensions()
	res := make(map[string]bool, len(exts))
	for _, ext := range exts {
		res[strings.ToLower(ext)] = true
	}
	return res
}

// getHighValueMarkers returns path markers that identify high-value/sensitive components.
func getHighValueMarkers() []string {
	return utils.HighValueMarkers()
}

// getInterestingParameters returns parameters names that often contain security vulnerabilities.
func getInterestingParameters() []string {
	return utils.InterestingParameters()
}

// isJunkDomain returns true if the host belongs to a known 3rd-party service.
func isJunkDomain(host string) bool {
	host = strings.ToLower(host)
	for _, suffix := range getJunkDomains() {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// hasStaticExtension returns true if the URL path ends with a static file extension.
func hasStaticExtension(rawURL string) bool {
	parsed, err := neturl.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for ext := range getStaticExtensions() {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// pathKey extracts a deduplication key from a URL — the scheme+host+path
// without query parameters, so /api/user?id=1 and /api/user?id=2 map
// to the same key.
func pathKey(rawURL string) string {
	parsed, err := neturl.Parse(rawURL)
	if err != nil || (parsed.Scheme == "" && parsed.Host == "") {
		return rawURL
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host + parsed.Path)
}

// urlItem represents a tracked, evaluated URL target candidate.
type urlItem struct {
	raw   string
	path  string
	score int
	index int // Index inside heap
}

// urlHeap implements a min-heap structure on urlItems for top-N ranking.
type urlHeap []*urlItem

func (h urlHeap) Len() int { return len(h) }

func (h urlHeap) Less(i, j int) bool { return h[i].score < h[j].score } // Min-heap: lowest score first

func (h urlHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *urlHeap) Push(x any) {
	n := len(*h)
	item, ok := x.(*urlItem)
	if !ok {
		panic(fmt.Sprintf("urlHeap.Push: expected *urlItem, got %T", x))
	}
	item.index = n
	*h = append(*h, item)
}

func (h *urlHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	item.index = -1
	*h = old[0 : n-1]
	return item
}

// CollectScopedURLs filters all_urls_live.txt for DAST-suitable URLs using O(1) heap pipelines.
func CollectScopedURLs(c *Ctx, inputFile, outputFile string, maxURLs int) int {
	file, err := os.Open(inputFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	// Determine whether to filter 3rd-party domains.
	// Default: filter ON. Config field SkipThirdParty defaults to true,
	// meaning "yes, skip/filter junk domains". When set to false the
	// filter is disabled — the negation below reads: "if NOT skipping
	// third-party → don't filter".
	filterJunk := shouldFilterJunkDomains(c)

	scanner := bufio.NewScanner(file)

	if maxURLs > 0 {
		// Bounded pipeline space: use a min-heap of size N to keep memory O(1)
		pq := make(urlHeap, 0, maxURLs)
		heap.Init(&pq)
		pathIndex := make(map[string]*urlItem)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if scopedURLCandidate(line, filterJunk) == "" {
				continue
			}
			trackBoundedScopedURL(&pq, pathIndex, line, maxURLs)
		}

		if pq.Len() == 0 {
			return 0
		}

		// Sort the bounded results in memory for execution
		return writeScopedURLResults(outputFile, drainURLHeap(&pq))
	}

	// Unbounded pipeline space (still capped at O(Unique Paths) instead of O(All Crawls))
	bestPerPath := make(map[string]*urlItem)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if scopedURLCandidate(line, filterJunk) == "" {
			continue
		}
		trackUnboundedScopedURL(bestPerPath, line)
	}

	if len(bestPerPath) == 0 {
		return 0
	}

	results := make([]*urlItem, 0, len(bestPerPath))
	for _, item := range bestPerPath {
		results = append(results, item)
	}
	return writeScopedURLResults(outputFile, results)
}

// shouldFilterJunkDomains reports whether 3rd-party junk domains should be
// filtered out of the DAST URL set.
func shouldFilterJunkDomains(c *Ctx) bool {
	if c.Cfg != nil && c.Cfg.Tools.Dalfox.SkipThirdParty != nil && !*c.Cfg.Tools.Dalfox.SkipThirdParty {
		return false
	}
	return true
}

// scopedURLCandidate returns the lowercase host when line is a parameterized,
// non-static URL that passes junk-domain filtering, otherwise "".
func scopedURLCandidate(line string, filterJunk bool) string {
	if line == "" {
		return ""
	}
	// Must have parameters
	if !strings.Contains(line, "?") || !strings.Contains(line, "=") {
		return ""
	}
	// Skip static extensions
	if hasStaticExtension(line) {
		return ""
	}
	// Extract host for scope and junk checks
	parsed, err := neturl.Parse(line)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return ""
	}
	// Skip 3rd-party domains (when enabled)
	if filterJunk && isJunkDomain(host) {
		return ""
	}
	return host
}

// trackBoundedScopedURL maintains a size-capped min-heap of the best URL per
// path key.
func trackBoundedScopedURL(pq *urlHeap, pathIndex map[string]*urlItem, line string, maxURLs int) {
	// Score this URL for ROI ordering
	score := urlROIScore(line)
	pk := pathKey(line)

	if existing, exists := pathIndex[pk]; exists {
		if score > existing.score {
			existing.raw = line
			existing.score = score
			heap.Fix(pq, existing.index)
		}
		return
	}

	if pq.Len() < maxURLs {
		item := &urlItem{raw: line, path: pk, score: score}
		heap.Push(pq, item)
		pathIndex[pk] = item
	} else if score > (*pq)[0].score {
		minItem, _ := heap.Pop(pq).(*urlItem)
		delete(pathIndex, minItem.path)

		item := &urlItem{raw: line, path: pk, score: score}
		heap.Push(pq, item)
		pathIndex[pk] = item
	}
}

// trackUnboundedScopedURL keeps the highest-scoring raw URL per path key.
func trackUnboundedScopedURL(bestPerPath map[string]*urlItem, line string) {
	score := urlROIScore(line)
	pk := pathKey(line)

	if existing, ok := bestPerPath[pk]; ok {
		if score > existing.score {
			existing.raw = line
			existing.score = score
		}
		return
	}
	bestPerPath[pk] = &urlItem{raw: line, path: pk, score: score}
}

// drainURLHeap pops every item from the heap and returns them.
func drainURLHeap(pq *urlHeap) []*urlItem {
	results := make([]*urlItem, 0, pq.Len())
	for pq.Len() > 0 {
		item, _ := heap.Pop(pq).(*urlItem)
		results = append(results, item)
	}
	return results
}

// writeScopedURLResults sorts results by score (descending) and writes their
// raw URLs to outputFile, returning the number written.
func writeScopedURLResults(outputFile string, results []*urlItem) int {
	slices.SortFunc(results, func(a, b *urlItem) int {
		return cmp.Compare(b.score, a.score)
	})

	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	for _, su := range results {
		fmt.Fprintln(f, su.raw)
		count++
	}
	return count
}

// urlROIScore assigns a priority score to a URL for DAST/XSS scanning.
// Higher score = more likely to contain exploitable vulnerabilities.
func urlROIScore(rawURL string) int {
	score := 0
	lower := strings.ToLower(rawURL)

	// More parameters = more injection surface (+2 per param)
	parsed, err := neturl.Parse(rawURL)
	if err == nil {
		score += len(parsed.Query()) * 2
	}

	// High-value path markers (auth, API, debug, etc.)
	for _, marker := range getHighValueMarkers() {
		if strings.Contains(lower, marker) {
			score += 5
			break // one marker match is enough
		}
	}

	// Interesting parameter names (+3 each)
	if parsed != nil {
		for _, key := range getInterestingParameters() {
			if parsed.Query().Get(key) != "" {
				score += 3
			}
		}
	}

	return score
}

// collectScopedParamURLs filters URLs for Dalfox XSS scanning.
func collectScopedParamURLs(c *Ctx, inputFile, outputFile string) int {
	maxURLs := 500
	if c.Cfg != nil && c.Cfg.Tools.Dalfox.MaxURLs > 0 {
		maxURLs = c.Cfg.Tools.Dalfox.MaxURLs
	}
	return CollectScopedURLs(c, inputFile, outputFile, maxURLs)
}
