package wildcard_flow

import (
	"bufio"
	"cmp"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/utils"
)

const (
	jsAnalysisHostCap  = 1000
	ffufHostCap        = 1000
	paramDiscoveryCap  = 150
	metadataHostCap    = 250
	jsSecretMaxMatches = 100
	jsFileMaxBytes     = 10 * 1024 * 1024
)

var jsGFPatterns = map[string]bool{
	"domxss":   true,
	"execs":    true,
	"js-sinks": true,
}

var secretGFPatterns = map[string]bool{
	"api-keys":      true,
	"aws-keys":      true,
	"firebase":      true,
	"github":        true,
	"jwt":           true,
	"slack-webhook": true,
	"google-api":    true,
	"stripe-api":    true,
	"db-connection": true,
	"private-key":   true,
}

// ─────────────────────────────────────────────────────────────
// Skip-tool support
// ─────────────────────────────────────────────────────────────

// ErrToolSkipped is returned by runWithSkip when the user presses 's'.
var ErrToolSkipped = fmt.Errorf("tool skipped by user")

// resumeOrSkip checks if a step is already completed.
// If it is, it logs the resumed header and returns true with context cancelled status.
// Otherwise, it logs the normal step header and returns false.
func (c *Ctx) resumeOrSkip(stepName, stepHeader string) (bool, bool) {
	if c.State != nil && c.State.IsStepCompleted(stepName) {
		logger.StepHeader("%s [RESUMED — skipping]", stepHeader)
		return true, c.cancelled()
	}
	logger.StepHeader("%s", stepHeader)
	return false, false
}

// markStepCompleteIfNoFailure marks the step as completed in the StateManager only if it hasn't failed.
func (c *Ctx) markStepCompleteIfNoFailure(stepName string) {
	if c.StateMgr == nil || c.State == nil {
		return
	}
	hasFailure := false
	for _, fs := range c.State.FailedSteps {
		if fs.Name == stepName {
			hasFailure = true
			break
		}
	}
	if !hasFailure {
		c.StateMgr.MarkStepComplete(c.State, stepName)
	}
}

// markStepFailedSafe marks a step failed only when state tracking is active.
func (c *Ctx) markStepFailedSafe(stepName string, stepErr error) {
	if c.StateMgr == nil || c.State == nil || stepErr == nil {
		return
	}
	_ = c.StateMgr.MarkStepFailed(c.State, stepName, stepErr)
}

// markStepCompleteSafe marks a step complete only when state tracking is active.
func (c *Ctx) markStepCompleteSafe(stepName string) {
	if c.StateMgr == nil || c.State == nil {
		return
	}
	c.StateMgr.MarkStepComplete(c.State, stepName)
}

// runWithSkip executes fn in a goroutine and monitors the skip channel.
// If the user presses 's', fn's context is cancelled and ErrToolSkipped
// is returned. Parent cancellation propagates as ctx.Err().
func runWithSkip(c *Ctx, toolName string, fn func(ctx context.Context) error) error {
	drainSkipSignal(c)

	toolCtx, toolCancel := context.WithCancel(c.GoCtx)
	defer toolCancel()

	done := make(chan error, 1)
	go func() {
		done <- fn(toolCtx)
	}()

	select {
	case err := <-done:
		return err
	case <-c.SkipChan:
		toolCancel()
		logger.Warning("⏭ Skip requested — skipping current tool...")
		logger.Warning("⏭ Skipped: %s", toolName)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			// Tool ignored cancellation or hung on I/O, proceed anyway
		}
		return ErrToolSkipped
	case <-c.GoCtx.Done():
		toolCancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		return c.GoCtx.Err()
	}
}

// drainSkipSignal discards any pending skip signal before starting a tool,
// so leftover signals from a previous step don't immediately skip the next.
func drainSkipSignal(c *Ctx) {
	for {
		select {
		case <-c.SkipChan:
		default:
			return
		}
	}
}

// ─────────────────────────────────────────────────────────────
// File helpers
// ─────────────────────────────────────────────────────────────

// existingFiles returns only those paths that exist on disk.
func existingFiles(paths ...string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p != "" && utils.FileExists(p) {
			out = append(out, p)
		}
	}
	return out
}

// copyFile copies src to dst using memory-efficient io.Copy.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// fileModifiedAfter returns true if the file at path was modified after the
// given time. Used to distinguish partial output written during this scan
// from stale files left over from a previous run.
func fileModifiedAfter(path string, after time.Time) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.ModTime().After(after)
}

// collectLiveHostTargetsFromHttpx reads a JSONL httpx output file and
// writes unique host URLs to outputFile. Returns the number written.
func collectLiveHostTargetsFromHttpx(inputFile, outputFile string) int {
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

	type httpxTarget struct {
		URL string `json:"url"`
	}

	seen := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(file)
	// 4 MB max line buffer — httpx JSONL can exceed 1 MB when extensive
	// tech detection, header data, or TLS info is emitted.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var result httpxTarget
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}
		if result.URL == "" || seen[result.URL] {
			continue
		}
		seen[result.URL] = true
		fmt.Fprintln(f, result.URL)
		count++
	}
	if err := scanner.Err(); err != nil {
		logger.Warning("httpx JSONL scanner error (some lines may have been skipped): %v", err)
	}
	return count
}

// loadLineSlice reads up to limit non-empty lines from inputFile into a slice.
// Pass limit ≤ 0 to read all lines.
func loadLineSlice(inputFile string, limit int) []string {
	file, err := os.Open(inputFile)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if limit > 0 && len(lines) >= limit {
			break
		}
	}
	return lines
}

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
func writeEmptyFile(path string) {
	_ = os.WriteFile(path, nil, 0644)
}

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
func extractUncoverHosts(uncoverJSON, outputFile string, targetDomain string) int {
	type uncoverLine struct {
		Host string `json:"host"`
		IP   string `json:"ip"`
	}

	f, err := os.Open(uncoverJSON)
	if err != nil {
		return 0
	}
	defer f.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer out.Close()

	seen := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec uncoverLine
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		host := rec.Host
		if host == "" {
			host = rec.IP
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || seen[host] {
			continue
		}
		// Validate that the host is a valid domain and is in-scope
		if utils.ValidateDomain(host) != nil {
			continue
		}
		if targetDomain != "" && host != targetDomain && !strings.HasSuffix(host, "."+targetDomain) {
			continue
		}
		seen[host] = true
		fmt.Fprintln(out, host)
		count++
	}
	return count
}

// ─────────────────────────────────────────────────────────────
// CNAME filtering for takeover detection
// ─────────────────────────────────────────────────────────────

// filterCNAMESubdomains reads dnsx_resolved.json and extracts subdomains
// that have CNAME records. Only these are real takeover candidates — a
// subdomain with only A/AAAA records can't be taken over via dangling CNAME.
func filterCNAMESubdomains(dnsxJSONFile, outputFile string) int {
	file, err := os.Open(dnsxJSONFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer out.Close()

	type dnsxRecord struct {
		Host  string   `json:"host"`
		CNAME []string `json:"cname"`
	}

	seen := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec dnsxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if len(rec.CNAME) == 0 || rec.Host == "" {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(rec.Host))
		if seen[host] {
			continue
		}
		seen[host] = true
		fmt.Fprintln(out, host)
		count++
	}
	return count
}

// ─────────────────────────────────────────────────────────────
// Scoped URL filtering for DAST and Dalfox
// ─────────────────────────────────────────────────────────────

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

func (h urlHeap) Len() int           { return len(h) }
func (h urlHeap) Less(i, j int) bool { return h[i].score < h[j].score } // Min-heap: lowest score first
func (h urlHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *urlHeap) Push(x any) {
	n := len(*h)
	item := x.(*urlItem)
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
	filterJunk := true
	if c.Cfg != nil && c.Cfg.Tools.Dalfox.SkipThirdParty != nil && !*c.Cfg.Tools.Dalfox.SkipThirdParty {
		filterJunk = false
	}

	scanner := bufio.NewScanner(file)

	if maxURLs > 0 {
		// Bounded pipeline space: use a min-heap of size N to keep memory O(1)
		pq := make(urlHeap, 0, maxURLs)
		heap.Init(&pq)
		pathIndex := make(map[string]*urlItem)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// Must have parameters
			if !strings.Contains(line, "?") || !strings.Contains(line, "=") {
				continue
			}
			// Skip static extensions
			if hasStaticExtension(line) {
				continue
			}
			// Extract host for scope and junk checks
			parsed, err := neturl.Parse(line)
			if err != nil {
				continue
			}
			host := strings.ToLower(parsed.Hostname())
			if host == "" {
				continue
			}
			// Skip 3rd-party domains (when enabled)
			if filterJunk && isJunkDomain(host) {
				continue
			}

			// Score this URL for ROI ordering
			score := urlROIScore(line)
			pk := pathKey(line)

			if existing, exists := pathIndex[pk]; exists {
				if score > existing.score {
					existing.raw = line
					existing.score = score
					heap.Fix(&pq, existing.index)
				}
			} else {
				if pq.Len() < maxURLs {
					item := &urlItem{raw: line, path: pk, score: score}
					heap.Push(&pq, item)
					pathIndex[pk] = item
				} else if score > pq[0].score {
					minItem := heap.Pop(&pq).(*urlItem)
					delete(pathIndex, minItem.path)

					item := &urlItem{raw: line, path: pk, score: score}
					heap.Push(&pq, item)
					pathIndex[pk] = item
				}
			}
		}

		if pq.Len() == 0 {
			return 0
		}

		// Sort the bounded results in memory for execution
		results := make([]*urlItem, 0, pq.Len())
		for pq.Len() > 0 {
			results = append(results, heap.Pop(&pq).(*urlItem))
		}
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

	} else {
		// Unbounded pipeline space (still capped at O(Unique Paths) instead of O(All Crawls))
		bestPerPath := make(map[string]*urlItem)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if !strings.Contains(line, "?") || !strings.Contains(line, "=") {
				continue
			}
			if hasStaticExtension(line) {
				continue
			}
			parsed, err := neturl.Parse(line)
			if err != nil {
				continue
			}
			host := strings.ToLower(parsed.Hostname())
			if host == "" {
				continue
			}
			if filterJunk && isJunkDomain(host) {
				continue
			}

			score := urlROIScore(line)
			pk := pathKey(line)

			if existing, ok := bestPerPath[pk]; ok {
				if score > existing.score {
					existing.raw = line
					existing.score = score
				}
			} else {
				bestPerPath[pk] = &urlItem{raw: line, path: pk, score: score}
			}
		}

		if len(bestPerPath) == 0 {
			return 0
		}

		results := make([]*urlItem, 0, len(bestPerPath))
		for _, item := range bestPerPath {
			results = append(results, item)
		}
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
