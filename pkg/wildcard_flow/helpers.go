package wildcard_flow

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/utils"
)

const (
	ffufHostCap       = 1000
	paramDiscoveryCap = 150
	metadataHostCap   = 250
)

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
		_ = c.StateMgr.MarkStepComplete(c.State, stepName)
	}
}

// markStepFailedSafe marks a step failed only when state tracking is active.
func (c *Ctx) markStepFailedSafe(stepName string, stepErr error) {
	if c.StateMgr == nil || c.State == nil || stepErr == nil {
		return
	}
	// A user cancellation (Ctrl-C / signal) aborts the running tool with a
	// context error — that is an interruption, not a failure. Marking the
	// step failed would break resume semantics; leave it incomplete instead.
	if c.cancelled() {
		return
	}
	_ = c.StateMgr.MarkStepFailed(c.State, stepName, stepErr)
}

// markStepCompleteSafe marks a step complete only when state tracking is active.
func (c *Ctx) markStepCompleteSafe(stepName string) {
	if c.StateMgr == nil || c.State == nil {
		return
	}
	_ = c.StateMgr.MarkStepComplete(c.State, stepName)
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
		logger.Skip("Skipped %s — continuing with next tool", toolName)
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

// hostInScope reports whether a hostname is inside the scan scope. When no
// scope filter is configured, only the target domain and its subdomains
// qualify; with no domain at all nothing can be anchored, so everything
// passes (the wildcard flow always sets c.Domain).
func (c *Ctx) hostInScope(host string) bool {
	if c.ScopeFilter != nil {
		return c.ScopeFilter.IsInScope(host) && !c.ScopeFilter.IsOutOfScope(host)
	}
	if c.Domain == "" {
		return true
	}
	host = strings.ToLower(host)
	return host == c.Domain || strings.HasSuffix(host, "."+c.Domain)
}

// isDefaultSchemePort reports whether port is the well-known port for scheme.
func isDefaultSchemePort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

// hostURLKey returns the dedup key for a host URL: lowercased hostname,
// suffixed with the port when it is not the scheme's default.
func hostURLKey(u *url.URL) string {
	key := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && !isDefaultSchemePort(u.Scheme, port) {
		key += ":" + port
	}
	return key
}

// collectLiveHostTargetsFromHttpx reads a JSONL httpx output file and writes
// unique in-scope host URLs to outputFile. Redirect destinations outside the
// scope are dropped, and a host seen under both http:// and https:// is kept
// once (https preferred). Explicit host:port variants (naabu discoveries)
// stay separate targets. Returns the number written.
func collectLiveHostTargetsFromHttpx(c *Ctx, inputFile, outputFile string) int {
	file, err := os.Open(inputFile)
	if err != nil {
		return 0
	}
	defer file.Close()

	type httpxTarget struct {
		URL string `json:"url"`
	}

	// Dedup key -> chosen URL, preserving first-seen order; https wins over
	// http for the same host key.
	best := make(map[string]string)
	var order []string
	seenURLs := make(map[string]bool)

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
		if result.URL == "" || seenURLs[result.URL] {
			continue
		}
		seenURLs[result.URL] = true

		// httpx with -follow-redirects records the final redirect target in
		// "url", which can sit outside the scan scope — never emit those.
		u, err := url.Parse(result.URL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if !c.hostInScope(u.Hostname()) {
			continue
		}

		key := hostURLKey(u)

		existing, ok := best[key]
		if !ok {
			best[key] = result.URL
			order = append(order, key)
			continue
		}
		if strings.HasPrefix(existing, "http://") && strings.HasPrefix(result.URL, "https://") {
			best[key] = result.URL
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Warning("httpx JSONL scanner error (some lines may have been skipped): %v", err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	for _, key := range order {
		fmt.Fprintln(f, best[key])
	}
	return len(order)
}

// dedupeHostURLsFile rewrites a host URL list file in place, keeping one URL
// per host key (https preferred over http; explicit non-default ports stay
// separate). Unparseable lines are dropped.
func dedupeHostURLsFile(filePath string) {
	lines, err := utils.ReadNonEmptyLines(filePath)
	if err != nil || len(lines) == 0 {
		return
	}
	best := make(map[string]string)
	var order []string
	for _, line := range lines {
		u, err := url.Parse(strings.TrimSpace(line))
		if err != nil || u.Hostname() == "" {
			continue
		}
		key := hostURLKey(u)
		existing, ok := best[key]
		if !ok {
			best[key] = strings.TrimSpace(line)
			order = append(order, key)
			continue
		}
		if strings.HasPrefix(existing, "http://") && strings.HasPrefix(strings.TrimSpace(line), "https://") {
			best[key] = strings.TrimSpace(line)
		}
	}
	out := make([]string, 0, len(order))
	for _, key := range order {
		out = append(out, best[key])
	}
	writeStringLinesFile(filePath, out)
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
