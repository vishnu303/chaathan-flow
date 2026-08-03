package wildcard_flow

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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
