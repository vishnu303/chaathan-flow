// Package ingest owns tool-output ingestion: it parses JSONL / text output
// files produced by external recon tools and persists the discovered
// subdomains, ports, URLs, endpoints, and vulnerabilities into the SQLite
// database via pkg/database.
//
// This package was extracted from utils/ (IMPROVEMENT_PLAN §3.4 — leaf-package
// inversion) so utils could remain a pure leaf package with no database or
// logger dependency. The public surface of every Parse* function and result
// struct is preserved; existing external Go consumers can keep using the
// utils.Parse* / utils.*Result shims, which now delegate here.
package ingest

// Note: Per-line json.Unmarshal is used for file parsers. While sequential
// unmarshaling incurs some allocation overhead, it is simple and robust. Defer
// more complex optimizations (e.g., json.RawMessage or custom scanning) unless
// profiling shows it is a hot performance path.

import (
	"bufio"
	"encoding/json"
	"net"
	neturl "net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/utils"
)

// maxScanBufferSize is the buffer size limit used when scanning large output files (4MB)
const maxScanBufferSize = 4 * 1024 * 1024

// scanJSONLines reads a JSONL output file line by line with the shared large
// scan buffer, invoking fn for every non-empty line. The file is always closed
// before scanJSONLines returns.
func scanJSONLines(filePath string, fn func(line string)) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScanBufferSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fn(line)
	}
	return scanner.Err()
}

// scanTextLines reads a plain-text output file line by line with the shared
// large scan buffer, invoking fn for every trimmed, non-empty line that is not
// a "#" comment. The file is always closed before scanTextLines returns.
func scanTextLines(filePath string, fn func(line string)) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScanBufferSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fn(line)
	}
	return scanner.Err()
}

// writeLines writes a slice of strings to a file using buffered I/O.
// Close errors on the success path are returned so a failed final
// flush-to-disk is not silently dropped.
func writeLines(filePath string, lines []string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}

	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// getTargetDomain gets the target domain of a scan from database if it's a valid domain
func getTargetDomain(scanID int64) string {
	if scanID <= 0 {
		return ""
	}
	scan, err := database.GetScan(scanID)
	if err != nil || scan == nil {
		return ""
	}
	t := strings.ToLower(strings.TrimSpace(scan.Target))
	if utils.ValidateDomain(t) == nil {
		return t
	}
	return ""
}

// isDomainInScope checks if a given domain/hostname is within the target domain scope
func isDomainInScope(domain, targetDomain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	targetDomain = strings.ToLower(strings.TrimSpace(targetDomain))
	if targetDomain == "" {
		return utils.ValidateDomain(domain) == nil
	}
	return domain == targetDomain || strings.HasSuffix(domain, "."+targetDomain)
}

// isURLInScope checks if a given URL is within the target domain scope
func isURLInScope(urlStr, targetDomain string) bool {
	if targetDomain == "" {
		return true
	}
	u, err := neturl.Parse(urlStr)
	if err != nil {
		return false
	}
	return isDomainInScope(u.Hostname(), targetDomain)
}

// extractDomainsFromLine extracts potential domains from a line (including Amass relation lines)
func extractDomainsFromLine(line string) []string {
	var found []string

	// Remove common amass suffixes
	line = strings.ReplaceAll(line, " (FQDN)", "")
	line = strings.ReplaceAll(line, "(FQDN)", "")
	line = strings.ReplaceAll(line, " (IPAddress)", "")
	line = strings.ReplaceAll(line, "(IPAddress)", "")

	words := strings.Fields(line)
	for _, w := range words {
		w = strings.Trim(w, ",.;:()<>\"'")

		// If it looks like a URL, extract the hostname
		if strings.HasPrefix(strings.ToLower(w), "http://") || strings.HasPrefix(strings.ToLower(w), "https://") {
			if u, err := neturl.Parse(w); err == nil && u.Hostname() != "" {
				w = u.Hostname()
			}
		}

		if utils.ValidateDomain(w) == nil {
			found = append(found, w)
		}
	}
	return found
}

// ParseSubdomainsFile reads a file with one subdomain per line, extracts valid domains
// (including from Amass relationship lines), inserts them into the database,
// and rewrites the file in-place to only contain the unique, validated subdomains.
func ParseSubdomainsFile(scanID int64, filePath, source string) (int, error) {
	targetDomain := getTargetDomain(scanID)
	var domains []string
	seen := make(map[string]bool)

	err := scanTextLines(filePath, func(line string) {
		// Extract any valid domains from the line (e.g. Amass graph relation lines)
		for _, d := range extractDomainsFromLine(line) {
			if !isDomainInScope(d, targetDomain) {
				continue
			}
			d = strings.ToLower(d)
			if !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
	})
	if err != nil {
		return 0, err
	}

	// Rewrite the file in-place with clean, sorted subdomains
	slices.Sort(domains)
	if err := writeLines(filePath, domains); err != nil {
		logger.Warning("failed to rewrite subdomains file %s: %v", filePath, err)
	}

	if len(domains) > 0 && scanID > 0 {
		if err := database.AddSubdomains(scanID, domains, source); err != nil {
			return 0, err
		}
	}

	return len(domains), nil
}

// SyncSubdomainsWithConsolidated reads the consolidated subdomains file and purges
// any out-of-scope/unconsolidated subdomains from the database for the given scan ID.
func SyncSubdomainsWithConsolidated(scanID int64, consolidatedFilePath string) (int, error) {
	if scanID <= 0 || !utils.FileExists(consolidatedFilePath) {
		return 0, nil
	}

	var domains []string
	seen := make(map[string]bool)
	err := scanTextLines(consolidatedFilePath, func(line string) {
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "" && !seen[line] {
			seen[line] = true
			domains = append(domains, line)
		}
	})
	if err != nil {
		return 0, err
	}

	deleted, err := database.PurgeUnconsolidatedSubdomains(scanID, domains)
	if err != nil {
		return 0, err
	}
	return int(deleted), nil
}

// HttpxResult represents a line from httpx JSON output
type HttpxResult struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title"`
	ContentType  string   `json:"content_type"`
	Technologies []string `json:"tech"`
	Host         string   `json:"host"`
	Input        string   `json:"input"`
	ResponseTime string   `json:"response_time"`
}

// ParseHttpxOutput parses httpx JSON output and stores in database
func ParseHttpxOutput(scanID int64, filePath string) (int, error) {
	targetDomain := getTargetDomain(scanID)
	count := 0

	err := scanJSONLines(filePath, func(line string) {
		var result HttpxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return
		}

		if strings.TrimSpace(result.URL) == "" {
			return
		}

		if targetDomain != "" && !isURLInScope(result.URL, targetDomain) {
			return
		}

		tech := ""
		if len(result.Technologies) > 0 {
			techJSON, _ := json.Marshal(result.Technologies)
			tech = string(techJSON)
		}

		if err := database.AddURL(scanID, result.URL, result.StatusCode, result.ContentType, result.Title, tech, "httpx"); err != nil {
			logger.FileDebug("parser: AddURL failed for %s: %v", result.URL, err)
			return
		}

		// Also mark subdomain as live
		subdomain := ""
		if parsed, err := neturl.Parse(result.URL); err == nil && parsed.Hostname() != "" {
			subdomain = strings.ToLower(parsed.Hostname())
		} else {
			subdomain = utils.NormalizeHostValue(result.Input)
		}

		if subdomain != "" {
			ipAddr := normalizeIPHost(result.Host)
			if err := database.UpdateSubdomainLive(scanID, subdomain, true, ipAddr); err != nil {
				logger.FileDebug("parser: UpdateSubdomainLive failed for %s: %v", subdomain, err)
			}
		}

		count++
	})

	return count, err
}

// normalizeIPHost strips a port suffix from an httpx host value ("1.2.3.4:443"
// or "[::1]:8443") and returns the bare IP without brackets. Bare IPv6
// addresses (no brackets, multiple colons) are left untouched.
func normalizeIPHost(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 &&
		(strings.Count(host, ":") == 1 || strings.HasSuffix(host[:idx], "]")) {
		// Only strip when the suffix is actually a port number.
		if _, err := strconv.Atoi(host[idx+1:]); err == nil {
			host = host[:idx]
		}
	}
	return strings.Trim(host, "[]")
}

// NucleiResult represents a line from nuclei JSON output.
// Nuclei puts name, severity, and description inside a nested "info" object.
type NucleiResult struct {
	TemplateID    string           `json:"template-id"`
	Info          NucleiResultInfo `json:"info"`
	Host          string           `json:"host"`
	MatchedAt     string           `json:"matched-at"`
	ExtractorName string           `json:"extractor-name"`
	Matcher       string           `json:"matcher-name"`
	Extracted     []string         `json:"extracted-results"`
}

// NucleiResultInfo holds the nested info fields from Nuclei's JSONL output.
type NucleiResultInfo struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// ParseNucleiOutput parses nuclei JSON output and stores in database
func ParseNucleiOutput(scanID int64, filePath string) (int, error) {
	count := 0

	err := scanJSONLines(filePath, func(line string) {
		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return
		}

		evidence := ""
		if len(result.Extracted) > 0 {
			evidence = strings.Join(result.Extracted, "\n")
		}
		if result.ExtractorName != "" {
			if evidence != "" {
				evidence = "Extractor: " + result.ExtractorName + "\n" + evidence
			} else {
				evidence = "Extractor: " + result.ExtractorName
			}
		}

		name := result.Info.Name
		if name == "" {
			name = result.TemplateID
		}

		// matched-at is the per-finding URL; if a template omits it, fall
		// back to the host so distinct findings of the same template across
		// hosts are not collapsed by the (scan_id, host, template_id, url)
		// unique index.
		matchedAt := result.MatchedAt
		if matchedAt == "" {
			matchedAt = result.Host
		}

		err := database.AddVulnerability(
			scanID,
			result.Host,
			matchedAt,
			result.TemplateID,
			name,
			strings.ToLower(result.Info.Severity),
			result.Info.Description,
			result.Matcher,
			evidence,
		)
		if err != nil {
			logger.FileDebug("parser: AddVulnerability failed for %s: %v", result.Host, err)
			return
		}
		count++
	})

	return count, err
}

// NaabuResult represents a line from naabu output
type NaabuResult struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// validNaabuHost reports whether a naabu host value is a plausible network
// target: a valid domain name or a parseable IP address. Bare tokens like
// "foo" (host:123 lines from noisy output) are rejected.
func validNaabuHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return utils.ValidateDomain(host) == nil
}

// FfufResult represents a single ffuf discovery item.
type FfufResult struct {
	Input  map[string]string `json:"input"`
	URL    string            `json:"url"`
	Status int               `json:"status"`
}

// ParseNaabuOutput parses naabu output and stores in database.
// Supports both JSON output format and standard host:port/ip:port format.
func ParseNaabuOutput(scanID int64, filePath string) (int, error) {
	count := 0

	err := scanTextLines(filePath, func(line string) {
		var host string
		var port int
		var proto string

		// Try JSON first
		var result NaabuResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			host = result.Host
			if host == "" {
				host = result.IP
			}
			port = result.Port
			proto = result.Protocol
		} else {
			// Try host:port format using net.SplitHostPort to support IPv6 correctly
			if h, pStr, err := net.SplitHostPort(line); err == nil {
				host = h
				if portVal, err := strconv.Atoi(pStr); err == nil {
					port = portVal
				}
			}
		}

		if proto == "" {
			proto = "tcp"
		}

		if host == "" || port < 1 || port > 65535 {
			return
		}
		if !validNaabuHost(host) {
			return
		}

		if err := database.AddPort(scanID, host, port, proto, ""); err != nil {
			logger.FileDebug("parser: AddPort failed for %s:%d: %v", host, port, err)
			return
		}
		count++
	})

	return count, err
}

// ParseEndpointsFile parses a file with endpoints (one per line)
func ParseEndpointsFile(scanID int64, filePath, source string) (int, error) {
	targetDomain := getTargetDomain(scanID)
	count := 0
	seen := make(map[string]struct{})

	err := scanTextLines(filePath, func(line string) {
		method := ""
		url := line

		// Some tools output "METHOD URL"
		parts := strings.Fields(line)
		if len(parts) >= 2 && utils.IsHTTPMethod(parts[0]) {
			method = parts[0]
			url = parts[1]
		}

		key := method + "\x00" + url
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}

		// Relative/path-only endpoints (e.g. golinkfinder output like
		// "/api/v1/users") carry no host, so scope cannot apply — keep
		// them. Absolute URLs with a host are filtered against the target.
		if targetDomain != "" {
			if u, err := neturl.Parse(url); err == nil && u.Hostname() != "" && !isURLInScope(url, targetDomain) {
				return
			}
		}

		if err := database.AddEndpoint(scanID, url, method, source); err != nil {
			logger.FileDebug("parser: AddEndpoint failed for %s: %v", url, err)
			return
		}
		count++
	})

	return count, err
}

// ParseURLsFile parses a file with URLs (one per line)
func ParseURLsFile(scanID int64, filePath, source string) (int, error) {
	targetDomain := getTargetDomain(scanID)
	count := 0

	err := scanTextLines(filePath, func(line string) {
		if targetDomain != "" && !isURLInScope(line, targetDomain) {
			return
		}

		if err := database.AddURL(scanID, line, 0, "", "", "", source); err != nil {
			logger.FileDebug("parser: AddURL failed for %s: %v", line, err)
			return
		}
		count++
	})

	return count, err
}

// ParseLiveURLsFile parses httpx plain-text output where each line may be
// "https://url [STATUS_CODE]" (produced by -status-code without -json).
// Only the primary URL field (before any whitespace) is stored in the DB,
// so status suffixes never corrupt stored URLs.
func ParseLiveURLsFile(scanID int64, filePath, source string) (int, error) {
	targetDomain := getTargetDomain(scanID)
	seen := make(map[string]bool)
	count := 0

	err := scanTextLines(filePath, func(line string) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return
		}
		url := fields[0]
		if url == "" {
			return
		}
		key := strings.ToLower(url)
		if seen[key] {
			return
		}

		if targetDomain != "" && !isURLInScope(url, targetDomain) {
			return
		}

		seen[key] = true
		if err := database.AddURL(scanID, url, 0, "", "", "", source); err != nil {
			logger.FileDebug("parser: AddURL failed for %s: %v", url, err)
			return
		}
		count++
	})

	return count, err
}

// ParseFfufOutput parses ffuf JSON output and stores discovered paths as both
// URLs and endpoints so later ranking/reporting can use the fuzzing data.
func ParseFfufOutput(scanID int64, filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var payload struct {
		Results []FfufResult `json:"results"`
	}
	if err := json.NewDecoder(file).Decode(&payload); err != nil {
		return 0, err
	}

	targetDomain := getTargetDomain(scanID)
	count := 0
	for _, result := range payload.Results {
		if strings.TrimSpace(result.URL) == "" {
			continue
		}
		if targetDomain != "" && !isURLInScope(result.URL, targetDomain) {
			continue
		}

		urlOK := true
		if err := database.AddURL(scanID, result.URL, result.Status, "", "", "", "ffuf"); err != nil {
			logger.FileDebug("parser: AddURL failed for %s: %v", result.URL, err)
			urlOK = false
		}
		if err := database.AddEndpoint(scanID, result.URL, "GET", "ffuf"); err != nil {
			logger.FileDebug("parser: AddEndpoint failed for %s: %v", result.URL, err)
			urlOK = false
		}
		if urlOK {
			count++
		}
	}

	return count, nil
}

// TlsxResult represents a line from tlsx JSON output
type TlsxResult struct {
	Host        string   `json:"host"`
	Port        string   `json:"port"`
	SubjectCN   string   `json:"subject_cn"`
	SubjectOrg  []string `json:"subject_org"`
	SANs        []string `json:"san"`
	SubjectAN   []string `json:"subject_an"`
	Issuer      string   `json:"issuer_cn"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	Expired     bool     `json:"expired"`
	SelfSigned  bool     `json:"self_signed"`
	MisMatched  bool     `json:"mismatched"`
	TLSVersion  string   `json:"tls_version"`
	CipherSuite string   `json:"cipher"`
}

// ParseTlsxOutput parses tlsx JSON output.
// Extracts SANs as new subdomains and flags expired/weak certs as vulnerabilities.
func ParseTlsxOutput(scanID int64, filePath string, targetDomain string) (newSubs int, vulns int, err error) {
	seenSANs := make(map[string]bool)
	var sanBatch []string

	err = scanJSONLines(filePath, func(line string) {
		var result TlsxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return
		}

		// Extract SANs as new subdomains. Newer tlsx JSON uses subject_an,
		// while older probe-driven output may still emit san. Collect them
		// and insert once after the scan; newSubs counts the unique in-scope
		// SANs discovered (INSERT OR IGNORE may store fewer if the DB
		// already holds them from a prior source).
		sans := result.SANs
		if len(sans) == 0 {
			sans = result.SubjectAN
		}
		for _, san := range sans {
			san = strings.TrimPrefix(san, "*.")
			san = strings.ToLower(strings.TrimSpace(san))
			if utils.ValidateDomain(san) != nil {
				continue
			}
			if targetDomain == "" || seenSANs[san] || !isDomainInScope(san, targetDomain) {
				continue
			}
			seenSANs[san] = true
			sanBatch = append(sanBatch, san)
			newSubs++
		}

		// Track certificate issues for host metadata and step stats without creating vulnerability findings
		if result.Expired || result.SelfSigned || result.MisMatched {
			vulns++
		}

		host := utils.NormalizeHostValue(result.Host)
		if host != "" {
			weakTLS := utils.IsWeakTLSVersion(result.TLSVersion)
			if err := database.UpsertHostMetadata(scanID, database.HostMetadata{
				Host:          host,
				SSLExpired:    result.Expired,
				SSLSelfSigned: result.SelfSigned,
				SSLMismatch:   result.MisMatched,
				WeakTLS:       weakTLS,
			}); err != nil {
				logger.FileDebug("parser: UpsertHostMetadata failed for %s: %v", host, err)
			}
		}
	})

	// Persist all unique in-scope SANs in a single transaction.
	if len(sanBatch) > 0 {
		if err := database.AddSubdomains(scanID, sanBatch, "tlsx-san"); err != nil {
			logger.FileDebug("parser: AddSubdomains batch failed for %d SANs: %v", len(sanBatch), err)
		}
	}

	return newSubs, vulns, err
}

// UncoverResult represents a line from uncover JSON output
type UncoverResult struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	URL      string `json:"url"`
	Source   string `json:"source"`
	Protocol string `json:"protocol"`
}

// ParseUncoverOutput parses uncover JSON output and extracts subdomains/ports.
func ParseUncoverOutput(scanID int64, filePath string, targetDomain string) (subs int, ports int, err error) {
	seenHosts := make(map[string]bool)
	// Batch subdomains by source to reduce per-host DB transactions.
	batchBySource := make(map[string][]string)

	err = scanJSONLines(filePath, func(line string) {
		var result UncoverResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return
		}

		// Add host as subdomain
		host := result.Host
		if host == "" {
			host = result.IP
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" && !seenHosts[host] {
			seenHosts[host] = true
			if utils.ValidateDomain(host) == nil && isDomainInScope(host, targetDomain) {
				src := "uncover-" + result.Source
				batchBySource[src] = append(batchBySource[src], host)
				subs++
			}
		}

		// Add port if found
		if result.Port > 0 && host != "" {
			proto := result.Protocol
			if proto == "" {
				proto = "tcp"
			}
			if err := database.AddPort(scanID, host, result.Port, proto, ""); err != nil {
				logger.FileDebug("parser: AddPort failed for %s:%d: %v", host, result.Port, err)
			} else {
				ports++
			}
		}
	})

	// Flush batched subdomains in one transaction per source.
	for src, hosts := range batchBySource {
		if err := database.AddSubdomains(scanID, hosts, src); err != nil {
			logger.FileDebug("parser: AddSubdomains batch failed for source %s (%d hosts): %v", src, len(hosts), err)
		}
	}

	return subs, ports, err
}

// DalfoxResult represents a line from dalfox output
type DalfoxResult struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Data     string `json:"data"`
	Payload  string `json:"payload"`
	Param    string `json:"param"`
	CWE      string `json:"cwe"`
	Method   string `json:"method"`
}

// ParseDalfoxOutput parses dalfox output for XSS findings.
func ParseDalfoxOutput(scanID int64, filePath string) (int, error) {
	count := 0

	err := scanJSONLines(filePath, func(line string) {
		// Try JSON first
		var result DalfoxResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			targetURL := strings.TrimSpace(result.URL)
			if targetURL == "" {
				targetURL = strings.TrimSpace(result.Data)
			}
			if targetURL == "" {
				return
			}

			severity := "medium"
			if result.Severity != "" {
				severity = strings.ToLower(result.Severity)
			}

			templateID := "xss"
			if result.Type != "" {
				templateID = "xss-" + strings.ToLower(result.Type)
			}

			name := "XSS Finding"
			if result.Type != "" && result.Param != "" {
				name = "XSS (" + result.Type + ") - Param: " + result.Param
			} else if result.Type != "" {
				name = "XSS (" + result.Type + ")"
			} else if result.Param != "" {
				name = "XSS - Param: " + result.Param
			}

			desc := "Potential XSS detected by Dalfox"
			if result.Param != "" {
				desc = "Cross-Site Scripting found via parameter: " + result.Param
			}

			var evidenceParts []string
			if result.Payload != "" {
				evidenceParts = append(evidenceParts, "Payload: "+result.Payload)
			}
			if result.Method != "" {
				evidenceParts = append(evidenceParts, "Method: "+result.Method)
			}
			if result.CWE != "" {
				evidenceParts = append(evidenceParts, "CWE: "+result.CWE)
			}

			err := database.AddVulnerability(
				scanID,
				targetURL,
				targetURL,
				templateID,
				name,
				severity,
				desc,
				"",
				strings.Join(evidenceParts, "\n"),
			)
			if err != nil {
				logger.FileDebug("parser: AddVulnerability failed for %s: %v", targetURL, err)
				return
			}
			count++
		} else if strings.Contains(line, "[POC]") || strings.Contains(line, "[V]") {
			// Text format fallback: extract host/URL from line
			var targetURL string
			var host string

			// Find token starting with http:// or https://
			if idx := strings.Index(line, "http://"); idx != -1 {
				targetURL = extractURLFromToken(line[idx:])
			} else if idx := strings.Index(line, "https://"); idx != -1 {
				targetURL = extractURLFromToken(line[idx:])
			}

			if targetURL != "" {
				host = utils.NormalizeHostValue(targetURL)
			} else {
				return
			}

			err := database.AddVulnerability(
				scanID, host, targetURL, "xss",
				"XSS Finding", "medium",
				"Potential XSS detected by Dalfox",
				"", line,
			)
			if err != nil {
				logger.FileDebug("parser: AddVulnerability failed for %s: %v", host, err)
				return
			}
			count++
		}
	})

	return count, err
}

func extractURLFromToken(s string) string {
	endIdx := len(s)
	for i, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ']' || r == '[' || r == '"' || r == '\'' || r == '`' || r == '>' || r == '<' {
			endIdx = i
			break
		}
	}
	return s[:endIdx]
}
