// Package ingest owns tool-output ingestion: it parses JSONL / text output
// files produced by external recon tools and persists the discovered
// subdomains, ports, URLs, endpoints, and vulnerabilities into the SQLite
// database via pkg/database.
//
// The package is split into two layers:
//   - parser.go  — pure parsing: reads tool output files and returns typed
//     structs. Never writes to the database or the logger.
//   - persist.go — orchestration: takes parsed structs and writes them to
//     the database via pkg/database.
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
	"strconv"
	"strings"

	"github.com/vishnu303/chaathan/pkg/database"
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

// parseSubdomainLines extracts unique, in-scope subdomains from a file with
// one subdomain (or Amass relation line) per line.
func parseSubdomainLines(filePath, targetDomain string) ([]string, error) {
	var domains []string
	seen := make(map[string]bool)

	err := scanTextLines(filePath, func(line string) {
		// Extract any valid domain from the line (e.g. Amass graph relation lines)
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
	return domains, err
}

// parseConsolidatedSubdomains reads unique lowercase subdomains from a
// consolidated subdomains file.
func parseConsolidatedSubdomains(filePath string) ([]string, error) {
	var domains []string
	seen := make(map[string]bool)
	err := scanTextLines(filePath, func(line string) {
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "" && !seen[line] {
			seen[line] = true
			domains = append(domains, line)
		}
	})
	return domains, err
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

// parseHttpxFile parses httpx JSON output into URL records plus the list of
// live subdomains referenced by those URLs.
func parseHttpxFile(filePath, targetDomain string) ([]database.URLRecord, []string, error) {
	var urlRecords []database.URLRecord
	var liveSubs []string

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

		urlRecords = append(urlRecords, database.URLRecord{
			RawURL:      result.URL,
			StatusCode:  result.StatusCode,
			ContentType: result.ContentType,
			Title:       result.Title,
			Tech:        tech,
			Source:      "httpx",
		})

		// Collect subdomain for live marking
		subdomain := ""
		if parsed, err := neturl.Parse(result.URL); err == nil && parsed.Hostname() != "" {
			subdomain = strings.ToLower(parsed.Hostname())
		} else {
			subdomain = utils.NormalizeHostValue(result.Input)
		}
		if subdomain != "" {
			liveSubs = append(liveSubs, subdomain)
		}
	})
	return urlRecords, liveSubs, err
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

// parseNucleiFile parses nuclei JSON output into vulnerability records.
// WAF detection findings are deduplicated by host (ignoring port) to avoid
// reporting the same WAF multiple times for different ports on the same host.
func parseNucleiFile(filePath string) ([]database.Vulnerability, error) {
	var vulns []database.Vulnerability
	// Deduplicate WAF findings by host+template (ignore port variants).
	wafSeen := make(map[string]bool)

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

		// Deduplicate WAF findings: one per host+template, ignoring port.
		if isWAFTemplate(result.TemplateID) {
			dedupKey := result.Host + "|" + result.TemplateID + "|" + result.Matcher
			if wafSeen[dedupKey] {
				return
			}
			wafSeen[dedupKey] = true
			// Normalize URL to host (strip port) for WAF findings.
			matchedAt = result.Host
		}

		vulns = append(vulns, database.Vulnerability{
			Host:        result.Host,
			URL:         matchedAt,
			TemplateID:  result.TemplateID,
			Name:        name,
			Severity:    strings.ToLower(result.Info.Severity),
			Description: result.Info.Description,
			Matcher:     result.Matcher,
			Evidence:    evidence,
		})
	})
	return vulns, err
}

// isWAFTemplate returns true if the template ID indicates a WAF detection template.
func isWAFTemplate(templateID string) bool {
	lower := strings.ToLower(templateID)
	return strings.Contains(lower, "waf") || strings.Contains(lower, "firewall")
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

// parseNaabuFile parses naabu output into port records.
// Supports both JSON output format and standard host:port/ip:port format.
func parseNaabuFile(filePath string) ([]database.Port, error) {
	var ports []database.Port

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

		ports = append(ports, database.Port{Host: host, Port: port, Protocol: proto})
	})
	return ports, err
}

// parseEndpointsFile parses a file with endpoints (one per line) into
// endpoint records.
func parseEndpointsFile(filePath, targetDomain, source string) ([]database.Endpoint, error) {
	seen := make(map[string]struct{})
	var endpoints []database.Endpoint

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

		// Relative/path-only endpoints (e.g. jsluice output like
		// "/api/v1/users") carry no host, so scope cannot apply — keep
		// them. Absolute URLs with a host are filtered against the target.
		if targetDomain != "" {
			if u, err := neturl.Parse(url); err == nil && u.Hostname() != "" && !isURLInScope(url, targetDomain) {
				return
			}
		}

		endpoints = append(endpoints, database.Endpoint{URL: url, Method: method, Source: source})
	})
	return endpoints, err
}

// parseURLLines parses a file with URLs (one per line) into URL records.
func parseURLLines(filePath, targetDomain, source string) ([]database.URLRecord, error) {
	var records []database.URLRecord

	err := scanTextLines(filePath, func(line string) {
		// Drop banner/progress/error noise: only absolute http(s) URLs are stored.
		if !utils.IsValidHTTPURL(line) {
			return
		}
		if targetDomain != "" && !isURLInScope(line, targetDomain) {
			return
		}
		records = append(records, database.URLRecord{RawURL: line, Source: source})
	})
	return records, err
}

// parseLiveURLLines parses httpx plain-text output where each line may be
// "https://url [STATUS_CODE]" (produced by -status-code without -json).
// Only the primary URL field (before any whitespace) is kept, so status
// suffixes never corrupt stored URLs.
func parseLiveURLLines(filePath, targetDomain, source string) ([]database.URLRecord, error) {
	seen := make(map[string]bool)
	var records []database.URLRecord

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
		records = append(records, database.URLRecord{RawURL: url, Source: source})
	})
	return records, err
}

// FfufResult represents a single ffuf discovery item.
type FfufResult struct {
	Input  map[string]string `json:"input"`
	URL    string            `json:"url"`
	Status int               `json:"status"`
}

// parseFfufFile parses ffuf JSON output into URL records and GET endpoints.
func parseFfufFile(filePath, targetDomain string) ([]database.URLRecord, []database.Endpoint, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var payload struct {
		Results []FfufResult `json:"results"`
	}
	if err := json.NewDecoder(file).Decode(&payload); err != nil {
		return nil, nil, err
	}

	var urlRecords []database.URLRecord
	var endpoints []database.Endpoint

	for _, result := range payload.Results {
		if strings.TrimSpace(result.URL) == "" {
			continue
		}
		if targetDomain != "" && !isURLInScope(result.URL, targetDomain) {
			continue
		}

		urlRecords = append(urlRecords, database.URLRecord{
			RawURL:     result.URL,
			StatusCode: result.Status,
			Source:     "ffuf",
		})
		endpoints = append(endpoints, database.Endpoint{URL: result.URL, Method: "GET", Source: "ffuf"})
	}
	return urlRecords, endpoints, nil
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

// tlsxParseResult carries the parsed output of a tlsx JSONL file: unique
// in-scope SANs, per-host TLS metadata, and a count of certificate issues.
type tlsxParseResult struct {
	SANs       []string
	Metadata   []database.HostMetadata
	CertIssues int
}

// parseTlsxFile parses tlsx JSON output. Newer tlsx JSON uses subject_an,
// while older probe-driven output may still emit san. newSubs counts the
// unique in-scope SANs discovered (INSERT OR IGNORE may store fewer if the
// DB already holds them from a prior source).
func parseTlsxFile(filePath, targetDomain string) (*tlsxParseResult, error) {
	res := &tlsxParseResult{}
	seenSANs := make(map[string]bool)

	err := scanJSONLines(filePath, func(line string) {
		var result TlsxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return
		}

		// Extract SANs as new subdomains.
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
			res.SANs = append(res.SANs, san)
		}

		// Track certificate issues for host metadata and step stats without creating vulnerability findings
		if result.Expired || result.SelfSigned || result.MisMatched {
			res.CertIssues++
		}

		host := utils.NormalizeHostValue(result.Host)
		if host != "" {
			weakTLS := utils.IsWeakTLSVersion(result.TLSVersion)
			res.Metadata = append(res.Metadata, database.HostMetadata{
				Host:          host,
				SSLExpired:    result.Expired,
				SSLSelfSigned: result.SelfSigned,
				SSLMismatch:   result.MisMatched,
				WeakTLS:       weakTLS,
			})
		}
	})
	return res, err
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

// uncoverParseResult carries the parsed output of an uncover JSONL file:
// subdomains batched by source label, port records, and their counts.
type uncoverParseResult struct {
	SubsBySource map[string][]string
	Ports        []database.Port
	SubCount     int
	PortCount    int
}

// parseUncoverFile parses uncover JSON output into subdomains (batched by
// source) and port records.
func parseUncoverFile(filePath, targetDomain string) (*uncoverParseResult, error) {
	res := &uncoverParseResult{SubsBySource: make(map[string][]string)}
	seenHosts := make(map[string]bool)

	err := scanJSONLines(filePath, func(line string) {
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
				res.SubsBySource[src] = append(res.SubsBySource[src], host)
				res.SubCount++
			}
		}

		// Collect port for batch insert
		if result.Port > 0 && host != "" {
			proto := result.Protocol
			if proto == "" {
				proto = "tcp"
			}
			res.Ports = append(res.Ports, database.Port{Host: host, Port: result.Port, Protocol: proto})
			res.PortCount++
		}
	})
	return res, err
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

// dalfoxVulnFromJSON converts one parsed dalfox JSON finding into a
// vulnerability record. Returns ok=false when the finding has no target URL.
func dalfoxVulnFromJSON(result DalfoxResult) (database.Vulnerability, bool) {
	targetURL := strings.TrimSpace(result.URL)
	if targetURL == "" {
		targetURL = strings.TrimSpace(result.Data)
	}
	if targetURL == "" {
		return database.Vulnerability{}, false
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

	return database.Vulnerability{
		Host:        targetURL,
		URL:         targetURL,
		TemplateID:  templateID,
		Name:        name,
		Severity:    severity,
		Description: desc,
		Evidence:    strings.Join(evidenceParts, "\n"),
	}, true
}

// dalfoxVulnFromText converts one dalfox text-format finding line into a
// vulnerability record. Returns ok=false when no URL is present.
func dalfoxVulnFromText(line string) (database.Vulnerability, bool) {
	var targetURL string

	// Find token starting with http:// or https://
	if idx := strings.Index(line, "http://"); idx != -1 {
		targetURL = extractURLFromToken(line[idx:])
	} else if idx := strings.Index(line, "https://"); idx != -1 {
		targetURL = extractURLFromToken(line[idx:])
	}

	if targetURL == "" {
		return database.Vulnerability{}, false
	}

	return database.Vulnerability{
		Host:        utils.NormalizeHostValue(targetURL),
		URL:         targetURL,
		TemplateID:  "xss",
		Name:        "XSS Finding",
		Severity:    "medium",
		Description: "Potential XSS detected by Dalfox",
		Evidence:    line,
	}, true
}

// parseDalfoxFile parses dalfox output (JSONL with a text-format fallback)
// into XSS vulnerability records.
func parseDalfoxFile(filePath string) ([]database.Vulnerability, error) {
	var vulns []database.Vulnerability

	err := scanJSONLines(filePath, func(line string) {
		// Try JSON first
		var result DalfoxResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			if v, ok := dalfoxVulnFromJSON(result); ok {
				vulns = append(vulns, v)
			}
			return
		}
		if strings.Contains(line, "[POC]") || strings.Contains(line, "[V]") {
			if v, ok := dalfoxVulnFromText(line); ok {
				vulns = append(vulns, v)
			}
		}
	})
	return vulns, err
}

// extractURLFromToken trims a URL token at the first whitespace or delimiter.
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
