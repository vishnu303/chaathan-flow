// persist.go is the persistence layer of pkg/ingest: every exported Parse*
// function orchestrates a pure parser from parser.go and writes the parsed
// structs to the database via pkg/database. No parsing logic lives here.
package ingest

import (
	"bufio"
	"os"
	"slices"
	"strings"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/utils"
)

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

// ParseSubdomainsFile reads a file with one subdomain per line, extracts valid domains
// (including from Amass relationship lines), inserts them into the database,
// and rewrites the file in-place to only contain the unique, validated subdomains.
func ParseSubdomainsFile(scanID int64, filePath, source string) (int, error) {
	domains, err := parseSubdomainLines(filePath, getTargetDomain(scanID))
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

	domains, err := parseConsolidatedSubdomains(consolidatedFilePath)
	if err != nil {
		return 0, err
	}

	deleted, err := database.PurgeUnconsolidatedSubdomains(scanID, domains)
	if err != nil {
		return 0, err
	}
	return int(deleted), nil
}

// ParseHttpxOutput parses httpx JSON output and stores in database
func ParseHttpxOutput(scanID int64, filePath string) (int, error) {
	urlRecords, liveSubs, err := parseHttpxFile(filePath, getTargetDomain(scanID))
	if err != nil {
		return 0, err
	}

	count, err := database.AddURLsBatch(scanID, urlRecords)
	if err != nil {
		logger.FileDebug("parser: AddURLsBatch failed for httpx: %v", err)
		return 0, err
	}

	// Mark subdomains as live in bulk
	if len(liveSubs) > 0 {
		if err := database.UpdateSubdomainsLiveBulk(scanID, liveSubs); err != nil {
			logger.FileDebug("parser: UpdateSubdomainsLiveBulk failed: %v", err)
		}
	}

	return count, nil
}

// ParseNucleiOutput parses nuclei JSON output and stores in database.
func ParseNucleiOutput(scanID int64, filePath string) (int, error) {
	vulns, err := parseNucleiFile(filePath)
	if err != nil {
		return 0, err
	}

	if len(vulns) == 0 {
		return 0, nil
	}
	count, err := database.AddVulnerabilitiesBatch(scanID, vulns)
	if err != nil {
		logger.FileDebug("parser: AddVulnerabilitiesBatch failed: %v", err)
		return 0, err
	}
	return count, nil
}

// ParseNaabuOutput parses naabu output and stores in database.
// Supports both JSON output format and standard host:port/ip:port format.
func ParseNaabuOutput(scanID int64, filePath string) (int, error) {
	ports, err := parseNaabuFile(filePath)
	if err != nil {
		return 0, err
	}

	if len(ports) == 0 {
		return 0, nil
	}
	if err := database.AddPorts(scanID, ports); err != nil {
		logger.FileDebug("parser: AddPorts batch failed: %v", err)
		return 0, err
	}
	return len(ports), nil
}

// ParseEndpointsFile parses a file with endpoints (one per line)
func ParseEndpointsFile(scanID int64, filePath, source string) (int, error) {
	endpoints, err := parseEndpointsFile(filePath, getTargetDomain(scanID), source)
	if err != nil {
		return 0, err
	}

	if len(endpoints) == 0 {
		return 0, nil
	}
	if err := database.AddEndpoints(scanID, endpoints); err != nil {
		logger.FileDebug("parser: AddEndpoints batch failed for source %s: %v", source, err)
		return 0, err
	}
	return len(endpoints), nil
}

// ParseURLsFile parses a file with URLs (one per line)
func ParseURLsFile(scanID int64, filePath, source string) (int, error) {
	records, err := parseURLLines(filePath, getTargetDomain(scanID), source)
	if err != nil {
		return 0, err
	}

	if len(records) == 0 {
		return 0, nil
	}

	count, err := database.AddURLsBatch(scanID, records)
	if err != nil {
		logger.FileDebug("parser: AddURLsBatch failed for source %s: %v", source, err)
		return 0, err
	}
	return count, nil
}

// ParseLiveURLsFile parses httpx plain-text output where each line may be
// "https://url [STATUS_CODE]" (produced by -status-code without -json).
// Only the primary URL field (before any whitespace) is stored in the DB,
// so status suffixes never corrupt stored URLs.
func ParseLiveURLsFile(scanID int64, filePath, source string) (int, error) {
	records, err := parseLiveURLLines(filePath, getTargetDomain(scanID), source)
	if err != nil {
		return 0, err
	}

	if len(records) == 0 {
		return 0, nil
	}

	count, err := database.AddURLsBatch(scanID, records)
	if err != nil {
		logger.FileDebug("parser: AddURLsBatch failed for source %s: %v", source, err)
		return 0, err
	}
	return count, nil
}

// ParseFfufOutput parses ffuf JSON output and stores discovered paths as both
// URLs and endpoints so later ranking/reporting can use the fuzzing data.
func ParseFfufOutput(scanID int64, filePath string) (int, error) {
	urlRecords, endpoints, err := parseFfufFile(filePath, getTargetDomain(scanID))
	if err != nil {
		return 0, err
	}

	if len(urlRecords) == 0 {
		return 0, nil
	}

	if _, err := database.AddURLsBatch(scanID, urlRecords); err != nil {
		logger.FileDebug("parser: AddURLsBatch failed for ffuf: %v", err)
	}
	if err := database.AddEndpoints(scanID, endpoints); err != nil {
		logger.FileDebug("parser: AddEndpoints batch failed for ffuf: %v", err)
	}

	return len(urlRecords), nil
}

// ParseTlsxOutput parses tlsx JSON output.
// Extracts SANs as new subdomains and flags expired/weak certs as vulnerabilities.
func ParseTlsxOutput(scanID int64, filePath string, targetDomain string) (newSubs int, vulns int, err error) {
	res, err := parseTlsxFile(filePath, targetDomain)
	if res != nil {
		newSubs = len(res.SANs)
		vulns = res.CertIssues

		// Persist all unique in-scope SANs in a single transaction.
		if len(res.SANs) > 0 {
			if dbErr := database.AddSubdomains(scanID, res.SANs, "tlsx-san"); dbErr != nil {
				logger.FileDebug("parser: AddSubdomains batch failed for %d SANs: %v", len(res.SANs), dbErr)
			}
		}

		// Persist host metadata in a single transaction.
		if len(res.Metadata) > 0 {
			if _, dbErr := database.UpsertHostMetadataBatch(scanID, res.Metadata); dbErr != nil {
				logger.FileDebug("parser: UpsertHostMetadataBatch failed for %d hosts: %v", len(res.Metadata), dbErr)
			}
		}
	}

	return newSubs, vulns, err
}

// ParseUncoverOutput parses uncover JSON output and extracts subdomains/ports.
func ParseUncoverOutput(scanID int64, filePath string, targetDomain string) (subs int, ports int, err error) {
	res, err := parseUncoverFile(filePath, targetDomain)
	if res != nil {
		subs = res.SubCount
		ports = res.PortCount

		// Flush batched subdomains in one transaction per source.
		for src, hosts := range res.SubsBySource {
			if dbErr := database.AddSubdomains(scanID, hosts, src); dbErr != nil {
				logger.FileDebug("parser: AddSubdomains batch failed for source %s (%d hosts): %v", src, len(hosts), dbErr)
			}
		}

		// Flush batched ports in a single transaction.
		if len(res.Ports) > 0 {
			if dbErr := database.AddPorts(scanID, res.Ports); dbErr != nil {
				logger.FileDebug("parser: AddPorts batch failed for uncover (%d ports): %v", len(res.Ports), dbErr)
			}
		}
	}

	return subs, ports, err
}

// ParseDalfoxOutput parses dalfox output for XSS findings.
func ParseDalfoxOutput(scanID int64, filePath string) (int, error) {
	vulns, err := parseDalfoxFile(filePath)
	if err != nil {
		return 0, err
	}

	if len(vulns) == 0 {
		return 0, nil
	}
	count, err := database.AddVulnerabilitiesBatch(scanID, vulns)
	if err != nil {
		logger.FileDebug("parser: AddVulnerabilitiesBatch failed for dalfox: %v", err)
		return 0, err
	}
	return count, nil
}
