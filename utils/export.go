package utils

// export.go provides the canonical filename constants and severity ordering
// used across the codebase. The actual DB→file exporters were extracted to
// pkg/ingest as part of the §3.4 leaf-package inversion so this file no
// longer imports pkg/database. Callers should use pkg/ingest.Export*
// directly; the filename and severity constants below remain the single
// source of truth.

import (
	"slices"
)

// severityOrder is the canonical vulnerability severity ordering (highest to lowest).
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// SeverityOrder returns a copy of the canonical severity ordering. Use it
// anywhere severities are listed, sorted, or summarized.
func SeverityOrder() []string { return slices.Clone(severityOrder) }

// Exported result filenames — the single source of truth for final_files/
// output names. Referenced by the exporter (pkg/ingest), the scan workflows,
// and the CLI.
const (
	FileFinalSubdomains      = "final_subdomains.txt"
	FileLiveSubdomains       = "live_subdomains.txt"
	FileOpenPorts            = "open_ports.txt"
	FileAllURLs              = "all_urls.txt"
	FileURLs200              = "urls_200.txt"
	FileVulnerabilities      = "vulnerabilities.txt"
	FileVulnCriticalHigh     = "vulnerabilities_critical_high.txt"
	FileEndpoints            = "endpoints.txt"
	FileEndpointsInteresting = "endpoints_interesting.txt"
	FileGFSecrets            = "gf_secrets_findings.txt"
	FileNucleiVulns          = "nuclei_vulns.json"
	FileNucleiURLVulns       = "nuclei_url_vulns.json"
	FileDalfoxXSS            = "dalfox_xss.jsonl"
	FileSummary              = "SUMMARY.txt"
)

// ExportFilenames lists every exported file, in manifest order.
var ExportFilenames = []string{
	FileFinalSubdomains,
	FileLiveSubdomains,
	FileOpenPorts,
	FileAllURLs,
	FileURLs200,
	FileVulnerabilities,
	FileVulnCriticalHigh,
	FileEndpoints,
	FileEndpointsInteresting,
	FileGFSecrets,
	FileNucleiVulns,
	FileNucleiURLVulns,
	FileDalfoxXSS,
}
