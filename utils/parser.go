package utils

// parser.go holds the pure string/host-normalization helpers that were
// originally grouped with the tool-output parsers. The DB-coupled Parse*
// family was extracted to pkg/ingest as part of the §3.4 leaf-package
// inversion; those functions are now reachable via pkg/ingest, and utils
// remains a true leaf package (no database or logger dependency).
//
// Kept here because they have no DB / logger coupling and are widely reused
// as foundation helpers across the codebase.

import (
	"net"
	neturl "net/url"
	"strings"
)

// IsHTTPMethod checks if a string is a standard HTTP method in an allocation-free manner.
func IsHTTPMethod(s string) bool {
	switch strings.ToUpper(s) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return true
	default:
		return false
	}
}

// NormalizeHostValue extracts a lowercase bare hostname from a raw value that
// may be a URL, a host:port pair, or a bracketed IPv6 literal.
func NormalizeHostValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if strings.Contains(raw, "://") {
		if parsed, err := neturl.Parse(raw); err == nil {
			return strings.ToLower(parsed.Hostname())
		}
	}

	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.ToLower(host)
	}

	return strings.ToLower(strings.Trim(raw, "[]"))
}

// IsWeakTLSVersion reports whether a TLS version string (as emitted by tlsx)
// denotes a weak/deprecated protocol version (TLS 1.0/1.1 or SSLv3).
func IsWeakTLSVersion(version string) bool {
	version = strings.ToLower(strings.TrimSpace(version))
	return strings.Contains(version, "tls10") ||
		strings.Contains(version, "tls1.0") ||
		strings.Contains(version, "tls11") ||
		strings.Contains(version, "tls1.1") ||
		strings.Contains(version, "ssl3")
}

// maxScanBufferSize is the buffer size limit used when scanning large output files (4MB).
// A private copy is kept here because file.go uses it; pkg/ingest carries its
// own copy so utils remains a true leaf package with no ingest dependency.
const maxScanBufferSize = 4 * 1024 * 1024
