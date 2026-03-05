package utils

import (
	"fmt"
	"regexp"
	"strconv"
)

// domainRegex validates a standard domain name format
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)

// ValidateDomain checks if the given string is a valid domain name.
// Rejects empty strings, strings with path traversal, whitespace, and
// anything that doesn't look like a real FQDN.
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain too long: %d characters (max 253)", len(domain))
	}
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %q — expected something like example.com", domain)
	}
	return nil
}

// ParseScanID parses a string argument into a positive int64 scan ID.
// Returns a clear error message on invalid input instead of silently returning 0.
func ParseScanID(arg string) (int64, error) {
	id, err := strconv.ParseInt(arg, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid scan ID %q: must be a positive number", arg)
	}
	if id <= 0 {
		return 0, fmt.Errorf("invalid scan ID %d: must be a positive number", id)
	}
	return id, nil
}

// ParseDays parses a string argument into a positive int for day counts.
func ParseDays(arg string) (int, error) {
	days, err := strconv.Atoi(arg)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q: must be a positive integer", arg)
	}
	if days < 1 {
		return 0, fmt.Errorf("days must be at least 1, got %d", days)
	}
	return days, nil
}
