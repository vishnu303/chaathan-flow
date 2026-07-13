package scope

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/vishnu303/chaathan/pkg/config"
)

// Scope manages in-scope and out-of-scope targets
type Scope struct {
	inScopePatterns  []*regexp.Regexp
	outScopePatterns []*regexp.Regexp
	excludeNets      []*net.IPNet
	allowedPorts     map[int]bool
}

// New creates a new Scope from config
func New(cfg *config.ScopeConfig) (*Scope, error) {
	s := &Scope{
		allowedPorts: make(map[int]bool),
	}

	var err error
	// Compile in-scope patterns
	s.inScopePatterns, err = compilePatterns(cfg.InScope)
	if err != nil {
		return nil, err
	}

	// Compile out-of-scope patterns
	s.outScopePatterns, err = compilePatterns(cfg.OutOfScope)
	if err != nil {
		return nil, err
	}

	// Parse excluded IP ranges
	for _, cidr := range cfg.ExcludeIPs {
		ipNet, err := parseIPOrCIDR(cidr)
		if err != nil {
			return nil, err
		}
		if ipNet != nil {
			s.excludeNets = append(s.excludeNets, ipNet)
		}
	}

	// Set allowed ports
	for _, port := range cfg.AllowedPorts {
		s.allowedPorts[port] = true
	}

	return s, nil
}

// parseIPOrCIDR parses a string which can be a single IP or CIDR network.
func parseIPOrCIDR(input string) (*net.IPNet, error) {
	input = strings.TrimSpace(input)
	_, ipNet, err := net.ParseCIDR(input)
	if err == nil {
		return ipNet, nil
	}

	ip := net.ParseIP(input)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP or CIDR: %q", input)
	}

	bits := 32
	if ip.To4() == nil {
		bits = 128
	}

	_, ipNet, err = net.ParseCIDR(fmt.Sprintf("%s/%d", input, bits))
	return ipNet, err
}

// compilePatterns is a helper that compiles a slice of string regex patterns, anchoring them if not already done.
func compilePatterns(patterns []string) ([]*regexp.Regexp, error) {
	regexes := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		p := pattern
		if !strings.HasPrefix(p, "^") && !strings.HasSuffix(p, "$") {
			p = "^(?:" + p + ")$"
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		regexes = append(regexes, re)
	}
	return regexes, nil
}

// IsInScope checks if a domain/host is in scope
func (s *Scope) IsInScope(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))

	// If no in-scope patterns defined, everything is in scope
	if len(s.inScopePatterns) == 0 {
		return !s.IsOutOfScope(target)
	}

	// Check if matches any in-scope pattern
	for _, re := range s.inScopePatterns {
		if re.MatchString(target) {
			return !s.IsOutOfScope(target)
		}
	}

	return false
}

// IsOutOfScope checks if a domain/host is explicitly out of scope
func (s *Scope) IsOutOfScope(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))

	for _, re := range s.outScopePatterns {
		if re.MatchString(target) {
			return true
		}
	}

	return false
}

// IsIPExcluded checks if an IP is in the excluded ranges
func (s *Scope) IsIPExcluded(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, ipNet := range s.excludeNets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// IsPortAllowed checks if a port is allowed
// If no ports are specified, all ports are allowed
func (s *Scope) IsPortAllowed(port int) bool {
	if len(s.allowedPorts) == 0 {
		return true
	}
	return s.allowedPorts[port]
}

// FilterDomains filters a list of domains to only in-scope ones
func (s *Scope) FilterDomains(domains []string) []string {
	if len(s.inScopePatterns) == 0 && len(s.outScopePatterns) == 0 {
		return domains
	}

	var filtered []string
	for _, domain := range domains {
		if s.IsInScope(domain) {
			filtered = append(filtered, domain)
		}
	}
	return filtered
}

// FilterIPs filters a list of IPs to only non-excluded ones
func (s *Scope) FilterIPs(ips []string) []string {
	if len(s.excludeNets) == 0 {
		return ips
	}

	var filtered []string
	for _, ip := range ips {
		if !s.IsIPExcluded(ip) {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}

// Summary returns a string summary of the scope configuration
func (s *Scope) Summary() string {
	var parts []string

	if len(s.inScopePatterns) > 0 {
		parts = append(parts, "In-scope patterns defined")
	} else {
		parts = append(parts, "All domains in scope")
	}

	if len(s.outScopePatterns) > 0 {
		parts = append(parts, "Out-of-scope patterns defined")
	}

	if len(s.excludeNets) > 0 {
		parts = append(parts, "IP exclusions defined")
	}

	if len(s.allowedPorts) > 0 {
		parts = append(parts, "Port restrictions active")
	}

	return strings.Join(parts, ", ")
}

// WildcardScope creates a scope for a wildcard domain
// e.g., "example.com" allows "*.example.com" and "example.com"
func WildcardScope(domain string) (*Scope, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Escape dots for regex
	escapedDomain := strings.ReplaceAll(domain, ".", "\\.")

	// Pattern: exact domain or any subdomain
	pattern := "^(" + escapedDomain + "|.*\\." + escapedDomain + ")$"

	cfg := &config.ScopeConfig{
		InScope: []string{pattern},
	}

	return New(cfg)
}

// ValidateTarget checks if a target should be scanned based on scope rules
func (s *Scope) ValidateTarget(domain string, ip string, port int) bool {
	if len(s.inScopePatterns) > 0 && domain == "" {
		return false // IP-only target + scope rules = deny
	}

	// Check domain scope
	if domain != "" && !s.IsInScope(domain) {
		return false
	}

	// Check IP exclusion
	if ip != "" && s.IsIPExcluded(ip) {
		return false
	}

	// Check port allowlist
	if port > 0 && !s.IsPortAllowed(port) {
		return false
	}

	return true
}
