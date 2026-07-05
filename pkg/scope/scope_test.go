package scope

import (
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
)

func TestScopeAnchoringAndBypass(t *testing.T) {
	cfg := &config.ScopeConfig{
		InScope:    []string{"example.com", ".*\\.example.com"},
		OutOfScope: []string{"out.example.com"},
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	tests := []struct {
		target   string
		expected bool
	}{
		{"example.com", true},
		{"foo.example.com", true},
		{"sub.foo.example.com", true},
		{"evil-example.com", false},         // bypass attempt
		{"example.com.attacker.io", false}, // bypass attempt
		{"out.example.com", false},         // out-of-scope override
	}

	for _, tt := range tests {
		got := s.IsInScope(tt.target)
		if got != tt.expected {
			t.Errorf("IsInScope(%q) = %v, want %v", tt.target, got, tt.expected)
		}
	}
}

func TestIPExclusion(t *testing.T) {
	cfg := &config.ScopeConfig{
		ExcludeIPs: []string{"192.168.0.0/16", "10.0.0.1"},
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	tests := []struct {
		ip       string
		expected bool // true means excluded
	}{
		{"192.168.1.1", true},
		{"192.168.254.254", true},
		{"10.0.0.1", true},
		{"10.0.0.2", false},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		got := s.IsIPExcluded(tt.ip)
		if got != tt.expected {
			t.Errorf("IsIPExcluded(%q) = %v, want %v", tt.ip, got, tt.expected)
		}
	}
}

func TestNoScopePassthrough(t *testing.T) {
	cfg := &config.ScopeConfig{}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	if !s.IsInScope("attacker.io") {
		t.Error("expected attacker.io to be in scope when no scope defined")
	}

	if !s.IsPortAllowed(80) || !s.IsPortAllowed(65535) {
		t.Error("expected all ports allowed when no scope defined")
	}

	if !s.ValidateTarget("", "192.168.1.1", 80) {
		t.Error("expected ValidateTarget to return true for IP-only target when no scope configured")
	}
}

func TestValidateTargetWithScopeConstraint(t *testing.T) {
	cfg := &config.ScopeConfig{
		InScope: []string{"example.com"},
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	if s.ValidateTarget("", "192.168.1.1", 80) {
		t.Error("expected ValidateTarget with empty domain to return false when inScopePatterns is configured")
	}

	if !s.ValidateTarget("example.com", "192.168.1.1", 80) {
		t.Error("expected ValidateTarget with matching domain to return true")
	}

	if s.ValidateTarget("evil.com", "192.168.1.1", 80) {
		t.Error("expected ValidateTarget with non-matching domain to return false")
	}
}
