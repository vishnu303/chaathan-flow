package scope_test
 
import (
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/scope"
)
 
func TestScope_IsInScope(t *testing.T) {
	cfg := &config.ScopeConfig{
		InScope:    []string{`^.*\.example\.com$`, `^exact-domain\.org$`},
		OutOfScope: []string{`^exclude\.example\.com$`, `^bad.*\.com$`},
	}

	s, err := scope.New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	tests := []struct {
		target   string
		expected bool
	}{
		{"sub.example.com", true},
		{"exact-domain.org", true},
		{"exclude.example.com", false},
		{"bad-domain.com", false},
		{"google.com", false},
	}

	for _, tc := range tests {
		actual := s.IsInScope(tc.target)
		if actual != tc.expected {
			t.Errorf("IsInScope(%q) = %v, expected %v", tc.target, actual, tc.expected)
		}
	}
}

func TestScopeAnchoringAndBypass(t *testing.T) {
	cfg := &config.ScopeConfig{
		InScope:    []string{"example.com", ".*\\.example.com"},
		OutOfScope: []string{"out.example.com"},
	}

	s, err := scope.New(cfg)
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

func TestScope_IsIPExcluded(t *testing.T) {
	cfg := &config.ScopeConfig{
		ExcludeIPs: []string{
			"192.168.1.1",
			"10.0.0.0/24",
		},
	}

	s, err := scope.New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.2", false},
		{"10.0.0.50", true},
		{"10.0.0.255", true},
		{"10.0.1.50", false},
		{"invalid-ip", false},
	}

	for _, tc := range tests {
		actual := s.IsIPExcluded(tc.ip)
		if actual != tc.expected {
			t.Errorf("IsIPExcluded(%q) = %v, expected %v", tc.ip, actual, tc.expected)
		}
	}
}

func TestIPExclusion(t *testing.T) {
	cfg := &config.ScopeConfig{
		ExcludeIPs: []string{"192.168.0.0/16", "10.0.0.1"},
	}

	s, err := scope.New(cfg)
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

func TestScope_IsPortAllowed(t *testing.T) {
	cfg := &config.ScopeConfig{
		AllowedPorts: []int{80, 443, 8080},
	}

	s, err := scope.New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	// Allowed
	if !s.IsPortAllowed(80) {
		t.Error("expected port 80 to be allowed")
	}
	if !s.IsPortAllowed(8080) {
		t.Error("expected port 8080 to be allowed")
	}

	// Excluded
	if s.IsPortAllowed(22) {
		t.Error("expected port 22 to be disallowed")
	}

	// Empty allowed ports = all allowed
	emptyCfg := &config.ScopeConfig{}
	emptyScope, _ := scope.New(emptyCfg)
	if !emptyScope.IsPortAllowed(22) {
		t.Error("expected port 22 to be allowed under empty scope config")
	}
}

func TestWildcardScope(t *testing.T) {
	s, err := scope.WildcardScope("example.com")
	if err != nil {
		t.Fatalf("failed to create wildcard scope: %v", err)
	}

	tests := []struct {
		target   string
		expected bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"nested.sub.example.com", true},
		{"notexample.com", false},
		{"example.com.org", false},
	}

	for _, tc := range tests {
		actual := s.IsInScope(tc.target)
		if actual != tc.expected {
			t.Errorf("WildcardScope match(%q) = %v, expected %v", tc.target, actual, tc.expected)
		}
	}
}

func TestScope_FilterDomains(t *testing.T) {
	cfg := &config.ScopeConfig{
		InScope: []string{`^.*\.example\.com$`},
	}

	s, err := scope.New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	input := []string{"sub.example.com", "other.com", "nested.example.com"}
	expected := []string{"sub.example.com", "nested.example.com"}

	actual := s.FilterDomains(input)
	if len(actual) != len(expected) {
		t.Fatalf("FilterDomains returned %v, expected %v", actual, expected)
	}
	for i := range expected {
		if actual[i] != expected[i] {
			t.Errorf("at index %d: expected %q, got %q", i, expected[i], actual[i])
		}
	}
}

func TestNoScopePassthrough(t *testing.T) {
	cfg := &config.ScopeConfig{}

	s, err := scope.New(cfg)
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

	s, err := scope.New(cfg)
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
