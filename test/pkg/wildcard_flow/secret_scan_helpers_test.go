package wildcard_flow_test

import (
	"testing"

	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"", 0.0},
		{"aaaaa", 0.0},
		{"abab", 1.0},
	}

	for _, tc := range tests {
		got := wildcard_flow.ShannonEntropy(tc.input)
		if got != tc.expected {
			t.Errorf("ShannonEntropy(%q) = %f; want %f", tc.input, got, tc.expected)
		}
	}

	// High entropy string should be > 3.0
	highEntropy := "aBcD1!eFgH2@iJkL"
	got := wildcard_flow.ShannonEntropy(highEntropy)
	if got < 3.0 {
		t.Errorf("ShannonEntropy(%q) = %f; want > 3.0", highEntropy, got)
	}
}

func TestIsLikelySecret(t *testing.T) {
	tests := []struct {
		pattern  string
		val      string
		expected bool
	}{
		{"generic-secret", "placeholder", false},
		{"generic-secret", "your_token", false},
		{"generic-secret", "undefined", false},
		{"generic-secret", "aaaaaaaaaa", false},
		{"generic-secret", "ababababab", false},
		{"generic-secret", "aBcD1eFgH2iJkLmN", true}, // high entropy token
		{"slack-webhook", "placeholder", false},        // placeholder check is universal
		{"slack-webhook", "ababababab", true},          // entropy check is only for generic patterns
	}

	for _, tc := range tests {
		got := wildcard_flow.IsLikelySecret(tc.pattern, tc.val)
		if got != tc.expected {
			t.Errorf("IsLikelySecret(%q, %q) = %t; want %t", tc.pattern, tc.val, got, tc.expected)
		}
	}
}
