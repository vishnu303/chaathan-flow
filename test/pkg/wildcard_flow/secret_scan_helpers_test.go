package wildcard_flow_test

import (
	"strings"
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
		{"api-keys", "placeholder", false},
		{"api-keys", "your_token", false},
		{"api-keys", "undefined", false},
		{"api-keys", "aaaaaaaaaa", false},
		{"api-keys", "ababababab", false},
		{"api-keys", "aBcD1eFgH2iJkLmN", true},  // high entropy token
		{"slack-webhook", "placeholder", false}, // placeholder check is universal
		{"slack-webhook", "ababababab", true},   // entropy check is only for generic "api-keys"
	}

	for _, tc := range tests {
		got := wildcard_flow.IsLikelySecret(tc.pattern, tc.val)
		if got != tc.expected {
			t.Errorf("IsLikelySecret(%q, %q) = %t; want %t", tc.pattern, tc.val, got, tc.expected)
		}
	}
}

func TestExtractContext(t *testing.T) {
	line := "some prefix text here and then the secret token to match followed by suffix text here"
	match := "secret token to match"
	start := strings.Index(line, match)
	end := start + len(match)

	// Test extraction with context size 10
	got := wildcard_flow.ExtractContext(line, start, end, 10)
	expected := "...then the secret token to match followed..."
	if got != expected {
		t.Errorf("ExtractContext(...) = %q; want %q", got, expected)
	}

	// Test boundary at start
	gotStart := wildcard_flow.ExtractContext(line, 0, 4, 10) // "some"
	if !strings.HasPrefix(gotStart, "some") || strings.HasPrefix(gotStart, "...") {
		t.Errorf("ExtractContext(...) for start boundary = %q; did not expect leading ellipsis", gotStart)
	}
}
