package wildcard_flow_test

import (
	"reflect"
	"testing"

	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

func TestFilterAndDeduplicateHosts(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name: "Standard port filtering and scheme prefix",
			input: []string{
				"http://0-edge-chat.facebook.com:8000",
				"http://01.eze1.facebook.com:8888",
				"https://facebook.com:443",
				"http://facebook.com:80",
			},
			expected: []string{
				"https://facebook.com:443",
			},
		},
		{
			name: "Bare hostname and port scheme mapping",
			input: []string{
				"facebook.com:8443", // mapped to https:// but filtered out since port is not 80/443
				"facebook.com:443",  // mapped to https://facebook.com:443 and kept
				"example.com:80",    // mapped to http://example.com:80 and kept
				"barehost.com",      // mapped to https://barehost.com and kept (port 443 implicit)
			},
			expected: []string{
				"http://example.com:80",
				"https://barehost.com",
				"https://facebook.com:443",
			},
		},
		{
			name: "Hostname deduplication preferring HTTPS",
			input: []string{
				"http://example.com",
				"https://example.com",
			},
			expected: []string{
				"https://example.com",
			},
		},
		{
			name: "Standard ports implicit and explicit mapping",
			input: []string{
				"http://example.com:80",
				"http://example.com",
				"https://example.com:443",
				"https://example.com",
			},
			expected: []string{
				"https://example.com:443", // parsed.Port() would output "443" for explicit, keeping whichever was processed last or highest priority
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := wildcard_flow.FilterAndDeduplicateHosts(tc.input)
			// Deduplication order is sorted, so we compare got vs expected.
			// The expected slice should also be sorted.
			if len(got) != len(tc.expected) {
				t.Fatalf("expected length %d, got %d. Got: %v", len(tc.expected), len(got), got)
			}
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("got %v; want %v", got, tc.expected)
			}
		})
	}
}
