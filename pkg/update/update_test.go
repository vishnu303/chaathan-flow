package update

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsNewer(t *testing.T) {
	tests := []struct {
		current  string
		latest   string
		expected bool
	}{
		{"1.0.0", "1.0.1", true},
		{"1.0.1", "1.0.0", false},
		{"1.0.0", "2.0.0", true},
		{"2.0.0", "1.0.0", false},
		{"1.1.0", "1.2.0", true},
		{"1.2.0", "1.1.0", false},
		{"1.0.0", "1.0.0", false},
		{"v1.0.0", "v1.0.1", true},

		{"1.0.0-rc.1", "1.0.0", true},
		{"1.0.0", "1.0.0-rc.1", false},

		{"1.0.0-rc.2", "1.0.0-rc.10", true},
		{"1.0.0-rc.10", "1.0.0-rc.2", false},
		{"1.0.0-beta.1", "1.0.0-beta.2", true},
		{"1.0.0-beta.2", "1.0.0-beta.1", false},
		{"1.0.0-alpha", "1.0.0-beta", true},
		{"1.0.0-rc.1", "1.0.0-rc.1.1", true},

		{"1.2", "1.2.0", false},
		{"1.2.3.4", "1.2.3.5", true},

		{"dev", "1.0.0", false},
		{"dev-1234", "1.0.0", false},
		{"", "1.0.0", false},
	}

	for _, tt := range tests {
		got := IsNewer(tt.current, tt.latest)
		if got != tt.expected {
			t.Errorf("IsNewer(%q, %q) = %t, want %t", tt.current, tt.latest, got, tt.expected)
		}
	}
}

func TestParseVersionNumbers_DroppedComponent(t *testing.T) {
	nums, err := parseVersionNumbers("1.2.3")
	if err != nil {
		t.Errorf("expected no error for '1.2.3', got %v", err)
	}
	if nums != [3]int{1, 2, 3} {
		t.Errorf("expected [1, 2, 3], got %v", nums)
	}

	numsShort, err := parseVersionNumbers("1.2")
	if err != nil {
		t.Errorf("expected no error for '1.2', got %v", err)
	}
	if numsShort != [3]int{1, 2, 0} {
		t.Errorf("expected [1, 2, 0], got %v", numsShort)
	}

	_, err = parseVersionNumbers("1.2.3.4")
	if err == nil {
		t.Error("expected error for 4-part version '1.2.3.4', got nil")
	}

	_, err = parseVersionNumbers("1.a.3")
	if err == nil {
		t.Error("expected error for non-numeric version '1.a.3', got nil")
	}
}

func TestCheckForUpdates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respData := map[string]string{
			"tag_name": "v2.0.0",
			"html_url": "https://github.com/vishnu303/chaathan/releases/tag/v2.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "60")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(respData)
	}))
	defer server.Close()

	// Override API base URL for testing
	oldBase := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = oldBase }()

	info, err := CheckForUpdates("1.0.0")
	if err != nil {
		t.Fatalf("CheckForUpdates error: %v", err)
	}

	if info.LatestVersion != "v2.0.0" {
		t.Errorf("expected version 'v2.0.0', got %q", info.LatestVersion)
	}
	if info.URL != "https://github.com/vishnu303/chaathan/releases/tag/v2.0.0" {
		t.Errorf("expected URL match, got %q", info.URL)
	}
	if !info.IsNewer {
		t.Error("expected IsNewer to be true")
	}
}
