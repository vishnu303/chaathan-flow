package update_test
 
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vishnu303/chaathan/pkg/update"
)
 
func TestIsNewer(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		// Basic upgrades
		{"v1.0.0", "v1.1.0", true},
		{"v1.0.0", "v1.0.1", true},
		{"v1.0.0", "v2.0.0", true},
		{"1.0.0", "v1.0.1", true},
		{"v1.0.0", "1.0.1", true},

		// Same versions
		{"v1.0.0", "v1.0.0", false},
		{"v2.1.3", "v2.1.3", false},

		// Downgrades / Older latest
		{"v1.1.0", "v1.0.0", false},
		{"v1.0.1", "v1.0.0", false},
		{"v2.0.0", "v1.0.0", false},

		// Pre-releases
		{"v1.0.0-beta.1", "v1.0.0", true},
		{"v1.0.0-rc.1", "v1.0.0", true},
		{"v1.0.0", "v1.0.0-beta.1", false},
		{"v1.0.0-beta.1", "v1.0.0-beta.2", true},
		{"v1.0.0-beta.2", "v1.0.0-beta.1", false},

		// Dev builds (should not alert for new versions to prevent dev environment spam)
		{"dev", "v1.0.0", false},
		{"dev-dirty", "v1.0.0", false},
		{"", "v1.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.current+" vs "+tt.latest, func(t *testing.T) {
			got := update.IsNewer(tt.current, tt.latest)
			if got != tt.want {
				t.Errorf("IsNewer(%q, %q) = %v; want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

func TestParseVersionNumbers_DroppedComponent(t *testing.T) {
	nums, err := update.ParseVersionNumbers("1.2.3")
	if err != nil {
		t.Errorf("expected no error for '1.2.3', got %v", err)
	}
	if nums != [3]int{1, 2, 3} {
		t.Errorf("expected [1, 2, 3], got %v", nums)
	}

	numsShort, err := update.ParseVersionNumbers("1.2")
	if err != nil {
		t.Errorf("expected no error for '1.2', got %v", err)
	}
	if numsShort != [3]int{1, 2, 0} {
		t.Errorf("expected [1, 2, 0], got %v", numsShort)
	}

	_, err = update.ParseVersionNumbers("1.2.3.4")
	if err == nil {
		t.Error("expected error for 4-part version '1.2.3.4', got nil")
	}

	_, err = update.ParseVersionNumbers("1.a.3")
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

	// Override API base URL for testing via bridge pointer
	oldBase := *update.APIBaseURL
	*update.APIBaseURL = server.URL
	defer func() { *update.APIBaseURL = oldBase }()

	info, err := update.CheckForUpdates("1.0.0")
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
