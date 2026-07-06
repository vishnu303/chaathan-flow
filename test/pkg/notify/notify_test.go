package notify_test
 
import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/notify"
)
 
func TestEscapeMarkdown(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello_world", "hello\\_world"},
		{"hello*world", "hello\\*world"},
		{"back\\slash", "back\\\\slash"},
		{"nested[bracket]test", "nested\\[bracket\\]test"},
	}

	for _, tc := range tests {
		actual := notify.EscapeMarkdown(tc.input)
		if actual != tc.expected {
			t.Errorf("escapeMarkdown(%q) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestTitleCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"a", "A"},
		{"hello", "Hello"},
	}

	for _, tc := range tests {
		actual := notify.TitleCase(tc.input)
		if actual != tc.expected {
			t.Errorf("titleCase(%q) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected string
	}{
		{45 * time.Second, "45s"},
		{19*time.Minute + 56*time.Second, "19m 56s"},
		{2 * time.Hour, "2h"},
		{2*time.Hour + 3*time.Minute, "2h 3m"},
	}

	for _, tc := range tests {
		actual := notify.FormatDuration(tc.input)
		if actual != tc.expected {
			t.Errorf("formatDuration(%v) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestGetOrderedStatsKeys(t *testing.T) {
	stats := map[string]int{
		"urls":            10,
		"subdomains":      5,
		"vulnerabilities": 1,
		"unknown_metric":  3,
	}

	expected := []string{"subdomains", "urls", "vulnerabilities", "unknown_metric"}
	actual := notify.GetOrderedStatsKeys(stats)

	if len(actual) != len(expected) {
		t.Fatalf("expected length %d, got %d", len(expected), len(actual))
	}
	for i := range expected {
		if actual[i] != expected[i] {
			t.Errorf("at index %d: expected %q, got %q", i, expected[i], actual[i])
		}
	}
}

func TestNotifier_SendFinding_Discord(t *testing.T) {
	var receivedPayload map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		err := json.NewDecoder(r.Body).Decode(&receivedPayload)
		if err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.NotificationConfig{
		Enabled:        true,
		MinSeverity:    "high",
		DiscordWebhook: server.URL,
	}

	notifier := notify.New(cfg)

	finding := notify.Finding{
		Target:    "example.com",
		Type:      "vulnerability",
		Name:      "Critical Vulnerability",
		Severity:  "critical",
		Timestamp: time.Now(),
	}

	err := notifier.SendFinding(finding)
	if err != nil {
		t.Fatalf("SendFinding returned error: %v", err)
	}

	if receivedPayload == nil {
		t.Fatal("no payload received by test server")
	}

	embeds, ok := receivedPayload["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatal("no embeds in Discord payload")
	}

	embed := embeds[0].(map[string]any)
	title := embed["title"].(string)
	if !strings.Contains(title, "CRITICAL") || !strings.Contains(title, "Critical Vulnerability") {
		t.Errorf("unexpected title in embed: %s", title)
	}
}

func TestShouldNotify(t *testing.T) {
	tests := []struct {
		minSeverity string
		findingSev  string
		want        bool
	}{
		{"high", "critical", true},
		{"high", "high", true},
		{"high", "medium", false},
		{"high", "low", false},
		{"high", "info", false},
		{"low", "medium", true},
		{"low", "info", false},
		{"critical", "high", false},
	}

	for _, tt := range tests {
		cfg := &config.NotificationConfig{
			Enabled:     true,
			MinSeverity: tt.minSeverity,
		}
		n := notify.New(cfg)
		if got := n.ShouldNotify(tt.findingSev); got != tt.want {
			t.Errorf("ShouldNotify(min=%s, finding=%s) = %v, want %v", tt.minSeverity, tt.findingSev, got, tt.want)
		}
	}
}

func TestPostJSONRetry(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		att := atomic.AddInt32(&attempts, 1)
		if att == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := notify.New(&config.NotificationConfig{Enabled: true})
	n.SetClient(server.Client()) // use mock client

	err := n.PostJSON(server.URL, map[string]string{"foo": "bar"})
	if err != nil {
		t.Fatalf("expected success on retry, got: %v", err)
	}

	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestPostJSONNoRetryOn400(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	n := notify.New(&config.NotificationConfig{Enabled: true})
	n.SetClient(server.Client())

	err := n.PostJSON(server.URL, map[string]string{"foo": "bar"})
	if err == nil {
		t.Fatal("expected error on 400, got nil")
	}

	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("expected only 1 attempt for 400 Bad Request, got %d", attempts)
	}
}

func TestSendScanCompleteWebhook(t *testing.T) {
	var receivedPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := notify.New(&config.NotificationConfig{
		Enabled:    true,
		WebhookURL: server.URL,
	})
	n.SetClient(server.Client())

	scanComplete := notify.ScanComplete{
		Target:   "example.com",
		ScanID:   42,
		Duration: 5 * time.Minute,
		Stats:    map[string]int{"subdomains": 10},
	}

	err := n.SendScanComplete(scanComplete)
	if err != nil {
		t.Fatalf("SendScanComplete failed: %v", err)
	}

	if receivedPayload == nil {
		t.Fatal("expected webhook payload, got nil")
	}

	if receivedPayload["event"] != "scan_complete" {
		t.Errorf("expected event 'scan_complete', got %v", receivedPayload["event"])
	}

	scanMap, ok := receivedPayload["scan"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'scan' key in payload, got: %v", receivedPayload)
	}

	if scanMap["target"] != "example.com" {
		t.Errorf("expected target 'example.com', got %v", scanMap["target"])
	}

	if int64(scanMap["scan_id"].(float64)) != 42 {
		t.Errorf("expected scan_id 42, got %v", scanMap["scan_id"])
	}
}
