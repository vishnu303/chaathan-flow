package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
)

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
		n := New(cfg)
		if got := n.ShouldNotify(tt.findingSev); got != tt.want {
			t.Errorf("ShouldNotify(min=%s, finding=%s) = %v, want %v", tt.minSeverity, tt.findingSev, got, tt.want)
		}
	}
}

func TestEscapeMarkdown(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello_world", "hello\\_world"},
		{"hello*world", "hello\\*world"},
		{"hello.world", "hello\\.world"},
		{"hello!world", "hello\\!world"},
		{"[hello](world)", "\\[hello\\]\\(world\\)"},
	}

	for _, tt := range tests {
		got := telegramEscaper.Replace(tt.input)
		if got != tt.want {
			t.Errorf("telegramEscaper.Replace(%q) = %q, want %q", tt.input, got, tt.want)
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

	n := New(&config.NotificationConfig{Enabled: true})
	n.client = server.Client() // use mock client

	err := n.postJSON(server.URL, map[string]string{"foo": "bar"})
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

	n := New(&config.NotificationConfig{Enabled: true})
	n.client = server.Client()

	err := n.postJSON(server.URL, map[string]string{"foo": "bar"})
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

	n := New(&config.NotificationConfig{
		Enabled:    true,
		WebhookURL: server.URL,
	})
	n.client = server.Client()

	scanComplete := ScanComplete{
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
