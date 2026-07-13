package setup_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/setup"
)

func TestContainsWord(t *testing.T) {
	tests := []struct {
		s        string
		word     string
		expected bool
	}{
		{"ubuntu debian arch", "debian", true},
		{"ubuntu debian arch", "debi", false},
		{"ubuntu debian arch", "ubuntu", true},
		{"ubuntu debian arch", "centos", false},
		{"  debian   ", "debian", true},
	}

	for _, tt := range tests {
		got := setup.ContainsWord(tt.s, tt.word)
		if got != tt.expected {
			t.Errorf("ContainsWord(%q, %q) = %v, want %v", tt.s, tt.word, got, tt.expected)
		}
	}
}

func TestPathListContains(t *testing.T) {
	tests := []struct {
		list     string
		dir      string
		expected bool
	}{
		{"/usr/bin:/bin:/usr/local/bin", "/usr/bin", true},
		{"/usr/bin:/bin:/usr/local/bin", "/usr/local/bin", true},
		{"/usr/bin:/bin:/usr/local/bin", "/bin", true},
		{"/usr/bin:/bin:/usr/local/bin", "/usr/bin/../bin", true},
		{"/usr/binbackup:/bin:/usr/local/bin", "/usr/bin", false},
		{"/usr/bin:/bin:/usr/local/bin", "/usr/binbackup", false},
	}

	for _, tt := range tests {
		list := strings.ReplaceAll(tt.list, ":", string(os.PathListSeparator))
		dir := tt.dir
		got := setup.PathListContains(list, dir)
		if got != tt.expected {
			t.Errorf("PathListContains(%q, %q) = %v, want %v", list, dir, got, tt.expected)
		}
	}
}

func TestAppendLinesToFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "chaathan_prereq_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "test_config")

	initialContent := "line1\nline2\n"
	err = os.WriteFile(filePath, []byte(initialContent), 0644)
	if err != nil {
		t.Fatalf("failed to write initial file: %v", err)
	}

	comment := "# test comment"
	lines := []string{"line3", "line4"}

	added, err := setup.AppendLinesToFile(filePath, lines, comment)
	if err != nil {
		t.Fatalf("AppendLinesToFile first run failed: %v", err)
	}
	if !added {
		t.Error("expected added = true on first run, got false")
	}

	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	content := string(contentBytes)
	if !strings.Contains(content, "line3") || !strings.Contains(content, "line4") || !strings.Contains(content, comment) {
		t.Errorf("file content missing expected appended lines: %s", content)
	}

	addedSecond, err := setup.AppendLinesToFile(filePath, lines, comment)
	if err != nil {
		t.Fatalf("AppendLinesToFile second run failed: %v", err)
	}
	if addedSecond {
		t.Error("expected added = false on second run (idempotency check), got true")
	}

	contentBytesSecond, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	contentSecond := string(contentBytesSecond)
	if contentSecond != content {
		t.Errorf("file content changed on second run: %s", contentSecond)
	}
}
