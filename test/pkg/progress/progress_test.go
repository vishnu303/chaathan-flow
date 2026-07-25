package progress_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/progress"
)

func TestProgressHelpers(t *testing.T) {
	// Simple tests to make sure display helpers don't crash
	progress.Header("Setup Tools")
	progress.Section("System Tools", "Checking path dependencies")
	progress.ItemOK("go")
	progress.ItemFail("massdns", "binary not found")
	progress.ItemPending("python3")
	progress.ItemInfo("Using BlackArch repositories")
	progress.Summary(1, 0, 1, 15*time.Second)
	progress.Tip("Add ~/.local/bin to PATH")
}

func TestProgressTracker(t *testing.T) {
	tracker := progress.NewTracker(3)
	if tracker == nil {
		t.Fatal("expected NewTracker to return non-nil")
	}

	tracker.Start("nuclei")
	tracker.Start("subfinder")

	tracker.Complete("subfinder")
	tracker.Fail("nuclei", "failed to extract package")
	tracker.Skip("assetfinder")

	installed, skipped, failed := tracker.Stats()
	if installed != 1 {
		t.Errorf("expected 1 installed, got %d", installed)
	}
	if skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", skipped)
	}
	if failed != 1 {
		t.Errorf("expected 1 failed, got %d", failed)
	}

	// Spinner tests
	tracker.RunSpinner()
	time.Sleep(100 * time.Millisecond)
	tracker.StopSpinner()
}

func TestTrackerSequentialCounts(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	tracker := progress.NewTracker(5)
	tracker.Start("subfinder")
	tracker.Complete("subfinder")
	tracker.Start("amass")
	tracker.Fail("amass", "api key missing")
	tracker.Skip("assetfinder")

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	os.Stdout = oldStdout
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("drain pipe: %v", err)
	}

	completed, skipped, failed := tracker.Stats()
	if completed != 1 {
		t.Errorf("expected completed=1, got %d", completed)
	}
	if failed != 1 {
		t.Errorf("expected failed=1, got %d", failed)
	}
	if skipped != 1 {
		t.Errorf("expected skipped=1, got %d", skipped)
	}
}

func TestItemFailMultibyteTruncation(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	cjkDetail := "这是一个非常非常非常非常非常非常非常非常非常非常非常非常非常非常非常长的测试字符串包含 multi-byte 字符用于验证截断"

	progress.ItemFail("test-item", cjkDetail)

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("drain pipe: %v", err)
	}
	os.Stdout = oldStdout

	output := buf.String()
	if !strings.Contains(output, "...") {
		t.Errorf("expected output to be truncated and contain '...', got %q", output)
	}
}

func TestStopSpinnerCleansLine(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	tracker := progress.NewTracker(2)
	tracker.RunSpinner()
	time.Sleep(100 * time.Millisecond)
	tracker.StopSpinner()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("drain pipe: %v", err)
	}
	os.Stdout = oldStdout

	output := buf.String()
	if !strings.Contains(output, progress.TestClearLn) {
		t.Errorf("expected stdout to be cleared with ClearLn sequence, got %q", output)
	}
}

func TestStopSpinnerWithoutRun(t *testing.T) {
	// Must return promptly: no goroutine was started, and the once-guard
	// makes a second stop a no-op instead of a panic.
	tracker := progress.NewTracker(1)
	tracker.StopSpinner()
	tracker.StopSpinner()
}
