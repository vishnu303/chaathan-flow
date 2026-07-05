package progress

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTrackerSequentialCounts(t *testing.T) {
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	tracker := NewTracker(5)
	tracker.Start("subfinder")
	tracker.Complete("subfinder")
	tracker.Start("amass")
	tracker.Fail("amass", "api key missing")
	tracker.Skip("assetfinder")

	w.Close()
	os.Stdout = oldStdout

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
	r, w, _ := os.Pipe()
	os.Stdout = w

	cjkDetail := "这是一个非常非常非常非常非常非常非常非常非常非常非常非常非常非常非常长的测试字符串包含多字节字符用于验证截断"
	
	ItemFail("test-item", cjkDetail)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = oldStdout

	output := buf.String()
	if !strings.Contains(output, "...") {
		t.Errorf("expected output to be truncated and contain '...', got %q", output)
	}
}

func TestStopSpinnerCleansLine(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	tracker := NewTracker(2)
	tracker.RunSpinner()
	time.Sleep(100 * time.Millisecond)
	tracker.StopSpinner()

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stdout = oldStdout

	output := buf.String()
	if !strings.Contains(output, ClearLn) {
		t.Errorf("expected stdout to be cleared with ClearLn sequence, got %q", output)
	}
}
