package logger_test

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vishnu303/chaathan/pkg/logger"
)

func TestSmartStepHeaderIncrement(t *testing.T) {
	logger.InitScanUI(23)

	// 1. First step call: increments to 1
	logger.StepHeader("Step 1: Passive Recon")
	if logger.GetCurrentStep() != 1 {
		t.Errorf("expected step 1, got %d", logger.GetCurrentStep())
	}

	// 2. Second step call (different step): increments to 2
	logger.StepHeader("Step 2: Active Subdomain Enumeration (Amass)")
	if logger.GetCurrentStep() != 2 {
		t.Errorf("expected step 2, got %d", logger.GetCurrentStep())
	}

	// 3. Skip call for same step: should NOT increment (stays at 2)
	logger.StepHeader("Step 2: Skipping Amass (--skip-amass)")
	if logger.GetCurrentStep() != 2 {
		t.Errorf("expected step 2 to remain, got %d", logger.GetCurrentStep())
	}

	// 4. Next step (different step): increments to 3
	logger.StepHeader("Step 3: GitHub Subdomain Discovery")
	if logger.GetCurrentStep() != 3 {
		t.Errorf("expected step 3, got %d", logger.GetCurrentStep())
	}

	// 5. Alternate/skip call for same step: should NOT increment (stays at 3)
	logger.StepHeader("Step 3: Skipping GitHub Recon (no token provided)")
	if logger.GetCurrentStep() != 3 {
		t.Errorf("expected step 3 to remain, got %d", logger.GetCurrentStep())
	}

	// 6. Non-step prefix call: should increment (since prefix is "")
	logger.StepHeader("Some random header")
	if logger.GetCurrentStep() != 4 {
		t.Errorf("expected step 4, got %d", logger.GetCurrentStep())
	}
}

func TestStepHeaderConcurrent(t *testing.T) {
	logger.InitScanUI(100)

	var wg sync.WaitGroup
	numWorkers := 10
	numCalls := 10

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < numCalls; j++ {
				logger.StepHeader("Step %d: Worker %d Run %d", workerID*numCalls+j, workerID, j)
			}
		}(i)
	}

	wg.Wait()

	finalStep := logger.GetCurrentStep()

	if finalStep <= 0 {
		t.Errorf("expected final step count > 0, got %d", finalStep)
	}
}

func TestLogWriteStripsANSI(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "chaathan_logger_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logPath := filepath.Join(tempDir, "test.log")
	if err := logger.InitFileLog(logPath); err != nil {
		t.Fatalf("failed to init log file: %v", err)
	}
	defer logger.CloseFileLog()

	ansiStr := "\033[31mRed Bold Text\033[0m"
	logger.LogWrite(io.Discard, ansiStr)

	logger.CloseFileLog()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	contentStr := string(content)
	if strings.Contains(contentStr, "\x1b[") || strings.Contains(contentStr, "\033") {
		t.Errorf("log file contains ANSI escape sequences: %q", contentStr)
	}

	if !strings.Contains(contentStr, "Red Bold Text") {
		t.Errorf("expected text 'Red Bold Text' in log file, got: %q", contentStr)
	}
}

func TestFmtDurationAndElapsed(t *testing.T) {
	tests := []struct {
		d        time.Duration
		expected string
	}{
		{0, "0s"},
		{5 * time.Second, "5s"},
		{5*time.Minute + 4*time.Second, "5m04s"},
		{1*time.Hour + 2*time.Minute + 3*time.Second, "1h02m03s"},
	}

	for _, tt := range tests {
		got := logger.FmtDuration(tt.d)
		if got != tt.expected {
			t.Errorf("FmtDuration(%v) = %q, want %q", tt.d, got, tt.expected)
		}
	}

	elapsedTests := []struct {
		d        time.Duration
		expected string
	}{
		{5 * time.Second, "[5s]"},
		{5*time.Minute + 4*time.Second, "[5m04s]"},
	}

	for _, tt := range elapsedTests {
		got := logger.FmtElapsed(tt.d)
		if got != tt.expected {
			t.Errorf("FmtElapsed(%v) = %q, want %q", tt.d, got, tt.expected)
		}
	}
}

func TestLogToolFailureTruncation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "chaathan_logger_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logPath := filepath.Join(tempDir, "failure.log")
	if err := logger.InitFileLog(logPath); err != nil {
		t.Fatalf("failed to init log: %v", err)
	}
	defer logger.CloseFileLog()

	var sb strings.Builder
	for i := 1; i <= 50; i++ {
		sb.WriteString(fmt.Sprintf("Error line %d\n", i))
	}

	logger.LogToolFailure("test_tool", "run command", sb.String(), nil)
	logger.CloseFileLog()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")

	errLineCount := 0
	for _, l := range lines {
		if strings.Contains(l, "Error line") {
			errLineCount++
		}
	}

	if errLineCount != 30 {
		t.Errorf("expected exactly 30 lines of stderr in log, got %d", errLineCount)
	}

	if !strings.Contains(contentStr, "... (20 more lines truncated)") {
		t.Error("expected truncation message in log file, not found")
	}
}

// ── Shared UI primitive tests ─────────────────────────────────────────

var ansiStripRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string {
	return ansiStripRE.ReplaceAllString(s, "")
}

func TestBarGlyphsAndClamping(t *testing.T) {
	tests := []struct {
		pct       float64
		width     int
		wantFill  int
		wantWidth int
	}{
		{0, 10, 0, 10},
		{50, 10, 5, 10},
		{100, 10, 10, 10},
		{-20, 10, 0, 10},  // clamped low
		{150, 10, 10, 10}, // clamped high
		{50, 0, 5, 10},    // non-positive width defaults to 10
	}

	for _, tt := range tests {
		bar := stripANSI(logger.Bar(tt.pct, tt.width))
		if got := strings.Count(bar, "▰"); got != tt.wantFill {
			t.Errorf("Bar(%v, %d): got %d filled glyphs, want %d (%q)", tt.pct, tt.width, got, tt.wantFill, bar)
		}
		if got := utf8.RuneCountInString(bar); got != tt.wantWidth {
			t.Errorf("Bar(%v, %d): visible width %d, want %d", tt.pct, tt.width, got, tt.wantWidth)
		}
	}
}

func TestTableHeaderAndRow(t *testing.T) {
	var sb strings.Builder
	logger.TableHeader(&sb, "id", "Target", "STATUS")
	logger.TableRow(&sb, "1", "example.com", "completed")

	lines := strings.Split(strings.TrimRight(stripANSI(sb.String()), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), lines)
	}
	if lines[0] != "ID\tTARGET\tSTATUS" {
		t.Errorf("header not uppercased/tab-joined: %q", lines[0])
	}
	if lines[1] != "──\t──────\t──────" {
		t.Errorf("dash underline mismatch: %q", lines[1])
	}
	if lines[2] != "1\texample.com\tcompleted" {
		t.Errorf("row mismatch: %q", lines[2])
	}
}

func TestBoxAlignment(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "chaathan_logger_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logPath := filepath.Join(tempDir, "box.log")
	if err := logger.InitFileLog(logPath); err != nil {
		t.Fatalf("failed to init log file: %v", err)
	}
	defer logger.CloseFileLog()

	logger.Box("Test Title", []string{
		"plain line",
		logger.BrightGreen + "colored line" + logger.Reset,
	})
	logger.CloseFileLog()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	// File log is ANSI-stripped but prefixes each line with "[HH:MM:SS] ".
	tsRE := regexp.MustCompile(`(?m)^\[\d{2}:\d{2}:\d{2}\] `)
	plain := tsRE.ReplaceAllString(string(content), "")
	lines := strings.Split(strings.Trim(plain, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 box lines (2 borders + title + 2 content), got %d: %q", len(lines), lines)
	}

	width := utf8.RuneCountInString(lines[0])
	for i, l := range lines {
		if got := utf8.RuneCountInString(l); got != width {
			t.Errorf("box line %d has visible width %d, want %d: %q", i, got, width, l)
		}
	}

	if !strings.Contains(lines[1], "Test Title") {
		t.Errorf("title missing from box: %q", lines[1])
	}
	if !strings.Contains(lines[3], "colored line") {
		t.Errorf("colored content missing (ANSI should be stripped in log): %q", lines[3])
	}
}
