package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSmartStepHeaderIncrement(t *testing.T) {
	InitScanUI(23)

	// 1. First step call: increments to 1
	StepHeader("Step 1: Passive Recon")
	if currentStep != 1 {
		t.Errorf("expected step 1, got %d", currentStep)
	}

	// 2. Second step call (different step): increments to 2
	StepHeader("Step 2: Active Subdomain Enumeration (Amass)")
	if currentStep != 2 {
		t.Errorf("expected step 2, got %d", currentStep)
	}

	// 3. Skip call for same step: should NOT increment (stays at 2)
	StepHeader("Step 2: Skipping Amass (--skip-amass)")
	if currentStep != 2 {
		t.Errorf("expected step 2 to remain, got %d", currentStep)
	}

	// 4. Next step (different step): increments to 3
	StepHeader("Step 3: GitHub Subdomain Discovery")
	if currentStep != 3 {
		t.Errorf("expected step 3, got %d", currentStep)
	}

	// 5. Alternate/skip call for same step: should NOT increment (stays at 3)
	StepHeader("Step 3: Skipping GitHub Recon (no token provided)")
	if currentStep != 3 {
		t.Errorf("expected step 3 to remain, got %d", currentStep)
	}

	// 6. Non-step prefix call: should increment (since prefix is "")
	StepHeader("Some random header")
	if currentStep != 4 {
		t.Errorf("expected step 4, got %d", currentStep)
	}
}

func TestStepHeaderConcurrent(t *testing.T) {
	InitScanUI(100)

	var wg sync.WaitGroup
	numWorkers := 10
	numCalls := 10

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < numCalls; j++ {
				StepHeader("Step %d: Worker %d Run %d", workerID*numCalls+j, workerID, j)
			}
		}(i)
	}

	wg.Wait()

	scanUIMu.Lock()
	finalStep := currentStep
	scanUIMu.Unlock()

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
	if err := InitFileLog(logPath); err != nil {
		t.Fatalf("failed to init log file: %v", err)
	}
	defer CloseFileLog()

	ansiStr := "\033[31mRed Bold Text\033[0m"
	logWrite(io.Discard, ansiStr)

	CloseFileLog()

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
		got := FmtDuration(tt.d)
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
		got := fmtElapsed(tt.d)
		if got != tt.expected {
			t.Errorf("fmtElapsed(%v) = %q, want %q", tt.d, got, tt.expected)
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
	if err := InitFileLog(logPath); err != nil {
		t.Fatalf("failed to init log: %v", err)
	}
	defer CloseFileLog()

	var sb strings.Builder
	for i := 1; i <= 50; i++ {
		sb.WriteString(fmt.Sprintf("Error line %d\n", i))
	}

	LogToolFailure("test_tool", "run command", sb.String(), nil)
	CloseFileLog()

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
