package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

// ── File-log tee ─────────────────────────────────────────────────────────────

type logWriter interface {
	io.WriteCloser
	Sync() error
}

type sizeTrackingWriter struct {
	w            *os.File
	bytesWritten int64
	warned100MB  bool
	stopped500MB bool
}

func (s *sizeTrackingWriter) Write(p []byte) (n int, err error) {
	if s.bytesWritten >= 500*1024*1024 {
		if !s.stopped500MB {
			s.stopped500MB = true
			ts := time.Now().Format("15:04:05")
			_, _ = s.w.Write([]byte(fmt.Sprintf("[%s] DEBUG Log file size exceeded 500MB. Mirroring stopped.\n", ts)))
		}
		return len(p), nil
	}

	n, err = s.w.Write(p)
	s.bytesWritten += int64(n)

	if s.bytesWritten >= 100*1024*1024 && !s.warned100MB {
		s.warned100MB = true
		ts := time.Now().Format("15:04:05")
		_, _ = s.w.Write([]byte(fmt.Sprintf("[%s] DEBUG [WARN] Log file size has exceeded 100MB.\n", ts)))
	}

	return n, err
}

func (s *sizeTrackingWriter) Close() error {
	return s.w.Close()
}

func (s *sizeTrackingWriter) Sync() error {
	return s.w.Sync()
}

var (
	logFileMu sync.Mutex
	logFile   logWriter
)

// ansiRE strips ANSI escape sequences so log files are readable plain text.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// InitFileLog opens (or creates) the file at path and begins mirroring all
// logger output to it with ANSI codes stripped. Call CloseFileLog() to flush
// and close when the scan ends.
func InitFileLog(path string) error {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFile != nil {
		_ = logFile.Sync()
		logFile.Close()
		logFile = nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create log directory %q: %w", dir, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("cannot open log file %q: %w", path, err)
	}
	logFile = &sizeTrackingWriter{w: f}
	return nil
}

// CloseFileLog flushes and closes the active log file.
func CloseFileLog() {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFile != nil {
		_ = logFile.Sync()
		logFile.Close()
		logFile = nil
	}
}

var (
	isTTYOnce sync.Once
	isTTY     bool
)

// logWrite writes to stdout and, if a log file is open, to the file with
// ANSI codes stripped and a [HH:MM:SS] timestamp prefixed to each non-empty line.
func logWrite(w io.Writer, s string) {
	isTTYOnce.Do(func() {
		isTTY = term.IsTerminal(int(os.Stdout.Fd()))
	})

	out := s
	if w == os.Stdout && !isTTY {
		out = ansiRE.ReplaceAllString(s, "")
	}
	fmt.Fprint(w, out)

	// Prepare the formatted string outside the critical section to minimize lock hold time.
	clean := ansiRE.ReplaceAllString(s, "")
	ts := time.Now().Format("15:04:05")
	lines := strings.Split(clean, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = "[" + ts + "] " + line
		}
	}
	formatted := strings.Join(lines, "\n")

	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFile != nil {
		fmt.Fprint(logFile, formatted)
	}
}

// WriteLogHeader writes a structured header to the open log file.
// Call this immediately after InitFileLog. It writes directly to the file
// (not through logWrite) so the header is not timestamped as a regular line.
func WriteLogHeader(domain string, scanID int64, logFilePath string) {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFile == nil {
		return
	}
	now := time.Now().Format(time.RFC3339)
	fmt.Fprintf(logFile, "=== Chaathan Wildcard Scan Log ===\n")
	fmt.Fprintf(logFile, "Domain:   %s\n", domain)
	if scanID > 0 {
		fmt.Fprintf(logFile, "Scan ID:  %d\n", scanID)
	}
	fmt.Fprintf(logFile, "Started:  %s\n", now)
	fmt.Fprintf(logFile, "Log file: %s\n", logFilePath)
	fmt.Fprintf(logFile, "===================================\n\n")
}

// LogCommand writes the exact command invocation to the log file only.
// Call this from the runner regardless of verbose mode so the log always
// captures what was run. The terminal is not affected.
func LogCommand(cmd string) {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFile == nil {
		return
	}
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(logFile, "[%s]   $ %s\n", ts, cmd)
}

// LogToolFailure writes a structured tool failure block to the log file only.
// Call this from the runner when a tool exits with an error. The terminal
// still shows only the existing logger.Warning/Error messages.
// Stderr is truncated to 30 lines to avoid log noise from tools that
// emit excessive repetitive output (e.g. Nuclei HTTP/2 warnings).
func LogToolFailure(tool, command, stderr string, exitErr error) {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFile == nil {
		return
	}
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(logFile, "[%s] TOOL ERROR: %s\n", ts, tool)
	fmt.Fprintf(logFile, "[%s]   Command: %s\n", ts, command)
	if exitErr != nil {
		fmt.Fprintf(logFile, "[%s]   Exit:    %v\n", ts, exitErr)
	}
	if stderr != "" {
		lines := strings.Split(strings.TrimSpace(stderr), "\n")
		totalLines := len(lines)
		const maxStderrLines = 30
		truncated := totalLines > maxStderrLines
		if truncated {
			lines = lines[:maxStderrLines]
		}
		fmt.Fprintf(logFile, "[%s]   Stderr:\n", ts)
		for _, line := range lines {
			fmt.Fprintf(logFile, "[%s]     %s\n", ts, line)
		}
		if truncated {
			fmt.Fprintf(logFile, "[%s]     ... (%d more lines truncated)\n", ts, totalLines-maxStderrLines)
		}
	}
	fmt.Fprintf(logFile, "\n")
}

// LogToolSkipped writes a structured skip entry to the log file only.
// Call this instead of LogToolFailure when the tool was cancelled by user
// skip request, to distinguish intentional skips from real errors.
func LogToolSkipped(tool, command string) {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFile == nil {
		return
	}
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(logFile, "[%s] TOOL SKIPPED: %s\n", ts, tool)
	fmt.Fprintf(logFile, "[%s]   Command: %s\n", ts, command)
	fmt.Fprintf(logFile, "\n")
}
// FileDebug writes a debug-level line to the log file only.
// It never prints to the terminal, making it safe to use for verbose internal
// state (file sizes, skip decisions, pipeline counts) without adding noise.
func FileDebug(format string, args ...any) {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFile == nil {
		return
	}
	ts := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(logFile, "[%s] DEBUG %s\n", ts, msg)
}



const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Italic    = "\033[3m"
	Underline = "\033[4m"

	// Standard colors
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	Gray   = "\033[37m"
	White  = "\033[97m"

	// Bright colors
	BrightRed    = "\033[91m"
	BrightGreen  = "\033[92m"
	BrightYellow = "\033[93m"
	BrightBlue   = "\033[94m"
	BrightPurple = "\033[95m"
	BrightCyan   = "\033[96m"

	// Background
	BgRed    = "\033[41m"
	BgGreen  = "\033[42m"
	BgYellow = "\033[43m"
	BgBlue   = "\033[44m"
	BgCyan   = "\033[46m"
)

// ── Scan step tracking ──────────────────────────────────────────────────────

var (
	scanUIMu       sync.Mutex
	currentStep    int
	totalSteps     int
	scanStartTime  time.Time
	lastStepPrefix string
)

// InitScanUI initializes the scan UI with the total number of steps.
func InitScanUI(total int) {
	scanUIMu.Lock()
	defer scanUIMu.Unlock()
	currentStep = 0
	totalSteps = total
	scanStartTime = time.Now()
	lastStepPrefix = ""
}

// ── Primary output functions ────────────────────────────────────────────────

// Info prints a styled info message
func Info(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s %s\n", Dim, Reset, msg))
}

// Success prints a styled success message
func Success(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s %s✓%s %s\n", Dim, Reset, BrightGreen, Reset, msg))
}

// Warning prints a styled warning message
func Warning(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s %s⚠%s %s\n", Dim, Reset, BrightYellow, Reset, msg))
}

// Error prints a styled error message
func Error(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s %s✗%s %s%s%s\n", Dim, Reset, BrightRed, Reset, Red, msg, Reset))
}

// Debug prints a styled debug message (only visible contextually)
func Debug(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s│  %s%s\n", Dim, msg, Reset))
}

// Section prints a generic section heading without incrementing the step counter.
// Use this in non-scan commands (status, diff, export, delete, query, etc.)
// that don't participate in the step-tracking workflow.
func Section(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("\n  %s┌─%s %s%s%s%s\n", Cyan, Reset, BrightCyan+Bold, msg, Reset, ""))
}

// StepHeader prints a scan-step heading that increments the step counter
// and shows elapsed time. Use this only in scan workflow phases.
func StepHeader(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	// Extract the step identifier prefix (e.g. "Step 2" or "Proxy Scraping")
	var prefix string
	if strings.HasPrefix(msg, "Step ") {
		parts := strings.SplitN(msg, ":", 2)
		if len(parts) > 0 {
			prefix = parts[0]
		}
	} else if strings.HasPrefix(msg, "Proxy Scraping") {
		prefix = "Proxy Scraping"
	}

	scanUIMu.Lock()
	if prefix == "" || prefix != lastStepPrefix {
		currentStep++
		if prefix != "" {
			lastStepPrefix = prefix
		}
	}

	current := currentStep
	total := totalSteps
	start := scanStartTime
	scanUIMu.Unlock()

	elapsed := ""
	if !start.IsZero() {
		elapsed = fmt.Sprintf(" %s%s%s", Dim, fmtElapsed(time.Since(start)), Reset)
	}

	stepIndicator := ""
	if total > 0 {
		stepIndicator = fmt.Sprintf("%s[%d/%d]%s ", Dim, current, total, Reset)
	}

	logWrite(os.Stdout, fmt.Sprintf("\n  %s┌─%s %s%s%s%s%s%s\n", Cyan, Reset, stepIndicator, BrightCyan+Bold, msg, Reset, elapsed, ""))
}

// ScanHeader prints the main scan workflow header
func ScanHeader(scanType string, target string, scanID int64) {
	w := 52
	line := strings.Repeat("─", w)

	logWrite(os.Stdout, "\n")
	logWrite(os.Stdout, fmt.Sprintf("  %s╭%s╮%s\n", Cyan+Bold, line, Reset))
	
	scanTypeRunes := utf8.RuneCountInString(scanType + " Scan")
	padScanType := 46 - scanTypeRunes
	if padScanType < 0 {
		padScanType = 0
	}
	scanTypeStr := scanType + " Scan" + strings.Repeat(" ", padScanType)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s  🔍 %s%s%s %s│%s\n", Cyan+Bold, Reset, White+Bold, scanTypeStr, Reset, Cyan+Bold, Reset))

	targetRunes := utf8.RuneCountInString(target)
	padTarget := 38 - targetRunes
	if padTarget < 0 {
		padTarget = 0
	}
	targetStr := target + strings.Repeat(" ", padTarget)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s  %s🎯 Target:%s %s %s│%s\n", Cyan+Bold, Reset, Dim, Reset, targetStr, Cyan+Bold, Reset))

	if scanID > 0 {
		scanIDStr := fmt.Sprintf("%d", scanID)
		scanIDRunes := utf8.RuneCountInString(scanIDStr)
		padScanID := 37 - scanIDRunes
		if padScanID < 0 {
			padScanID = 0
		}
		scanIDText := scanIDStr + strings.Repeat(" ", padScanID)
		logWrite(os.Stdout, fmt.Sprintf("  %s│%s  %s🆔 Scan ID:%s %s %s│%s\n", Cyan+Bold, Reset, Dim, Reset, scanIDText, Cyan+Bold, Reset))
	}
	logWrite(os.Stdout, fmt.Sprintf("  %s╰%s╯%s\n", Cyan+Bold, line, Reset))
	logWrite(os.Stdout, "\n")
}

// SubStep prints an indented sub-step with arrow
func SubStep(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s   %s▸%s %s\n", Dim, Reset, Purple, Reset, msg))
}

// Command prints the command being executed
func Command(cmd string) {
	logWrite(os.Stdout, fmt.Sprintf("  %s│     $ %s%s\n", Dim, cmd, Reset))
}

// ── Summary helpers ─────────────────────────────────────────────────────────

// ScanSummary prints a modern scan completion summary
func ScanSummary(status string, target string, scanID int64, duration time.Duration, stats map[string]string) {
	w := 52
	line := strings.Repeat("─", w)

	statusIcon := "✓"
	statusColor := BrightGreen
	switch status {
	case "cancelled":
		statusIcon = "⚠"
		statusColor = BrightYellow
	case "failed":
		statusIcon = "✗"
		statusColor = BrightRed
	}

	logWrite(os.Stdout, "\n")
	logWrite(os.Stdout, fmt.Sprintf("  %s╭%s╮%s\n", Cyan+Bold, line, Reset))

	statusStr := capitalize(status)
	pad1 := w - 2 - 1 - 6 - utf8.RuneCountInString(statusStr) // '  ' (2), statusIcon (1), ' Scan ' (6)
	if pad1 < 0 {
		pad1 = 0
	}
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s  %s%s%s %sScan %s%s%s%s│%s\n",
		Cyan+Bold, Reset, statusColor+Bold, statusIcon, Reset,
		White+Bold, statusStr, Reset,
		strings.Repeat(" ", pad1), Cyan+Bold, Reset))

	pad2 := w - 5 - utf8.RuneCountInString(target)
	if pad2 < 0 {
		pad2 = 0
	}
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s  %s🎯 %s%s%s%s│%s\n", Cyan+Bold, Reset, Dim, target, Reset, strings.Repeat(" ", pad2), Cyan+Bold, Reset))

	durStr := FmtDuration(duration)
	pad3 := w - 6 - utf8.RuneCountInString(durStr) // '  ' (2) + '⏱  ' (4)
	if pad3 < 0 {
		pad3 = 0
	}
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s  %s⏱  %s%s%s%s│%s\n", Cyan+Bold, Reset, Dim, durStr, Reset, strings.Repeat(" ", pad3), Cyan+Bold, Reset))

	if len(stats) > 0 {
		logWrite(os.Stdout, fmt.Sprintf("  %s│%s  %s%s%s%s│%s\n", Cyan+Bold, Reset, Dim, strings.Repeat("╌", w-2), Reset, Cyan+Bold, Reset))
		for label, value := range stats {
			used := 2 + utf8.RuneCountInString(label) + 1 + utf8.RuneCountInString(value)
			padding := w - used
			if padding < 1 {
				padding = 1
			}
			logWrite(os.Stdout, fmt.Sprintf("  %s│%s  %s%s%s %s%s%s%s %s│%s\n",
				Cyan+Bold, Reset,
				Dim, label+":", Reset,
				BrightCyan+Bold, value, Reset,
				strings.Repeat(" ", padding-1),
				Cyan+Bold, Reset))
		}
	}

	logWrite(os.Stdout, fmt.Sprintf("  %s╰%s╯%s\n", Cyan+Bold, line, Reset))
}

// NextSteps prints styled next step hints
func NextSteps(hints []string) {
	if len(hints) == 0 {
		return
	}
	logWrite(os.Stdout, fmt.Sprintf("\n  %s💡 Next steps:%s\n", Dim, Reset))
	for _, h := range hints {
		logWrite(os.Stdout, fmt.Sprintf("     %s▸%s %s%s%s\n", Purple, Reset, Dim, h, Reset))
	}
	logWrite(os.Stdout, "\n")
}

// ── Utility ─────────────────────────────────────────────────────────────────

// capitalize returns the string with the first letter uppercased.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func fmtElapsed(d time.Duration) string {
	d = d.Round(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("[%dm%02ds]", m, s)
	}
	return fmt.Sprintf("[%ds]", s)
}

// FmtDuration formats a duration into a readable string (e.g. 1h02m03s, 2m05s, 5s).
func FmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
