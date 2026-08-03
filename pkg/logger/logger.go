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
		_ = logFile.Close()
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
		_ = logFile.Close()
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

	// Cheap check first: skip the file-log rendering work entirely when no
	// log file is active (the common case for non-scan commands).
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if logFile == nil {
		return
	}

	clean := ansiRE.ReplaceAllString(s, "")
	ts := time.Now().Format("15:04:05")
	lines := strings.Split(clean, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = "[" + ts + "] " + line
		}
	}
	fmt.Fprint(logFile, strings.Join(lines, "\n"))
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

		// Optional: strip nuclei stats logs from stderr
		if strings.Contains(strings.ToLower(tool), "nuclei") {
			var filtered []string
			for _, line := range lines {
				if !strings.Contains(line, `{"duration":`) {
					filtered = append(filtered, line)
				}
			}
			lines = filtered
		}

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

// ── Scan step tracking ──────────────────────────────────────────────────────

var (
	scanUIMu       sync.Mutex
	currentStep    int
	totalSteps     int
	lastStepPrefix string
	stepStartTime  time.Time // when the current step header was printed
)

// InitScanUI initializes the scan UI with the total number of steps.
func InitScanUI(total int) {
	scanUIMu.Lock()
	defer scanUIMu.Unlock()
	currentStep = 0
	totalSteps = total
	lastStepPrefix = ""
	stepStartTime = time.Time{}
}

// ── Primary output functions ────────────────────────────────────────────────

// Print writes a raw formatted message to stdout and mirrors it to the file
// log (ANSI-stripped, timestamped). It adds no styling of its own — use it
// for output that is already fully formatted (e.g. the progress package).
func Print(format string, args ...any) {
	logWrite(os.Stdout, fmt.Sprintf(format, args...))
}

// Info prints a styled info message
func Info(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s   %s\n", Dim, Reset, msg))
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

// Skip prints a user-initiated tool skip notice. Rendered calmer than
// Warning (dim text, single ⊘ marker) because skipping is an intentional
// user action, not a problem.
func Skip(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s %s⊘%s %s%s%s\n", Dim, Reset, BrightYellow, Reset, Dim, msg, Reset))
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
	logWrite(os.Stdout, fmt.Sprintf("\n  %s┌─%s %s%s%s\n", Cyan, Reset, BrightCyan+Bold, msg, Reset))
}

// StepHeader prints a scan-step heading that increments the step counter,
// shows a mini progress bar, and displays the previous step's duration.
// Use this only in scan workflow phases.
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
	isNewStep := prefix == "" || prefix != lastStepPrefix
	if isNewStep {
		currentStep++
		if prefix != "" {
			lastStepPrefix = prefix
		}
	}

	current := currentStep
	total := totalSteps

	// Per-step duration: show how long the previous step took.
	var prevDur string
	if isNewStep && !stepStartTime.IsZero() {
		prevDur = fmtElapsed(time.Since(stepStartTime))
	}
	if isNewStep {
		stepStartTime = time.Now()
	}
	scanUIMu.Unlock()

	// Mini progress bar (10 segments)
	var bar string
	if total > 0 {
		pct := stepPct(current, total)
		filled := pct / 10
		bar = BrightGreen + strings.Repeat("▰", filled) + Dim + strings.Repeat("▱", 10-filled) + Reset
		bar = fmt.Sprintf(" %s %s%d%%%s", bar, Dim, pct, Reset)
	}

	// Counter
	counter := ""
	if total > 0 {
		counter = fmt.Sprintf(" %s%d%s/%d", Bold, current, Reset, total)
	}

	// Previous step duration
	durStr := ""
	if prevDur != "" {
		durStr = fmt.Sprintf("  %s%s%s", Dim, prevDur, Reset)
	}

	logWrite(os.Stdout, fmt.Sprintf("\n  %s┌─%s%s%s ─ %s%s%s%s\n", Cyan, Reset, bar, counter, BrightCyan+Bold, msg, Reset, durStr))
}

// PhaseBanner prints a phase separator during scan workflows. Call this
// when transitioning between scan phases. stepRange (e.g. "Steps 2–5") and
// elapsed (time spent in the preceding phase) are optional — pass an empty
// range and zero duration to omit them. The first phase banner typically
// omits elapsed since nothing preceded it.
func PhaseBanner(num int, name string, stepRange string, elapsed time.Duration) {
	label := fmt.Sprintf(" PHASE %d · %s ", num, strings.ToUpper(name))
	if stepRange != "" {
		label += "· " + stepRange + " "
	}
	if elapsed > 0 {
		label += "· " + FmtDuration(elapsed) + " "
	}
	fill := 56 - utf8.RuneCountInString(label) - 3
	if fill < 4 {
		fill = 4
	}
	logWrite(os.Stdout, fmt.Sprintf("\n  %s━━━%s%s%s\n\n",
		BrightPurple+Bold, label, strings.Repeat("━", fill), Reset))
}

// ScanHeader prints the main scan workflow header with a fixed-width box.
// No emojis are used here — emoji terminal widths vary across fonts and
// caused right-edge misalignment in the previous design.
func ScanHeader(scanType string, target string, scanID int64) {
	logWrite(os.Stdout, "\n")
	logWrite(os.Stdout, fmt.Sprintf("  %s╭%s╮%s\n", Cyan+Bold, strings.Repeat("─", boxInnerWidth), Reset))
	renderBoxLine(fmt.Sprintf("%sCHAATHAN%s · %s%s SCAN%s", Dim, Reset, White+Bold, strings.ToUpper(scanType), Reset))
	renderBoxLine(fmt.Sprintf("%sTarget%s    %s%s%s", Dim, Reset, BrightCyan+Bold, target, Reset))
	if scanID > 0 {
		renderBoxLine(fmt.Sprintf("%sScan ID%s   %s%d%s", Dim, Reset, White, scanID, Reset))
	}
	logWrite(os.Stdout, fmt.Sprintf("  %s╰%s╯%s\n", Cyan+Bold, strings.Repeat("─", boxInnerWidth), Reset))
	logWrite(os.Stdout, "\n")
}

// SubStep prints an indented sub-step with arrow
func SubStep(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s   %s▸%s %s\n", Dim, Reset, Purple, Reset, msg))
}

// ToolStart prints a "running" indicator for a tool.
func ToolStart(name string) {
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s   %s●%s %s\n", Dim, Reset, BrightCyan, Reset, name))
}

// ToolDone prints a "completed" indicator for a tool.
func ToolDone(name string) {
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s   %s✓%s %s\n", Dim, Reset, BrightGreen, Reset, name))
}

// ToolFail prints a "failed" indicator for a tool with the error reason.
func ToolFail(name string, reason string) {
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s   %s✗%s %s %s(%s)%s\n", Dim, Reset, BrightRed, Reset, name, Dim, reason, Reset))
}

// ToolSkip prints a "skipped" indicator for a tool with the reason.
func ToolSkip(name string, reason string) {
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s   %s⊘%s %s %s— %s%s\n", Dim, Reset, BrightYellow, Reset, name, Dim, reason, Reset))
}

// Command prints the command being executed
func Command(cmd string) {
	logWrite(os.Stdout, fmt.Sprintf("  %s│     $ %s%s\n", Dim, cmd, Reset))
}

// Result prints a step finding with a highlighted count. Use this for the
// key result line of each scan step so findings stand out from plain info.
// Zero counts render dim; positive counts render bright green.
func Result(count int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if count > 0 {
		logWrite(os.Stdout, fmt.Sprintf("  %s│%s %s●%s %s%d%s %s\n", Dim, Reset, BrightGreen, Reset, BrightGreen+Bold, count, Reset, msg))
	} else {
		logWrite(os.Stdout, fmt.Sprintf("  %s│ ● 0 %s%s\n", Dim, msg, Reset))
	}
}

// ResultSev prints a vulnerability finding line with severity-colored dot
// and count. Expected severities: critical, high, medium, low, info.
func ResultSev(severity string, count int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	color := sevDotColor(severity)
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s %s●%s %s%d%s %s\n", Dim, Reset, color, Reset, color+Bold, count, Reset, msg))
}

// sevDotColor maps a severity name to an ANSI color for result dots.
func sevDotColor(sev string) string {
	return SevColor(sev)
}

// ── Summary helpers ─────────────────────────────────────────────────────────

// Stat is a single label/value line in a scan summary. Stats are rendered in
// the order given, so callers control the layout deterministically.
type Stat struct {
	Label string
	Value string
}

// ScanSummary prints a scan completion summary in a fixed-width box.
// Vulnerability stats (labels containing "Vuln") are severity-colored.
func ScanSummary(status string, target string, scanID int64, duration time.Duration, stats []Stat) {
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
	logWrite(os.Stdout, fmt.Sprintf("  %s╭%s╮%s\n", Cyan+Bold, strings.Repeat("─", boxInnerWidth), Reset))
	renderBoxLine(fmt.Sprintf("%s%s %s SCAN%s", statusColor+Bold, statusIcon, strings.ToUpper(status), Reset))
	renderBoxLine(fmt.Sprintf("%s%s%s · Scan #%d · %s%s%s", White+Bold, target, Reset, scanID, BrightCyan, FmtDuration(duration), Reset))

	if len(stats) > 0 {
		renderBoxLine(fmt.Sprintf("%s%s%s", Dim, strings.Repeat("─", boxInnerWidth-3), Reset))
		for _, stat := range stats {
			valueColor := BrightCyan + Bold
			if strings.HasPrefix(stat.Label, "Vuln (") {
				sev := strings.TrimSuffix(strings.TrimPrefix(stat.Label, "Vuln ("), ")")
				valueColor = sevDotColor(sev) + Bold
			}
			renderBoxLine(fmt.Sprintf("%s%s%s %s%s%s", Dim, padRight(stat.Label, 14), Reset, valueColor, stat.Value, Reset))
		}
	}

	logWrite(os.Stdout, fmt.Sprintf("  %s╰%s╯%s\n", Cyan+Bold, strings.Repeat("─", boxInnerWidth), Reset))
}

// NextSteps prints styled next step hints
func NextSteps(hints []string) {
	if len(hints) == 0 {
		return
	}
	logWrite(os.Stdout, fmt.Sprintf("\n  %sNext steps:%s\n", Dim, Reset))
	for _, h := range hints {
		logWrite(os.Stdout, fmt.Sprintf("     %s▸%s %s%s%s\n", Purple, Reset, Dim, h, Reset))
	}
	logWrite(os.Stdout, "\n")
}

// ── Shared UI primitives ────────────────────────────────────────────────────

// boxInnerWidth is the inner content width shared by all box renderers
// (ScanHeader, ScanSummary, Box). Matches the ─ run in box borders.
const boxInnerWidth = 48

// renderBoxLine writes one aligned box content line. Padding is computed
// from the visible width only, so content may carry ANSI colors safely.
func renderBoxLine(content string) {
	pad := boxInnerWidth - 3 - visibleLen(content)
	if pad < 0 {
		pad = 0
	}
	logWrite(os.Stdout, fmt.Sprintf("  %s│%s  %s %s%s│%s\n",
		Cyan+Bold, Reset, content, strings.Repeat(" ", pad), Cyan+Bold, Reset))
}

// Box prints a generic fixed-width box with an optional bold title line
// followed by content lines. Lines may contain ANSI colors.
func Box(title string, lines []string) {
	logWrite(os.Stdout, "\n")
	logWrite(os.Stdout, fmt.Sprintf("  %s╭%s╮%s\n", Cyan+Bold, strings.Repeat("─", boxInnerWidth), Reset))
	if title != "" {
		renderBoxLine(fmt.Sprintf("%s%s%s", White+Bold, title, Reset))
	}
	for _, l := range lines {
		renderBoxLine(l)
	}
	logWrite(os.Stdout, fmt.Sprintf("  %s╰%s╯%s\n", Cyan+Bold, strings.Repeat("─", boxInnerWidth), Reset))
	logWrite(os.Stdout, "\n")
}

// Bar renders a progress bar of the given width using ▰▱ glyphs with the
// filled portion in bright green. pct is clamped to [0, 100].
func Bar(pct float64, width int) string {
	if width <= 0 {
		width = 10
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	return BrightGreen + strings.Repeat("▰", filled) + Dim + strings.Repeat("▱", width-filled) + Reset
}

// TableHeader writes a dim uppercase column-header row plus a matching
// dash-underline row to w (typically a *tabwriter.Writer).
func TableHeader(w io.Writer, cols ...string) {
	upper := make([]string, len(cols))
	dashes := make([]string, len(cols))
	for i, c := range cols {
		upper[i] = strings.ToUpper(c)
		n := utf8.RuneCountInString(c)
		if n < 2 {
			n = 2
		}
		dashes[i] = strings.Repeat("─", n)
	}
	fmt.Fprintf(w, "%s%s%s\n", Dim, strings.Join(upper, "\t"), Reset)
	fmt.Fprintf(w, "%s%s%s\n", Dim, strings.Join(dashes, "\t"), Reset)
}

// TableRow writes a single tab-separated row to w.
func TableRow(w io.Writer, cells ...string) {
	fmt.Fprintln(w, strings.Join(cells, "\t"))
}

// Added prints a diff addition line with a green + marker.
func Added(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s+%s %s\n", BrightGreen, Reset, msg))
}

// Removed prints a diff removal line with a red − marker.
func Removed(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWrite(os.Stdout, fmt.Sprintf("  %s−%s %s\n", BrightRed, Reset, msg))
}

// ── Utility ─────────────────────────────────────────────────────────────────

// padRight pads s with spaces to width n (rune-aware).
func padRight(s string, n int) string {
	if r := utf8.RuneCountInString(s); r < n {
		return s + strings.Repeat(" ", n-r)
	}
	return s
}

// visibleLen returns the terminal-visible width of s, ignoring ANSI escape
// sequences. Used for box padding calculations where content carries colors.
func visibleLen(s string) int {
	return utf8.RuneCountInString(ansiRE.ReplaceAllString(s, ""))
}

// stepPct returns the completion percentage for step current of total.
// It reports the progress *before* the current step finishes: step 1 of 23
// shows 0%, step 23 of 23 shows 96% (100% is reserved for the summary).
func stepPct(current, total int) int {
	if total <= 0 {
		return 0
	}
	p := (current - 1) * 100 / total
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return p
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
