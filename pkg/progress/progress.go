package progress

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
)

// ── ANSI codes ───────────────────────────────────────────────────────────────

const (
	Reset   = logger.Reset
	Bold    = logger.Bold
	Dim     = logger.Dim
	// L6: progress color constants are aliased directly from logger.Red to maintain single source of truth.
	Red     = logger.Red
	Green   = logger.Green
	Yellow  = logger.Yellow
	Blue    = logger.Blue
	Cyan    = logger.Cyan
	White   = logger.White
	ClearLn = "\033[2K"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ── Display helpers ──────────────────────────────────────────────────────────

// Header prints a styled header box.
func Header(title string) {
	w := len(title) + 4
	top := "╭" + strings.Repeat("─", w) + "╮"
	mid := "│  " + title + "  │"
	bot := "╰" + strings.Repeat("─", w) + "╯"
	fmt.Printf("\n%s%s%s%s\n%s%s%s\n%s%s%s%s\n",
		Cyan+Bold, top, Reset, "",
		Cyan+Bold, mid, Reset,
		Cyan+Bold, bot, Reset, "")
}

// Section prints a section header with optional detail text.
func Section(name string, detail string) {
	if detail != "" {
		fmt.Printf("\n  %s▸ %s%s  %s%s%s\n", White+Bold, name, Reset, Dim, detail, Reset)
	} else {
		fmt.Printf("\n  %s▸ %s%s\n", White+Bold, name, Reset)
	}
}

// ItemOK prints a green ✓ status line.
func ItemOK(name string) {
	fmt.Printf("    %s✓%s %s\n", Green, Reset, name)
}

// ItemFail prints a red ✗ status line.
func ItemFail(name string, detail string) {
	if detail != "" {
		runes := []rune(detail)
		if len(runes) > 40 {
			detail = string(runes[:37]) + "..."
		}
		fmt.Printf("    %s✗%s %s  %s%s%s\n", Red, Reset, name, Red+Dim, detail, Reset)
	} else {
		fmt.Printf("    %s✗%s %s\n", Red, Reset, name)
	}
}

// ItemPending prints a → pending item.
func ItemPending(name string) {
	fmt.Printf("    %s→%s %s\n", Yellow, Reset, name)
}

// ItemInfo prints a dim info line.
func ItemInfo(msg string) {
	fmt.Printf("    %s%s%s\n", Dim, msg, Reset)
}

// Summary prints the final aggregated summary bar.
func Summary(installed, skipped, failed int32, duration time.Duration) {
	fmt.Println()
	line := strings.Repeat("━", 50)
	fmt.Printf("  %s%s%s\n", Dim, line, Reset)

	var parts []string
	if installed > 0 {
		parts = append(parts, fmt.Sprintf("%s✓ %d installed%s", Green, installed, Reset))
	}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%s⊘ %d skipped%s", Yellow, skipped, Reset))
	}
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%s✗ %d failed%s", Red, failed, Reset))
	}
	parts = append(parts, fmt.Sprintf("%s⏱  %s%s", Dim, fmtDuration(duration), Reset))

	fmt.Printf("  %s\n", strings.Join(parts, "  "))
	fmt.Printf("  %s%s%s\n", Dim, line, Reset)
}

// Tip prints a dim tip line.
func Tip(msg string) {
	fmt.Printf("\n  %s💡 %s%s\n\n", Dim, msg, Reset)
}

// ── Tracker ──────────────────────────────────────────────────────────────────
// Thread-safe progress tracker with a live spinner.
// Contract: Safe for sequential Start/Complete/Fail; the only concurrency
// is the internal render goroutine.

type Tracker struct {
	mu sync.Mutex

	total     int
	completed int
	failed    int
	skipped   int

	active   map[string]time.Time
	start    time.Time
	frameIdx int

	stopCh    chan struct{}
	stoppedCh chan struct{}
}

func (t *Tracker) writefLocked(format string, args ...any) {
	fmt.Printf(format, args...)
}

func (t *Tracker) writef(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writefLocked(format, args...)
}

// NewTracker creates a new tracker for `total` items to install.
func NewTracker(total int) *Tracker {
	return &Tracker{
		total:     total,
		active:    make(map[string]time.Time),
		start:     time.Now(),
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}
}

// RunSpinner starts the animated spinner in a background goroutine.
func (t *Tracker) RunSpinner() {
	go func() {
		defer close(t.stoppedCh)
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-t.stopCh:
				t.writef("\r%s", ClearLn) // erase spinner line
				return
			case <-ticker.C:
				t.render()
			}
		}
	}()
}

// StopSpinner stops the spinner goroutine and waits for it to finish.
func (t *Tracker) StopSpinner() {
	close(t.stopCh)
	<-t.stoppedCh
}

func (t *Tracker) render() {
	t.mu.Lock()
	defer t.mu.Unlock()

	frame := spinnerFrames[t.frameIdx%len(spinnerFrames)]
	t.frameIdx++

	done := t.completed + t.failed
	elapsed := time.Since(t.start)

	// ── progress bar ──
	barW := 20
	filled := 0
	if t.total > 0 {
		filled = int(float64(done) / float64(t.total) * float64(barW))
		if filled > barW {
			filled = barW
		}
	}
	bar := Green + strings.Repeat("━", filled) + Reset + Dim + strings.Repeat("╌", barW-filled) + Reset

	// ── active tool names ──
	var names []string
	for n := range t.active {
		names = append(names, n)
	}
	activeStr := ""
	if len(names) > 0 {
		if len(names) <= 3 {
			activeStr = strings.Join(names, ", ")
		} else {
			activeStr = fmt.Sprintf("%s +%d more", strings.Join(names[:3], ", "), len(names)-3)
		}
	}

	t.writefLocked("\r%s    %s%s%s %s [%s%d%s/%d] %s %s%s%s",
		ClearLn,
		Cyan, frame, Reset,
		bar,
		Bold, done, Reset, t.total,
		activeStr,
		Dim, fmtDuration(elapsed), Reset,
	)
}

// Start marks a tool as being actively installed.
func (t *Tracker) Start(name string) {
	t.mu.Lock()
	t.active[name] = time.Now()
	t.mu.Unlock()
}

// Complete marks a tool as successfully installed. Prints a ✓ line.
func (t *Tracker) Complete(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	startTime, ok := t.active[name]
	delete(t.active, name)
	dur := time.Duration(0)
	if ok {
		dur = time.Since(startTime)
	}
	t.completed++

	t.writefLocked("\r%s", ClearLn)
	t.writefLocked("    %s✓%s %-30s %s%s%s\n", Green, Reset, name, Dim, fmtShort(dur), Reset)
}

// Fail marks a tool as failed. Prints a ✗ line.
func (t *Tracker) Fail(name string, errMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, ok := t.active[name]
	delete(t.active, name)
	_ = ok
	t.failed++

	runes := []rune(errMsg)
	short := errMsg
	if len(runes) > 35 {
		short = string(runes[:32]) + "..."
	}

	t.writefLocked("\r%s", ClearLn)
	t.writefLocked("    %s✗%s %-30s %s%s%s\n", Red, Reset, name, Red+Dim, short, Reset)
}

// Skip records a skipped item (already installed).
func (t *Tracker) Skip(name string) {
	t.mu.Lock()
	t.skipped++
	t.mu.Unlock()
}

// Stats returns the final counts.
func (t *Tracker) Stats() (installed, skipped, failed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.completed, t.skipped, t.failed
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func fmtDuration(d time.Duration) string {
	return logger.FmtDuration(d)
}

func fmtShort(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmtDuration(d)
}
