package logger

import "strings"

// ANSI style and color constants shared by all terminal output.
const (
	Reset = "\033[0m"
	Bold  = "\033[1m"
	Dim   = "\033[2m"

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
)

// ColorStatus returns an ANSI-coloured string for a scan status value.
// Expected values: "completed", "running", "failed", "cancelled".
func ColorStatus(status string) string {
	switch status {
	case "completed":
		return BrightGreen + status + Reset
	case "running":
		return BrightYellow + status + Reset
	case "failed":
		return BrightRed + status + Reset
	case "cancelled":
		return Gray + status + Reset
	default:
		return status
	}
}

// ColorSeverity returns an ANSI-coloured string for a vulnerability severity.
// Expected values: "critical", "high", "medium", "low", "info".
func ColorSeverity(sev string) string {
	switch sev {
	case "critical":
		return BrightRed + sev + Reset
	case "high":
		return Red + sev + Reset
	case "medium":
		return Yellow + sev + Reset
	case "low":
		return Green + sev + Reset
	case "info":
		return Blue + sev + Reset
	default:
		return sev
	}
}

// SevColor returns the raw ANSI color code for a vulnerability severity.
// Used for severity dots (●) and markers in finding lines.
func SevColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return BrightRed
	case "high":
		return Red
	case "medium":
		return BrightYellow
	case "low":
		return BrightGreen
	default:
		return BrightBlue
	}
}
