package logger

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

// EmojiStatus returns an emoji-prefixed status string for CLI table output.
func EmojiStatus(status string) string {
	switch status {
	case "completed":
		return "✅ completed"
	case "running":
		return "🔄 running"
	case "failed":
		return "❌ failed"
	case "cancelled":
		return "⚠️  cancelled"
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

// EmojiSeverity returns an emoji-prefixed, uppercased severity label
// for CLI table output (e.g. "🔴 CRITICAL").
func EmojiSeverity(sev string) string {
	switch sev {
	case "critical":
		return "🔴 CRITICAL"
	case "high":
		return "🟠 HIGH"
	case "medium":
		return "🟡 MEDIUM"
	case "low":
		return "🟢 LOW"
	case "info":
		return "🔵 INFO"
	default:
		return sev
	}
}
