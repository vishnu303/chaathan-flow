package utils

import (
	"fmt"
	"strings"
)

// Truncate shortens s to at most max runes, appending "..." when truncated.
func Truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

// TruncateURL is an alias for Truncate, used to signal intent when the value
// being truncated is specifically a URL.
func TruncateURL(url string, max int) string {
	return Truncate(url, max)
}

// FormatSize returns a human-readable representation of a byte count.
//
//	>= 1 MB  → "X.X MB"
//	>= 1 KB  → "X.X KB"
//	otherwise → "X B"
func FormatSize(bytes int64) string {
	switch {
	case bytes >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/1024/1024)
	case bytes >= 1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// SummarizeSeverityCounts merges two severity→count maps (exact-URL matches and
// host-level matches) and returns a compact string like "c:2 h:1 m:3", or "-"
// when there are no findings.
func SummarizeSeverityCounts(exact, host map[string]int) string {
	order := []string{"critical", "high", "medium", "low", "info"}
	var parts []string
	for _, sev := range order {
		total := exact[sev] + host[sev]
		if total > 0 {
			short := "?"
			if len(sev) > 0 {
				short = sev[:1]
			}
			parts = append(parts, fmt.Sprintf("%s:%d", short, total))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}
