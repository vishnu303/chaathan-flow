package utils

import (
	"fmt"
)

// Truncate shortens s to at most max runes, appending "..." when truncated.
// When max <= 3 there is no room for the ellipsis, so the string is cut
// without it.
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
