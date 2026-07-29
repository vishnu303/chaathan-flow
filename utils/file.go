package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"maps"
	neturl "net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// MergeAndDeduplicate merges unique non-empty lines from multiple files and writes them sorted to outputFile.
func MergeAndDeduplicate(inputFiles []string, outputFile string) error {
	uniqueLines := make(map[string]struct{})

	for _, file := range inputFiles {
		if err := readFileInto(file, uniqueLines); err != nil {
			return err
		}
	}

	// Sort keys
	result := slices.Sorted(maps.Keys(uniqueLines))

	// Write to output using the shared helper
	if err := writeLines(outputFile, result); err != nil {
		return fmt.Errorf("failed to write output file %s: %w", outputFile, err)
	}
	return nil
}

// readFileInto reads non-empty lines from a single file into the dest map.
// The file handle is closed when this function returns, avoiding FD leaks.
func readFileInto(path string, dest map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // missing files are silently skipped
		}
		return fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			dest[line] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed reading %s: %w", path, err)
	}
	return nil
}

// FileExists checks if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// CountFileLines returns the number of non-empty lines in a file.
// Uses allocation-free scanner.Bytes() matching to optimize performance.
func CountFileLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScanBufferSize)
	for scanner.Scan() {
		if isNonWhitespace(scanner.Bytes()) {
			count++
		}
	}
	return count, scanner.Err()
}

// isNonWhitespace returns true if the slice contains any non-whitespace characters.
// Note on byte semantics: this checks ASCII spacing bytes (' ', '\t', '\n', '\r')
// and does not handle multibyte Unicode spacing marks.
func isNonWhitespace(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return true
		}
	}
	return false
}

// readFilteredLines reads a file and returns only non-empty lines that match keep().
func readFilteredLines(filePath string, keep func(string) bool) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var kept []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScanBufferSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && keep(line) {
			kept = append(kept, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return kept, nil
}

// writeLines writes a slice of strings to a file using buffered I/O.
// Close errors on the success path are returned so a failed final
// flush-to-disk is not silently dropped.
func writeLines(filePath string, lines []string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}

	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// WriteToFile writes a string to a file, creating parent directories if they don't exist.
// It flushes, calls Sync(), and explicitly checks the Close() error on the success path.
func WriteToFile(filePath string, content string) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return err
	}
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return err
	}

	if err := f.Sync(); err != nil {
		return err
	}

	return f.Close()
}

// FilterFileLines reads a file, keeps only lines where keep() returns true,
// and writes the result back in place. Empty lines are always dropped.
func FilterFileLines(filePath string, keep func(string) bool) error {
	kept, err := readFilteredLines(filePath, keep)
	if err != nil {
		return err
	}
	return writeLines(filePath, kept)
}

// readSanitizedURLLines reads a file and returns sanitized, distinct URLs.
// If isAllowedHost is not nil, it filters out URLs with hostnames that don't pass the check.
func readSanitizedURLLines(filePath string, isAllowedHost func(string) bool) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cleaned []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScanBufferSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Unescape \\uXXXX → \uXXXX → actual character
		line = UnescapeUnicodeURL(line)

		// Strip trailing backslashes left over from JS string extraction
		line = strings.TrimRight(line, "\\")

		// Skip non-URL lines (GoSpider tags, relative paths, bare words)
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}

		// Apply host filter if provided
		if isAllowedHost != nil {
			parsed, err := neturl.Parse(line)
			if err != nil {
				continue
			}
			hostname := parsed.Hostname()
			if hostname == "" || !isAllowedHost(hostname) {
				continue
			}
		}

		if _, ok := seen[line]; !ok {
			seen[line] = struct{}{}
			cleaned = append(cleaned, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cleaned, nil
}

// SanitizeURLFile reads a URL file, cleans each line (unescaping unicode,
// stripping non-URL lines), and writes the result back in place.
// This prevents downstream tools (Nuclei, Dalfox, httpx) from receiving
// malformed URLs that contain literal \uXXXX sequences or GoSpider tags.
// An optional isAllowedHost filter can be provided to exclude out-of-scope hostnames.
func SanitizeURLFile(filePath string, isAllowedHost func(string) bool) error {
	cleaned, err := readSanitizedURLLines(filePath, isAllowedHost)
	if err != nil {
		return err
	}
	slices.Sort(cleaned)
	return writeLines(filePath, cleaned)
}

// UnescapeUnicodeURL replaces literal \uXXXX sequences with their actual characters.
func UnescapeUnicodeURL(s string) string {
	// Handle double-escaped \\u first
	s = strings.ReplaceAll(s, "\\\\u", "\\u")

	// Fast path: no unicode escapes
	if !strings.Contains(s, "\\u") {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if i+5 < len(s) && s[i] == '\\' && s[i+1] == 'u' {
			// Try to parse 4 hex digits after \u
			hex := s[i+2 : i+6]
			if r, ok := ParseHex4(hex); ok {
				// Check if r is a UTF-16 high surrogate
				if r >= 0xD800 && r <= 0xDBFF && i+11 < len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
					hex2 := s[i+8 : i+12]
					if r2, ok2 := ParseHex4(hex2); ok2 && r2 >= 0xDC00 && r2 <= 0xDFFF {
						// Decode UTF-16 surrogate pair
						combined := 0x10000 + ((int32(r) - 0xD800) << 10) + (int32(r2) - 0xDC00)
						b.WriteRune(rune(combined))
						i += 11 // skip both \uXXXX and \uYYYY
						continue
					}
				}
				b.WriteRune(r)
				i += 5 // skip \uXXXX (loop adds 1)
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ParseHex4 parses exactly 4 hex digits into a rune using standard library strconv.
func ParseHex4(s string) (rune, bool) {
	if len(s) != 4 {
		return 0, false
	}
	val, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, false
	}
	return rune(val), true
}

// DeduplicateSlice returns a unique, deduplicated slice of comparable elements.
func DeduplicateSlice[T comparable](in []T) []T {
	seen := make(map[T]struct{}, len(in))
	var out []T
	for _, val := range in {
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			out = append(out, val)
		}
	}
	return out
}

// CountUniqueDNSxHosts reads a DNSx JSONL output file and counts the unique hosts resolved
func CountUniqueDNSxHosts(jsonPath string) (int, error) {
	file, err := os.Open(jsonPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	type dnsxRecord struct {
		Host string `json:"host"`
	}

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec dnsxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Host != "" {
			seen[strings.ToLower(strings.TrimSpace(rec.Host))] = true
		}
	}
	return len(seen), scanner.Err()
}
