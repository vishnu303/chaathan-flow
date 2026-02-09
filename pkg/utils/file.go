package utils

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// MergeAndDeduplicate reads multiple input files, merges their content,
// deduplicates lines, sorts them, and writes to an output file.
func MergeAndDeduplicate(inputFiles []string, outputFile string) error {
	uniqueLines := make(map[string]bool)

	for _, file := range inputFiles {
		// Skip if file doesn't exist or is empty
		if _, err := os.Stat(file); os.IsNotExist(err) {
			continue
		}

		f, err := os.Open(file)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", file, err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				uniqueLines[line] = true
			}
		}
	}

	// Sort keys
	result := make([]string, 0, len(uniqueLines))
	for line := range uniqueLines {
		result = append(result, line)
	}
	sort.Strings(result)

	// Write to output
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outputFile, err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range result {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

// FileExists checks if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
