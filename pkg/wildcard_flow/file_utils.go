package wildcard_flow

import (
	"io"
	"os"
	"time"

	"github.com/vishnu303/chaathan/utils"
)

// existingFiles returns only those paths that exist on disk.
func existingFiles(paths ...string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p != "" && utils.FileExists(p) {
			out = append(out, p)
		}
	}
	return out
}

// copyFile copies src to dst using memory-efficient io.Copy.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// fileModifiedAfter returns true if the file at path was modified after the
// given time. Used to distinguish partial output written during this scan
// from stale files left over from a previous run.
func fileModifiedAfter(path string, after time.Time) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.ModTime().After(after)
}

// writeEmptyFile truncates or creates a file so retry paths do not reuse stale output.
func writeEmptyFile(path string) {
	_ = os.WriteFile(path, nil, 0644)
}
