package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// setupHTTPClient returns a configured *http.Client with the specified timeout.
func setupHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
	}
}

// pathListContains returns true if the given list (e.g. PATH environment variable)
// contains the specified directory. It cleans and matches exact path segments
// to avoid false positives.
func pathListContains(list, dir string) bool {
	dirClean := filepath.Clean(dir)
	for _, p := range filepath.SplitList(list) {
		if filepath.Clean(p) == dirClean {
			return true
		}
	}
	return false
}

// verifySHA256 reads from r, calculates its SHA256 sum, and compares it
// with expectedHex. expectedHex can contain trailing fields/whitespace (e.g. from a .sha256 file).
func verifySHA256(r io.Reader, expectedHex string) error {
	fields := strings.Fields(expectedHex)
	if len(fields) == 0 {
		return fmt.Errorf("empty expected SHA256 checksum")
	}
	expected := strings.TrimSpace(fields[0])

	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))

	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("SHA256 checksum mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}
