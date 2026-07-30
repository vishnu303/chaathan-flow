// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vishnu303/chaathan/pkg/progress"
)

const (
	x8Version       = "v4.3.0"
	x8MinBinarySize = 500000 // 500 KB minimum binary size check
)

// installX8Section checks and installs x8.
// It first attempts to download the precompiled binary from GitHub Releases.
// If that fails, it falls back to installing via Cargo.
func installX8Section(ctx *SetupContext) (installed, skipped, failed int) {
	progress.Section("[4/6] Rust Tools (x8)", "parameter discovery tool")

	if !ctx.IsForceUpdate() {
		if _, err := exec.LookPath("x8"); err == nil {
			progress.ItemOK("Already installed")
			return 0, 1, 0
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		progress.ItemFail("x8", "failed to find user home dir: "+err.Error())
		return 0, 0, 1
	}
	localDir := filepath.Join(home, ".local")
	binDir := filepath.Join(localDir, "bin")
	dst := filepath.Join(binDir, "x8")

	// Ensure bin directory exists
	if err := os.MkdirAll(binDir, 0755); err != nil {
		progress.ItemFail("x8", "failed to create local bin dir: "+err.Error())
		return 0, 0, 1
	}

	// Use single tracker for the entire installation attempt
	tracker := progress.NewTracker(1)
	tracker.RunSpinner()
	tracker.Start("installing x8")

	// Try downloading precompiled binary first if on Linux AMD64
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		downloadURL := fmt.Sprintf("https://github.com/Sh1Yo/x8/releases/download/%s/x86_64-linux-x8.gz", x8Version)
		err := downloadAndDecompressGzip(downloadURL, dst)
		if err == nil {
			// Warn that we did not perform checksum verification but did a size sanity check
			if ctx.Logger != nil {
				ctx.Logger.Write("Warning: No checksum verification asset available for x8, performing size sanity check instead")
			}
			// Size sanity check
			if info, statErr := os.Stat(dst); statErr != nil {
				_ = os.Remove(dst) // clean up partial file
				tracker.Fail("installing x8", "failed to stat downloaded x8 binary: "+statErr.Error())
				tracker.StopSpinner()
				return 0, 0, 1
			} else if info.Size() < x8MinBinarySize {
				_ = os.Remove(dst) // clean up partial file
				tracker.Fail("installing x8", fmt.Sprintf("downloaded x8 binary size is too small: %d bytes", info.Size()))
				tracker.StopSpinner()
				return 0, 0, 1
			}

			tracker.Complete("installing x8")
			tracker.StopSpinner()
			return 1, 0, 0
		}

		if ctx.Logger != nil {
			ctx.Logger.Write("Precompiled x8 download failed: %v; falling back to Cargo build", err)
		}
	}

	// Fallback to Cargo install
	err = ctx.RunCommand("x8 (cargo install)", "cargo", "install", "x8", "--root", localDir)
	if err != nil {
		tracker.Fail("installing x8", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}

	tracker.Complete("installing x8")
	tracker.StopSpinner()
	return 1, 0, 0
}

// downloadAndDecompressGzip downloads a gzipped file and extracts it to destination.
func downloadAndDecompressGzip(url, dst string) error {
	client := setupHTTPClient(5 * time.Minute)
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code: %s", resp.Status)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gr.Close()

	// Clean up partial file on write error
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, gr)
	if err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("failed to close file: %w", err)
	}
	return nil
}
