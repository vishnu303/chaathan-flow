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

// installX8Section checks and installs x8.
// It first attempts to download the precompiled binary from GitHub Releases.
// If that fails, it falls back to installing via Cargo.
func installX8Section(ctx *SetupContext) (installed, skipped, failed int) {
	progress.Section("[5/7] Rust Tools (x8)", "parameter discovery tool")

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

	// L8: Single tracker for the entire installation attempt
	tracker := progress.NewTracker(1)
	tracker.RunSpinner()
	tracker.Start("installing x8")

	// Try downloading precompiled binary first if on Linux AMD64
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		downloadURL := "https://github.com/Sh1Yo/x8/releases/download/v4.3.0/x86_64-linux-x8.gz"
		err := downloadAndDecompressGzip(downloadURL, dst)
		if err == nil {
			// Warn that we did not perform checksum verification but did a size sanity check (H5)
			if ctx.Logger != nil {
				ctx.Logger.Write("Warning: No checksum verification asset available for x8, performing size sanity check instead")
			}
			// Size sanity check (H5)
			if info, statErr := os.Stat(dst); statErr != nil {
				_ = os.Remove(dst) // clean up (L9)
				tracker.Fail("installing x8", "failed to stat downloaded x8 binary: "+statErr.Error())
				tracker.StopSpinner()
				return 0, 0, 1
			} else if info.Size() < 500000 { // Check that file is at least 500 KB
				_ = os.Remove(dst) // clean up (L9)
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

	// L9: make sure to clean up partial file on write error
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, gr)
	out.Close() // close explicitly before handling error / removing
	if err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}
