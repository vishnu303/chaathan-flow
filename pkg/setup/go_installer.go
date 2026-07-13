package setup

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// minGoVersion is the minimum required minor version of Go 1.x (e.g. 26 for Go 1.26).
const minGoVersion = 26

// goArchSuffix maps runtime.GOARCH to the architecture suffix used in Go release packages.
// Bails on unsupported architectures.
func goArchSuffix() (string, error) {
	switch runtime.GOARCH {
	case "amd64", "arm64", "386":
		return runtime.GOARCH, nil
	default:
		return "", fmt.Errorf("unsupported Go architecture: %s", runtime.GOARCH)
	}
}

// checkGoVersion checks if go is in PATH and if its version is >= 1.minGoVersion.
func checkGoVersion() (bool, string) {
	path, err := exec.LookPath("go")
	if err != nil {
		return false, ""
	}
	cmd := exec.Command(path, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return false, path
	}
	return parseGoVersion(out.String())
}

// parseGoVersion cleans and parses a Go version output string (e.g. "go version go1.26.1 linux/amd64").
func parseGoVersion(versionStr string) (bool, string) {
	fields := strings.Fields(versionStr)
	for _, f := range fields {
		if strings.HasPrefix(f, "go") && f != "go" {
			v := strings.TrimPrefix(f, "go")
			// Remove non-numeric suffixes like rc1, beta2
			if idx := strings.IndexAny(v, "abcdefghijklmnopqrstuvwxyz"); idx >= 0 {
				v = v[:idx]
			}
			parts := strings.Split(v, ".")
			if len(parts) >= 2 {
				major, _ := strconv.Atoi(parts[0])
				minor, _ := strconv.Atoi(parts[1])
				if major > 1 || (major == 1 && minor >= minGoVersion) {
					return true, f
				}
			}
			return false, f
		}
	}
	return false, ""
}


// ensureSystemGoOnPath checks if Go is installed under the user-local or system directory
// and adds it to the current process's PATH if found.
func ensureSystemGoOnPath() {
	if runtime.GOOS == "linux" {
		currentPath := os.Getenv("PATH")
		home, err := os.UserHomeDir()
		if err == nil {
			localGoBin := filepath.Join(home, ".local", "go", "bin")
			if !pathListContains(currentPath, localGoBin) {
				if _, err := os.Stat(filepath.Join(localGoBin, "go")); err == nil {
					currentPath = localGoBin + string(os.PathListSeparator) + currentPath
					_ = os.Setenv("PATH", currentPath)
				}
			}
		}

		usrGoBin := "/usr/local/go/bin"
		if !pathListContains(currentPath, usrGoBin) {
			if _, err := os.Stat(filepath.Join(usrGoBin, "go")); err == nil {
				currentPath = currentPath + string(os.PathListSeparator) + usrGoBin
				_ = os.Setenv("PATH", currentPath)
			}
		}
	}
}

// downloadLatestGo fetches the latest Go version string from go.dev, falling back to go1.26.0 on failure.
func downloadLatestGo(ctx *SetupContext) (string, error) {
	progress.ItemPending("Checking latest Go version on go.dev...")
	client := setupHTTPClient(30 * time.Second)
	resp, err := client.Get("https://go.dev/VERSION?m=text")
	if err != nil {
		progress.ItemInfo("Failed to check go.dev/VERSION (using go1.26.0 as fallback)")
		return "go1.26.0", nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		progress.ItemInfo("Failed to read go.dev/VERSION (using go1.26.0 as fallback)")
		return "go1.26.0", nil
	}
	version := strings.TrimSpace(string(body))
	if idx := strings.Index(version, "\n"); idx >= 0 {
		version = strings.TrimSpace(version[:idx])
	}
	if !strings.HasPrefix(version, "go") {
		progress.ItemInfo("Invalid go.dev/VERSION output (using go1.26.0 as fallback)")
		return "go1.26.0", nil
	}
	progress.ItemOK(fmt.Sprintf("Latest Go version: %s", version))
	return version, nil
}

// downloadTarball downloads the Go binary and its sha256 checksum from go.dev, verifies it,
// and saves the tarball to the destination path.
func downloadTarball(ctx *SetupContext, version, destPath string) error {
	arch, err := goArchSuffix()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://go.dev/dl/%s.linux-%s.tar.gz", version, arch)
	checksumURL := url + ".sha256"

	progress.ItemPending(fmt.Sprintf("Downloading Go archive: %s", url))

	client := setupHTTPClient(10 * time.Minute)

	// Fetch checksum first
	checksumResp, err := client.Get(checksumURL)
	if err != nil {
		return fmt.Errorf("failed to fetch Go checksum from %s: %w", checksumURL, err)
	}
	defer checksumResp.Body.Close()
	if checksumResp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code from go.dev for checksum: %s", checksumResp.Status)
	}
	checksumBytes, err := io.ReadAll(checksumResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read Go checksum body: %w", err)
	}
	expectedChecksum := string(checksumBytes)

	// Fetch tarball
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code from go.dev: %s", resp.Status)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save Go archive: %w", err)
	}

	// Close the file before verifying to avoid access issues
	_ = out.Close()

	// Verify checksum
	r, err := os.Open(destPath)
	if err != nil {
		return fmt.Errorf("failed to open downloaded archive for verification: %w", err)
	}
	defer r.Close()

	if err := verifySHA256(r, expectedChecksum); err != nil {
		_ = os.Remove(destPath) // clean up invalid download
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	progress.ItemOK("Go archive downloaded and checksum verified successfully")
	return nil
}

// installGoBinary extracts the tarball to ~/.local/go.
func installGoBinary(ctx *SetupContext, tarPath string) error {
	progress.ItemPending("Extracting Go tarball to ~/.local...")

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}

	localDir := filepath.Join(home, ".local")
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return fmt.Errorf("failed to create ~/.local directory: %w", err)
	}

	localGo := filepath.Join(localDir, "go")
	_ = os.RemoveAll(localGo) // remove old custom installation if exists

	// Extract new package to ~/.local (which creates ~/.local/go)
	if err := runSysCmd(ctx, "tar", "-C", localDir, "-xzf", tarPath); err != nil {
		return fmt.Errorf("tar extract to ~/.local failed: %w", err)
	}

	return nil
}

// ensureGoPATH adds ~/.local/go/bin to the configuration files of common shells.
func ensureGoPATH() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	comment := "# Go installation PATH"
	pathsToAdd := []string{
		`export PATH="$HOME/.local/go/bin:$PATH"`,
	}

	rcFiles := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
	}

	for _, rc := range rcFiles {
		if _, err := os.Stat(rc); os.IsNotExist(err) {
			continue
		}
		_, _ = appendLinesToFile(rc, pathsToAdd, comment)
	}

	// Fish shell support
	fishConfig := filepath.Join(home, ".config", "fish", "config.fish")
	if _, err := os.Stat(fishConfig); err == nil {
		fishPaths := []string{
			`fish_add_path -g $HOME/.local/go/bin`,
		}
		_, _ = appendLinesToFile(fishConfig, fishPaths, comment)
	}

	// Update PATH of the current running process so LookPath resolves immediately
	currentPath := os.Getenv("PATH")
	goBin := filepath.Join(home, ".local", "go", "bin")
	if !pathListContains(currentPath, goBin) {
		currentPath = goBin + string(os.PathListSeparator) + currentPath
		_ = os.Setenv("PATH", currentPath)
	}
}

// EnsureGoInstalled checks if Go runtime is ready and runs the installer if missing or old.
func EnsureGoInstalled(ctx *SetupContext) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("automated Go installation is only supported on Linux")
	}

	ensureSystemGoOnPath()
	ok, currentVer := checkGoVersion()
	if ok {
		progress.ItemOK(fmt.Sprintf("Go is ready (version: %s)", currentVer))
		return true, nil
	}

	if currentVer != "" {
		progress.ItemInfo(fmt.Sprintf("Go version %s is too old (minimum required: Go 1.%d)", currentVer, minGoVersion))
	} else {
		progress.ItemInfo("Go is not installed on the system")
	}

	progress.ItemPending("Preparing Go installer...")

	version, err := downloadLatestGo(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to detect latest Go version: %w", err)
	}

	// Create temp folder inside user space to avoid global /tmp pollution or permissions issues
	home, err := os.UserHomeDir()
	if err != nil {
		return false, fmt.Errorf("failed to get user home: %w", err)
	}
	tempDir := filepath.Join(home, ".chaathan", "temp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return false, fmt.Errorf("failed to create temp directory: %w", err)
	}
	tarPath := filepath.Join(tempDir, "go.tar.gz")
	defer os.Remove(tarPath)

	if err := downloadTarball(ctx, version, tarPath); err != nil {
		return false, fmt.Errorf("download Go tarball failed: %w", err)
	}

	if err := installGoBinary(ctx, tarPath); err != nil {
		return false, fmt.Errorf("install Go binary failed: %w", err)
	}

	ensureGoPATH()

	// Verify new Go path resolutions
	ensureSystemGoOnPath()
	okVerify, newVer := checkGoVersion()
	if !okVerify {
		return false, fmt.Errorf("Go installation completed but verification failed (version check resolved: %s)", newVer)
	}

	progress.ItemOK(fmt.Sprintf("Go version %s successfully installed", newVer))
	return true, nil
}
