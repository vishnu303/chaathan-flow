package proxy_scraping

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
)

// RotatorConfig controls the mubeng proxy rotation server.
type RotatorConfig struct {
	ProxyListFile string // path to proxy_pool.txt
	ListenAddr    string // local listen address (default: "127.0.0.1:0" for random port)
	RotateEvery   int    // rotate IP every N requests (default: 1)
	Method        string // rotation method: "sequent" or "random" (default: "random")
	Verbose       bool   // enable mubeng verbose logging
}

// Rotator manages the mubeng background process.
type Rotator struct {
	Addr     string // actual listen address (e.g. "127.0.0.1:38291")
	ProxyURL string // full proxy URL for tools (e.g. "http://127.0.0.1:38291")
	cmd      *exec.Cmd
}

// StartRotator launches mubeng as a background rotating proxy server.
// It picks a free port on localhost, starts mubeng with the proxy list,
// and waits briefly to confirm the server is listening.
// The caller must call Stop() to kill mubeng (typically in finalizeScan).
func StartRotator(ctx context.Context, cfg RotatorConfig) (*Rotator, error) {
	// Verify mubeng is available
	binPath, err := exec.LookPath("mubeng")
	if err != nil {
		return nil, fmt.Errorf("mubeng not found: install via 'go install github.com/mubeng/mubeng@latest' or 'chaathan setup'")
	}

	// Verify proxy list file exists and has content
	if err := validateProxyList(cfg.ProxyListFile); err != nil {
		return nil, fmt.Errorf("invalid proxy list: %w", err)
	}

	// Find a free port
	listenAddr := cfg.ListenAddr
	isDynamicPort := listenAddr == "" || listenAddr == "127.0.0.1:0"
	if isDynamicPort {
		port, err := findFreePort()
		if err != nil {
			return nil, fmt.Errorf("cannot find free port: %w", err)
		}
		listenAddr = fmt.Sprintf("127.0.0.1:%d", port)
	}

	// Build mubeng command
	args := buildRotatorArgs(cfg, listenAddr)

	logger.FileDebug("mubeng command: %s %s", binPath, strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	logFile := attachRotatorOutput(cmd, cfg)
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		if logFile != nil {
			logFile.Close()
		}
		return nil, fmt.Errorf("failed to start mubeng: %w", err)
	}

	// Wait briefly for mubeng to start listening
	if err := waitForPort(listenAddr, 5*time.Second); err != nil {
		// Kill if it didn't start properly
		killProcessGroup(cmd)
		if logFile != nil {
			logFile.Close()
			logFile = nil
		}

		if !isDynamicPort {
			return nil, fmt.Errorf("mubeng did not start listening on %s: %w", listenAddr, err)
		}

		// TOCTOU mitigation: retry once with a fresh port (M2)
		cmd, logFile, listenAddr, err = retryRotatorOnNewPort(ctx, cfg, binPath, args, listenAddr, err)
		if err != nil {
			return nil, err
		}
	}

	if logFile != nil {
		logFile.Close()
	}

	proxyURL := "http://" + listenAddr

	logger.FileDebug("mubeng started: pid=%d addr=%s", cmd.Process.Pid, listenAddr)

	return &Rotator{
		Addr:     listenAddr,
		ProxyURL: proxyURL,
		cmd:      cmd,
	}, nil
}

// buildRotatorArgs assembles the mubeng command-line arguments, applying
// defaults for rotation interval and method.
func buildRotatorArgs(cfg RotatorConfig, listenAddr string) []string {
	rotateEvery := cfg.RotateEvery
	if rotateEvery <= 0 {
		rotateEvery = 1
	}
	method := cfg.Method
	if method == "" {
		method = "random"
	}

	args := []string{
		"-f", cfg.ProxyListFile,
		"-a", listenAddr,
		"-r", fmt.Sprintf("%d", rotateEvery),
		"-m", method,
		"-t", "30s",
	}
	if cfg.Verbose {
		args = append(args, "-v")
	}
	return args
}

// attachRotatorOutput wires mubeng output: os.Stdout/Stderr in verbose mode,
// otherwise a mubeng.log file next to the proxy list. Returns the opened
// log file, or nil when verbose or the file cannot be created.
func attachRotatorOutput(cmd *exec.Cmd, cfg RotatorConfig) *os.File {
	if cfg.Verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return nil
	}
	logPath := filepath.Join(filepath.Dir(cfg.ProxyListFile), "mubeng.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	return logFile
}

// retryRotatorOnNewPort starts mubeng once more on a freshly allocated port.
// On success it returns the running cmd, its log file, and the new address.
func retryRotatorOnNewPort(ctx context.Context, cfg RotatorConfig, binPath string, args []string, prevAddr string, prevErr error) (*exec.Cmd, *os.File, string, error) {
	logger.FileDebug("mubeng failed to bind to port on %s: %v. Retrying once with a new port...", prevAddr, prevErr)
	port, err := findFreePort()
	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot find second free port: %w", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Rebuild arguments and cmd for new port
	args[3] = listenAddr
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	logFile := attachRotatorOutput(cmd, cfg)
	cmd.Stdin = nil

	if errStart := cmd.Start(); errStart != nil {
		if logFile != nil {
			logFile.Close()
		}
		return nil, nil, "", fmt.Errorf("failed to start mubeng on retry: %w", errStart)
	}

	if errWait := waitForPort(listenAddr, 5*time.Second); errWait != nil {
		killProcessGroup(cmd)
		if logFile != nil {
			logFile.Close()
		}
		return nil, nil, "", fmt.Errorf("mubeng did not start listening on retry %s: %w", listenAddr, errWait)
	}

	return cmd, logFile, listenAddr, nil
}

// Stop kills the mubeng process and its entire process group.
func (r *Rotator) Stop() {
	if r == nil || r.cmd == nil || r.cmd.Process == nil {
		return
	}
	killProcessGroup(r.cmd)
	// Wait briefly for clean exit
	done := make(chan struct{})
	go func() {
		_ = r.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	logger.FileDebug("mubeng stopped: pid=%d", r.cmd.Process.Pid)
}

// killProcessGroup sends SIGKILL to the entire process group.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// findFreePort asks the OS for an available TCP port on localhost.
func findFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	addr, ok := l.Addr().(*net.TCPAddr)
	_ = l.Close()
	if !ok {
		return 0, fmt.Errorf("unexpected non-TCP listener address")
	}
	return addr.Port, nil
}

// waitForPort polls until the given address is accepting TCP connections.
func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

// validateProxyList checks that the proxy list file exists and has at least one line.
func validateProxyList(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			return nil // at least one non-empty line
		}
	}
	return fmt.Errorf("proxy list file is empty: %s", path)
}
