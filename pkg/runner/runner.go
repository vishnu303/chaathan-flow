package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
)

// Runner executes an external command, optionally with retries and a timeout.
type Runner interface {
	Run(ctx context.Context, command string, args []string, opts ...Option) (string, error)
}

// NativeRunner runs tools directly on the host.
type NativeRunner struct {
	Verbose    bool
	MaxRetries int           // number of retries on failure (0 = no retry)
	RetryDelay time.Duration // delay between retries
}

// DockerRunner runs tools inside Docker containers with path translation.
type DockerRunner struct {
	Verbose    bool
	MaxRetries int
	RetryDelay time.Duration
}

// RunOptions are per-run execution knobs set via Option funcs.
type RunOptions struct {
	Dir     string
	Env     []string
	Timeout time.Duration // per-tool timeout (0 = use context timeout)
	Stdin   func() io.Reader
	NoRetry bool // if true, disables retries for this run
}

// Option configures one field of RunOptions.
type Option func(*RunOptions)

// WithDir sets the working directory for the command.
func WithDir(dir string) Option {
	return func(o *RunOptions) {
		o.Dir = dir
	}
}

// WithNoRetry disables the retry loop for this single run.
func WithNoRetry() Option {
	return func(o *RunOptions) {
		o.NoRetry = true
	}
}

// WithTimeout sets a per-tool execution timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *RunOptions) {
		o.Timeout = d
	}
}

// WithEnv appends environment variables (in "KEY=VALUE" form) to the
// command's environment. The variables are added on top of os.Environ().
func WithEnv(env ...string) Option {
	return func(o *RunOptions) {
		o.Env = append(o.Env, env...)
	}
}

// WithStdin buffers the contents of the given reader once and returns a factory
// that produces a fresh reader from that buffer on every retry attempt. A read
// failure is logged (the partial buffer is used) rather than silently swallowed.
func WithStdin(r io.Reader) Option {
	var buf []byte
	if r != nil {
		var readErr error
		buf, readErr = io.ReadAll(r)
		if readErr != nil {
			logger.Warning("runner: failed to buffer stdin: %v (using partial input)", readErr)
		}
	}
	return func(o *RunOptions) {
		o.Stdin = func() io.Reader {
			return bytes.NewReader(buf)
		}
	}
}

// defaultRetryDelay is used when RetryDelay is zero; matches config default RetryDelaySec.
const defaultRetryDelay = 3 * time.Second

// ── Shared retry logic ──────────────────────────────────────────────────────

// runOnceFunc executes a single attempt and returns (stdout, error).
type runOnceFunc func(ctx context.Context) (string, error)

// retryRun executes fn up to maxRetries+1 times, with delay between attempts.
// It respects context cancellation and logs retries via logger.Warning.
func retryRun(ctx context.Context, command string, maxRetries int, retryDelay time.Duration, fn runOnceFunc) (string, error) {
	maxAttempts := maxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastOut string
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		output, err := fn(ctx)
		if err == nil {
			return output, nil
		}

		lastOut = output
		lastErr = err

		// Don't retry on context cancellation (user pressed Ctrl+C)
		if ctx.Err() != nil {
			return output, fmt.Errorf("cancelled: %w", err)
		}

		// Log retry
		if attempt < maxAttempts {
			delay := retryDelay
			if delay == 0 {
				delay = defaultRetryDelay
			}
			logger.Warning("[Retry %d/%d] %s failed: %v — retrying in %s...",
				attempt, maxAttempts, command, err, delay)

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return lastOut, fmt.Errorf("cancelled: %w", lastErr)
			}
		}
	}

	// Preserve whatever output the final attempt produced instead of dropping it.
	return lastOut, lastErr
}

// executeWithRetry abstracts the option processing, per-tool timeout context creation,
// and retry loop execution shared by both NativeRunner and DockerRunner.
func executeWithRetry(ctx context.Context, command string, maxRetries int, retryDelay time.Duration, opts []Option, runOnceFn func(context.Context, *RunOptions) (string, error)) (string, error) {
	options := &RunOptions{}
	for _, o := range opts {
		o(options)
	}

	// Apply per-tool timeout if configured
	runCtx := ctx
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	actualMaxRetries := maxRetries
	if options.NoRetry {
		actualMaxRetries = 0
	}

	return retryRun(runCtx, command, actualMaxRetries, retryDelay, func(rCtx context.Context) (string, error) {
		return runOnceFn(rCtx, options)
	})
}

// ── NativeRunner ────────────────────────────────────────────────────────────

func (r *NativeRunner) Run(ctx context.Context, command string, args []string, opts ...Option) (string, error) {
	return executeWithRetry(ctx, command, r.MaxRetries, r.RetryDelay, opts, func(rCtx context.Context, options *RunOptions) (string, error) {
		return r.runOnce(rCtx, command, args, options)
	})
}

func (r *NativeRunner) runOnce(ctx context.Context, command string, args []string, options *RunOptions) (string, error) {
	cmd := exec.CommandContext(ctx, command, args...)

	if options.Dir != "" {
		cmd.Dir = options.Dir
	}
	if len(options.Env) > 0 {
		cmd.Env = append(os.Environ(), options.Env...)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	cmdStr := formatCmdStr(command, args, options)
	// Always write command to log file (file-only, no terminal noise)
	logger.LogCommand(cmdStr)
	if r.Verbose {
		logger.Command(cmdStr)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if options.Stdin != nil {
		cmd.Stdin = options.Stdin()
	}

	err := startAndWait(ctx, cmd)
	if err != nil {
		// Distinguish user-skipped tools from real errors in log file
		if ctx.Err() != nil {
			logger.LogToolSkipped(command, cmdStr)
		} else {
			logger.LogToolFailure(command, cmdStr, stderr.String(), err)
		}
		if r.Verbose {
			logger.Debug("CMD Error: %v | Stderr: %s", err, stderr.String())
		}
		// Return stderr as error description if available
		if stderr.Len() > 0 {
			return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
		}
		return stdout.String(), err
	}

	return stdout.String(), nil
}

// ── DockerRunner ────────────────────────────────────────────────────────────

func (r *DockerRunner) Run(ctx context.Context, command string, args []string, opts ...Option) (string, error) {
	return executeWithRetry(ctx, command, r.MaxRetries, r.RetryDelay, opts, func(rCtx context.Context, options *RunOptions) (string, error) {
		return r.runOnce(rCtx, command, args, options)
	})
}

func (r *DockerRunner) runOnce(ctx context.Context, command string, args []string, options *RunOptions) (string, error) {
	mountDir := options.Dir
	if mountDir == "" {
		mountDir, _ = os.Getwd()
	}
	translatedArgs := translatePathsForDocker(args, mountDir)

	image := getDockerImage(command)

	// We do NOT use -t (tty) here because it messes up output capturing usually
	dockerArgs := []string{"run", "--rm", "-i"}

	// Mount the working directory
	if options.Dir != "" {
		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/data", options.Dir))
	} else {
		dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/data", mountDir))
	}
	dockerArgs = append(dockerArgs, "-w", "/data")

	// Mount nuclei config and templates if running nuclei in Docker
	if command == "nuclei" {
		if home, err := os.UserHomeDir(); err == nil {
			hostConfigDir := filepath.Join(home, ".config", "nuclei")
			hostTemplatesDir := filepath.Join(home, "nuclei-templates")
			// Create directories on host if they don't exist yet to prevent docker from creating them as root directories
			_ = os.MkdirAll(hostConfigDir, 0755)
			_ = os.MkdirAll(hostTemplatesDir, 0755)

			dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/root/.config/nuclei", hostConfigDir))
			dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/root/nuclei-templates", hostTemplatesDir))
		}
	}

	// Pass environment variables
	for _, env := range options.Env {
		dockerArgs = append(dockerArgs, "-e", env)
	}

	dockerArgs = append(dockerArgs, image)

	// For images that don't use ENTRYPOINT, the tool name must be passed as argv[0].
	if !isEntrypointImage(command) {
		dockerArgs = append(dockerArgs, command)
	}

	dockerArgs = append(dockerArgs, translatedArgs...)

	cmdStr := formatDockerCmdStr(dockerArgs, options)
	// Always write command to log file (file-only, no terminal noise)
	logger.LogCommand(cmdStr)
	if r.Verbose {
		logger.Command(cmdStr)
	}

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if options.Stdin != nil {
		cmd.Stdin = options.Stdin()
	}

	err := startAndWait(ctx, cmd)
	if err != nil {
		// Distinguish user-skipped tools from real errors in log file
		if ctx.Err() != nil {
			logger.LogToolSkipped(command, cmdStr)
		} else {
			logger.LogToolFailure(command, cmdStr, stderr.String(), err)
		}
		if stderr.Len() > 0 {
			return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
		}
		return stdout.String(), err
	}

	return stdout.String(), nil
}

// ── Shared helpers ──────────────────────────────────────────────────────────

// startAndWait ensures context cancellation terminates the entire process group,
// not just the top-level command. Many recon tools spawn child processes, and
// skip/cancel must tear those down so the workflow can advance immediately.
func startAndWait(ctx context.Context, cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		killProcessGroup(cmd)

		// Wait at most 2 seconds for process and its I/O to cleanly exit.
		// If child processes inherited stdout/stderr and didn't die from the group kill,
		// Wait() would block indefinitely. This prevents the hang.
		select {
		case err := <-done:
			if err == nil {
				return ctx.Err()
			}
			return err
		case <-time.After(2 * time.Second):
			return ctx.Err()
		}
	}
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	// Negative PID targets the entire process group created via Setpgid.
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}

// ── Docker image registry ────────────────────────────────────────────────────
//
// Single lookup table for tool → Docker image + entry-point flag.
// Tools without an official Docker image use "alpine" as a fallback,
// meaning they won't work in Docker mode. These are tagged with a comment
// so operators can supply custom images via config override.

type dockerImageInfo struct {
	Image      string // Docker Hub image name
	Entrypoint bool   // true if the image uses ENTRYPOINT (don't pass tool name)
}

var dockerImages = map[string]dockerImageInfo{
	// Project Discovery tools — all use ENTRYPOINT
	"subfinder":  {"projectdiscovery/subfinder", true},
	"nuclei":     {"projectdiscovery/nuclei", true},
	"httpx":      {"projectdiscovery/httpx", true},
	"naabu":      {"projectdiscovery/naabu", true},
	"dnsx":       {"projectdiscovery/dnsx", true},
	"katana":     {"projectdiscovery/katana", true},
	"tlsx":       {"projectdiscovery/tlsx", true},
	"uncover":    {"projectdiscovery/uncover", true},
	"shuffledns": {"projectdiscovery/shuffledns", true},

	// Third-party tools with ENTRYPOINT
	"amass":        {"caffix/amass", true},
	"ffuf":         {"ffuf/ffuf", true},
	"dalfox":       {"hahwul/dalfox", true},
	"GoLinkFinder": {"alpine", false}, // no official image; go binary compiled from source

	// Third-party tools WITHOUT ENTRYPOINT (need command passed)
	"assetfinder":       {"tomnomnom/assetfinder", false},
	"gau":               {"sxcurity/gau", false},
	"waybackurls":       {"sxcurity/waybackurls", false},
	"metabigor":         {"j3ssie/metabigor", false},
	"gospider":          {"jaeles-project/gospider", false},
	"github-subdomains": {"gwen001/github-subdomains", false},

	// No official Docker image — alpine fallback (won't work without custom image)
	"sublist3r":  {"alpine", false},           // Python script — no official image
	"cloud_enum": {"alpine", false},           // Python script — no official image
	"massdns":    {"alpine", false},           // compiled from source
	"anew":       {"alpine", false},           // tiny Go binary — unlikely to need Docker
	"gf":         {"alpine", false},           // tiny Go binary — unlikely to need Docker
	"x8":         {"alpine", false},           // Rust binary — no official Docker image
	"mubeng":     {"alpine", false},           // Go binary — no official Docker image
}

func getDockerImage(tool string) string {
	if info, ok := dockerImages[tool]; ok {
		return info.Image
	}
	logger.Warning("runner: no docker image registered for %q — using alpine fallback (likely won't work)", tool)
	return "alpine"
}

func isEntrypointImage(tool string) bool {
	if info, ok := dockerImages[tool]; ok {
		return info.Entrypoint
	}
	return false
}

// NewWithRetry creates a runner with retry logic for the given execution mode
// ("native" or "docker").
func NewWithRetry(mode string, verbose bool, maxRetries int, retryDelay time.Duration) Runner {
	if mode == "docker" {
		return &DockerRunner{Verbose: verbose, MaxRetries: maxRetries, RetryDelay: retryDelay}
	}
	return &NativeRunner{Verbose: verbose, MaxRetries: maxRetries, RetryDelay: retryDelay}
}

func translatePathsForDocker(args []string, hostDir string) []string {
	if hostDir == "" {
		return args
	}
	// Normalize hostDir to forward slashes for matching
	hostDirNormalized := strings.ReplaceAll(hostDir, "\\", "/")

	translated := make([]string, len(args))
	for i, arg := range args {
		// Normalize arg to forward slashes for matching
		argNormalized := strings.ReplaceAll(arg, "\\", "/")

		if len(argNormalized) >= len(hostDirNormalized) {
			argPrefix := argNormalized[:len(hostDirNormalized)]
			if strings.EqualFold(argPrefix, hostDirNormalized) {
				rel := argNormalized[len(hostDirNormalized):]
				translated[i] = "/data" + rel
				continue
			}
		}
		translated[i] = arg
	}
	return translated
}

func formatCmdStr(command string, args []string, options *RunOptions) string {
	quotedArgs := make([]string, len(args))
	for i, arg := range args {
		if strings.Contains(arg, " ") || strings.Contains(arg, "\t") {
			quotedArgs[i] = fmt.Sprintf("%q", arg)
		} else {
			quotedArgs[i] = arg
		}
	}

	var rawCmd string
	if len(quotedArgs) > 0 {
		rawCmd = command + " " + strings.Join(quotedArgs, " ")
	} else {
		rawCmd = command
	}

	if options != nil && options.Stdin != nil {
		stdinContent := ""
		if r := options.Stdin(); r != nil {
			if b, err := io.ReadAll(r); err == nil {
				stdinContent = strings.TrimSuffix(string(b), "\n")
			}
		}
		if stdinContent != "" {
			return fmt.Sprintf("echo %q | %s", stdinContent, rawCmd)
		}
		return "echo '' | " + rawCmd
	}

	return rawCmd
}

func formatDockerCmdStr(dockerArgs []string, options *RunOptions) string {
	quotedArgs := make([]string, len(dockerArgs))
	for i, arg := range dockerArgs {
		if strings.Contains(arg, " ") || strings.Contains(arg, "\t") {
			quotedArgs[i] = fmt.Sprintf("%q", arg)
		} else {
			quotedArgs[i] = arg
		}
	}

	rawCmd := "DOCKER " + strings.Join(quotedArgs, " ")

	if options != nil && options.Stdin != nil {
		stdinContent := ""
		if r := options.Stdin(); r != nil {
			if b, err := io.ReadAll(r); err == nil {
				stdinContent = strings.TrimSuffix(string(b), "\n")
			}
		}
		if stdinContent != "" {
			return fmt.Sprintf("echo %q | %s", stdinContent, rawCmd)
		}
		return "echo '' | " + rawCmd
	}

	return rawCmd
}
