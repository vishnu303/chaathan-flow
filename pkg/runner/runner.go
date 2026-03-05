package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/logger"
)

type Runner interface {
	Run(ctx context.Context, command string, args []string, opts ...Option) (string, error)
}

type NativeRunner struct {
	Verbose    bool
	MaxRetries int           // number of retries on failure (0 = no retry)
	RetryDelay time.Duration // delay between retries
}

type DockerRunner struct {
	Verbose    bool
	MaxRetries int
	RetryDelay time.Duration
}

type RunOptions struct {
	Dir     string
	Env     []string
	Timeout time.Duration // per-tool timeout (0 = use context timeout)
}

type Option func(*RunOptions)

func WithDir(dir string) Option {
	return func(o *RunOptions) {
		o.Dir = dir
	}
}

func WithTimeout(d time.Duration) Option {
	return func(o *RunOptions) {
		o.Timeout = d
	}
}

func (r *NativeRunner) Run(ctx context.Context, command string, args []string, opts ...Option) (string, error) {
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

	var lastErr error
	maxAttempts := r.MaxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		output, err := r.runOnce(runCtx, command, args, options)
		if err == nil {
			return output, nil
		}

		lastErr = err

		// Don't retry on context cancellation (user pressed Ctrl+C)
		if runCtx.Err() != nil {
			return output, fmt.Errorf("cancelled: %w", err)
		}

		// Log retry
		if attempt < maxAttempts {
			delay := r.RetryDelay
			if delay == 0 {
				delay = 3 * time.Second
			}
			logger.Warning("[Retry %d/%d] %s failed: %v — retrying in %s...",
				attempt, r.MaxRetries, command, err, delay)
			time.Sleep(delay)
		}
	}

	return "", lastErr
}

func (r *NativeRunner) runOnce(ctx context.Context, command string, args []string, options *RunOptions) (string, error) {
	var cmd *exec.Cmd

	switch command {
	case "cloud_enum":
		cmd = exec.CommandContext(ctx, "cloud_enum", args...)
	case "subdomainizer":
		cmd = exec.CommandContext(ctx, "subdomainizer", args...)
	default:
		cmd = exec.CommandContext(ctx, command, args...)
	}

	if options.Dir != "" {
		cmd.Dir = options.Dir
	}
	if len(options.Env) > 0 {
		cmd.Env = append(os.Environ(), options.Env...)
	}

	if r.Verbose {
		logger.Command(fmt.Sprintf("%s %s", command, strings.Join(args, " ")))
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if r.Verbose {
			logger.Debug("CMD Error: %v | Stderr: %s", err, stderr.String())
		}
		// Return stderr as error description if available
		if stderr.Len() > 0 {
			return stdout.String(), fmt.Errorf("%v: %s", err, stderr.String())
		}
		return stdout.String(), err
	}

	return stdout.String(), nil
}

func (r *DockerRunner) Run(ctx context.Context, command string, args []string, opts ...Option) (string, error) {
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

	var lastErr error
	maxAttempts := r.MaxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		output, err := r.runOnce(runCtx, command, args, options)
		if err == nil {
			return output, nil
		}

		lastErr = err

		if runCtx.Err() != nil {
			return output, fmt.Errorf("cancelled: %w", err)
		}

		if attempt < maxAttempts {
			delay := r.RetryDelay
			if delay == 0 {
				delay = 3 * time.Second
			}
			logger.Warning("[Retry %d/%d] %s (docker) failed: %v — retrying in %s...",
				attempt, r.MaxRetries, command, err, delay)
			time.Sleep(delay)
		}
	}

	return "", lastErr
}

func (r *DockerRunner) runOnce(ctx context.Context, command string, args []string, options *RunOptions) (string, error) {
	image := getDockerImage(command)

	// We do NOT use -t (tty) here because it messes up output capturing usually
	dockerArgs := []string{"run", "--rm", "-i"}

	pwd, _ := os.Getwd()
	dockerArgs = append(dockerArgs, "-v", fmt.Sprintf("%s:/data", pwd))
	dockerArgs = append(dockerArgs, "-w", "/data")

	dockerArgs = append(dockerArgs, image)

	if !isEntrypointImage(command) {
		switch command {
		// Handle cases where command needs to be passed to container
		default:
			dockerArgs = append(dockerArgs, command)
		}
	}

	dockerArgs = append(dockerArgs, args...)

	if r.Verbose {
		logger.Command(fmt.Sprintf("DOCKER %s", strings.Join(dockerArgs, " ")))
	}

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return stdout.String(), fmt.Errorf("%v: %s", err, stderr.String())
		}
		return stdout.String(), err
	}

	return stdout.String(), nil
}

func getDockerImage(tool string) string {
	switch tool {
	case "amass":
		return "caffix/amass"
	case "subfinder":
		return "projectdiscovery/subfinder"
	case "nuclei":
		return "projectdiscovery/nuclei"
	case "httpx":
		return "projectdiscovery/httpx"
	case "naabu":
		return "projectdiscovery/naabu"
	case "gau":
		return "sxcurity/gau"
	case "assetfinder":
		return "tomnomnom/assetfinder"
	case "metabigor":
		return "j3ssie/metabigor"
	case "dnsx":
		return "projectdiscovery/dnsx"
	case "katana":
		return "projectdiscovery/katana"
	case "gospider":
		return "jaeles-project/gospider"
	case "ffuf":
		return "ffuf/ffuf"
	case "waybackurls":
		return "sxcurity/waybackurls"
	case "linkfinder":
		return "ghcr.io/gerben-stavenga/linkfinder"
	case "cewl":
		return "digininja/cewl"
	case "github-endpoints":
		return "gwen001/github-endpoints"
	case "github-subdomains":
		return "gwen001/github-subdomains"
	// Phase 3 tools
	case "alterx":
		return "projectdiscovery/alterx"
	case "tlsx":
		return "projectdiscovery/tlsx"
	case "uncover":
		return "projectdiscovery/uncover"
	case "dalfox":
		return "hahwul/dalfox"
	case "subjack":
		return "alpine" // no official docker image
	default:
		return "alpine"
	}
}

func isEntrypointImage(tool string) bool {
	switch tool {
	case "amass", "nuclei", "httpx", "naabu", "subfinder", "dnsx", "katana", "ffuf", "cewl", "linkfinder",
		"alterx", "tlsx", "uncover", "dalfox":
		return true
	default:
		return false
	}
}

func New(mode string, verbose bool) Runner {
	if mode == "docker" {
		return &DockerRunner{Verbose: verbose}
	}
	return &NativeRunner{Verbose: verbose}
}

// NewWithRetry creates a runner with retry logic.
func NewWithRetry(mode string, verbose bool, maxRetries int, retryDelay time.Duration) Runner {
	if mode == "docker" {
		return &DockerRunner{Verbose: verbose, MaxRetries: maxRetries, RetryDelay: retryDelay}
	}
	return &NativeRunner{Verbose: verbose, MaxRetries: maxRetries, RetryDelay: retryDelay}
}
