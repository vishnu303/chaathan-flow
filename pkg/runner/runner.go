package runner

import (
	"bytes"
	"chaathan/pkg/logger"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Runner interface {
	Run(ctx context.Context, command string, args []string, opts ...Option) (string, error)
}

type NativeRunner struct {
	Verbose bool
}

type DockerRunner struct {
	Verbose bool
}

type RunOptions struct {
	Dir string
	Env []string
}

type Option func(*RunOptions)

func WithDir(dir string) Option {
	return func(o *RunOptions) {
		o.Dir = dir
	}
}

func (r *NativeRunner) Run(ctx context.Context, command string, args []string, opts ...Option) (string, error) {
	var cmd *exec.Cmd
	
	switch command {
	case "cloud_enum":
		cmd = exec.CommandContext(ctx, "cloud_enum", args...)
	case "subdomainizer":
		cmd = exec.CommandContext(ctx, "subdomainizer", args...)
	default:
		cmd = exec.CommandContext(ctx, command, args...)
	}

	options := &RunOptions{}
	for _, o := range opts {
		o(options)
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
	default:
		return "alpine"
	}
}

func isEntrypointImage(tool string) bool {
	switch tool {
	case "amass", "nuclei", "httpx", "naabu", "subfinder", "dnsx", "katana", "ffuf", "cewl", "linkfinder":
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
