package tools

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/vishnu303/chaathan/pkg/runner"
	"github.com/vishnu303/chaathan/utils"
)

func (t *ToolBox) RunSubfinder(ctx context.Context, domain string, outputFile string) error {
	args := []string{
		"-d", domain,
		"-silent",
		"-all",
		"-t", strconv.Itoa(t.subfinderThreads()),
		"-timeout", strconv.Itoa(t.subfinderTimeout()),
		"-o", outputFile,
	}

	// Pass API keys as env vars so subfinder picks them up as provider keys.
	var opts []runner.Option
	if t.APIKeys != nil {
		var envVars []string
		if t.APIKeys.VirusTotal != "" {
			envVars = append(envVars, "VT_API_KEY="+t.APIKeys.VirusTotal)
		}
		if t.APIKeys.Chaos != "" {
			envVars = append(envVars, "PDCP_API_KEY="+t.APIKeys.Chaos)
		}
		if t.APIKeys.SecurityTrails != "" {
			envVars = append(envVars, "SECURITYTRAILS_API_KEY="+t.APIKeys.SecurityTrails)
		}
		if t.APIKeys.Shodan != "" {
			envVars = append(envVars, "SHODAN_API_KEY="+t.APIKeys.Shodan)
		}
		if len(envVars) > 0 {
			opts = append(opts, runner.WithEnv(envVars...))
		}
	}

	opts = append(opts, runner.WithTimeout(t.subfinderMaxTimeout()))
	_, err := t.Runner.Run(ctx, ToolSubfinder, args, opts...)
	return err
}

func (t *ToolBox) RunAssetfinder(ctx context.Context, domain string, outputFile string) error {
	args := []string{"--subs-only", domain}
	output, err := t.Runner.Run(ctx, ToolAssetfinder, args, runner.WithTimeout(t.assetfinderTimeout()))
	// Keep only valid domain lines — assetfinder may emit banner/error noise on stdout.
	output = utils.FilterOutputLines(output, func(line string) bool {
		return utils.ValidateDomain(line) == nil
	})
	if output != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// RunSublist3r runs Sublist3r.
// Note: Sublist3r is a python tool, and the docker image (alpine) doesn't have python.
// Therefore, Sublist3r runs natively only; docker runner will fail due to lack of python in the alpine base.
func (t *ToolBox) RunSublist3r(ctx context.Context, domain string, outputFile string) error {
	args := []string{"-d", domain, "-t", "50", "-o", outputFile}
	_, err := t.Runner.Run(ctx, ToolSublist3r, args, runner.WithTimeout(t.sublist3rMaxTimeout()))
	return err
}

// --- Active Enumeration ---

func (t *ToolBox) RunAmass(ctx context.Context, domain string, outputFile string) error {
	args := []string{"enum", "-active", "-alts", "-d", domain, "-o", outputFile}
	if t.Config != nil && t.Config.Amass.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(t.Config.Amass.Timeout))
	}
	_, err := t.Runner.Run(ctx, ToolAmass, args, runner.WithTimeout(t.amassMaxTimeout()))
	return err
}

// RunAmassIntel runs `amass intel -whois` to discover root domains owned by an org.
func (t *ToolBox) RunAmassIntel(ctx context.Context, org string, outputFile string) error {
	args := []string{"intel", "-whois", "-d", org, "-o", outputFile}
	if t.Config != nil && t.Config.Amass.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(t.Config.Amass.Timeout))
	}
	_, err := t.Runner.Run(ctx, ToolAmass, args, runner.WithTimeout(t.amassMaxTimeout()))
	return err
}

// RunDnsx resolves hosts from inputFile. When resolversPath points to an
// existing resolver list it is passed via -r so dnsx honors the scan's
// configured resolvers instead of the system default.
func (t *ToolBox) RunDnsx(ctx context.Context, inputFile string, outputFile string, resolversPath string) error {
	args := []string{
		"-l", inputFile,
		"-a", "-aaaa", "-cname", "-mx", "-txt", "-resp", "-json",
		"-timeout", "3", // seconds per DNS query
		"-retry", "2", // retry failed queries twice before giving up
		"-wt", "5", // wildcard detection threshold
		"-o", outputFile,
	}
	if resolversPath != "" && utils.FileExists(resolversPath) {
		args = append(args, "-r", resolversPath)
	}
	_, err := t.Runner.Run(ctx, ToolDnsx, args, runner.WithTimeout(t.dnsxMaxTimeout()))
	return err
}

// --- Live Probing ---

// RunNaabuList port-scans all hosts from a file (the correct way for recon).
func (t *ToolBox) RunNaabuList(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-rate", strconv.Itoa(t.effectiveRate(t.naabuRate())),
		"-c", strconv.Itoa(t.naabuThreads()),
		"-timeout", "3", // seconds per probe; prevents hanging on filtered ports
		"-exclude-cdn",
		"-o", outputFile,
	}
	// Use explicit port list if configured, otherwise use -top-ports
	if ports := t.naabuPorts(); ports != "" {
		if strings.ToLower(ports) == "top" || strings.ToLower(ports) == "top-100" {
			args = append(args, "-top-ports", "100")
		} else if strings.ToLower(ports) == "top-1000" {
			args = append(args, "-top-ports", "1000")
		} else if strings.ToLower(ports) == "full" || strings.ToLower(ports) == "-" {
			args = append(args, "-p", "-")
		} else {
			args = append(args, "-p", ports)
		}
	} else {
		args = append(args, "-top-ports", strconv.Itoa(t.naabuTopPorts()))
	}
	args = t.appendProxy(args, "-proxy")
	_, err := t.Runner.Run(ctx, ToolNaabu, args, runner.WithTimeout(t.naabuMaxTimeout()))
	return err
}

// --- Web Crawling & Fuzzing ---

func (t *ToolBox) RunMetabigorNet(ctx context.Context, org string, outputFile string) error {
	args := []string{"net", "--org", "-v", org}
	output, err := t.Runner.Run(ctx, ToolMetabigor, args)
	if strings.TrimSpace(output) != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func (t *ToolBox) RunCloudEnum(ctx context.Context, keyword string, outputFile string) error {
	// Note: cloud_enum automatically appends ".json" to the log path specified by -l,
	// so the actual output file created will be outputFile + ".json".
	args := []string{"-k", keyword, "-l", outputFile}
	_, err := t.Runner.Run(ctx, ToolCloudEnum, args)
	return err
}

// --- URL Discovery ---

// RunWaybackurls fetches historical URLs from Wayback Machine

// RunGithubSubdomains searches GitHub for subdomains
func (t *ToolBox) RunGithubSubdomains(ctx context.Context, domain string, githubToken string, outputFile string) error {
	if githubToken == "" {
		return fmt.Errorf("github-subdomains requires a GitHub token")
	}
	args := []string{"-d", domain, "-t", githubToken, "-o", outputFile}
	_, err := t.Runner.Run(ctx, ToolGithubSubdomains, args, runner.WithTimeout(githubSubdomainsMaxTimeout))
	return err
}

// --- DNS Brute-force ---

// RunShuffleDNS performs DNS brute-forcing using shuffledns (massdns wrapper).
// It takes a domain, a wordlist for brute-forcing, and an optional resolvers file.
func (t *ToolBox) RunShuffleDNS(ctx context.Context, domain string, wordlist string, resolversFile string, outputFile string) error {
	if wordlist == "" {
		return fmt.Errorf("shuffledns requires a wordlist path")
	}
	args := []string{
		"-d", domain,
		"-w", wordlist,
		"-o", outputFile,
		"-silent",
	}
	if resolversFile != "" {
		args = append(args, "-r", resolversFile)
	}
	// Check for massdns in PATH and use it
	args = append(args, "-mode", "bruteforce")
	_, err := t.Runner.Run(ctx, "shuffledns", args, runner.WithTimeout(t.shufflednsMaxTimeout()))
	return err
}

// --- Subdomain Takeover ---

// RunNucleiTakeovers runs nuclei specifically for subdomain takeovers.

// RunTlsx grabs TLS certificate information from live hosts.
// tlsx v1.2.2 rejects -san/-cn when mixed with other probes, but plain JSON
// output already includes certificate metadata needed for post-processing.
func (t *ToolBox) RunTlsx(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-o", outputFile,
		"-json",
		"-silent",
		"-nc",
		"-duc",
		"-c", "50",
		"-timeout", "5", // seconds per TLS handshake; prevents hanging on blocked hosts
	}
	_, err := t.Runner.Run(ctx, ToolTlsx, args, runner.WithTimeout(t.tlsxMaxTimeout()))
	return err
}

// --- Passive Search Engine Recon ---

// RunUncover queries search engines (Shodan, Censys, Fofa, etc.) for exposed assets.
// 100% passive — no packets sent to the target.
// Returns ErrNoAPIKeys if no API keys are configured for any engine.
func (t *ToolBox) RunUncover(ctx context.Context, domain string, outputFile string) error {
	engines := t.uncoverEngines()
	if len(engines) == 0 {
		return fmt.Errorf("no uncover API keys configured — set shodan/censys/fofa/quake/zoomeye keys in config.yaml")
	}

	args := []string{
		"-q", domain,
		"-o", outputFile,
		"-json",
		"-silent",
		"-e", strings.Join(engines, ","),
		"-limit", "200",
	}

	var opts []runner.Option
	if t.APIKeys != nil {
		var envVars []string
		if t.APIKeys.Shodan != "" {
			envVars = append(envVars, "SHODAN_API_KEY="+t.APIKeys.Shodan)
		}
		if t.APIKeys.CensysID != "" && t.APIKeys.CensysSecret != "" {
			envVars = append(envVars, "CENSYS_API_ID="+t.APIKeys.CensysID, "CENSYS_API_SECRET="+t.APIKeys.CensysSecret)
		} else if t.APIKeys.Censys != "" {
			parts := strings.SplitN(t.APIKeys.Censys, ":", 2)
			if len(parts) == 2 {
				envVars = append(envVars, "CENSYS_API_ID="+parts[0], "CENSYS_API_SECRET="+parts[1])
			}
		}
		// FOFA classic two-factor auth requires both key + email.
		if t.APIKeys.Fofa != "" && t.APIKeys.FofaEmail != "" {
			envVars = append(envVars, "FOFA_KEY="+t.APIKeys.Fofa, "FOFA_EMAIL="+t.APIKeys.FofaEmail)
		}
		// Quake (360) — email + key pair.
		if t.APIKeys.Quake != "" && t.APIKeys.QuakeEmail != "" {
			envVars = append(envVars, "QUAKE_KEY="+t.APIKeys.Quake, "QUAKE_EMAIL="+t.APIKeys.QuakeEmail)
		}
		// ZoomEye — email + key pair.
		if t.APIKeys.ZoomEye != "" && t.APIKeys.ZoomEyeEmail != "" {
			envVars = append(envVars, "ZOOMEYE_KEY="+t.APIKeys.ZoomEye, "ZOOMEYE_EMAIL="+t.APIKeys.ZoomEyeEmail)
		}
		if len(envVars) > 0 {
			opts = append(opts, runner.WithEnv(envVars...))
		}
	}

	opts = append(opts, runner.WithTimeout(t.uncoverTimeout()))
	_, err := t.Runner.Run(ctx, ToolUncover, args, opts...)
	return err
}

// uncoverEngines returns only the engines for which API keys are configured.
// If no keys are set, returns an empty slice so RunUncover can skip gracefully.
func (t *ToolBox) uncoverEngines() []string {
	if t.APIKeys == nil {
		return nil
	}
	var engines []string
	if t.APIKeys.Shodan != "" {
		engines = append(engines, "shodan")
	}
	if t.APIKeys.Censys != "" || (t.APIKeys.CensysID != "" && t.APIKeys.CensysSecret != "") {
		engines = append(engines, "censys")
	}
	// FOFA classic needs both key and email; anything less is treated as unconfigured.
	if t.APIKeys.Fofa != "" && t.APIKeys.FofaEmail != "" {
		engines = append(engines, "fofa")
	}
	// Quake (360) needs both key and email.
	if t.APIKeys.Quake != "" && t.APIKeys.QuakeEmail != "" {
		engines = append(engines, "quake")
	}
	// ZoomEye needs both key and email.
	if t.APIKeys.ZoomEye != "" && t.APIKeys.ZoomEyeEmail != "" {
		engines = append(engines, "zoomeye")
	}
	return engines
}

// --- Fingerprinting & WAF ---

// RunHttpxFingerprint runs HTTPX purely for tech detection, gathering technologies used by live hosts.
