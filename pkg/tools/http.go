package tools

import (
	"context"
	"strconv"
	"strings"

	"github.com/vishnu303/chaathan/pkg/runner"
	"github.com/vishnu303/chaathan/utils"
)

func (t *ToolBox) RunGau(ctx context.Context, domain string, outputFile string) error {
	args := []string{
		"--providers", "wayback,commoncrawl,otx,urlscan",
		"--subs",
		"--threads", "3",
		"--blacklist", "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot",
		domain,
	}
	args = t.appendProxy(args, "--proxy")
	output, err := t.Runner.Run(ctx, ToolGau, args, runner.WithTimeout(t.gauMaxTimeout()))
	// Keep only absolute http(s) URL lines — gau may print warnings to stdout.
	output = utils.FilterOutputLines(output, utils.IsValidHTTPURL)
	if output != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// --- DNS & Brute Force ---

func (t *ToolBox) RunHttpx(ctx context.Context, domainsFile string, outputFile string) error {
	args := []string{
		"-l", domainsFile,
		"-ports", t.httpxPorts(),
		"-threads", strconv.Itoa(t.httpxThreads()),
		"-timeout", strconv.Itoa(t.httpxTimeout()),
		"-tech-detect", "-title", "-status-code", "-content-length", "-web-server", "-json",
		"-o", outputFile,
	}
	if t.Config != nil && t.Config.Httpx.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	args = t.appendCommon(args, appendOptions{
		uaHeader:    true,
		tlsOpSec:    true,
		customHFlag: "-H",
		cookieFlag:  "-cookie",
		proxyFlag:   "-http-proxy",
	})
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rl", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, ToolHttpx, args)
	return err
}

// RunNaabuList port-scans all hosts from a file (the correct way for recon).

func (t *ToolBox) RunGoSpider(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{"-S", inputFile, "-q", "-c", "10", "-d", "3", "-t", "10", "--include-subs"} // -t = per-request timeout (seconds)
	args = t.appendGoSpiderUA(args)
	output, err := t.Runner.Run(ctx, ToolGospider, args, runner.WithTimeout(t.goSpiderMaxTimeout()))
	// Keep only absolute http(s) URL lines — gospider may emit tagged lines and
	// progress notices on stdout even with -q.
	output = utils.FilterOutputLines(output, utils.IsValidHTTPURL)
	if output != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

func (t *ToolBox) RunKatana(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-list", inputFile,
		"-o", outputFile,
		"-jc",
		"-d", "3",
		"-aff",
		"-kf", "all",
		"-c", "10",
		"-timeout", "15", // seconds per request; extra headroom for proxy pools
	}
	args = t.appendCommon(args, appendOptions{
		uaHeader:    true,
		tlsOpSec:    true,
		customHFlag: "-H",
		proxyFlag:   "-proxy",
	})
	if t.CustomCookie != "" {
		args = append(args, "-H", "Cookie: "+t.CustomCookie)
	}
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, ToolKatana, args, runner.WithTimeout(t.katanaMaxTimeout()))
	return err
}

// RunWaybackurls fetches historical URLs from Wayback Machine
func (t *ToolBox) RunWaybackurls(ctx context.Context, domain string, outputFile string) error {
	args := []string{}
	// waybackurls reads the domain from standard input
	output, err := t.Runner.Run(ctx, ToolWaybackurls, args, runner.WithStdin(strings.NewReader(domain+"\n")), runner.WithTimeout(t.waybackurlsMaxTimeout()))
	// Keep only absolute http(s) URL lines — waybackurls may emit API noise on stdout.
	output = utils.FilterOutputLines(output, utils.IsValidHTTPURL)
	if output != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// RunJsluiceURLs extracts URLs and API routes from a local JavaScript file
// using jsluice's AST-based analysis. Output is JSON lines written to outputFile.

// RunHttpxURLCheck live-checks a list of URLs (not subdomains) and outputs only live URLs.
// Intentionally omits -status-code to prevent format poisoning in downstream nuclei runs and in-process gf-pattern matching.
func (t *ToolBox) RunHttpxURLCheck(ctx context.Context, urlsFile string, outputFile string) error {
	args := []string{
		"-l", urlsFile,
		"-threads", strconv.Itoa(t.httpxThreads()),
		"-timeout", strconv.Itoa(t.httpxTimeout()),
		"-no-fallback",
		"-o", outputFile,
	}
	if t.Config != nil && t.Config.Httpx.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	args = t.appendCommon(args, appendOptions{
		uaHeader:    true,
		tlsOpSec:    true,
		customHFlag: "-H",
		cookieFlag:  "-cookie",
		proxyFlag:   "-http-proxy",
	})
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rl", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, ToolHttpx, args)
	return err
}

// RunGithubSubdomains searches GitHub for subdomains

// RunHttpxFingerprint runs HTTPX purely for tech detection, gathering technologies used by live hosts.
func (t *ToolBox) RunHttpxFingerprint(ctx context.Context, inputFile string, outputFile string) error {
	args := []string{
		"-l", inputFile,
		"-threads", strconv.Itoa(t.httpxThreads()),
		"-timeout", strconv.Itoa(t.httpxTimeout()),
		"-tech-detect", "-json",
		"-o", outputFile,
	}
	args = t.appendCommon(args, appendOptions{
		uaHeader:    true,
		tlsOpSec:    true,
		customHFlag: "-H",
		cookieFlag:  "-cookie",
		proxyFlag:   "-http-proxy",
	})
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rl", strconv.Itoa(rps))
	}
	_, err := t.Runner.Run(ctx, ToolHttpx, args, runner.WithTimeout(t.httpxFingerprintTimeout()))
	return err
}

// RunNucleiWAF runs Nuclei specifically for WAF detection with a conservative rate limit.
