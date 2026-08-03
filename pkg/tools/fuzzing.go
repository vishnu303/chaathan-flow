package tools

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/vishnu303/chaathan/pkg/runner"
)

func (t *ToolBox) buildFfufArgs(url string, wordlist string, outputFile string) []string {
	args := []string{
		"-u", url,
		"-w", wordlist,
		"-mc", t.ffufMatchCodes(),
		"-fc", "404",
		"-ac", // auto-calibrate: detect and filter uniform responses
		"-o", outputFile,
		"-of", "json",
		"-t", strconv.Itoa(t.ffufThreads()),
		"-timeout", strconv.Itoa(t.ffufTimeout()),
	}
	args = t.appendCommon(args, appendOptions{
		uaHeader:    true,
		customHFlag: "-H",
		cookieFlag:  "-b",
		proxyFlag:   "-x",
	})
	if rps := t.globalRPS(); rps > 0 {
		args = append(args, "-rate", strconv.Itoa(rps))
	}
	return args
}

// RunFfufWithFUZZ runs ffuf with a FUZZ placeholder in the URL.
// No per-host timeout is applied; the caller should wrap the entire
// fuzzing loop with a single context deadline (ffuf MaxTimeout).
func (t *ToolBox) RunFfufWithFUZZ(ctx context.Context, baseURL string, wordlist string, outputFile string) error {
	if wordlist == "" {
		return fmt.Errorf("ffuf requires a wordlist path")
	}
	// Ensure FUZZ is in URL
	url := baseURL
	if !strings.Contains(url, "FUZZ") {
		url = baseURL + "/FUZZ"
	}
	args := t.buildFfufArgs(url, wordlist, outputFile)
	_, err := t.Runner.Run(ctx, ToolFfuf, args)
	return err
}

// RunNucleiSmartCVE runs tech-targeted CVE scanning using Nuclei's -as (automatic scan).
// Wappalyzer fingerprints each host and selects only templates matching detected technologies.
// This reduces effective template count from ~3,800 to ~100-400 per host.

// RunX8WithWordlist discovers hidden HTTP parameters using x8 and the given wordlist.
func (t *ToolBox) RunX8WithWordlist(ctx context.Context, inputFile string, outputFile string, wordlist string) error {
	args := []string{"-u", inputFile, "-o", outputFile, "-O", "json"}
	if wordlist != "" {
		if _, err := os.Stat(wordlist); err == nil {
			args = append(args, "-w", wordlist)
		}
	} else if t.General != nil && t.General.Wordlists.Parameters != "" {
		if _, err := os.Stat(t.General.Wordlists.Parameters); err == nil {
			args = append(args, "-w", t.General.Wordlists.Parameters)
		}
	}

	args = t.appendX8Headers(args)

	if p := t.proxy(); p != "" {
		args = append(args, "-x", p)
	}

	// NoRetry: a retry would re-run the full (up to 2h) discovery and append a
	// second JSON document to outputFile, invalidating whole-file parsing below.
	_, err := t.Runner.Run(ctx, ToolX8, args, runner.WithTimeout(t.x8MaxTimeout()), runner.WithNoRetry())
	return err
}

// RunHttpxURLCheck live-checks a list of URLs (not subdomains) and outputs only live URLs.
// Intentionally omits -status-code to prevent format poisoning in downstream nuclei runs and in-process gf-pattern matching.
