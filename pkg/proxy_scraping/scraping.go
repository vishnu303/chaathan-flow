package proxy_scraping

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/tools"
)

// HarvestConfig controls the proxy scraping and validation.
type HarvestConfig struct {
	TimeoutMin      int      // max scraper runtime in minutes (default: 10)
	ProxyTypes      []string // preferred types: ["socks5","http","socks4"]
	MaxConcurrent   int      // concurrent checks (default: 256)
	OutputDir       string   // working directory for temp files and output
	CheckTimeoutSec int      // mubeng per-check timeout in seconds (default: 5)
}

// HarvestResult holds the output of a proxy scraping run.
type HarvestResult struct {
	ProxyListFile string        // path to proxy_pool.txt (one proxy per line)
	TotalScraped  int           // proxies scraped from sources
	TotalValid    int           // proxies that passed check
	AllValid      []string      // all valid proxy URLs
	Duration      time.Duration // wall-clock duration of the harvest
}

// Source URLs from the original proxy-scraper-checker template.
// L1: These slices are read-only internals and should not be mutated from outside.
var httpSources = []string{
	"https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http",
	"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
	"https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/http/data.txt",
	"https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
	"https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/http_proxies.txt",
	"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
	"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
	"https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",
	"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
}

var socks4Sources = []string{
	"https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks4",
	"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks4.txt",
	"https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks4/data.txt",
	"https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS4_RAW.txt",
	"https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks4_proxies.txt",
	"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
	"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
	"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
}

var socks5Sources = []string{
	"https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5",
	"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt",
	"https://raw.githubusercontent.com/hookzof/socks5_list/refs/heads/master/proxy.txt",
	"https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
	"https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS5_RAW.txt",
	"https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks5_proxies.txt",
	"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
	"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
	"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
}

// contains checks if a string is present in a slice (case-insensitive).
// If the slice is empty, it returns true to enable all protocols by default.
func contains(slice []string, val string) bool {
	if len(slice) == 0 {
		return true
	}
	for _, item := range slice {
		if strings.EqualFold(item, val) {
			return true
		}
	}
	return false
}

// RunHarvest fetches proxies, validates them with mubeng, and writes valid proxies.
func RunHarvest(ctx context.Context, cfg HarvestConfig) (*HarvestResult, error) {
	start := time.Now()

	// 1. Verify mubeng is installed
	mubengPath, err := exec.LookPath("mubeng")
	if err != nil {
		return nil, fmt.Errorf("mubeng not found: install via 'chaathan setup' or 'go install github.com/mubeng/mubeng@latest'")
	}

	// 2. Setup working directory
	workDir := filepath.Join(cfg.OutputDir, "proxy_scraping_work")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create proxy scraping work dir: %w", err)
	}

	// Clean up stale files from previous runs to prevent reusing old results
	_ = os.Remove(filepath.Join(workDir, "raw_proxies.txt"))
	_ = os.Remove(filepath.Join(workDir, "live_proxies.txt"))
	_ = os.Remove(filepath.Join(cfg.OutputDir, "proxy_pool.txt"))

	// 3. Apply timeout
	timeoutMin := cfg.TimeoutMin
	if timeoutMin <= 0 {
		timeoutMin = 10
	}
	harvestCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMin)*time.Minute)
	defer cancel()

	// 4. Phase 1: Fetch proxies from sources
	rawProxiesPath := filepath.Join(workDir, "raw_proxies.txt")
	totalScraped, err := fetchProxySources(harvestCtx, cfg.ProxyTypes, rawProxiesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch proxies: %w", err)
	}

	if totalScraped == 0 {
		return &HarvestResult{Duration: time.Since(start)}, nil
	}
	logger.FileDebug("Scraped %d total proxies to %s", totalScraped, rawProxiesPath)

	// 5. Phase 2: Validate with mubeng
	liveProxiesPath := filepath.Join(workDir, "live_proxies.txt")
	
	// mubeng checking args
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 256
	}

	logger.SubStep("Validating proxies with mubeng...")

	checkTimeoutSec := cfg.CheckTimeoutSec
	if checkTimeoutSec <= 0 {
		checkTimeoutSec = 5
	}

	cmd := exec.Command(mubengPath,
		"-f", rawProxiesPath,
		"--check",
		"--output", liveProxiesPath,
		"-g", fmt.Sprintf("%d", maxConcurrent),
		"-t", fmt.Sprintf("%ds", checkTimeoutSec),
	)
	cmd.Dir = workDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Capture output
	logPath := filepath.Join(workDir, "mubeng-check.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("cannot create mubeng log file: %w", err)
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var runErr error
	select {
	case runErr = <-done:
		// completed naturally
	case <-harvestCtx.Done():
		if ctx.Err() != nil {
			logger.Info("Proxy check cancelled/skipped — saving checked proxies...")
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			<-done
		} else {
			logger.Info("Proxy check reached timeout — stopping gracefully...")
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
			}

			select {
			case runErr = <-done:
			case <-time.After(5 * time.Second):
				if cmd.Process != nil {
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				}
				runErr = <-done
			}
		}
	}

	if runErr != nil {
		// Log but don't strictly fail, maybe some proxies were saved
		logger.FileDebug("mubeng check exited with error: %v", runErr)
	}

	// 6. Read valid proxies
	var allValid []string
	if data, err := os.ReadFile(liveProxiesPath); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				allValid = append(allValid, line)
			}
		}
	}

	// 7. Write to pool
	proxyListFile := filepath.Join(cfg.OutputDir, "proxy_pool.txt")
	if len(allValid) > 0 {
		if err := os.WriteFile(proxyListFile, []byte(strings.Join(allValid, "\n")+"\n"), 0644); err != nil {
			return nil, fmt.Errorf("cannot write proxy pool file: %w", err)
		}
	}

	return &HarvestResult{
		ProxyListFile: proxyListFile,
		TotalScraped:  totalScraped,
		TotalValid:    len(allValid),
		AllValid:      allValid,
		Duration:      time.Since(start),
	}, nil
}

// fetchProxySources concurrently fetches proxy lists and writes them to outPath.
func fetchProxySources(ctx context.Context, proxyTypes []string, outPath string) (int, error) {
	var sources []struct {
		url      string
		protocol string
	}

	if contains(proxyTypes, "http") {
		for _, u := range httpSources {
			sources = append(sources, struct{ url, protocol string }{u, "http"})
		}
	}
	if contains(proxyTypes, "socks4") {
		for _, u := range socks4Sources {
			sources = append(sources, struct{ url, protocol string }{u, "socks4"})
		}
	}
	if contains(proxyTypes, "socks5") {
		for _, u := range socks5Sources {
			sources = append(sources, struct{ url, protocol string }{u, "socks5"})
		}
	}

	var mu sync.Mutex
	uniqueProxies := make(map[string]bool)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	var wg sync.WaitGroup
	for _, src := range sources {
		wg.Add(1)
		go func(srcUrl, protocol string) {
			defer wg.Done()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srcUrl, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", tools.RandomUA())

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return
			}

			scanner := bufio.NewScanner(resp.Body)
			var localProxies []string
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "<") {
					continue
				}
				// Basic sanity check for host:port format
				if strings.Contains(line, ":") && !strings.Contains(line, "://") {
					localProxies = append(localProxies, fmt.Sprintf("%s://%s", protocol, line))
				} else if strings.Contains(line, "://") {
					localProxies = append(localProxies, line)
				}
			}

			mu.Lock()
			for _, p := range localProxies {
				uniqueProxies[p] = true
			}
			mu.Unlock()
		}(src.url, src.protocol)
	}

	wg.Wait()

	if len(uniqueProxies) == 0 {
		return 0, nil
	}

	var all []string
	for p := range uniqueProxies {
		all = append(all, p)
	}

	if err := os.WriteFile(outPath, []byte(strings.Join(all, "\n")+"\n"), 0644); err != nil {
		return 0, err
	}

	return len(all), nil
}


