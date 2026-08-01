package tools_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/tools"
	"github.com/vishnu303/chaathan/test/pkg/runner/runnerfaketest"
)

func TestToolBoxOptionsAndHelpers(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)

	if tb == nil {
		t.Fatal("expected non-nil ToolBox")
	}

	// 1. Random User-Agent
	ua := tools.RandomUA()
	if len(ua) == 0 {
		t.Error("expected non-empty User-Agent")
	}

	// 2. Custom Auth configuration
	tb.WithCustomAuth("cookie_val", []string{"Auth: token_val"})
	if tb.CustomCookie != "cookie_val" {
		t.Errorf("expected cookie_val, got %q", tb.CustomCookie)
	}
	if len(tb.CustomHeaders) != 1 || tb.CustomHeaders[0] != "Auth: token_val" {
		t.Errorf("unexpected custom headers: %v", tb.CustomHeaders)
	}

	// 3. Configurations attaching
	gen := &config.GeneralConfig{UARotation: true, Proxy: "http://proxy"}
	tb.WithGeneral(gen)
	tb.WithRateLimits(&config.RateLimitConfig{GlobalRPS: 100})
	tb.WithAPIKeys(&config.APIKeysConfig{GitHub: "github_token"})

	// 4. Test tool invocation (Subfinder)
	ctx := context.Background()
	err := tb.RunSubfinder(ctx, "target.com", "out.txt")
	if err != nil {
		t.Fatalf("unexpected error running Subfinder: %v", err)
	}

	if dr.LastCmd != "subfinder" {
		t.Errorf("expected command 'subfinder', got %q", dr.LastCmd)
	}

	// Check arguments contains target domain
	argsJoined := strings.Join(dr.LastArgs, " ")
	if !strings.Contains(argsJoined, "-d target.com") {
		t.Errorf("expected arguments to contain domain target.com, got %q", argsJoined)
	}
}

func TestX8Headers(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)

	tb.WithCustomAuth("my_cookie_val", []string{"X-My-Header: header_val"})
	// Set general config
	tb.WithGeneral(&config.GeneralConfig{UARotation: false})

	ctx := context.Background()
	err := tb.RunX8(ctx, "in.txt", "out.json")
	if err != nil {
		t.Fatalf("unexpected error running x8: %v", err)
	}

	if dr.LastCmd != "x8" {
		t.Errorf("expected command 'x8', got %q", dr.LastCmd)
	}

	// Verify that "-H" arguments are present with correct values
	foundCookie := false
	foundCustomHeader := false
	for i, arg := range dr.LastArgs {
		if arg == "-H" && i+1 < len(dr.LastArgs) {
			val := dr.LastArgs[i+1]
			if strings.Contains(val, "Cookie: my_cookie_val") {
				foundCookie = true
			}
			if strings.Contains(val, "X-My-Header: header_val") {
				foundCustomHeader = true
			}
		}
	}
	if !foundCookie {
		t.Error("expected -H 'Cookie: my_cookie_val' argument in x8 command")
	}
	if !foundCustomHeader {
		t.Error("expected -H 'X-My-Header: header_val' argument in x8 command")
	}
}

func TestGoSpiderUA(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)
	tb.WithGeneral(&config.GeneralConfig{UserAgent: "custom_gospider_ua"})

	ctx := context.Background()
	err := tb.RunGoSpider(ctx, "in.txt", "out.txt")
	if err != nil {
		t.Fatalf("unexpected error running GoSpider: %v", err)
	}

	if dr.LastCmd != "gospider" {
		t.Errorf("expected command 'gospider', got %q", dr.LastCmd)
	}

	foundUA := false
	for i, arg := range dr.LastArgs {
		if arg == "-u" && i+1 < len(dr.LastArgs) {
			foundUA = true
			if dr.LastArgs[i+1] != "custom_gospider_ua" {
				t.Errorf("expected custom_gospider_ua, got %q", dr.LastArgs[i+1])
			}
			break
		}
	}
	if !foundUA {
		t.Error("expected native -u argument in GoSpider command")
	}
}

func TestDalfoxUA(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)
	tb.WithGeneral(&config.GeneralConfig{UserAgent: "custom_dalfox_ua"})

	ctx := context.Background()
	err := tb.RunDalfox(ctx, "in.txt", "out.jsonl")
	if err != nil {
		t.Fatalf("unexpected error running Dalfox: %v", err)
	}

	if dr.LastCmd != "dalfox" {
		t.Errorf("expected command 'dalfox', got %q", dr.LastCmd)
	}

	foundUA := false
	for i, arg := range dr.LastArgs {
		if arg == "--user-agent" && i+1 < len(dr.LastArgs) {
			foundUA = true
			if dr.LastArgs[i+1] != "custom_dalfox_ua" {
				t.Errorf("expected custom_dalfox_ua, got %q", dr.LastArgs[i+1])
			}
			break
		}
	}
	if !foundUA {
		t.Error("expected native --user-agent argument in Dalfox command")
	}
}

func TestRunAmassIntel(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)

	// Attach amass config
	tb.Config = &config.ToolsConfig{
		Amass: config.AmassConfig{
			Timeout: 45,
		},
	}

	ctx := context.Background()
	err := tb.RunAmassIntel(ctx, "company_name", "root_domains.txt")
	if err != nil {
		t.Fatalf("unexpected error running RunAmassIntel: %v", err)
	}

	if dr.LastCmd != "amass" {
		t.Errorf("expected command 'amass', got %q", dr.LastCmd)
	}

	// Verify arguments: intel, -whois, -d, company_name, -o, root_domains.txt, -timeout, 45
	argsJoined := strings.Join(dr.LastArgs, " ")
	expectedArgs := []string{"intel", "-whois", "-d company_name", "-o root_domains.txt", "-timeout 45"}
	for _, expected := range expectedArgs {
		if !strings.Contains(argsJoined, expected) {
			t.Errorf("expected arguments to contain %q, got %q", expected, argsJoined)
		}
	}
}

func TestRunUncoverEnvVars(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)
	tb.APIKeys = &config.APIKeysConfig{
		Shodan:       "shodan_key",
		CensysID:     "censys_id_val",
		CensysSecret: "censys_secret_val",
	}

	ctx := context.Background()
	err := tb.RunUncover(ctx, "target.com", "out.txt")
	if err != nil {
		t.Fatalf("unexpected error running RunUncover: %v", err)
	}

	opts := dr.GetOptions()
	expectedEnv := []string{"SHODAN_API_KEY=shodan_key", "CENSYS_API_ID=censys_id_val", "CENSYS_API_SECRET=censys_secret_val"}
	for _, env := range expectedEnv {
		found := false
		for _, e := range opts.Env {
			if e == env {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected env var %q, not found in options.Env: %v", env, opts.Env)
		}
	}

	// Only shodan + censys were configured; fofa/quake/zoomeye must NOT be selected.
	argsJoined := strings.Join(dr.LastArgs, " ")
	for _, unwanted := range []string{"fofa", "quake", "zoomeye"} {
		if strings.Contains(argsJoined, ","+unwanted) || strings.Contains(argsJoined, unwanted+",") || argsJoined == "-e "+unwanted {
			t.Errorf("engine %q should not be selected when its keys are missing; got args %q", unwanted, argsJoined)
		}
	}
}

// TestRunUncoverFofaQuakeZoomEye covers the F-022 wiring fix: when FOFA,
// Quake, and ZoomEye are fully configured (key + email), all three engines
// must be selected and their env vars must be exported to the runner.
func TestRunUncoverFofaQuakeZoomEye(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)
	tb.APIKeys = &config.APIKeysConfig{
		Fofa:         "fofa_key",
		FofaEmail:    "fofa@example.com",
		Quake:        "quake_key",
		QuakeEmail:   "quake@example.com",
		ZoomEye:      "zoomeye_key",
		ZoomEyeEmail: "zoomeye@example.com",
	}

	ctx := context.Background()
	if err := tb.RunUncover(ctx, "target.com", "out.txt"); err != nil {
		t.Fatalf("unexpected error running RunUncover: %v", err)
	}

	// Engines selection: all three must appear in -e.
	argsJoined := strings.Join(dr.LastArgs, " ")
	for _, want := range []string{"fofa", "quake", "zoomeye"} {
		if !strings.Contains(argsJoined, want) {
			t.Errorf("engine %q missing from -e selection; got %q", want, argsJoined)
		}
	}

	// Env var wiring.
	opts := dr.GetOptions()
	wantEnv := []string{
		"FOFA_KEY=fofa_key", "FOFA_EMAIL=fofa@example.com",
		"QUAKE_KEY=quake_key", "QUAKE_EMAIL=quake@example.com",
		"ZOOMEYE_KEY=zoomeye_key", "ZOOMEYE_EMAIL=zoomeye@example.com",
	}
	for _, env := range wantEnv {
		found := false
		for _, e := range opts.Env {
			if e == env {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected env var %q, not found in options.Env: %v", env, opts.Env)
		}
	}
}

// TestRunUncoverFofaPartialConfig verifies F-022 fix robustness: a half-set
// FOFA (key only, email missing) must NOT select the fofa engine, and must
// NOT emit a stale warning. It should run with no engines selected and
// surface the actionable error message.
func TestRunUncoverFofaPartialConfig(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)
	tb.APIKeys = &config.APIKeysConfig{
		Fofa:      "fofa_key",
		FofaEmail: "", // intentionally missing — must drop fofa from engines
	}

	if err := tb.RunUncover(context.Background(), "target.com", "out.txt"); err == nil {
		t.Fatalf("expected no-api-keys error when only a partial FOFA is configured, got nil")
	}
}

func TestRunKatanaProxy(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)
	tb.WithGeneral(&config.GeneralConfig{Proxy: "http://katana-proxy:8080"})

	ctx := context.Background()
	err := tb.RunKatana(ctx, "in.txt", "out.txt")
	if err != nil {
		t.Fatalf("unexpected error running RunKatana: %v", err)
	}

	argsJoined := strings.Join(dr.LastArgs, " ")
	if !strings.Contains(argsJoined, "-proxy http://katana-proxy:8080") {
		t.Errorf("expected arguments to contain proxy, got %q", argsJoined)
	}
}

func TestNucleiScanAppendCommon(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)
	tb.WithGeneral(&config.GeneralConfig{Proxy: "socks5://127.0.0.1:9050", UserAgent: "nuclei_ua"})
	tb.WithCustomAuth("cookie_val", []string{"Auth: token"})

	scanner, err := tb.GetScanner("nuclei")
	if err != nil {
		t.Fatalf("unexpected error getting nuclei scanner: %v", err)
	}

	ctx := context.Background()
	err = scanner.Scan(ctx, "targets.txt", "out.txt", tools.ScanOptions{
		Mode: "standard",
	})
	if err != nil {
		t.Fatalf("unexpected error running nuclei Scan: %v", err)
	}

	argsJoined := strings.Join(dr.LastArgs, " ")
	if !strings.Contains(argsJoined, "User-Agent: nuclei_ua") {
		t.Errorf("expected arguments to contain User-Agent header, got %q", argsJoined)
	}
	if !strings.Contains(argsJoined, "-proxy socks5://127.0.0.1:9050") {
		t.Errorf("expected arguments to contain proxy, got %q", argsJoined)
	}
	if !strings.Contains(argsJoined, "-H Auth: token") {
		t.Errorf("expected arguments to contain custom Auth header, got %q", argsJoined)
	}
	if !strings.Contains(argsJoined, "Cookie: cookie_val") {
		t.Errorf("expected arguments to contain custom Cookie, got %q", argsJoined)
	}
}

func TestBuildFfufArgs(t *testing.T) {
	tb := tools.New(&runnerfaketest.DummyRunner{})
	tb.WithGeneral(&config.GeneralConfig{Proxy: "http://ffuf-proxy"})

	args := tb.RunFfufArgsTestHelper("http://target.com", "wordlist.txt", "out.json")
	argsJoined := strings.Join(args, " ")

	expected := []string{"-u http://target.com", "-w wordlist.txt", "-o out.json", "-x http://ffuf-proxy"}
	for _, exp := range expected {
		if !strings.Contains(argsJoined, exp) {
			t.Errorf("expected arguments to contain %q, got %q", exp, argsJoined)
		}
	}
}

func TestRunNaabuListPortParsing(t *testing.T) {
	tests := []struct {
		ports        string
		expectedArgs []string
	}{
		{"top", []string{"-top-ports", "100"}},
		{"top-100", []string{"-top-ports", "100"}},
		{"top-1000", []string{"-top-ports", "1000"}},
		{"full", []string{"-p", "-"}},
		{"-", []string{"-p", "-"}},
		{"80,443,8080", []string{"-p", "80,443,8080"}},
	}

	for _, tc := range tests {
		dr := &runnerfaketest.DummyRunner{}
		tb := tools.New(dr)
		tb.Config = &config.ToolsConfig{
			Naabu: config.NaabuConfig{
				Ports: tc.ports,
			},
		}

		ctx := context.Background()
		_ = tb.RunNaabuList(ctx, "hosts.txt", "out.txt")

		argsJoined := strings.Join(dr.LastArgs, " ")
		for _, exp := range tc.expectedArgs {
			if !strings.Contains(argsJoined, exp) {
				t.Errorf("for ports=%q, expected arguments to contain %q, got %q", tc.ports, exp, argsJoined)
			}
		}
	}
}

func TestAppendCommonMatrix(t *testing.T) {
	tb := tools.New(&runnerfaketest.DummyRunner{})
	tb.WithGeneral(&config.GeneralConfig{UserAgent: "test_ua", Proxy: "http://proxy"})
	tb.WithCustomAuth("cookie_val", []string{"X-Test: header_val"})

	args := tb.AppendCommonTestHelper([]string{"initial"}, true, true, "-H", "-cookie", "-proxy")
	argsJoined := strings.Join(args, " ")

	expected := []string{
		"-H User-Agent: test_ua",
		"-tls-impersonate",
		"-H X-Test: header_val",
		"-cookie cookie_val",
		"-proxy http://proxy",
	}

	for _, exp := range expected {
		if !strings.Contains(argsJoined, exp) {
			t.Errorf("expected arguments to contain %q, got %q", exp, argsJoined)
		}
	}
}

func TestWriteToFileHarden(t *testing.T) {
	tempDir := t.TempDir()

	targetPath := filepath.Join(tempDir, "nested", "sub", "test.txt")
	tb := tools.New(&runnerfaketest.DummyRunner{})

	err := tb.WriteToFileTestHelper(targetPath, "hello world")
	if err != nil {
		t.Fatalf("unexpected error in writeToFile helper: %v", err)
	}

	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	if string(content) != "hello world" {
		t.Errorf("expected file content to be 'hello world', got %q", string(content))
	}
}

func TestStdoutNoiseFiltering(t *testing.T) {
	tempDir := t.TempDir()
	ctx := context.Background()

	t.Run("gau keeps only http(s) URL lines", func(t *testing.T) {
		dr := &runnerfaketest.DummyRunner{Default: "banner noise\nhttps://example.com/a\n[WARN] rate limited\nhttp://example.com/b\n"}
		tb := tools.New(dr)
		out := filepath.Join(tempDir, "gau.txt")
		if err := tb.RunGau(ctx, "example.com", out); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(out)
		got := string(data)
		if strings.Contains(got, "banner noise") || strings.Contains(got, "[WARN]") {
			t.Errorf("noise leaked into gau output file: %q", got)
		}
		if !strings.Contains(got, "https://example.com/a") || !strings.Contains(got, "http://example.com/b") {
			t.Errorf("valid URLs missing from gau output file: %q", got)
		}
	})

	t.Run("gospider drops tagged and progress lines", func(t *testing.T) {
		dr := &runnerfaketest.DummyRunner{Default: "[+] Crawling: https://example.com/\n[js] https://cdn.example.com/app.js\nhttps://example.com/valid\n"}
		tb := tools.New(dr)
		out := filepath.Join(tempDir, "gospider.txt")
		if err := tb.RunGoSpider(ctx, "hosts.txt", out); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(out)
		got := string(data)
		if strings.Contains(got, "[+]") || strings.Contains(got, "[js]") {
			t.Errorf("tagged noise leaked into gospider output file: %q", got)
		}
		if !strings.Contains(got, "https://example.com/valid") {
			t.Errorf("valid URL missing from gospider output file: %q", got)
		}
	})

	t.Run("waybackurls keeps only http(s) URL lines", func(t *testing.T) {
		dr := &runnerfaketest.DummyRunner{Default: "fetching from wayback...\nhttps://example.com/historic\n"}
		tb := tools.New(dr)
		out := filepath.Join(tempDir, "wayback.txt")
		if err := tb.RunWaybackurls(ctx, "example.com", out); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(out)
		got := string(data)
		if strings.Contains(got, "fetching from wayback") {
			t.Errorf("noise leaked into wayback output file: %q", got)
		}
		if !strings.Contains(got, "https://example.com/historic") {
			t.Errorf("valid URL missing from wayback output file: %q", got)
		}
	})

	t.Run("assetfinder keeps only valid domains", func(t *testing.T) {
		dr := &runnerfaketest.DummyRunner{Default: "assetfinder v1.0\nwww.example.com\nbad line here\nsub.example.com\n"}
		tb := tools.New(dr)
		out := filepath.Join(tempDir, "assetfinder.txt")
		if err := tb.RunAssetfinder(ctx, "example.com", out); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(out)
		got := string(data)
		if strings.Contains(got, "assetfinder v1.0") || strings.Contains(got, "bad line here") {
			t.Errorf("noise leaked into assetfinder output file: %q", got)
		}
		if !strings.Contains(got, "www.example.com") || !strings.Contains(got, "sub.example.com") {
			t.Errorf("valid domains missing from assetfinder output file: %q", got)
		}
	})

	t.Run("jsluice keeps only JSON lines", func(t *testing.T) {
		dr := &runnerfaketest.DummyRunner{Default: "warning: something\n{\"url\":\"https://example.com/app.js\",\"method\":\"GET\"}\n"}
		tb := tools.New(dr)
		out := filepath.Join(tempDir, "jsluice.json")
		if err := tb.RunJsluiceURLs(ctx, "app.js", out); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(out)
		got := string(data)
		if strings.Contains(got, "warning:") {
			t.Errorf("noise leaked into jsluice output file: %q", got)
		}
		if !strings.Contains(got, "https://example.com/app.js") {
			t.Errorf("valid JSON missing from jsluice output file: %q", got)
		}
	})
}

func TestScannerRunsUseNoRetry(t *testing.T) {
	ctx := context.Background()

	t.Run("nuclei scanner disables retries", func(t *testing.T) {
		dr := &runnerfaketest.DummyRunner{}
		tb := tools.New(dr)
		s, err := tb.GetScanner("nuclei")
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Scan(ctx, "targets.txt", "out.json", tools.ScanOptions{Mode: "smart-cve"})
		if dr.LastCmd != "nuclei" {
			t.Fatalf("expected nuclei command, got %q", dr.LastCmd)
		}
		if opts := dr.GetOptions(); !opts.NoRetry {
			t.Error("expected NoRetry set on nuclei scan run")
		}
	})

	t.Run("dalfox scanner disables retries", func(t *testing.T) {
		dr := &runnerfaketest.DummyRunner{}
		tb := tools.New(dr)
		s, err := tb.GetScanner("dalfox")
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Scan(ctx, "params.txt", "out.json", tools.ScanOptions{})
		if dr.LastCmd != "dalfox" {
			t.Fatalf("expected dalfox command, got %q", dr.LastCmd)
		}
		if opts := dr.GetOptions(); !opts.NoRetry {
			t.Error("expected NoRetry set on dalfox scan run")
		}
	})

	t.Run("x8 disables retries", func(t *testing.T) {
		dr := &runnerfaketest.DummyRunner{}
		tb := tools.New(dr)
		_ = tb.RunX8(ctx, "input.txt", "out.json")
		if opts := dr.GetOptions(); !opts.NoRetry {
			t.Error("expected NoRetry set on x8 run")
		}
	})

	t.Run("nuclei WAF run disables retries", func(t *testing.T) {
		dr := &runnerfaketest.DummyRunner{}
		tb := tools.New(dr)
		_ = tb.RunNucleiWAF(ctx, "hosts.txt", "out.json")
		if opts := dr.GetOptions(); !opts.NoRetry {
			t.Error("expected NoRetry set on nuclei WAF run")
		}
	})
}
