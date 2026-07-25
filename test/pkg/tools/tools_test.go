package tools_test

import (
	"context"
	"io"
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
		Shodan: "shodan_key",
		CensysID: "censys_id_val",
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

func TestRunHakrawlerStdin(t *testing.T) {
	dr := &runnerfaketest.DummyRunner{}
	tb := tools.New(dr)

	ctx := context.Background()
	err := tb.RunHakrawler(ctx, "http://target.com", "out.txt")
	if err != nil {
		t.Fatalf("unexpected error running RunHakrawler: %v", err)
	}

	opts := dr.GetOptions()
	if opts.Stdin == nil {
		t.Fatal("expected Stdin to be configured in runner options")
	}

	reader := opts.Stdin()
	buf, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read stdin from factory: %v", err)
	}

	if string(buf) != "http://target.com\n" {
		t.Errorf("expected stdin to contain http://target.com\\n, got %q", string(buf))
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

