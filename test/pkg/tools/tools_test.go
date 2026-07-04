package tools_test

import (
	"context"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/runner"
	"github.com/vishnu303/chaathan/pkg/tools"
)

type DummyRunner struct {
	LastCmd  string
	LastArgs []string
}

func (d *DummyRunner) Run(ctx context.Context, command string, args []string, opts ...runner.Option) (string, error) {
	d.LastCmd = command
	d.LastArgs = args
	return "dummy output", nil
}

func TestToolBoxOptionsAndHelpers(t *testing.T) {
	dr := &DummyRunner{}
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
	dr := &DummyRunner{}
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
	dr := &DummyRunner{}
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
	dr := &DummyRunner{}
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
	dr := &DummyRunner{}
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

