package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/paths"
)

func TestConfigDefaultsAndSerialization(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("CHAATHAN_HOME", tempDir)

	cfg := config.DefaultConfig()
	if cfg == nil {
		t.Fatal("expected DefaultConfig to return non-nil")
	}

	if cfg.General.Mode != "native" {
		t.Errorf("expected default Mode to be native, got %q", cfg.General.Mode)
	}

	configFilePath := filepath.Join(tempDir, "config.yaml")
	err := config.Save(cfg, configFilePath)
	if err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	loaded, err := config.Load(configFilePath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if loaded.General.Mode != cfg.General.Mode {
		t.Errorf("loaded config Mode mismatch: got %q, want %q", loaded.General.Mode, cfg.General.Mode)
	}

	// Test LoadOrCreate when file does not exist
	newConfigPath := filepath.Join(tempDir, "subdir", "new_config.yaml")
	createdCfg, err := config.LoadOrCreate(newConfigPath)
	if err != nil {
		t.Fatalf("failed to LoadOrCreate new config: %v", err)
	}
	if createdCfg == nil {
		t.Fatal("expected created config to be non-nil")
	}

	// Test GetAPIKey from config or env
	t.Setenv("SHODAN_API_KEY", "env_shodan_key")

	// 1. Should fetch from env if not set in config
	createdCfg.APIKeys.Shodan = ""
	apiKey := createdCfg.GetAPIKey("shodan")
	if apiKey != "env_shodan_key" {
		t.Errorf("expected API key from env to be env_shodan_key, got %q", apiKey)
	}

	// 2. Should fetch from config if set
	createdCfg.APIKeys.Shodan = "config_shodan_key"
	apiKey = createdCfg.GetAPIKey("shodan")
	if apiKey != "config_shodan_key" {
		t.Errorf("expected API key from config to be config_shodan_key, got %q", apiKey)
	}
}

func TestGetDefaultConfigPath(t *testing.T) {
	path := config.GetDefaultConfigPath()
	expected := paths.ConfigPath()
	if path != expected {
		t.Errorf("expected default config path %q, got %q", expected, path)
	}
}

func TestUnknownKeysWarning(t *testing.T) {
	tempDir := t.TempDir()
	configContent := `
general:
  mode: native
nuclie:
  concurrency: 5
`
	configFilePath := filepath.Join(tempDir, "invalid_config.yaml")
	err := os.WriteFile(configFilePath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write invalid config file: %v", err)
	}

	cfg, err := config.Load(configFilePath)
	if err != nil {
		t.Fatalf("expected Load to succeed even with unknown keys, got error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.General.Mode != "native" {
		t.Errorf("expected General.Mode to be native, got %q", cfg.General.Mode)
	}
}

// TestLoadMatchesDefaultConfig pins the single-source-of-defaults invariant:
// loading a config file that sets nothing must yield exactly DefaultConfig(),
// and sparse files must inherit defaults for every field they omit.
func TestLoadMatchesDefaultConfig(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("CHAATHAN_HOME", tempDir)
	paths.ResetForTest()

	// 1. Empty config → identical to DefaultConfig.
	emptyPath := filepath.Join(tempDir, "empty.yaml")
	if err := os.WriteFile(emptyPath, []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(emptyPath)
	if err != nil {
		t.Fatalf("Load(empty) error: %v", err)
	}
	want := config.DefaultConfig()
	if !reflect.DeepEqual(loaded, want) {
		t.Errorf("Load(empty) diverged from DefaultConfig()\n got: %+v\nwant: %+v", loaded, want)
	}

	// 2. Sparse config → override wins, everything else inherits defaults.
	sparsePath := filepath.Join(tempDir, "sparse.yaml")
	if err := os.WriteFile(sparsePath, []byte("general:\n  mode: docker\ntools:\n  nuclei:\n    concurrency: 99\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sparse, err := config.Load(sparsePath)
	if err != nil {
		t.Fatalf("Load(sparse) error: %v", err)
	}
	if sparse.General.Mode != "docker" {
		t.Errorf("override lost: mode = %q, want docker", sparse.General.Mode)
	}
	if sparse.Tools.Nuclei.Concurrency != 99 {
		t.Errorf("override lost: nuclei concurrency = %d, want 99", sparse.Tools.Nuclei.Concurrency)
	}
	def := config.DefaultConfig()
	checks := map[string]any{
		"dalfox max_timeout (was missing from old DefaultConfig)": sparse.Tools.Dalfox.MaxTimeout,
		"httpx threads (was missing from old applyDefaults)":      sparse.Tools.Httpx.Threads,
		"subfinder threads": sparse.Tools.Subfinder.Threads,
		"ffuf max_timeout":  sparse.Tools.Ffuf.MaxTimeout,
		"max_retries":       sparse.General.MaxRetries,
	}
	wantVals := map[string]any{
		"dalfox max_timeout (was missing from old DefaultConfig)": def.Tools.Dalfox.MaxTimeout,
		"httpx threads (was missing from old applyDefaults)":      def.Tools.Httpx.Threads,
		"subfinder threads": def.Tools.Subfinder.Threads,
		"ffuf max_timeout":  def.Tools.Ffuf.MaxTimeout,
		"max_retries":       def.General.MaxRetries,
	}
	for name, got := range checks {
		if got != wantVals[name] {
			t.Errorf("%s = %v, want default %v", name, got, wantVals[name])
		}
	}
}
