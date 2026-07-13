package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/paths"
)

func TestConfigDefaultsAndSerialization(t *testing.T) {
	tempDir := t.TempDir()
	os.Setenv("CHAATHAN_HOME", tempDir)
	defer os.Unsetenv("CHAATHAN_HOME")

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
	os.Setenv("SHODAN_API_KEY", "env_shodan_key")
	defer os.Unsetenv("SHODAN_API_KEY")

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


