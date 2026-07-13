package paths_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vishnu303/chaathan/pkg/paths"
)

func TestPaths(t *testing.T) {
	tempDir := t.TempDir()
	
	// Set the environment variable so we have a deterministic home directory
	os.Setenv("CHAATHAN_HOME", tempDir)
	defer os.Unsetenv("CHAATHAN_HOME")

	err := paths.Init()
	if err != nil {
		t.Fatalf("unexpected error during paths.Init(): %v", err)
	}

	home := paths.ChaathanHome()
	if home != tempDir {
		t.Errorf("expected home to be %q, got %q", tempDir, home)
	}

	state := paths.StateDir()
	expectedState := filepath.Join(tempDir, "state")
	if state != expectedState {
		t.Errorf("expected state dir %q, got %q", expectedState, state)
	}

	scans := paths.ScansDir()
	expectedScans := filepath.Join(tempDir, "scans")
	if scans != expectedScans {
		t.Errorf("expected scans dir %q, got %q", expectedScans, scans)
	}

	reports := paths.ReportsDir()
	expectedReports := filepath.Join(tempDir, "reports")
	if reports != expectedReports {
		t.Errorf("expected reports dir %q, got %q", expectedReports, reports)
	}

	db := paths.DatabasePath()
	expectedDB := filepath.Join(tempDir, "chaathan.db")
	if db != expectedDB {
		t.Errorf("expected db path %q, got %q", expectedDB, db)
	}

	cfg := paths.ConfigPath()
	expectedCfg := filepath.Join(tempDir, "config.yaml")
	if cfg != expectedCfg {
		t.Errorf("expected config path %q, got %q", expectedCfg, cfg)
	}

	logs := paths.LogsDir()
	expectedLogs := filepath.Join(tempDir, "logs")
	if logs != expectedLogs {
		t.Errorf("expected logs dir %q, got %q", expectedLogs, logs)
	}
}

func TestEnvHomeDirectoryCreation(t *testing.T) {
	paths.ResetForTest()

	tempDir := t.TempDir()
	nonExistentSubdir := filepath.Join(tempDir, "new_home_env")
	os.Setenv("CHAATHAN_HOME", nonExistentSubdir)
	defer os.Unsetenv("CHAATHAN_HOME")

	err := paths.Init()
	if err != nil {
		t.Fatalf("unexpected error during paths.Init(): %v", err)
	}

	// Verify that the directory was created successfully
	if _, err := os.Stat(nonExistentSubdir); os.IsNotExist(err) {
		t.Errorf("expected directory %q to be created, but it does not exist", nonExistentSubdir)
	}
}
