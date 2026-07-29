package wildcard_flow_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/scan"
	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

func setupTestEnv(t *testing.T) (string, string) {
	t.Helper()
	paths.ResetForTest()
	tempDir := t.TempDir()
	t.Setenv("CHAATHAN_HOME", tempDir)

	if err := paths.Init(); err != nil {
		t.Fatalf("failed to init paths: %v", err)
	}

	dbPath := filepath.Join(tempDir, "chaathan.db")
	if err := database.Initialize(dbPath); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	t.Cleanup(func() {
		_ = database.Close()
	})

	resDir := filepath.Join(tempDir, "results")
	return tempDir, resDir
}

func TestResumeNoNewScanRow(t *testing.T) {
	_, resDir := setupTestEnv(t)

	dbScan, err := database.CreateScan("example.com", "wildcard", resDir, "{}")
	if err != nil {
		t.Fatalf("failed to create initial scan: %v", err)
	}

	stateMgr := scan.NewManager(paths.StateDir())
	state, err := stateMgr.CreateState(dbScan.ID, "example.com", "wildcard", resDir, len(scan.WildcardSteps), nil)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	// Mark all steps completed so Run exits immediately without invoking external tools
	for _, step := range scan.WildcardSteps {
		if err := stateMgr.MarkStepComplete(state, step.Name); err != nil {
			t.Fatalf("failed to mark step complete: %v", err)
		}
	}

	scansBefore, err := database.GetRecentScans(100)
	if err != nil {
		t.Fatalf("failed to get scans before resume: %v", err)
	}
	if len(scansBefore) != 1 {
		t.Fatalf("expected 1 scan before resume, got %d", len(scansBefore))
	}

	cfg := wildcard_flow.RunConfig{
		Domain:       "example.com",
		ResultDir:    resDir,
		ResumeScanID: dbScan.ID,
	}

	if err := wildcard_flow.Run(cfg); err != nil {
		t.Fatalf("unexpected error from Run during resume: %v", err)
	}

	scansAfter, err := database.GetRecentScans(100)
	if err != nil {
		t.Fatalf("failed to get scans after resume: %v", err)
	}

	if len(scansAfter) != 1 {
		t.Errorf("expected scan count to remain 1 after resume (no ghost scan row), got %d", len(scansAfter))
	}
}

func TestResumeStateMismatchRejection(t *testing.T) {
	_, resDir := setupTestEnv(t)

	stateMgr := scan.NewManager(paths.StateDir())
	_, err := stateMgr.CreateState(42, "example.com", "wildcard", resDir, len(scan.WildcardSteps), nil)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	cfg := wildcard_flow.RunConfig{
		Domain:       "mismatched.com",
		ResultDir:    resDir,
		ResumeScanID: 42,
	}

	err = wildcard_flow.Run(cfg)
	if err == nil {
		t.Fatal("expected error on target mismatch, got nil")
	}

	if !strings.Contains(err.Error(), "target mismatch") {
		t.Errorf("expected 'target mismatch' in error, got %q", err.Error())
	}
}

func TestResumeResultDirAdoption(t *testing.T) {
	tempDir, resDirA := setupTestEnv(t)
	resDirB := filepath.Join(tempDir, "results_b")

	stateMgr := scan.NewManager(paths.StateDir())
	state, err := stateMgr.CreateState(99, "example.com", "wildcard", resDirA, len(scan.WildcardSteps), nil)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	for _, step := range scan.WildcardSteps {
		_ = stateMgr.MarkStepComplete(state, step.Name)
	}

	cfg := wildcard_flow.RunConfig{
		Domain:       "example.com",
		ResultDir:    resDirB,
		ResumeScanID: 99,
	}

	if err := wildcard_flow.Run(cfg); err != nil {
		t.Fatalf("unexpected error running resume with different result dir: %v", err)
	}
}
