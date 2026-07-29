package scan_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishnu303/chaathan/pkg/scan"
)

func tempStateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "scan_state")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestMarkStepComplete_DoesNotEraseFailure validates that calling
// MarkStepComplete after MarkStepFailed for the SAME step clears
// the failure (the "later success" path). This is correct behaviour
// when a step is explicitly re-run or skipped.
func TestMarkStepComplete_ClearsFailureOnSuccess(t *testing.T) {
	mgr := scan.NewManager(tempStateDir(t))
	state, err := mgr.CreateState(1, "test.com", "wildcard", "/tmp/results", 21, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Step fails first
	mgr.MarkStepFailed(state, "vuln_scanning", fmt.Errorf("nuclei crashed"))
	if len(state.FailedSteps) != 1 {
		t.Fatalf("expected 1 failed step, got %d", len(state.FailedSteps))
	}
	if state.FailedSteps[0].Name != "vuln_scanning" {
		t.Fatalf("expected failed step 'vuln_scanning', got %q", state.FailedSteps[0].Name)
	}

	// Then step succeeds (retry or explicit skip → complete)
	mgr.MarkStepComplete(state, "vuln_scanning")

	// MarkStepComplete should clear the failure record
	if len(state.FailedSteps) != 0 {
		t.Fatalf("expected 0 failed steps after MarkStepComplete, got %d: %+v", len(state.FailedSteps), state.FailedSteps)
	}
	if !state.IsStepCompleted("vuln_scanning") {
		t.Fatal("step should be marked as completed")
	}
}

// TestMarkStepFailed_PreservesFailureRecord verifies that if only
// MarkStepFailed is called (no subsequent MarkStepComplete), the
// failure is preserved. This is the F-01 invariant: callers must NOT
// unconditionally call MarkStepComplete after MarkStepFailed.
func TestMarkStepFailed_PreservesFailureRecord(t *testing.T) {
	mgr := scan.NewManager(tempStateDir(t))
	state, err := mgr.CreateState(1, "test.com", "wildcard", "/tmp/results", 21, nil)
	if err != nil {
		t.Fatal(err)
	}

	mgr.MarkStepFailed(state, "web_crawling", fmt.Errorf("katana timeout"))

	if len(state.FailedSteps) != 1 {
		t.Fatalf("expected 1 failed step, got %d", len(state.FailedSteps))
	}
	if state.IsStepCompleted("web_crawling") {
		t.Fatal("step should NOT be marked as completed after only MarkStepFailed")
	}
}

// TestMarkStepFailed_RetryTracking verifies that re-failing the same
// step increments the retry counter.
func TestMarkStepFailed_RetryTracking(t *testing.T) {
	mgr := scan.NewManager(tempStateDir(t))
	state, err := mgr.CreateState(1, "test.com", "wildcard", "/tmp/results", 21, nil)
	if err != nil {
		t.Fatal(err)
	}

	mgr.MarkStepFailed(state, "nuclei_scan", fmt.Errorf("first failure"))
	mgr.MarkStepFailed(state, "nuclei_scan", fmt.Errorf("second failure"))

	if len(state.FailedSteps) != 1 {
		t.Fatalf("expected 1 failed step (deduplicated), got %d", len(state.FailedSteps))
	}
	if state.FailedSteps[0].Retries != 1 {
		t.Fatalf("expected 1 retry, got %d", state.FailedSteps[0].Retries)
	}
	if state.FailedSteps[0].Error != "second failure" {
		t.Fatalf("expected error to be updated to 'second failure', got %q", state.FailedSteps[0].Error)
	}
}

// TestMarkStepComplete_NoDuplicates verifies that calling
// MarkStepComplete twice doesn't double-count the step.
func TestMarkStepComplete_NoDuplicates(t *testing.T) {
	mgr := scan.NewManager(tempStateDir(t))
	state, err := mgr.CreateState(1, "test.com", "wildcard", "/tmp/results", 21, nil)
	if err != nil {
		t.Fatal(err)
	}

	mgr.MarkStepComplete(state, "passive_enum")
	mgr.MarkStepComplete(state, "passive_enum")

	count := 0
	for _, s := range state.CompletedSteps {
		if s == "passive_enum" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected step to appear once in CompletedSteps, appeared %d times", count)
	}
	if state.CurrentStep != 1 {
		t.Fatalf("expected CurrentStep=1, got %d", state.CurrentStep)
	}
}

// TestIsStepCompleted verifies the basic lookup.
func TestIsStepCompleted(t *testing.T) {
	mgr := scan.NewManager(tempStateDir(t))
	state, err := mgr.CreateState(1, "test.com", "wildcard", "/tmp/results", 21, nil)
	if err != nil {
		t.Fatal(err)
	}

	if state.IsStepCompleted("passive_enum") {
		t.Fatal("step should NOT be completed initially")
	}

	mgr.MarkStepComplete(state, "passive_enum")

	if !state.IsStepCompleted("passive_enum") {
		t.Fatal("step SHOULD be completed after MarkStepComplete")
	}
}

// TestStatePersistence verifies round-trip save/load.
func TestStatePersistence(t *testing.T) {
	dir := tempStateDir(t)
	mgr := scan.NewManager(dir)

	state, err := mgr.CreateState(42, "example.com", "wildcard", "/tmp/results", 21, map[string]bool{"verbose": true})
	if err != nil {
		t.Fatal(err)
	}

	mgr.MarkStepComplete(state, "passive_enum")
	mgr.MarkStepComplete(state, "active_enum")
	mgr.MarkStepFailed(state, "dns_resolution", fmt.Errorf("dns timeout"))

	// Reload
	loaded, err := mgr.LoadState(42)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.ScanID != 42 {
		t.Fatalf("expected ScanID=42, got %d", loaded.ScanID)
	}
	if loaded.Target != "example.com" {
		t.Fatalf("expected target=example.com, got %q", loaded.Target)
	}
	if len(loaded.CompletedSteps) != 2 {
		t.Fatalf("expected 2 completed steps, got %d", len(loaded.CompletedSteps))
	}
	if len(loaded.FailedSteps) != 1 {
		t.Fatalf("expected 1 failed step, got %d", len(loaded.FailedSteps))
	}
	if loaded.FailedSteps[0].Name != "dns_resolution" {
		t.Fatalf("expected failed step 'dns_resolution', got %q", loaded.FailedSteps[0].Name)
	}
}
