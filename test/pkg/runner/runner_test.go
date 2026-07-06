package runner_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/runner"
)

func getTestCmd() string {
	if path, err := exec.LookPath("whoami"); err == nil {
		return path
	}
	if path, err := exec.LookPath("echo"); err == nil {
		return path
	}
	return "echo"
}

func TestNativeRunner_Success(t *testing.T) {
	run := runner.NewWithRetry("native", false, 0, 0)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := getTestCmd()
	output, err := run.Run(ctx, cmd, nil)
	if err != nil {
		t.Fatalf("unexpected error running %s: %v", cmd, err)
	}

	if len(output) == 0 {
		t.Errorf("expected non-empty output from %s", cmd)
	}
}

func TestNativeRunner_RetryAndFailure(t *testing.T) {
	// NativeRunner with retries on a nonexistent command
	run := runner.NewWithRetry("native", false, 1, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := run.Run(ctx, "nonexistent-command-xyz-12345", nil)
	if err == nil {
		t.Fatal("expected error running nonexistent command, got nil")
	}
}

func TestRunnerOptions(t *testing.T) {
	// Test that we can use options
	run := runner.NewWithRetry("native", true, 0, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := getTestCmd()
	_, err := run.Run(ctx, cmd, nil,
		runner.WithDir(t.TempDir()),
		runner.WithTimeout(2*time.Second),
		runner.WithEnv("TEST_VAR=true"),
	)
	if err != nil {
		t.Fatalf("unexpected error running %s with options: %v", cmd, err)
	}
}
