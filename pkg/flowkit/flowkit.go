// Package flowkit defines the shared step-execution contract used by the
// wildcard and company scan workflows.
package flowkit

import (
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/scan"
)

// StepResult is the unified outcome of a workflow step.
type StepResult struct {
	Cancelled bool
	Err       error
}

// StepFunc is the common signature for workflow step implementations.
type StepFunc[C any] func(c *C) StepResult

// ExecuteStep runs fn and records a failure in the scan state when a state
// manager and state are provided. Steps that maintain their own state marking
// (e.g. resume-aware wildcard steps) pass a nil state to opt out. The step
// result is returned unchanged.
func ExecuteStep[C any](c *C, name string, fn StepFunc[C], stateMgr *scan.Manager, state *scan.State) StepResult {
	res := fn(c)
	if res.Err != nil && !res.Cancelled && state != nil && stateMgr != nil && !state.IsStepFailed(name) {
		if markErr := stateMgr.MarkStepFailed(state, name, res.Err); markErr != nil {
			logger.Warning("Failed to mark step %s failed: %v", name, markErr)
		}
	}
	return res
}
