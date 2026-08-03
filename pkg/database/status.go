package database

// Canonical scan status constants. Use these instead of raw string literals
// to prevent typos and enable compile-time checking.
const (
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)
