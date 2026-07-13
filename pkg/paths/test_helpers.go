package paths

import "sync"

// ResetForTest resets the paths package-level state for unit testing.
func ResetForTest() {
	chaathanHome = ""
	initOnce = sync.Once{}
	initErr = nil
}
