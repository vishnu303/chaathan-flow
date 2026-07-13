//go:build !linux

package setup

import "os/exec"

// setPGID is a no-op on non-Linux platforms.
func setPGID(cmd *exec.Cmd) {}
