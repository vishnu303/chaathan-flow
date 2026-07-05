//go:build linux

package setup

import (
	"os/exec"
	"syscall"
)

// setPGID sets the Setpgid field on SysProcAttr to isolate process groups on Linux.
func setPGID(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}
