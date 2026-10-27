//go:build unix

package execx

import (
	"os/exec"
	"syscall"
)

// setProcAttrs puts the child in its own process group so a timeout kills
// the whole tree, not only the direct child.
func setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
