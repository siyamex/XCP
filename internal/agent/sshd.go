package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/siyamex/XCP/internal/execx"
)

// Paths for the SSH settings (ADM-SEC-11, ADR-0019).
const (
	SSHDPath      = "/usr/sbin/sshd"
	SSHDConfDir   = "/etc/ssh/sshd_config.d"
	sshdConfName  = "00-xcp.conf" // first in order: sshd keeps the first value it reads
	sshHomeGlob   = "/home/*/.ssh/authorized_keys"
	sshRootKeys   = "/root/.ssh/authorized_keys"
	sshdService   = "ssh.service"
	rootLoginYes  = "yes"
	rootLoginKeys = "prohibit-password"
	rootLoginNo   = "no"
)

// SSHSettings are the SSH server's login rules.
type SSHSettings struct {
	PasswordAuth bool
	RootLogin    string // yes, prohibit-password or no
}

func (h *HostConfig) hasAuthorizedKeys() bool {
	files, _ := filepath.Glob(h.sshGlob())
	files = append(files, h.sshRoot())
	for _, f := range files {
		if st, err := os.Stat(f); err == nil && st.Size() > 0 && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func (h *HostConfig) sshGlob() string {
	if h.SSHKeysGlob != "" {
		return h.SSHKeysGlob
	}
	return sshHomeGlob
}

func (h *HostConfig) sshRoot() string {
	if h.SSHRootKeys != "" {
		return h.SSHRootKeys
	}
	return sshRootKeys
}

// SetSSHD writes the SSH login rules, checks the whole configuration with
// `sshd -t` (putting the old file back if it fails) and reloads sshd. It
// refuses to switch passwords off while no login has an authorized key:
// that would lock everyone out.
func (h *HostConfig) SetSSHD(ctx context.Context, s SSHSettings) (bool, error) {
	switch s.RootLogin {
	case rootLoginYes, rootLoginKeys, rootLoginNo:
	default:
		return false, fmt.Errorf("root login must be yes, prohibit-password or no")
	}
	if !s.PasswordAuth && !h.hasAuthorizedKeys() {
		return false, fmt.Errorf("no login has an SSH key yet: switching passwords off would lock everyone out")
	}
	pw := "no"
	if s.PasswordAuth {
		pw = "yes"
	}
	dir := h.SSHDConfDir
	if dir == "" {
		dir = SSHDConfDir
	}
	content := "# Managed by XCP (ADR-0019). Changes are overwritten.\nPasswordAuthentication " + pw + "\nPermitRootLogin " + s.RootLogin + "\n"
	old, readErr := os.ReadFile(filepath.Join(dir, sshdConfName))
	changed, err := writeFile(dir, sshdConfName, content, 0o644, "")
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	if _, err := h.Run.Run(ctx, execx.Cmd{Path: SSHDPath, Args: []string{"-t"}}); err != nil {
		if readErr == nil {
			_, _ = writeFile(dir, sshdConfName, string(old), 0o644, "")
		} else {
			_ = os.Remove(filepath.Join(dir, sshdConfName))
		}
		return false, fmt.Errorf("sshd refused the configuration: %w", err)
	}
	if _, err := h.Run.Run(ctx, execx.Cmd{Path: SystemctlPath, Args: []string{"reload", sshdService}}); err != nil {
		return true, fmt.Errorf("reload sshd: %w", err)
	}
	return true, nil
}

// SSHState reads the effective values back from the file XCP wrote.
func SSHState(content string) (SSHSettings, bool) {
	s := SSHSettings{PasswordAuth: true, RootLogin: rootLoginKeys}
	found := false
	for _, l := range strings.Split(content, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "PasswordAuthentication":
			s.PasswordAuth, found = f[1] == "yes", true
		case "PermitRootLogin":
			s.RootLogin, found = f[1], true
		}
	}
	return s, found
}
