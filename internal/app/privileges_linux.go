//go:build linux

package app

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// DropPrivileges switches a root process to the given service user (and its
// group, with no supplementary groups). It does nothing when not root.
// Go applies setuid/setgid to all threads (Go 1.16+), so this is safe in a
// running program.
func DropPrivileges(username string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("drop privileges: %w", err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || uid == 0 {
		return fmt.Errorf("drop privileges: unusable user %q (uid %s)", username, u.Uid)
	}
	if err := syscall.Setgroups(nil); err != nil {
		return fmt.Errorf("drop privileges: setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("drop privileges: setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("drop privileges: setuid: %w", err)
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("drop privileges: still root after setuid")
	}
	return nil
}
