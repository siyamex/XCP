package agent

import (
	"context"
	"io/fs"
	"os"
	"sync"

	"github.com/siyamex/XCP/internal/validate"
)

// helperMu serialises helper starts.
var helperMu sync.Mutex

// UserHelperSocket is where an account's file helper listens (ADR-0009).
func UserHelperSocket(username string) string { return UserHelperDir + "/" + username + ".sock" }

// UserHelperDir holds the helpers' sockets: root and the xcp group only.
const UserHelperDir = "/run/xcp-userd"

func userHelperUnits(username string) (socket, service string) {
	return "xcp-userd@" + username + ".socket", "xcp-userd@" + username + ".service"
}

// StartUserHelper starts an account's file helper socket; systemd starts
// the helper, as the account's user, on the first connection.
func (a *Accounts) StartUserHelper(ctx context.Context, username string) error {
	if err := validate.Username(username); err != nil {
		return invalid("username: %v", err)
	}
	u, err := lookup(username)
	if err != nil {
		return err
	}
	if u == nil || u.Name != AccountMarker {
		return ErrNotOurUser
	}
	socket, _ := userHelperUnits(username)
	// One start at a time: the panel asks for several files at once, and a
	// second start must not take the socket systemd is just making for stale.
	helperMu.Lock()
	defer helperMu.Unlock()
	// A socket file left by an earlier helper (or an earlier account of the
	// same name) is in the way: systemd would not replace it.
	if st, err := a.Services.Status(ctx, socket); err == nil && (st.ActiveState == "inactive" || st.ActiveState == "failed") {
		if fi, err := os.Lstat(UserHelperSocket(username)); err == nil && fi.Mode()&fs.ModeSocket != 0 {
			if err := os.Remove(UserHelperSocket(username)); err != nil {
				return err
			}
		}
	}
	return a.Services.Do(ctx, socket, ActionStart)
}

// stopUserHelper stops an account's file helper and its socket (when the
// account is suspended or removed). A helper that never ran is no error.
func (a *Accounts) stopUserHelper(ctx context.Context, username string) {
	socket, service := userHelperUnits(username)
	for _, unit := range []string{service, socket} {
		_ = a.Services.Do(ctx, unit, ActionStop)
	}
}
