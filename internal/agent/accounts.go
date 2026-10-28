package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/validate"
)

// Programs used for accounts; they must be on the agent's execx allow-list.
const (
	UseraddPath  = "/usr/sbin/useradd"
	UsermodPath  = "/usr/sbin/usermod"
	UserdelPath  = "/usr/sbin/userdel"
	PkillPath    = "/usr/bin/pkill"
	SetquotaPath = "/usr/sbin/setquota"
)

// AccountMarker is the GECOS comment of every Linux user XCP creates. The
// agent refuses to change or delete users without it.
const AccountMarker = "xcp account"

// ErrNotOurUser means a Linux user (or group) with that name or UID exists
// but was not created by XCP.
var ErrNotOurUser = errors.New("a Linux user or group with this name or UID exists and was not created by XCP")

// UID range of hosting accounts (mirrors store.FirstAccountUID/LastAccountUID).
const (
	MinAccountUID = 10000
	MaxAccountUID = 59999
)

// Shell is an account's shell access.
type Shell int

// Shell values, mirroring the proto enum.
const (
	ShellNone Shell = iota
	ShellJailed
	ShellFull
)

func (s Shell) path() string {
	if s == ShellNone {
		return "/usr/sbin/nologin"
	}
	return "/bin/bash" // the jail for ShellJailed arrives in P3
}

// Limits are resource limits; nil means unlimited.
type Limits struct {
	CPUPercent *uint32
	MemoryMB   *uint64
	Tasks      *uint32
	DiskMB     *uint64
	Inodes     *uint64
}

// CheckAccount validates the fields every account operation receives. The
// fake agent uses it too.
func CheckAccount(username string, uid uint32, domain string) error {
	if err := validate.Username(username); err != nil {
		return invalid("username: %v", err)
	}
	if uid < MinAccountUID || uid > MaxAccountUID {
		return invalid("uid %d outside %d..%d", uid, MinAccountUID, MaxAccountUID)
	}
	if domain != "" {
		if d, err := validate.Domain(domain); err != nil || d != domain {
			return invalid("primary domain %q is not a normalised domain name", domain)
		}
	}
	return nil
}

// Accounts manages the Linux side of hosting accounts.
type Accounts struct {
	Run       *execx.Runner
	HomesRoot string // usually /home
	UnitDir   string // usually /etc/systemd/system
	WebGroup  string // group the web server runs as (www-data); "" uses the user's own group
	Services  ServiceManager
}

// AccountResult reports what AccountEnsure did.
type AccountResult struct {
	Created      bool
	QuotaApplied bool
	Home         string
}

// lookup returns the user with that name, or nil if there is none.
func lookup(name string) (*user.User, error) {
	u, err := user.Lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return nil, nil
	}
	return u, err
}

// ours reports whether u is a user XCP created with the expected UID.
func ours(u *user.User, uid uint32) bool {
	return u.Name == AccountMarker && u.Uid == strconv.FormatUint(uint64(uid), 10)
}

// Ensure creates or updates the account's Linux user, home and limits.
func (a *Accounts) Ensure(ctx context.Context, username string, uid uint32, shell Shell, lim Limits, domain string) (AccountResult, error) {
	if err := CheckAccount(username, uid, domain); err != nil {
		return AccountResult{}, err
	}
	res := AccountResult{Home: filepath.Join(a.HomesRoot, username)}
	u, err := lookup(username)
	if err != nil {
		return res, err
	}
	switch {
	case u != nil && !ours(u, uid):
		return res, ErrNotOurUser
	case u == nil:
		// The UID and the group name must be free too, or useradd would reuse them.
		if _, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
			return res, ErrNotOurUser
		}
		if _, err := user.LookupGroup(username); err == nil {
			return res, ErrNotOurUser
		}
		// Check before useradd, so a refused create leaves nothing behind.
		if _, err := os.Lstat(res.Home); err == nil {
			return res, fmt.Errorf("%w: %s already exists; move it away first", ErrNotOurUser, res.Home)
		}
		if _, err := a.Run.Run(ctx, execx.Cmd{Path: UseraddPath, Args: []string{
			"--uid", strconv.FormatUint(uint64(uid), 10), "--user-group", "--no-create-home",
			"--home-dir", res.Home, "--shell", shell.path(), "--comment", AccountMarker, "--", username,
		}}); err != nil {
			return res, fmt.Errorf("useradd: %w", err)
		}
		res.Created = true
	default:
		if _, err := a.Run.Run(ctx, execx.Cmd{Path: UsermodPath, Args: []string{"--shell", shell.path(), "--", username}}); err != nil {
			return res, fmt.Errorf("usermod: %w", err)
		}
	}
	if err := a.home(username, int(uid), domain, res.Created); err != nil {
		return res, fmt.Errorf("home folder: %w", err)
	}
	if err := a.slices(ctx, username, uid, lim); err != nil {
		return res, fmt.Errorf("resource limits: %w", err)
	}
	res.QuotaApplied, err = a.quota(ctx, username, lim)
	return res, err
}

// home builds /home/<user>. A new home is assembled while owned by root
// and handed to the user last, so the user can never race the setup. For an
// existing home only missing parts are added, through fsx (no symlinks).
func (a *Accounts) home(username string, uid int, domain string, created bool) error {
	gid := uid // useradd --user-group creates a group with the same ID when it is free
	if g, err := user.LookupGroup(username); err == nil {
		if gid, err = strconv.Atoi(g.Gid); err != nil {
			return err
		}
	}
	webGID := gid
	if a.WebGroup != "" {
		if g, err := user.LookupGroup(a.WebGroup); err == nil {
			webGID, _ = strconv.Atoi(g.Gid)
		}
	}
	home := filepath.Join(a.HomesRoot, username)
	fi, err := os.Lstat(home)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(home, 0o700); err != nil {
			return err
		}
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%s exists and is not a directory", home)
	case created:
		// A folder left over from something else must not be handed to a new user.
		return fmt.Errorf("%s already exists; move it away before creating this account", home)
	}
	root, err := fsx.OpenRoot(home)
	if err != nil {
		return err
	}
	defer root.Close()

	dirs := []struct {
		name string
		mode fs.FileMode
		gid  int
	}{
		{"public_html", 0o750, webGID}, // the web server reads it through its group
		{"tmp", 0o700, gid},
		{".xcp", 0o700, gid},
	}
	for _, d := range dirs {
		if _, err := root.Lstat(d.name); err == nil {
			continue // keep whatever the user did with it
		}
		if err := root.Mkdir(d.name, d.mode); err != nil {
			return err
		}
		if err := root.Chmod(d.name, d.mode); err != nil {
			return err
		}
		if d.name == "public_html" {
			if err := root.WriteFileAtomic("public_html/index.html", []byte(indexPage(domain)), 0o644); err != nil {
				return err
			}
			if err := root.Chown("public_html/index.html", uid, gid); err != nil {
				return err
			}
		}
		if err := root.Chown(d.name, uid, d.gid); err != nil {
			return err
		}
	}
	// Last: hand the home to the user. Others may traverse it (0711) to reach
	// public_html, but cannot list it.
	if err := root.Chown(".", uid, gid); err != nil {
		return err
	}
	return os.Chmod(home, 0o711) //nolint:gosec // G302: 0711 lets the web server traverse into public_html
}

func indexPage(domain string) string {
	name := html.EscapeString(domain)
	if name == "" {
		name = "This site"
	}
	return "<!doctype html>\n<meta charset=\"utf-8\">\n<title>" + name + "</title>\n" +
		"<p style=\"font-family:sans-serif;margin:3em\"><b>" + name + "</b> is hosted with XCP. " +
		"Upload your website to <code>public_html</code>.</p>\n"
}

// SliceName is the systemd slice that the account's services (PHP-FPM, cron, apps) run in.
func SliceName(username string) string { return "xcp-u-" + username + ".slice" }

// sliceBody renders the [Slice] limits shared by the account slice and the
// drop-in for the user's login sessions (user-<uid>.slice).
func sliceBody(lim Limits) string {
	var b strings.Builder
	b.WriteString("[Slice]\n")
	if lim.CPUPercent != nil {
		fmt.Fprintf(&b, "CPUQuota=%d%%\n", *lim.CPUPercent)
	}
	if lim.MemoryMB != nil {
		fmt.Fprintf(&b, "MemoryMax=%dM\n", *lim.MemoryMB)
	}
	if lim.Tasks != nil {
		fmt.Fprintf(&b, "TasksMax=%d\n", *lim.Tasks)
	}
	return b.String()
}

// slices writes the account slice and a drop-in that applies the same limits
// to SSH and other login sessions, then reloads systemd if anything changed.
func (a *Accounts) slices(ctx context.Context, username string, uid uint32, lim Limits) error {
	root, err := fsx.OpenRoot(a.UnitDir)
	if err != nil {
		return err
	}
	defer root.Close()
	body := sliceBody(lim)
	files := map[string]string{
		SliceName(username):                             "# Managed by XCP. Do not edit.\n[Unit]\nDescription=XCP account " + username + "\n\n" + body,
		fmt.Sprintf("user-%d.slice.d/50-xcp.conf", uid): "# Managed by XCP. Do not edit.\n" + body,
	}
	changed := false
	for name, content := range files {
		if old, err := root.ReadFile(name, 1<<16); err == nil && string(old) == content {
			continue
		}
		if err := root.MkdirAll(filepath.ToSlash(filepath.Dir(name)), 0o755); err != nil {
			return err
		}
		if err := root.WriteFileAtomic(name, []byte(content), 0o644); err != nil {
			return err
		}
		changed = true
	}
	if changed && a.Services != nil {
		return a.Services.Do(ctx, "", ActionDaemonReload)
	}
	return nil
}

// quota sets the user's filesystem quota. It returns false (and no error)
// when the home filesystem has no user quotas enabled.
func (a *Accounts) quota(ctx context.Context, username string, lim Limits) (bool, error) {
	mnt, ok := quotaMount(a.HomesRoot)
	if !ok {
		return false, nil
	}
	if _, err := os.Stat(SetquotaPath); errors.Is(err, fs.ErrNotExist) {
		return false, nil // quotas are on, but the quota tools are not installed
	} else if err != nil {
		return false, err
	}
	blocks, inodes := uint64(0), uint64(0) // 0 = no limit for setquota
	if lim.DiskMB != nil {
		blocks = *lim.DiskMB * 1024 // setquota counts 1 KiB blocks
	}
	if lim.Inodes != nil {
		inodes = *lim.Inodes
	}
	b, i := strconv.FormatUint(blocks, 10), strconv.FormatUint(inodes, 10)
	_, err := a.Run.Run(ctx, execx.Cmd{Path: SetquotaPath, Args: []string{"-u", username, b, b, i, i, mnt}})
	return err == nil, err
}

// quotaMount finds the mount point holding dir and reports whether it has
// user quotas enabled (usrquota, usrjquota, quota or uquota).
func quotaMount(dir string) (string, bool) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", false
	}
	defer f.Close()
	best, opts := "", ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		mp := strings.ReplaceAll(fields[1], `\040`, " ")
		if (dir == mp || strings.HasPrefix(dir, strings.TrimSuffix(mp, "/")+"/")) && len(mp) >= len(best) {
			best, opts = mp, fields[3]
		}
	}
	for _, o := range strings.Split(opts, ",") {
		key, _, _ := strings.Cut(o, "=")
		switch key {
		case "usrquota", "usrjquota", "quota", "uquota":
			return best, true
		}
	}
	return best, false
}

// SetSuspended locks (no shell, all processes stopped) or unlocks the user.
func (a *Accounts) SetSuspended(ctx context.Context, username string, suspended bool, shell Shell) error {
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
	if !suspended {
		_, err := a.Run.Run(ctx, execx.Cmd{Path: UsermodPath, Args: []string{"--unlock", "--shell", shell.path(), "--", username}})
		return err
	}
	if _, err := a.Run.Run(ctx, execx.Cmd{Path: UsermodPath, Args: []string{"--lock", "--shell", "/usr/sbin/nologin", "--", username}}); err != nil {
		return err
	}
	return a.killAll(ctx, username)
}

// killAll stops every process of the user. pkill exits 1 when none matched.
func (a *Accounts) killAll(ctx context.Context, username string) error {
	_, err := a.Run.Run(ctx, execx.Cmd{Path: PkillPath, Args: []string{"-KILL", "-u", username}})
	var ee *execx.ExitError
	if errors.As(err, &ee) && ee.ExitCode == 1 {
		return nil
	}
	return err
}

// Delete removes the user, home folder and slice files. It returns false if
// the user did not exist.
func (a *Accounts) Delete(ctx context.Context, username string) (bool, error) {
	if err := validate.Username(username); err != nil {
		return false, invalid("username: %v", err)
	}
	u, err := lookup(username)
	if err != nil || u == nil {
		return false, err
	}
	if u.Name != AccountMarker {
		return false, ErrNotOurUser
	}
	if err := a.killAll(ctx, username); err != nil {
		return false, err
	}
	if _, err := a.Run.Run(ctx, execx.Cmd{Path: UserdelPath, Args: []string{"--remove", "--", username}}); err != nil {
		// Exit 12: the home folder could not be removed fully; the user itself is gone.
		var ee *execx.ExitError
		if !errors.As(err, &ee) || ee.ExitCode != 12 {
			return false, fmt.Errorf("userdel: %w", err)
		}
	}
	root, err := fsx.OpenRoot(a.UnitDir)
	if err != nil {
		return true, err
	}
	defer root.Close()
	for _, name := range []string{SliceName(username), "user-" + u.Uid + ".slice.d/50-xcp.conf", "user-" + u.Uid + ".slice.d"} {
		if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return true, err
		}
	}
	if a.Services != nil {
		return true, a.Services.Do(ctx, "", ActionDaemonReload)
	}
	return true, nil
}
