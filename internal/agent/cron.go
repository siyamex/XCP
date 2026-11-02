package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/validate"
)

// Cron runs the cron jobs of all accounts (ADR-0011): it keeps each
// account's jobs as a fragment and, once a minute, starts the due ones as
// transient units in the account's slice.
type Cron struct {
	Run         *execx.Runner
	FragmentDir string // /etc/xcp/cron/accounts, root only
	StateDir    string // /var/lib/xcp-cron: the last run of each job (root only)
	HomesRoot   string
	Log         *slog.Logger
	Now         func() time.Time

	mu      sync.Mutex
	stateMu sync.Mutex
	slots   chan struct{}
}

// Paths and limits of cron jobs.
const (
	SystemdRunPath    = "/usr/bin/systemd-run"
	CronRunPath       = "/usr/sbin/xcp-cronrun"
	CronFragmentDir   = "/etc/xcp/cron/accounts"
	CronStateDir      = "/var/lib/xcp-cron"
	CronMaxJobs       = 500 // per account
	CronMaxRuntime    = 12 * time.Hour
	CronMaxRunning    = 32 // runs at once on the server
	CronOutputKept    = 16 << 10
	cronOutputCapture = 64 << 10
)

// CronAccount is all cron jobs of one account, as the agent keeps them.
type CronAccount struct {
	Username string
	UID, GID int
	Home     string
	Jobs     []CronJob
}

// CronJob is one job.
type CronJob struct {
	ID       string // lower-case letters and digits; part of the unit name
	Schedule string // 5 fields, normalised by validate.CronSchedule
	Command  string // one line, run with /bin/sh -c as the account's user
	MailTo   string // "" = output is kept only
}

// CronRun is the last run of a job.
type CronRun struct {
	Start    time.Time
	Duration time.Duration
	ExitCode int
	Output   string // the last CronOutputKept bytes
	Skipped  string // set when the run did not start, and why
}

var cronIDRe = regexp.MustCompile(`^[a-z0-9]{1,40}$`)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// CheckCronAccount checks an account's jobs.
func CheckCronAccount(a CronAccount) error {
	if validate.Username(a.Username) != nil {
		return invalid("%q is not an account name", a.Username)
	}
	if len(a.Jobs) > CronMaxJobs {
		return invalid("at most %d cron jobs per account", CronMaxJobs)
	}
	seen := map[string]bool{}
	for _, j := range a.Jobs {
		if !cronIDRe.MatchString(j.ID) || seen[j.ID] {
			return invalid("cron job id %q is not a unique lower-case id", j.ID)
		}
		seen[j.ID] = true
		if s, err := validate.CronSchedule(j.Schedule); err != nil || s != j.Schedule {
			return invalid("cron job %s: schedule %q is not a normalised 5-field schedule", j.ID, j.Schedule)
		}
		if c, err := validate.CronCommand(j.Command); err != nil || c != j.Command {
			return invalid("cron job %s: the command is not one trimmed line", j.ID)
		}
		if j.MailTo != "" {
			if e, err := validate.Email(j.MailTo); err != nil || e != j.MailTo {
				return invalid("cron job %s: %q is not a normalised email address", j.ID, j.MailTo)
			}
		}
	}
	return nil
}

// ApplyAccount stores an account's jobs. It reports whether anything changed.
func (c *Cron) ApplyAccount(_ context.Context, a CronAccount) (bool, error) {
	if validate.Username(a.Username) != nil {
		return false, invalid("%q is not an account name", a.Username)
	}
	u, err := lookup(a.Username)
	if err != nil {
		return false, err
	}
	if u == nil || u.Name != AccountMarker {
		return false, ErrNotOurUser
	}
	a.UID, _ = strconv.Atoi(u.Uid)
	a.GID, _ = strconv.Atoi(u.Gid)
	a.Home = filepath.Join(c.HomesRoot, a.Username)
	if err := CheckCronAccount(a); err != nil {
		return false, err
	}
	b, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeFile(c.FragmentDir, a.Username+".json", string(b), 0o600, "")
}

// RemoveAccount drops an account's jobs and their last runs.
func (c *Cron) RemoveAccount(_ context.Context, username string) (bool, error) {
	if validate.Username(username) != nil {
		return false, invalid("%q is not an account name", username)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := false
	for _, dir := range []string{c.FragmentDir, c.StateDir} {
		root, err := fsx.OpenRoot(dir)
		if err != nil {
			return false, err
		}
		err = root.Remove(username + ".json")
		root.Close()
		switch {
		case err == nil:
			removed = removed || dir == c.FragmentDir
		case !errors.Is(err, fs.ErrNotExist):
			return false, err
		}
	}
	return removed, nil
}

func (c *Cron) accounts() ([]CronAccount, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	root, err := fsx.OpenRoot(c.FragmentDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	ents, err := root.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var out []CronAccount
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") || !e.Type().IsRegular() {
			continue
		}
		b, err := root.ReadFile(e.Name(), 16<<20)
		if err != nil {
			return nil, err
		}
		var a CronAccount
		if err := json.Unmarshal(b, &a); err != nil {
			return nil, fmt.Errorf("cron fragment %s: %w", e.Name(), err)
		}
		out = append(out, a)
	}
	return out, nil
}

// Due reports whether a schedule fires at minute m (whole minutes, local time).
func Due(schedule string, m time.Time) bool {
	s, err := cronParser.Parse(schedule)
	if err != nil {
		return false
	}
	return s.Next(m.Add(-time.Second)).Equal(m)
}

// Next returns the next n times a schedule fires after t.
func Next(schedule string, t time.Time, n int) []time.Time {
	s, err := cronParser.Parse(schedule)
	if err != nil {
		return nil
	}
	out := make([]time.Time, 0, n)
	for range n {
		t = s.Next(t)
		if t.IsZero() {
			break
		}
		out = append(out, t)
	}
	return out
}

func (c *Cron) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Loop starts the due jobs every minute until ctx ends.
func (c *Cron) Loop(ctx context.Context) {
	c.slots = make(chan struct{}, CronMaxRunning)
	for {
		now := c.now()
		next := now.Truncate(time.Minute).Add(time.Minute)
		select {
		case <-ctx.Done():
			return
		case <-time.After(next.Sub(now)):
		}
		c.Tick(ctx, next)
	}
}

// Tick starts the jobs due at minute m.
func (c *Cron) Tick(ctx context.Context, m time.Time) {
	accounts, err := c.accounts()
	if err != nil {
		c.Log.Error("read the cron jobs", "err", err)
		return
	}
	for _, a := range accounts {
		for _, j := range a.Jobs {
			if Due(j.Schedule, m) {
				go c.start(ctx, a, j, m)
			}
		}
	}
}

// UnitName is the transient unit of a job's runs.
func UnitName(username, id string) string { return "xcp-cron-" + username + "-" + id + ".service" }

func (c *Cron) start(ctx context.Context, a CronAccount, j CronJob, m time.Time) {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		c.record(a.Username, j.ID, CronRun{Start: m, Skipped: "too many cron jobs are running on the server"})
		return
	}
	args := []string{
		"--wait", "--pipe", "--quiet", "--collect", "--service-type=exec",
		"--unit=" + UnitName(a.Username, j.ID), "--slice=" + SliceName(a.Username),
		"--uid=" + strconv.Itoa(a.UID), "--gid=" + strconv.Itoa(a.GID), "--working-directory=" + a.Home,
		// No NoNewPrivileges: Postfix's sendmail needs setgid postdrop to queue the output mail.
		"--property=RuntimeMaxSec=" + strconv.Itoa(int(CronMaxRuntime.Seconds())),
		"--setenv=HOME=" + a.Home, "--setenv=USER=" + a.Username, "--setenv=LOGNAME=" + a.Username,
		"--setenv=SHELL=/bin/sh", "--setenv=PATH=/usr/local/bin:/usr/bin:/bin",
		"--", CronRunPath,
	}
	if j.MailTo != "" {
		// The sender is the account's user, as Postfix names it.
		args = append(args, "--mail-to="+j.MailTo, "--mail-subject=Cron <"+a.Username+"> "+j.Command)
	}
	args = append(args, "--", j.Command)
	res, err := c.Run.Run(ctx, execx.Cmd{Path: SystemdRunPath, Args: args, Timeout: CronMaxRuntime + time.Minute, MaxOutput: cronOutputCapture})
	run := CronRun{Start: m, Duration: res.Duration, ExitCode: res.ExitCode, Output: tail(string(res.Stdout)+string(res.Stderr), CronOutputKept)}
	var ee *execx.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee) && strings.Contains(ee.Stderr, "already"):
		run = CronRun{Start: m, Skipped: "the previous run is still going"}
	case errors.As(err, &ee):
		run.ExitCode = ee.ExitCode
	default:
		run.Skipped = "could not start: " + err.Error()
		c.Log.Error("start a cron job", "user", a.Username, "job", j.ID, "err", err)
	}
	c.record(a.Username, j.ID, run)
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// record stores a job's last run.
func (c *Cron) record(username, id string, run CronRun) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	runs, _ := c.readState(username)
	runs[id] = run
	b, err := json.Marshal(runs)
	if err == nil {
		_, err = writeFile(c.StateDir, username+".json", string(b), 0o600, "")
	}
	if err != nil {
		c.Log.Error("record a cron run", "user", username, "job", id, "err", err)
	}
}

func (c *Cron) readState(username string) (map[string]CronRun, error) {
	runs := map[string]CronRun{}
	root, err := fsx.OpenRoot(c.StateDir)
	if err != nil {
		return runs, err
	}
	defer root.Close()
	b, err := root.ReadFile(username+".json", 64<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return runs, nil
	}
	if err != nil {
		return runs, err
	}
	return runs, json.Unmarshal(b, &runs)
}

// Status returns the last run of each of an account's jobs.
func (c *Cron) Status(_ context.Context, username string) (map[string]CronRun, error) {
	if validate.Username(username) != nil {
		return nil, invalid("%q is not an account name", username)
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.readState(username)
}
