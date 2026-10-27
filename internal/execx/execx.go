// Package execx is the only place XCP runs external programs
// (07-security.md §6). It never uses a shell: callers give an absolute
// binary path from the runner's allow-list and an argv slice.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"time"
)

// Defaults applied when a Cmd leaves the field zero.
const (
	DefaultTimeout   = 60 * time.Second
	DefaultMaxOutput = 1 << 20 // 1 MiB per stream
)

// SafeEnv is the environment used when Cmd.Env is nil.
var SafeEnv = []string{
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"LANG=C.UTF-8",
	"LC_ALL=C.UTF-8",
}

// ErrNotAllowed is returned when the binary is not on the runner's allow-list.
var ErrNotAllowed = errors.New("execx: binary not allowed")

// Cmd describes one program run.
type Cmd struct {
	Path      string   // absolute path, must be allow-listed
	Args      []string // arguments, without argv[0]
	Env       []string // nil means SafeEnv; never inherits the parent environment
	Dir       string
	Stdin     io.Reader
	Timeout   time.Duration // 0 means DefaultTimeout
	MaxOutput int           // bytes kept per stream; 0 means DefaultMaxOutput
}

// Result holds the outcome of a finished command.
type Result struct {
	Stdout    []byte
	Stderr    []byte
	Truncated bool // output exceeded MaxOutput and was cut
	ExitCode  int
	Duration  time.Duration
}

// ExitError reports a non-zero exit. Stderr is included (truncated) for logs.
type ExitError struct {
	Path     string
	ExitCode int
	Stderr   string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("%s exited with code %d: %s", filepath.Base(e.Path), e.ExitCode, e.Stderr)
}

// Runner runs allow-listed binaries.
type Runner struct {
	allowed map[string]bool
}

// NewRunner returns a runner that may only execute the given absolute paths.
func NewRunner(allowed ...string) (*Runner, error) {
	r := &Runner{allowed: make(map[string]bool, len(allowed))}
	for _, p := range allowed {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, fmt.Errorf("execx: allow-list entry %q must be a clean absolute path", p)
		}
		r.allowed[p] = true
	}
	return r, nil
}

// Run executes c and waits for it. A non-zero exit returns *ExitError together
// with the Result, so callers can still read the output.
func (r *Runner) Run(ctx context.Context, c Cmd) (Result, error) {
	if !r.allowed[c.Path] {
		return Result{}, fmt.Errorf("%w: %q", ErrNotAllowed, c.Path)
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	limit := c.MaxOutput
	if limit <= 0 {
		limit = DefaultMaxOutput
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.Path, c.Args...) //nolint:gosec // path is allow-listed, args are argv (no shell)
	cmd.Env = c.Env
	if cmd.Env == nil {
		cmd.Env = SafeEnv
	}
	cmd.Dir = c.Dir
	cmd.Stdin = c.Stdin
	stdout := &capWriter{limit: limit}
	stderr := &capWriter{limit: limit}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	setProcAttrs(cmd)

	start := time.Now()
	err := cmd.Run()
	res := Result{
		Stdout:    stdout.buf.Bytes(),
		Stderr:    stderr.buf.Bytes(),
		Truncated: stdout.truncated || stderr.truncated,
		Duration:  time.Since(start),
	}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("execx: %s: %w", filepath.Base(c.Path), ctx.Err())
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return res, &ExitError{Path: c.Path, ExitCode: res.ExitCode, Stderr: tail(res.Stderr, 512)}
	}
	if err != nil {
		return res, fmt.Errorf("execx: %s: %w", filepath.Base(c.Path), err)
	}
	return res, nil
}

// capWriter keeps the first limit bytes and silently drops the rest,
// so a chatty program cannot exhaust memory.
type capWriter struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.limit - w.buf.Len(); room < len(p) {
		w.truncated = true
		if room > 0 {
			w.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return w.buf.Write(p)
}

func tail(b []byte, n int) string {
	b = bytes.TrimSpace(b)
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}
