package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
)

// MaxManagedFileSize bounds FileWriteManaged content.
const MaxManagedFileSize = 4 << 20

// Validator selects a fixed config check command.
type Validator int

// Validators, mirroring the proto enum.
const (
	ValidatorNone Validator = iota
	ValidatorApache
	ValidatorNginx
	ValidatorPostfix
)

// ValidatorCommands are the fixed commands behind each Validator. Their paths
// must be on the agent's execx allow-list.
var ValidatorCommands = map[Validator]execx.Cmd{
	ValidatorApache:  {Path: "/usr/sbin/apachectl", Args: []string{"-t"}},
	ValidatorNginx:   {Path: "/usr/sbin/nginx", Args: []string{"-t", "-q"}},
	ValidatorPostfix: {Path: "/usr/sbin/postfix", Args: []string{"check"}},
}

// ValidationFailedError: the new file failed its validator and the previous
// state was restored.
type ValidationFailedError struct {
	Output string
}

func (e *ValidationFailedError) Error() string {
	return "config validation failed, previous file restored: " + e.Output
}

// ConfigCheck runs a validator; it returns *ValidationFailedError when the check fails.
type ConfigCheck func(ctx context.Context, v Validator) error

// ExecConfigCheck runs ValidatorCommands with run.
func ExecConfigCheck(run *execx.Runner) ConfigCheck {
	return func(ctx context.Context, v Validator) error {
		cmd, ok := ValidatorCommands[v]
		if !ok {
			return invalid("unknown validator %d", v)
		}
		res, err := run.Run(ctx, cmd)
		var ee *execx.ExitError
		if errors.As(err, &ee) {
			return &ValidationFailedError{Output: strings.TrimSpace(string(res.Stderr) + "\n" + string(res.Stdout))}
		}
		return err
	}
}

// DefaultManagedDirs are the directories xcp-agent may write generated files
// into when the config does not list any.
var DefaultManagedDirs = []string{
	"/etc/xcp/generated",
	"/etc/apache2/xcp",
	"/etc/nginx/xcp",
}

var allowedModes = map[fs.FileMode]bool{0o600: true, 0o640: true, 0o644: true}

// Each element of a managed path: no leading dot (reserved for temp files).
var managedNameRe = regexp.MustCompile(`^[A-Za-z0-9_@+-][A-Za-z0-9._@+-]*$`)

// CheckWriteRequest applies the FileWriteManaged rules to a Linux path,
// without touching the disk. The fake agent uses it so development fails on
// the same requests as production.
func CheckWriteRequest(dirs []string, p string, content []byte, mode fs.FileMode) error {
	if err := checkModeAndSize(content, mode); err != nil {
		return err
	}
	return CheckRemoveRequest(dirs, p)
}

// CheckRemoveRequest applies the FileRemoveManaged path rules to a Linux path.
func CheckRemoveRequest(dirs []string, p string) error {
	if !path.IsAbs(p) || path.Clean(p) != p {
		return invalid("path %q must be clean and absolute", p)
	}
	_, _, err := managedRel(dirs, p)
	return err
}

func checkModeAndSize(content []byte, mode fs.FileMode) error {
	if !allowedModes[mode] {
		return invalid("mode %#o not allowed (use 0600, 0640 or 0644)", mode)
	}
	if len(content) > MaxManagedFileSize {
		return invalid("content larger than %d bytes", MaxManagedFileSize)
	}
	return nil
}

// managedRel finds which of dirs (slash form) contains p (slash form) and
// returns its index and the relative path, checking every path element.
func managedRel(dirs []string, p string) (int, string, error) {
	for i, d := range dirs {
		rel, ok := strings.CutPrefix(p, d+"/")
		if !ok {
			continue
		}
		for _, elem := range strings.Split(rel, "/") {
			if !managedNameRe.MatchString(elem) || len(elem) > fsx.MaxNameLen {
				return 0, "", invalid("path element %q is not allowed", elem)
			}
		}
		return i, rel, nil
	}
	return 0, "", invalid("path %q is not inside a managed directory", p)
}

// Files writes generated config files below allow-listed directories.
type Files struct {
	dirs  []string
	check ConfigCheck
	mu    sync.Mutex // one config change at a time, so validators see a consistent tree
}

// NewFiles returns a file manager for the given managed directories
// (absolute, clean, existing). check may be nil if no validators are used.
func NewFiles(dirs []string, check ConfigCheck) (*Files, error) {
	for _, d := range dirs {
		if !filepath.IsAbs(d) || filepath.Clean(d) != d {
			return nil, fmt.Errorf("managed dir %q must be a clean absolute path", d)
		}
	}
	return &Files{dirs: dirs, check: check}, nil
}

// resolve finds the managed dir containing p and returns the slash-separated rest.
func (f *Files) resolve(p string) (dir, rel string, err error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return "", "", invalid("path %q must be clean and absolute", p)
	}
	slashDirs := make([]string, len(f.dirs))
	for i, d := range f.dirs {
		slashDirs[i] = filepath.ToSlash(d)
	}
	i, rel, err := managedRel(slashDirs, filepath.ToSlash(p))
	if err != nil {
		return "", "", err
	}
	return f.dirs[i], rel, nil
}

// Write writes content to p atomically. It returns changed=false without
// touching anything when the file already has this content and mode.
func (f *Files) Write(ctx context.Context, p string, content []byte, mode fs.FileMode, v Validator) (changed bool, err error) {
	if err := checkModeAndSize(content, mode); err != nil {
		return false, err
	}
	dir, rel, err := f.resolve(p)
	if err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	root, err := fsx.OpenRoot(dir)
	if err != nil {
		return false, err
	}
	defer root.Close()

	prev, prevMode, existed, err := readPrevious(root, rel)
	if err != nil {
		return false, err
	}
	if existed && prevMode == mode && bytes.Equal(prev, content) {
		return false, nil
	}
	if err := root.MkdirAll(path.Dir(rel), 0o755); err != nil {
		return false, err
	}
	if err := root.WriteFileAtomic(rel, content, mode); err != nil {
		return false, err
	}
	if err := f.validate(ctx, v); err != nil {
		return false, errors.Join(err, restore(root, rel, prev, prevMode, existed))
	}
	return true, nil
}

// Remove deletes p. It returns changed=false if p did not exist.
func (f *Files) Remove(ctx context.Context, p string, v Validator) (changed bool, err error) {
	dir, rel, err := f.resolve(p)
	if err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	root, err := fsx.OpenRoot(dir)
	if err != nil {
		return false, err
	}
	defer root.Close()

	prev, prevMode, existed, err := readPrevious(root, rel)
	if err != nil || !existed {
		return false, err
	}
	if err := root.Remove(rel); err != nil {
		return false, err
	}
	if err := f.validate(ctx, v); err != nil {
		return false, errors.Join(err, restore(root, rel, prev, prevMode, true))
	}
	return true, nil
}

func (f *Files) validate(ctx context.Context, v Validator) error {
	if v == ValidatorNone {
		return nil
	}
	if f.check == nil {
		return invalid("validator %d requested but no config checker configured", v)
	}
	return f.check(ctx, v)
}

// readPrevious returns the current file, refusing anything but a regular file.
func readPrevious(root *fsx.Root, rel string) (content []byte, mode fs.FileMode, existed bool, err error) {
	fi, err := root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, 0, false, invalid("%s exists and is not a regular file", rel)
	}
	content, err = root.ReadFile(rel, MaxManagedFileSize)
	return content, fi.Mode().Perm(), true, err
}

func restore(root *fsx.Root, rel string, prev []byte, mode fs.FileMode, existed bool) error {
	if existed {
		return root.WriteFileAtomic(rel, prev, mode)
	}
	if err := root.Remove(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
