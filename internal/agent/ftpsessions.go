package agent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/siyamex/XCP/internal/execx"
)

// PureFTPWhoPath lists the connected FTP sessions (ADR-0026).
const PureFTPWhoPath = "/usr/sbin/pure-ftpwho" //nolint:gosec // G101: a program path

// FTPSession is one connection to the FTP server.
type FTPSession struct {
	PID      int
	Login    string // name@domain
	Seconds  int64  // connected for
	State    string // IDLE, DL, UP, ...
	File     string // being transferred, if any
	Peer     string // the client's address
	Current  int64  // bytes of the transfer so far
	Total    int64  // bytes the file has
	Percent  int
	BytesSec int64
}

// ParseFTPWho reads `pure-ftpwho -s` output:
// pid|account|seconds|state|file|peer|local|port|current|total|percent|bandwidth.
func ParseFTPWho(out []byte) []FTPSession {
	var res []FTPSession
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Split(strings.TrimSpace(sc.Text()), "|")
		if len(f) < 12 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil || pid <= 1 {
			continue
		}
		n := func(s string) int64 { v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return v }
		res = append(res, FTPSession{
			PID: pid, Login: f[1], Seconds: n(f[2]), State: f[3], File: f[4], Peer: f[5],
			Current: n(f[8]), Total: n(f[9]), Percent: int(n(f[10])), BytesSec: n(f[11]),
		})
	}
	return res
}

// Sessions returns the connected FTP sessions.
func (f *FTP) Sessions(ctx context.Context) ([]FTPSession, error) {
	if f.Run == nil {
		return nil, fmt.Errorf("%w: pure-ftpwho", ErrNotInstalled)
	}
	res, err := f.Run.Run(ctx, execx.Cmd{Path: PureFTPWhoPath, Args: []string{"-s", "-n"}, Timeout: 10 * time.Second, MaxOutput: 1 << 20})
	if err != nil {
		return nil, fmt.Errorf("pure-ftpwho: %w", err)
	}
	return ParseFTPWho(res.Stdout), nil
}

// Kill ends a session. Only a pid that pure-ftpwho lists for the login can
// be ended: the pid comes from a browser and must not name another process.
func (f *FTP) Kill(ctx context.Context, pid int, login string) (bool, error) {
	list, err := f.Sessions(ctx)
	if err != nil {
		return false, err
	}
	for _, s := range list {
		if s.PID == pid && s.Login == login {
			if err := f.signal(pid); err != nil {
				return false, fmt.Errorf("end session %d: %w", pid, err)
			}
			return true, nil
		}
	}
	return false, nil
}

func (f *FTP) signal(pid int) error {
	if f.kill != nil {
		return f.kill(pid)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Signal(syscall.SIGTERM)
}
