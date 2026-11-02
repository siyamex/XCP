// Package ftpauth answers Pure-FTPd's external authentication (extauth)
// requests from the FTP fragments xcp-agent writes (ADR-0010).
//
// Pure-FTPd connects to the socket once per login and sends lines
// "account:<login>", "password:<password>", "localhost:", "localport:",
// "peer:<ip>", "sni_name:", "encrypted:0|1" and "end". The answer is
// "auth_ok:1", "uid:", "gid:", "dir:" and optionally "user_quota_size:",
// then "end"; or "auth_ok:0" and "end" to refuse.
package ftpauth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/pwhash"
)

// Limits of one request.
const (
	maxLine     = 1024
	maxLines    = 16
	connTimeout = 10 * time.Second
	// MaxChecks is how many password checks run at once; each takes 64 MiB.
	MaxChecks = 4
	// reloadEvery rereads the fragments even when the folder looks unchanged.
	reloadEvery = time.Minute
)

type login struct {
	hash     string
	uid, gid int
	home     string
	dir      string
	quotaMB  int64
}

// Server checks logins against the fragments in Dir.
type Server struct {
	Dir string
	Log *slog.Logger

	once   sync.Once
	checks chan struct{}

	mu     sync.Mutex
	mtime  time.Time
	loaded time.Time
	logins map[string]login
}

func (s *Server) init() {
	s.once.Do(func() { s.checks = make(chan struct{}, MaxChecks) })
}

// load rereads the fragments when their folder changed (or a minute passed).
// On a read error it keeps the logins it had.
func (s *Server) load() map[string]login {
	s.mu.Lock()
	defer s.mu.Unlock()
	fi, err := os.Stat(s.Dir)
	if err == nil && s.logins != nil && fi.ModTime().Equal(s.mtime) && time.Since(s.loaded) < reloadEvery {
		return s.logins
	}
	accounts, err := agent.ReadFTPFragments(s.Dir)
	if err != nil {
		s.Log.Error("read the FTP logins", "dir", s.Dir, "err", err)
		if s.logins == nil {
			return map[string]login{}
		}
		return s.logins
	}
	m := map[string]login{}
	for _, a := range accounts {
		for _, l := range a.Logins {
			m[l.Login] = login{hash: l.PasswordHash, uid: a.UID, gid: a.GID, home: a.Home, dir: l.Dir, quotaMB: l.QuotaMB}
		}
	}
	s.logins, s.loaded = m, time.Now()
	if fi != nil {
		s.mtime = fi.ModTime()
	}
	return m
}

// Request is what Pure-FTPd asks.
type Request struct {
	Account, Password, Peer string
	Encrypted               bool
}

// ReadRequest reads one request.
func ReadRequest(r *bufio.Reader) (Request, error) {
	var req Request
	for range maxLines {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxLine {
			return req, errors.New("request line too long")
		}
		if err != nil {
			return req, err
		}
		key, val, _ := strings.Cut(strings.TrimSuffix(string(line), "\n"), ":")
		switch key {
		case "end":
			return req, nil
		case "account":
			req.Account = val
		case "password":
			req.Password = val
		case "peer":
			req.Peer = val
		case "encrypted":
			req.Encrypted = val == "1"
		}
	}
	return req, errors.New("request without end")
}

// Check answers a request.
func (s *Server) Check(ctx context.Context, req Request) string {
	s.init()
	const refuse = "auth_ok:0\nend\n"
	name := strings.ToLower(req.Account)
	l, ok := s.load()[name]
	hash := l.hash
	if !ok {
		hash = pwhash.Dummy() // the same work, so timing does not tell which logins exist
	}
	select {
	case s.checks <- struct{}{}:
	case <-ctx.Done():
		return refuse
	}
	good := pwhash.Check(hash, req.Password)
	<-s.checks
	if !ok || !good || len(req.Password) == 0 {
		s.Log.Info("FTP login refused", "login", name, "peer", req.Peer, "known", ok)
		return refuse
	}
	dir, err := folder(l.home, l.dir)
	if err != nil {
		s.Log.Warn("FTP login refused: its folder is not usable", "login", name, "peer", req.Peer, "err", err)
		return refuse
	}
	var b strings.Builder
	fmt.Fprintf(&b, "auth_ok:1\nuid:%d\ngid:%d\ndir:%s/\n", l.uid, l.gid, dir)
	if l.quotaMB > 0 {
		fmt.Fprintf(&b, "user_quota_size:%d\n", l.quotaMB<<20)
	}
	b.WriteString("end\n")
	s.Log.Info("FTP login", "login", name, "peer", req.Peer, "tls", req.Encrypted)
	return b.String()
}

// folder checks a login's folder at login time: inside the home, a real
// folder, no symlinks on the way.
func folder(home, rel string) (string, error) {
	root, err := fsx.OpenRoot(home)
	if err != nil {
		return "", err
	}
	defer root.Close()
	fi, err := root.Lstat(rel)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s: %w", rel, fs.ErrInvalid)
	}
	if rel == "." {
		return home, nil
	}
	return path.Join(home, rel), nil
}

// Serve answers connections until l fails; after ctx ends that is ctx's error.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.handle(ctx, c)
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(connTimeout))
	req, err := ReadRequest(bufio.NewReaderSize(c, maxLine))
	if err != nil {
		s.Log.Warn("bad extauth request", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, connTimeout)
	defer cancel()
	_, _ = c.Write([]byte(s.Check(ctx, req)))
}
