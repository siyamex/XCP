package ftpauth

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/pwhash"
)

var hash = pwhash.Hash("ftp password 1")

func setup(t *testing.T) (*Server, string, string) {
	t.Helper()
	dir, home := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "public_html", "shop"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFragment(t, dir, agent.FTPAccount{Username: "alice", UID: 10001, GID: 10001, Home: home, Logins: []agent.FTPLogin{
		{Login: "bob@example.com", PasswordHash: hash, Dir: "public_html/shop", QuotaMB: 100},
		{Login: "all@example.com", PasswordHash: hash, Dir: "."},
	}})
	return &Server{Dir: dir, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, dir, home
}

func writeFragment(t *testing.T, dir string, a agent.FTPAccount) {
	t.Helper()
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, a.Username+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCheck(t *testing.T) {
	s, _, home := setup(t)
	ctx := context.Background()
	got := s.Check(ctx, Request{Account: "Bob@Example.com", Password: "ftp password 1"})
	want := "auth_ok:1\nuid:10001\ngid:10001\ndir:" + filepath.ToSlash(filepath.Join(home, "public_html", "shop")) + "/\nuser_quota_size:104857600\nend\n"
	if filepath.Separator == '/' && got != want || !strings.HasPrefix(got, "auth_ok:1\n") {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := s.Check(ctx, Request{Account: "all@example.com", Password: "ftp password 1"}); !strings.Contains(got, "dir:"+home+"/\n") ||
		strings.Contains(got, "quota") {
		t.Errorf("whole home: %q", got)
	}
	for _, r := range []Request{
		{Account: "bob@example.com", Password: "wrong"},
		{Account: "bob@example.com", Password: ""},
		{Account: "nobody@example.com", Password: "ftp password 1"},
	} {
		if got := s.Check(ctx, r); got != "auth_ok:0\nend\n" {
			t.Errorf("%+v: %q", r, got)
		}
	}
}

func TestCheckRefusesAFolderThatIsNoLongerOne(t *testing.T) {
	s, _, home := setup(t)
	shop := filepath.Join(home, "public_html", "shop")
	if err := os.Remove(shop); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", shop); err != nil {
		t.Skip("no symlinks here:", err)
	}
	if got := s.Check(context.Background(), Request{Account: "bob@example.com", Password: "ftp password 1"}); got != "auth_ok:0\nend\n" {
		t.Errorf("a symlink became the folder: %q", got)
	}
}

func TestLoginsAreReadAgainAfterAChange(t *testing.T) {
	s, dir, home := setup(t)
	ctx := context.Background()
	req := Request{Account: "new@example.org", Password: "ftp password 1"}
	if got := s.Check(ctx, req); got != "auth_ok:0\nend\n" {
		t.Fatalf("before: %q", got)
	}
	time.Sleep(20 * time.Millisecond) // a new folder time
	writeFragment(t, dir, agent.FTPAccount{Username: "carol", UID: 10002, GID: 10002, Home: home, Logins: []agent.FTPLogin{
		{Login: "new@example.org", PasswordHash: hash, Dir: "."},
	}})
	if got := s.Check(ctx, req); !strings.HasPrefix(got, "auth_ok:1\nuid:10002\n") {
		t.Errorf("after: %q", got)
	}
}

func TestReadRequest(t *testing.T) {
	in := "account:bob@example.com\npassword:pa:ss word\nlocalhost:127.0.0.1\nlocalport:21\npeer:192.0.2.7\nsni_name:\nencrypted:1\nend\n"
	r, err := ReadRequest(bufio.NewReaderSize(strings.NewReader(in), maxLine))
	if err != nil || r != (Request{Account: "bob@example.com", Password: "pa:ss word", Peer: "192.0.2.7", Encrypted: true}) {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{
		"account:x\n",                         // no end
		strings.Repeat("x", 2000) + "\nend\n", // too long
		strings.Repeat("a:b\n", 20) + "end\n", // too many lines
	} {
		if _, err := ReadRequest(bufio.NewReaderSize(strings.NewReader(bad), maxLine)); err == nil {
			t.Errorf("%.30q accepted", bad)
		}
	}
}

func TestServe(t *testing.T) {
	s, _, _ := setup(t)
	sock := filepath.Join(t.TempDir(), "a.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets here:", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx, l) }()
	defer l.Close()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "account:all@example.com\npassword:ftp password 1\npeer:::1\nend\n"); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil || !strings.HasPrefix(string(b), "auth_ok:1\n") || !strings.HasSuffix(string(b), "end\n") {
		t.Fatalf("%q %v", b, err)
	}
}
