package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TOTP test helper
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/httpapi"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
)

const pw = "correct horse battery"

func TestParseOSRelease(t *testing.T) {
	m := parseOSRelease("# comment\nID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME='Ubuntu 24.04.1 LTS'\n\n")
	if m["ID"] != "ubuntu" || m["VERSION_ID"] != "24.04" || m["PRETTY_NAME"] != "Ubuntu 24.04.1 LTS" {
		t.Fatalf("parsed %v", m)
	}
}

func TestMountFor(t *testing.T) {
	mounts := `/dev/sda1 / ext4 rw,relatime 0 0
/dev/sdb1 /home ext4 rw,relatime,usrjquota=aquota.user,jqfmt=vfsv1 0 0
/dev/sdc1 /homes2 xfs rw,usrquota 0 0
/dev/sdd1 /srv/my\040data ext4 rw 0 0`
	cases := map[string]string{"/home": "/home", "/home/alice/x": "/home", "/homes2": "/homes2", "/var/lib": "/", "/srv/my data/x": "/srv/my data"}
	for dir, want := range cases {
		mp, _, ok := mountFor(mounts, dir)
		if !ok || mp != want {
			t.Errorf("mountFor(%q) = %q, want %q", dir, mp, want)
		}
	}
	_, opts, _ := mountFor(mounts, "/home/alice")
	if !strings.Contains(strings.Join(opts, ","), "usrjquota") {
		t.Errorf("opts = %v", opts)
	}
}

func totp(t *testing.T, secretB32 string, at time.Time) string {
	t.Helper()
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

func startAPI(t *testing.T) (*httptest.Server, *auth.Service) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, _ := secretbox.New(bytes.Repeat([]byte{5}, secretbox.KeySize))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := auth.NewService(db, audit.NewRecorder(db), box, auth.Options{
		SessionIdle: time.Hour, SessionMax: time.Hour, Argon: auth.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateLogin(ctx, auth.Client{}, nil, auth.NewLogin{Username: "root", Password: pw, Role: store.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(httpapi.New(httpapi.Deps{Auth: svc, Agent: agentrpc.NewFake(), Log: log}))
	t.Cleanup(srv.Close)
	dir := filepath.Join(t.TempDir(), "xcpctl")
	stateDir = func() (string, error) { return dir, nil }
	return srv, svc
}

func ctl(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, strings.NewReader(stdin), &out)
	return out.String(), err
}

func TestRemoteLoginMeSessionsLogout(t *testing.T) {
	srv, _ := startAPI(t)

	if _, err := ctl(t, "", "me"); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("me before login: %v", err)
	}
	if _, err := ctl(t, "wrong password!\n", "login", "--server", srv.URL, "--username", "root"); err == nil || !strings.Contains(err.Error(), "invalid_credentials") {
		t.Fatalf("wrong password: %v", err)
	}
	out, err := ctl(t, "root\n"+pw+"\n", "login", "--server", srv.URL)
	if err != nil || !strings.Contains(out, "logged in") {
		t.Fatalf("login: %q %v", out, err)
	}
	p, _ := statePath()
	if fi, err := os.Stat(p); err != nil || (fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf("state file %s: %v %v", p, fi, err)
	}
	if out, err := ctl(t, "", "me"); err != nil || !strings.Contains(out, "root") || !strings.Contains(out, "admin") {
		t.Fatalf("me: %q %v", out, err)
	}
	if out, err := ctl(t, "", "sessions", "list"); err != nil || !strings.Contains(out, "(this)") {
		t.Fatalf("sessions: %q %v", out, err)
	}
	if out, err := ctl(t, "", "logout"); err != nil || !strings.Contains(out, "logged out") {
		t.Fatalf("logout: %q %v", out, err)
	}
	if _, err := ctl(t, "", "me"); err == nil {
		t.Fatal("me works after logout")
	}
}

func TestRemoteLoginWithTwoFactorFromPipedInput(t *testing.T) {
	srv, svc := startAPI(t)
	ctx := context.Background()
	res, err := svc.Login(ctx, auth.Client{}, "root", pw)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := svc.Authenticate(ctx, res.Token)
	setup, err := svc.BeginTOTP(ctx, auth.Client{}, p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := svc.ConfirmTOTP(ctx, auth.Client{}, p, totp(t, setup.Secret, now)); err != nil {
		t.Fatal(err)
	}
	// Username, password and code arrive on one pipe; none may be lost between prompts.
	stdin := "root\n" + pw + "\n" + totp(t, setup.Secret, now.Add(30*time.Second)) + "\n"
	if out, err := ctl(t, stdin, "login", "--server", srv.URL); err != nil || !strings.Contains(out, "logged in") {
		t.Fatalf("2FA login: %q %v", out, err)
	}
	if out, err := ctl(t, "", "me"); err != nil || !strings.Contains(out, "true") {
		t.Fatalf("me: %q %v", out, err)
	}
}

func TestAdminCreateLocal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root, xcpctl switches to the service user, which does not exist in test containers")
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "xcp.toml")
	os.WriteFile(cfg, []byte(`
[api]
listen = "127.0.0.1:2443"
insecure_dev_http = true
[agent]
fake = true
[db]
path = "xcp.db"
[paths]
secrets_dir = "secrets"
`), 0o600)
	out, err := ctl(t, pw+"\n", "admin", "create", "--config", cfg, "--username", "admin")
	if err != nil || !strings.Contains(out, `created admin login "admin"`) {
		t.Fatalf("admin create: %q %v", out, err)
	}
	if _, err := ctl(t, pw+"\n", "admin", "create", "--config", cfg, "--username", "admin"); err == nil {
		t.Fatal("duplicate admin accepted")
	}
	if _, err := ctl(t, "short\n", "admin", "create", "--config", cfg, "--username", "other"); err == nil {
		t.Fatal("weak password accepted")
	}
	if out, err := ctl(t, pw+"\n", "admin", "create", "--config", cfg, "--username", "second", "--if-none"); err != nil || !strings.Contains(out, "skipped") {
		t.Fatalf("--if-none with an existing login: %q %v", out, err)
	}
	out, err = ctl(t, "", "doctor", "--config", cfg)
	// The API is not running in this test, so doctor reports that check as failed.
	if !strings.Contains(out, "OK    database") || !strings.Contains(out, "FAIL  api") || err == nil {
		t.Fatalf("doctor: %q %v", out, err)
	}
}
