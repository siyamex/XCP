package files_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/domains"
	"github.com/siyamex/XCP/internal/files"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/userfs"
	"github.com/siyamex/XCP/internal/validate"
	"github.com/siyamex/XCP/internal/zones"
)

const pw = "correct horse battery"

var (
	ctx    = context.Background()
	client = auth.Client{IP: "192.0.2.1"}
)

// helper serves a home folder over a Unix socket, as xcp-userd does.
func helper(t *testing.T, home string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "userd.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("no Unix sockets here: %v", err)
	}
	fsys, err := userfs.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: userfs.Handler(fsys, func() {}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Close(); fsys.Close() })
	return sock
}

func TestFiles(t *testing.T) {
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	rec := audit.NewRecorder(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au, err := auth.NewService(db, rec, box, auth.Options{
		SessionIdle: time.Hour, SessionMax: time.Hour, Argon: auth.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	pl := plans.NewService(db, rec)
	if err := pl.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	l, _ := au.CreateLogin(ctx, client, nil, auth.NewLogin{Username: "root", Password: pw, Role: store.RoleAdmin})
	admin := &auth.Principal{Login: l, Session: &store.Session{}}
	pkgs, _ := pl.ListPackages(ctx, admin)
	fake := agentrpc.NewFake()
	q := jobs.NewQueue(db)
	zs := zones.NewService(db, rec, pl, q, fake, zones.StaticHosts{})
	doms := domains.NewService(db, rec, pl, q, fake, zs, domains.StaticTXT{}, []byte("k"))
	accts := accounts.NewService(db, rec, au, pl, q, fake, doms, zs)
	w := jobs.NewWorker(q, "test", log)
	w.Poll = 10 * time.Millisecond
	for _, r := range []interface{ RegisterJobs(*jobs.Worker) }{accts, doms, zs} {
		r.RegisterJobs(w)
	}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done })

	home := t.TempDir()
	sock := helper(t, home)
	svc := files.NewService(db, rec, pl, fake, func(string) string { return sock })
	mk := func(user string) (accounts.Account, *auth.Principal) {
		a, err := accts.Create(ctx, client, admin, accounts.CreateInput{Username: user, Domain: user + ".example", PackageID: pkgs[0].ID, Password: pw})
		if err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if acc, _ := db.AccountByID(ctx, a.ID); acc.Status == store.AccountActive || time.Now().After(deadline) {
				break
			}
		}
		lg, _ := db.AccountLogin(ctx, a.ID)
		return a, &auth.Principal{Login: lg, Session: &store.Session{}}
	}
	a, alice := mk("alice")
	b, _ := mk("bob")

	acc, err := svc.Access(ctx, alice, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Access(ctx, alice, b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("alice reaches bob's files: %v", err)
	}
	if _, err := svc.Upload(ctx, client, acc, "public_html/index.html", false, strings.NewReader("<h1>hi</h1>")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(home, "public_html", "index.html")); string(b) != "<h1>hi</h1>" {
		t.Fatalf("uploaded %q", b)
	}
	resp, err := svc.Download(ctx, client, acc, "public_html/index.html")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "<h1>hi</h1>" {
		t.Fatalf("downloaded %q", body)
	}
	if _, err := svc.Upload(ctx, client, acc, "public_html/index.html", false, strings.NewReader("x")); !conflict(err, "exists") {
		t.Errorf("upload over a file: %v", err)
	}
	if _, err := svc.List(ctx, acc, "../.."); !field(err, "path") {
		t.Errorf("leaving the home: %v", err)
	}
	if _, err := svc.List(ctx, acc, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing folder: %v", err)
	}
	if _, err := svc.Op(ctx, client, acc, "rename", map[string]any{"from": "public_html/index.html", "to": "public_html/home.html"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Op(ctx, client, acc, "rm-rf", map[string]any{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown operation: %v", err)
	}
	if _, err := svc.WriteText(ctx, client, acc, ".htaccess", userfs.Text{Content: "Options -Indexes\n"}); err != nil {
		t.Fatal(err)
	}
	if tx, err := svc.ReadText(ctx, acc, ".htaccess", ""); err != nil || tx.Content != "Options -Indexes\n" {
		t.Fatalf("text: %+v %v", tx, err)
	}
	if _, err := accts.Suspend(ctx, client, admin, a.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Access(ctx, admin, a.ID); !conflict(err, "bad_status") {
		t.Errorf("files of a suspended account: %v", err)
	}
}

func conflict(err error, code string) bool {
	var c *apperr.Conflict
	return errors.As(err, &c) && c.Code == code
}

func field(err error, name string) bool {
	var ve *validate.Error
	return errors.As(err, &ve) && ve.Field == name
}
