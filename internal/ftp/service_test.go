package ftp_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
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
	"github.com/siyamex/XCP/internal/ftp"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/pwhash"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
	"github.com/siyamex/XCP/internal/zones"
)

const pw = "correct horse battery"

var (
	ctx    = context.Background()
	client = auth.Client{IP: "192.0.2.1"}
)

type host string

func (h host) Hostname(context.Context) string { return string(h) }

type env struct {
	svc   *ftp.Service
	accts *accounts.Service
	doms  *domains.Service
	db    *store.DB
	q     *jobs.Queue
	fake  *agentrpc.Fake
	admin *auth.Principal
	pkgID string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	rec := audit.NewRecorder(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au, err := auth.NewService(db, rec, box, auth.Options{
		SessionIdle: time.Hour, SessionMax: time.Hour,
		Argon: auth.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	pl := plans.NewService(db, rec)
	if err := pl.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	l, err := au.CreateLogin(ctx, client, nil, auth.NewLogin{Username: "root", Password: pw, Role: store.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	admin := &auth.Principal{Login: l, Session: &store.Session{}}
	pkgs, _ := pl.ListPackages(ctx, admin)
	fake := agentrpc.NewFake()
	q := jobs.NewQueue(db)
	zs := zones.NewService(db, rec, pl, q, fake, zones.StaticHosts{})
	if err := zs.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	doms := domains.NewService(db, rec, pl, q, fake, zs, domains.StaticTXT{}, []byte("test key"))
	accts := accounts.NewService(db, rec, au, pl, q, fake, doms, zs)
	svc := ftp.NewService(db, rec, pl, q, fake, host("ftp.host.example"))
	accts.Attach("ftp", svc)
	doms.SetMailHook(func(ctx context.Context, tx *sql.Tx, by, accountID string) error {
		_, err := svc.EnqueueApply(ctx, tx, by, accountID)
		return err
	})
	w := jobs.NewWorker(q, "test", log)
	w.Poll = 10 * time.Millisecond
	for _, r := range []interface{ RegisterJobs(*jobs.Worker) }{accts, doms, zs, svc} {
		r.RegisterJobs(w)
	}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return &env{svc: svc, accts: accts, doms: doms, db: db, q: q, fake: fake, admin: admin, pkgID: pkgs[0].ID}
}

func (e *env) account(t *testing.T, user string) (accounts.Account, *auth.Principal) {
	t.Helper()
	a, err := e.accts.Create(ctx, client, e.admin, accounts.CreateInput{Username: user, Domain: user + ".example", PackageID: e.pkgID, Password: pw})
	if err != nil {
		t.Fatalf("create %s: %v", user, err)
	}
	e.waitJob(t, a.JobID)
	l, err := e.db.AccountLogin(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	return a, &auth.Principal{Login: l, Session: &store.Session{}}
}

func (e *env) waitJob(t *testing.T, id string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		j, err := e.q.Get(ctx, id)
		if err == nil && (j.Status == jobs.StatusSucceeded || j.Status == jobs.StatusFailed) {
			if j.Status == jobs.StatusFailed {
				t.Fatalf("job %s (%s) failed: %s", id, j.Kind, j.Error)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s did not finish", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
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

func TestFTPLifecycle(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")
	o, err := e.svc.Overview(ctx, user, a.ID)
	if err != nil || len(o.Domains) != 1 || len(o.Logins) != 0 || o.Server != "ftp.host.example" || o.Port != 21 || o.MaxLogins == nil || *o.MaxLogins != 5 {
		t.Fatalf("overview: %+v %v", o, err)
	}
	dom := o.Domains[0].ID

	l, err := e.svc.Create(ctx, client, user, a.ID, ftp.Input{DomainID: dom, Name: " Upload ", Password: pw, Folder: "/public_html/shop/", QuotaMB: 500})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, l.JobID)
	if l.Login != "upload@alice.example" || l.Folder != "public_html/shop" || l.QuotaMB != 500 {
		t.Fatalf("login %+v", l)
	}
	got, ok := e.fake.FTPAccount("alice")
	if !ok || len(got.Logins) != 1 || got.Logins[0].Login != "upload@alice.example" || got.Logins[0].Dir != "public_html/shop" ||
		!pwhash.Check(got.Logins[0].PasswordHash, pw) {
		t.Fatalf("logins in the agent: %+v", got)
	}
	whole, err := e.svc.Create(ctx, client, user, a.ID, ftp.Input{DomainID: dom, Name: "all", Password: pw})
	if err != nil || whole.Folder != "." {
		t.Fatalf("whole home: %+v %v", whole, err)
	}

	for _, c := range []struct {
		in    ftp.Input
		field string
	}{
		{ftp.Input{DomainID: dom, Name: "x y", Password: pw}, "name"},
		{ftp.Input{DomainID: dom, Name: "-x", Password: pw}, "name"},
		{ftp.Input{DomainID: dom, Name: strings.Repeat("a", 33), Password: pw}, "name"},
		{ftp.Input{DomainID: dom, Name: "short", Password: "pw"}, "password"},
		{ftp.Input{DomainID: dom, Name: "up", Password: pw, Folder: "../bob"}, "folder"},
		{ftp.Input{DomainID: dom, Name: "up", Password: pw, Folder: ".xcp/secrets"}, "folder"},
		{ftp.Input{DomainID: dom, Name: "up", Password: pw, QuotaMB: -1}, "quota_mb"},
		{ftp.Input{DomainID: "nope", Name: "up", Password: pw}, "domain_id"},
	} {
		if _, err := e.svc.Create(ctx, client, user, a.ID, c.in); !field(err, c.field) {
			t.Errorf("%+v: %v", c.in, err)
		}
	}
	if _, err := e.svc.Create(ctx, client, user, a.ID, ftp.Input{DomainID: dom, Name: "upload", Password: pw}); !conflict(err, "login_taken") {
		t.Errorf("same login twice: %v", err)
	}

	l, err = e.svc.Update(ctx, client, user, l.ID, ftp.Update{Folder: "", QuotaMB: 0})
	if err != nil || l.Folder != "." || l.QuotaMB != 0 {
		t.Fatalf("update: %+v %v", l, err)
	}
	e.waitJob(t, l.JobID)
	jobID, err := e.svc.SetPassword(ctx, client, user, l.ID, "another long password")
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	got, _ = e.fake.FTPAccount("alice")
	if got.Logins[1].Login != "upload@alice.example" || got.Logins[1].Dir != "." || !pwhash.Check(got.Logins[1].PasswordHash, "another long password") {
		t.Fatalf("after update and password: %+v", got.Logins)
	}

	// Suspension leaves the account no logins; unsuspending brings them back.
	if _, err := e.accts.Suspend(ctx, client, e.admin, a.ID, "test"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { got, ok := e.fake.FTPAccount("alice"); return ok && len(got.Logins) == 0 })
	if _, err := e.accts.Unsuspend(ctx, client, e.admin, a.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { got, _ := e.fake.FTPAccount("alice"); return len(got.Logins) == 2 })

	if jobID, err = e.svc.Delete(ctx, client, user, whole.ID); err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	if got, _ = e.fake.FTPAccount("alice"); len(got.Logins) != 1 {
		t.Fatalf("after delete: %+v", got.Logins)
	}
	if _, err := e.accts.Terminate(ctx, client, e.admin, a.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, ok := e.fake.FTPAccount("alice"); return !ok })
}

func TestFTPIsolationAndLimits(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice")
	b, bob := e.account(t, "bob")
	o, _ := e.svc.Overview(ctx, alice, a.ID)
	dom := o.Domains[0].ID
	if _, err := e.svc.Overview(ctx, bob, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob reads alice's logins: %v", err)
	}
	if _, err := e.svc.Create(ctx, client, bob, b.ID, ftp.Input{DomainID: dom, Name: "steal", Password: pw}); !field(err, "domain_id") {
		t.Errorf("bob names a login after alice's domain: %v", err)
	}
	l, err := e.svc.Create(ctx, client, alice, a.ID, ftp.Input{DomainID: dom, Name: "web", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetPassword(ctx, client, bob, l.ID, "bob's own password"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob changes alice's login: %v", err)
	}
	if _, err := e.svc.Delete(ctx, client, bob, l.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob deletes alice's login: %v", err)
	}
	for i := range 4 {
		if _, err := e.svc.Create(ctx, client, alice, a.ID, ftp.Input{DomainID: dom, Name: "u" + string(rune('a'+i)), Password: pw}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.Create(ctx, client, alice, a.ID, ftp.Input{DomainID: dom, Name: "six", Password: pw}); !conflict(err, "limit_reached") {
		t.Errorf("a sixth login with the default package's 5: %v", err)
	}
}

func TestRemovingADomainRemovesItsLogins(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice")
	o, _ := e.svc.Overview(ctx, alice, a.ID)
	sub, err := e.doms.Add(ctx, client, alice, a.ID, domains.AddInput{Kind: store.DomainSub, Name: "blog", ParentID: o.Domains[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, sub.JobID)
	l, err := e.svc.Create(ctx, client, alice, a.ID, ftp.Input{DomainID: sub.ID, Name: "writer", Password: pw, Folder: "domains/blog.alice.example"})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, l.JobID)
	if got, _ := e.fake.FTPAccount("alice"); len(got.Logins) != 1 || got.Logins[0].Login != "writer@blog.alice.example" {
		t.Fatalf("before: %+v", got)
	}
	jobID, err := e.doms.Delete(ctx, client, alice, sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	waitFor(t, func() bool { got, _ := e.fake.FTPAccount("alice"); return len(got.Logins) == 0 })
	if o, _ = e.svc.Overview(ctx, alice, a.ID); len(o.Logins) != 0 {
		t.Errorf("the login outlived its domain: %+v", o.Logins)
	}
}
