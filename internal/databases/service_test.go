package databases_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/databases"
	"github.com/siyamex/XCP/internal/domains"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
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

type env struct {
	svc   *databases.Service
	accts *accounts.Service
	plans *plans.Service
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
	doms := domains.NewService(db, rec, pl, q, fake, zs, domains.StaticTXT{}, []byte("test key"))
	accts := accounts.NewService(db, rec, au, pl, q, fake, doms, zs)
	svc := databases.NewService(db, rec, pl, q, fake, box)
	accts.SetDatabases(svc)
	w := jobs.NewWorker(q, "test", log)
	w.Poll = 10 * time.Millisecond
	for _, r := range []interface{ RegisterJobs(*jobs.Worker) }{accts, doms, zs, svc} {
		r.RegisterJobs(w)
	}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return &env{svc: svc, accts: accts, plans: pl, db: db, q: q, fake: fake, admin: admin, pkgID: pkgs[0].ID}
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

func (e *env) waitJob(t *testing.T, id string) *jobs.Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		j, err := e.q.Get(ctx, id)
		if err == nil && (j.Status == jobs.StatusSucceeded || j.Status == jobs.StatusFailed) {
			if j.Status == jobs.StatusFailed {
				t.Fatalf("job %s (%s) failed: %s", id, j.Kind, j.Error)
			}
			return j
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s did not finish", id)
		}
		time.Sleep(10 * time.Millisecond)
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

func TestDatabaseLifecycle(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")

	res, err := e.svc.Wizard(ctx, client, user, a.ID, databases.WizardInput{Database: "shop", User: "app", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, res.JobID)
	if res.Database.Name != "alice_shop" || res.User.Name != "alice_app" || res.Host != "localhost" {
		t.Fatalf("wizard: %+v", res)
	}
	dbs, users, locked := e.fake.MySQLAccount("alice")
	if !slices.Equal(dbs, []string{"alice_shop"}) || len(users) != 1 || locked {
		t.Fatalf("MariaDB has %v %+v %v", dbs, users, locked)
	}
	if u := users[0]; u.PasswordHash != agent.NativePasswordHash(pw) || len(u.Grants) != 1 ||
		u.Grants[0].Database != "alice_shop" || !slices.Equal(u.Grants[0].Privileges, []string{"ALL"}) {
		t.Fatalf("user in MariaDB: %+v", u)
	}

	// A typed prefix is accepted; bad names are refused.
	d2, err := e.svc.CreateDatabase(ctx, client, user, a.ID, "alice_blog")
	if err != nil || d2.Name != "alice_blog" {
		t.Fatalf("create with prefix: %+v %v", d2, err)
	}
	e.waitJob(t, d2.JobID)
	for _, bad := range []string{"", "bad-name", "x;drop", "a" + string(make([]byte, 60))} {
		if _, err := e.svc.CreateDatabase(ctx, client, user, a.ID, bad); !field(err, "name") {
			t.Errorf("%q: want a name error, got %v", bad, err)
		}
	}
	if _, err := e.svc.CreateDatabase(ctx, client, user, a.ID, "shop"); !conflict(err, "name_taken") {
		t.Errorf("duplicate: %v", err)
	}

	// Custom privileges; every privilege listed means ALL.
	jobID, err := e.svc.SetGrant(ctx, client, user, res.User.ID, d2.ID, databases.GrantInput{Privileges: []string{"insert", "SELECT"}})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	if _, err := e.svc.SetGrant(ctx, client, user, res.User.ID, d2.ID, databases.GrantInput{Privileges: []string{"SUPER"}}); !field(err, "privileges") {
		t.Errorf("SUPER: %v", err)
	}
	o, err := e.svc.Overview(ctx, user, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if o.Prefix != "alice_" || len(o.Databases) != 2 || o.Databases[0].Name != "alice_blog" || o.Databases[0].SizeBytes == nil ||
		!slices.Equal(o.Users[0].Databases[0].Privileges, []string{"SELECT", "INSERT"}) || o.Server != "ok" || !o.PHPMyAdmin {
		t.Fatalf("overview: %+v", o)
	}

	// Rename moves the database; the job moves the grants.
	r, err := e.svc.RenameDatabase(ctx, client, user, d2.ID, "news")
	if err != nil || r.Name != "alice_news" {
		t.Fatalf("rename: %+v %v", r, err)
	}
	e.waitJob(t, r.JobID)
	_, users, _ = e.fake.MySQLAccount("alice")
	if g := users[0].Grants; len(g) != 2 || !slices.ContainsFunc(g, func(x agent.MySQLGrant) bool { return x.Database == "alice_news" }) {
		t.Fatalf("grants after rename: %+v", g)
	}
	if _, err := e.svc.RenameDatabase(ctx, client, user, d2.ID, "shop"); !conflict(err, "name_taken") {
		t.Errorf("rename onto another: %v", err)
	}

	// Password and revoke.
	jobID, err = e.svc.SetPassword(ctx, client, user, res.User.ID, "another long password")
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	if jobID, err = e.svc.RevokeGrant(ctx, client, user, res.User.ID, d2.ID); err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	_, users, _ = e.fake.MySQLAccount("alice")
	if users[0].PasswordHash != agent.NativePasswordHash("another long password") || len(users[0].Grants) != 1 {
		t.Fatalf("after password and revoke: %+v", users[0])
	}

	// Delete drops the database in MariaDB.
	jobID, err = e.svc.DeleteDatabase(ctx, client, user, d2.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	if dbs, _, _ := e.fake.MySQLAccount("alice"); !slices.Equal(dbs, []string{"alice_shop"}) {
		t.Fatalf("after delete: %v", dbs)
	}

	// Sign-on gets a ticket for the account's databases.
	ticket, err := e.svc.Signon(ctx, client, user, a.ID)
	if err != nil || len(ticket) != 64 || !slices.Equal(e.fake.MySQLSignons(), []string{"alice"}) {
		t.Fatalf("signon: %q %v %v", ticket, err, e.fake.MySQLSignons())
	}

	// Suspension locks the users; termination removes everything.
	if _, err := e.accts.Suspend(ctx, client, e.admin, a.ID, "test"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, _, l := e.fake.MySQLAccount("alice"); return l })
	if _, err := e.svc.Signon(ctx, client, e.admin, a.ID); !conflict(err, "bad_status") {
		t.Errorf("signon while suspended: %v", err)
	}
	if _, err := e.accts.Terminate(ctx, client, e.admin, a.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { dbs, users, _ := e.fake.MySQLAccount("alice"); return len(dbs) == 0 && len(users) == 0 })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
	}
}

func TestLimitsAndIsolation(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice")
	b, bob := e.account(t, "bob")

	d, err := e.svc.CreateDatabase(ctx, client, alice, a.ID, "one")
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.svc.CreateUser(ctx, client, bob, b.ID, "app", pw)
	if err != nil {
		t.Fatal(err)
	}
	// Bob cannot see or touch Alice's database, nor grant on it.
	if _, err := e.svc.Overview(ctx, bob, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob reads alice: %v", err)
	}
	if _, err := e.svc.DeleteDatabase(ctx, client, bob, d.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob deletes alice's database: %v", err)
	}
	if _, err := e.svc.SetGrant(ctx, client, bob, u.ID, d.ID, databases.GrantInput{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob grants on alice's database: %v", err)
	}
	if _, err := e.svc.CreateUser(ctx, client, alice, a.ID, "short", "short"); !field(err, "password") {
		t.Errorf("short password: %v", err)
	}
	if _, err := e.svc.CreateUser(ctx, client, alice, a.ID, "averyveryverylongusername12", pw); !field(err, "name") {
		t.Errorf("33-character user: %v", err)
	}

	// The package limit counts.
	pk, err := e.plans.GetPackage(ctx, e.admin, e.pkgID)
	if err != nil {
		t.Fatal(err)
	}
	one := int64(1)
	lim := pk.Limits
	lim.Databases = &one
	if _, err := e.plans.SavePackage(ctx, client, e.admin, e.pkgID, plans.PackageInput{
		Name: pk.Name, FeatureListID: pk.FeatureListID, Limits: lim,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateDatabase(ctx, client, alice, a.ID, "two"); !conflict(err, "limit_reached") {
		t.Errorf("over the limit: %v", err)
	}

	// Admin-only server settings.
	if _, err := e.svc.Status(ctx, alice); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("user reads server status: %v", err)
	}
	if st, err := e.svc.Status(ctx, e.admin); err != nil || !st.Installed || st.PHPMyAdmin == "" {
		t.Errorf("status: %+v %v", st, err)
	}
	if err := e.svc.SetRootPassword(ctx, client, e.admin, pw); err != nil || e.fake.MySQLRootHash() != agent.NativePasswordHash(pw) {
		t.Errorf("root password: %v", err)
	}
}
