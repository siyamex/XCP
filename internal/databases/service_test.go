package databases_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
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
	accts.Attach("databases", svc)
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

func TestDatabaseMap(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice")
	res, err := e.svc.Wizard(ctx, client, alice, a.ID, databases.WizardInput{Database: "shop", User: "app", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, res.JobID)
	if _, err := e.svc.Map(ctx, alice); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a customer: %v", err)
	}
	e.fake.SetMySQLStray("wordpress", "wp")
	m, err := e.svc.Map(ctx, e.admin)
	if err != nil {
		t.Fatal(err)
	}
	got := func(m databases.ServerMap) []string {
		var out []string
		for _, d := range m.Databases {
			out = append(out, "db "+d.Name+" "+d.State+" "+d.Account)
		}
		for _, u := range m.Users {
			out = append(out, "user "+u.Name+" "+u.State+" "+u.Account+" "+strings.Join(u.Hosts, ","))
		}
		return out
	}
	want := []string{"db wordpress orphan ", "db alice_shop ok alice", "user wp orphan  %", "user alice_app ok alice localhost"}
	if !slices.Equal(got(m), want) {
		t.Fatalf("map =\n%q\nwant\n%q", got(m), want)
	}

	// An account's database or user is never dropped as an orphan.
	if err := e.svc.DropOrphan(ctx, client, e.admin, "database", "alice_shop"); !conflict(err, "not_orphan") {
		t.Errorf("an account's database: %v", err)
	}
	if err := e.svc.DropOrphan(ctx, client, e.admin, "user", "alice_app"); !conflict(err, "not_orphan") {
		t.Errorf("an account's user: %v", err)
	}
	if err := e.svc.DropOrphan(ctx, client, e.admin, "database", "nothing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an unknown one: %v", err)
	}
	if err := e.svc.DropOrphan(ctx, client, e.admin, "table", "wordpress"); !field(err, "kind") {
		t.Errorf("a bad kind: %v", err)
	}
	if err := e.svc.DropOrphan(ctx, client, alice, "database", "wordpress"); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a customer drops: %v", err)
	}
	for _, x := range [][2]string{{"database", "wordpress"}, {"user", "wp"}} {
		if err := e.svc.DropOrphan(ctx, client, e.admin, x[0], x[1]); err != nil {
			t.Fatal(err)
		}
	}
	if m, _ := e.svc.Map(ctx, e.admin); !slices.Equal(got(m), []string{want[1], want[3]}) {
		t.Errorf("after dropping: %q", got(m))
	}

	// Gone from MariaDB behind the panel's back: missing, and made again.
	if _, err := e.fake.MySQLDatabaseDrop(ctx, &agentv1.MySQLDatabaseDropRequest{Username: "alice", Database: "alice_shop"}); err != nil {
		t.Fatal(err)
	}
	if m, _ := e.svc.Map(ctx, e.admin); m.Databases[0].State != databases.MapMissing || m.Databases[0].SizeBytes != nil {
		t.Fatalf("missing: %+v", m.Databases)
	}
	n, err := e.svc.RepairMissing(ctx, client, e.admin)
	if err != nil || n != 1 {
		t.Fatalf("repair: %d %v", n, err)
	}
	waitFor(t, func() bool {
		m, _ := e.svc.Map(ctx, e.admin)
		return len(m.Databases) == 1 && m.Databases[0].State == databases.MapOK
	})
	if n, _ := e.svc.RepairMissing(ctx, client, e.admin); n != 0 {
		t.Errorf("nothing left to repair: %d", n)
	}
}

func TestRemoteHosts(t *testing.T) {
	for in, want := range map[string]string{
		"%": "%", "Any": "%", " 192.0.2.7 ": "192.0.2.7", "192.0.2.0/24": "192.0.2.0/255.255.255.0", "10.0.0.0/8": "10.0.0.0/255.0.0.0",
		"192.0.2.7/32": "192.0.2.7", "2001:DB8::7": "2001:db8::7", "2001:db8::7/128": "2001:db8::7", "::ffff:192.0.2.9": "192.0.2.9",
	} {
		if got, err := databases.RemoteHost(in); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"example.com", "192.0.2.1/24", "2001:db8::/64", "192.0.2.%", "fe80::1%eth0", "1.2.3"} {
		if _, err := databases.RemoteHost(bad); !field(err, "hosts") {
			t.Errorf("%q: %v", bad, err)
		}
	}

	e := newEnv(t)
	a, alice := e.account(t, "alice")
	_, bob := e.account(t, "bob")
	if _, _, err := e.svc.SetRemote(ctx, client, bob, a.ID, []string{"192.0.2.7"}); err == nil {
		t.Fatal("bob set alice's hosts")
	}
	rm, jobID, err := e.svc.SetRemote(ctx, client, alice, a.ID, []string{"192.0.2.7", "", "198.51.100.0/24", "192.0.2.7"})
	if err != nil || !slices.Equal(rm.Hosts, []string{"192.0.2.7", "198.51.100.0/255.255.255.0"}) || rm.Enabled {
		t.Fatalf("%+v %v", rm, err)
	}
	e.waitJob(t, jobID)
	if _, hosts := e.fake.MySQLRemote("alice"); !slices.Equal(hosts, rm.Hosts) {
		t.Fatalf("the agent got %v", hosts)
	}
	many := make([]string, 21)
	for i := range many {
		many[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	if _, _, err := e.svc.SetRemote(ctx, client, alice, a.ID, many); !field(err, "hosts") {
		t.Errorf("21 hosts: %v", err)
	}
	if got, _ := e.svc.Remote(ctx, alice, a.ID); !slices.Equal(got.Hosts, rm.Hosts) {
		t.Errorf("read back %v", got.Hosts)
	}

	// The server switch is the admin's.
	if err := e.svc.SetRemoteEnabled(ctx, client, alice, true); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a customer: %v", err)
	}
	if err := e.svc.SetRemoteEnabled(ctx, client, e.admin, true); err != nil {
		t.Fatal(err)
	}
	if on, _ := e.fake.MySQLRemote("alice"); !on {
		t.Error("MariaDB does not listen")
	}
	if got, _ := e.svc.Remote(ctx, alice, a.ID); !got.Enabled {
		t.Error("the account does not see it on")
	}
	if st, _ := e.svc.Status(ctx, e.admin); !st.Remote {
		t.Error("the status does not say so")
	}
	if _, jobID, err := e.svc.SetRemote(ctx, client, alice, a.ID, nil); err != nil {
		t.Fatal(err)
	} else {
		e.waitJob(t, jobID)
	}
	if _, hosts := e.fake.MySQLRemote("alice"); len(hosts) != 0 {
		t.Errorf("after clearing: %v", hosts)
	}
}

func TestExportImport(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice")
	_, bob := e.account(t, "bob")
	d, err := e.svc.CreateDatabase(ctx, client, alice, a.ID, "shop")
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, d.JobID)
	if _, err := e.svc.Export(ctx, client, bob, d.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob exports alice's database: %v", err)
	}
	jobID, err := e.svc.Export(ctx, client, alice, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]any
	if err := json.Unmarshal(e.waitJob(t, jobID).Result, &res); err != nil || res["path"] != "db-dumps/alice_shop-20261111T100000Z.sql.gz" || res["size"] != float64(1234) {
		t.Fatalf("export result %v %v", res, err)
	}
	for _, bad := range []string{"", "../bob/dump.sql", "notes.txt"} {
		if _, err := e.svc.Import(ctx, client, alice, d.ID, bad); !field(err, "path") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := e.svc.Import(ctx, client, bob, d.ID, "dump.sql"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob imports into alice's database: %v", err)
	}
	jobID, err = e.svc.Import(ctx, client, alice, d.ID, "/db-dumps/./alice_shop.sql.gz")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(e.waitJob(t, jobID).Result, &res); err != nil || res["path"] != "db-dumps/alice_shop.sql.gz" {
		t.Fatalf("import result %v %v", res, err)
	}
	// A file that is not there fails the job with the agent's reason.
	jobID, err = e.svc.Import(ctx, client, alice, d.ID, "missing.sql")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { j, err := e.q.Get(ctx, jobID); return err == nil && j.Status == jobs.StatusFailed })
	if j, _ := e.q.Get(ctx, jobID); !strings.Contains(j.Error, "cannot open missing.sql") {
		t.Errorf("job error %q", j.Error)
	}
}

func TestMaintain(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice")
	_, bob := e.account(t, "bob")
	good, err := e.svc.CreateDatabase(ctx, client, alice, a.ID, "shop")
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, good.JobID)
	bad, err := e.svc.CreateDatabase(ctx, client, alice, a.ID, "old_broken")
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, bad.JobID)
	if _, err := e.svc.Maintain(ctx, client, alice, good.ID, "drop"); !field(err, "action") {
		t.Fatalf("a bad action: %v", err)
	}
	if _, err := e.svc.Maintain(ctx, client, bob, good.ID, "check"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob checks alice's database: %v", err)
	}
	result := func(id, action string) map[string]any {
		t.Helper()
		jobID, err := e.svc.Maintain(ctx, client, alice, id, action)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(e.waitJob(t, jobID).Result, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if r := result(good.ID, "optimize"); r["tables"] != float64(1) || r["errors"] != float64(0) || len(r["problems"].([]any)) != 0 || r["action"] != "optimize" {
		t.Fatalf("a healthy database: %v", r)
	}
	r := result(bad.ID, "check")
	problems := r["problems"].([]any)
	if r["tables"] != float64(2) || r["errors"] != float64(1) || len(problems) != 1 || problems[0].(map[string]any)["table"] != "bad" {
		t.Fatalf("a broken table: %v", r)
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
