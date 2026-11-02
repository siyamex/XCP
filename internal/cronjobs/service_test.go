package cronjobs_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/cronjobs"
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
	svc   *cronjobs.Service
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
	svc := cronjobs.NewService(db, rec, pl, q, fake)
	svc.Now = func() time.Time { return time.Date(2026, 11, 2, 10, 7, 0, 0, time.UTC) }
	accts.Attach("cron", svc)
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

func TestCronLifecycle(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")
	o, err := e.svc.Overview(ctx, user, a.ID)
	if err != nil || len(o.Jobs) != 0 || o.MaxJobs == nil || *o.MaxJobs != 10 || o.TimeZone != "UTC" {
		t.Fatalf("overview: %+v %v", o, err)
	}
	j, err := e.svc.Create(ctx, client, user, a.ID, cronjobs.Input{Schedule: " */15  * * * * ", Command: "  php ~/public_html/cron.php  ", Email: "Ops@Alice.Example"})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, j.JobID)
	if j.Schedule != "*/15 * * * *" || j.Command != "php ~/public_html/cron.php" || j.Email != "ops@alice.example" || !j.Enabled {
		t.Fatalf("job %+v", j)
	}
	want := []time.Time{time.Date(2026, 11, 2, 10, 15, 0, 0, time.UTC), time.Date(2026, 11, 2, 10, 30, 0, 0, time.UTC), time.Date(2026, 11, 2, 10, 45, 0, 0, time.UTC)}
	if !slices.EqualFunc(j.NextRuns, want, time.Time.Equal) {
		t.Errorf("next runs %v", j.NextRuns)
	}
	got, ok := e.fake.CronAccount("alice")
	if !ok || len(got.Jobs) != 1 || got.Jobs[0].ID != strings.ToLower(j.ID) || got.Jobs[0].MailTo != "ops@alice.example" {
		t.Fatalf("jobs in the agent: %+v", got)
	}

	for _, c := range []struct {
		in    cronjobs.Input
		field string
	}{
		{cronjobs.Input{Schedule: "* * *", Command: "true"}, "schedule"},
		{cronjobs.Input{Schedule: "@reboot", Command: "true"}, "schedule"},
		{cronjobs.Input{Schedule: "* * * * *", Command: "echo a\necho b"}, "command"},
		{cronjobs.Input{Schedule: "* * * * *", Command: " "}, "command"},
		{cronjobs.Input{Schedule: "* * * * *", Command: "true", Email: "not an address"}, "email"},
	} {
		if _, err := e.svc.Create(ctx, client, user, a.ID, c.in); !field(err, c.field) {
			t.Errorf("%+v: %v", c.in, err)
		}
	}

	// A switched-off job is kept but not given to the agent.
	off := false
	j, err = e.svc.Update(ctx, client, user, j.ID, cronjobs.Input{Schedule: "0 3 * * *", Command: "true", Enabled: &off})
	if err != nil || j.Enabled || len(j.NextRuns) != 0 {
		t.Fatalf("update: %+v %v", j, err)
	}
	e.waitJob(t, j.JobID)
	if got, _ = e.fake.CronAccount("alice"); len(got.Jobs) != 0 {
		t.Fatalf("a switched-off job reached the agent: %+v", got)
	}
	on := true
	if j, err = e.svc.Update(ctx, client, user, j.ID, cronjobs.Input{Schedule: "0 3 * * *", Command: "true", Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, j.JobID)

	// The last run comes from the agent.
	e.fake.SetCronRun("alice", strings.ToLower(j.ID), time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC), 3, "boom\n")
	o, _ = e.svc.Overview(ctx, user, a.ID)
	if lr := o.Jobs[0].LastRun; lr == nil || lr.ExitCode != 3 || lr.Output != "boom\n" {
		t.Fatalf("last run: %+v", o.Jobs[0])
	}

	if _, err := e.accts.Suspend(ctx, client, e.admin, a.ID, "test"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { got, _ := e.fake.CronAccount("alice"); return len(got.Jobs) == 0 })
	if _, err := e.accts.Unsuspend(ctx, client, e.admin, a.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { got, _ := e.fake.CronAccount("alice"); return len(got.Jobs) == 1 })

	jobID, err := e.svc.Delete(ctx, client, user, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	if got, _ = e.fake.CronAccount("alice"); len(got.Jobs) != 0 {
		t.Fatalf("after delete: %+v", got)
	}
	if _, err := e.accts.Terminate(ctx, client, e.admin, a.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, ok := e.fake.CronAccount("alice"); return !ok })
}

func TestCronIsolationAndLimits(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice")
	b, bob := e.account(t, "bob")
	j, err := e.svc.Create(ctx, client, alice, a.ID, cronjobs.Input{Schedule: "* * * * *", Command: "true"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Overview(ctx, bob, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob reads alice's jobs: %v", err)
	}
	if _, err := e.svc.Update(ctx, client, bob, j.ID, cronjobs.Input{Schedule: "* * * * *", Command: "id"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob changes alice's job: %v", err)
	}
	if _, err := e.svc.Delete(ctx, client, bob, j.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob deletes alice's job: %v", err)
	}
	for range 9 {
		if _, err := e.svc.Create(ctx, client, bob, b.ID, cronjobs.Input{Schedule: "* * * * *", Command: "true"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.Create(ctx, client, bob, b.ID, cronjobs.Input{Schedule: "* * * * *", Command: "true"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Create(ctx, client, bob, b.ID, cronjobs.Input{Schedule: "* * * * *", Command: "true"}); !conflict(err, "limit_reached") {
		t.Errorf("an eleventh job with the default package's 10: %v", err)
	}
}
