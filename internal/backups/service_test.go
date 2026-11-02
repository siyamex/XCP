package backups_test

import (
	"context"
	"encoding/json"
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
	"github.com/siyamex/XCP/internal/backups"
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
	svc   *backups.Service
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
	svc := backups.NewService(db, rec, pl, q, fake)
	svc.Now = func() time.Time { return time.Date(2026, 11, 2, 2, 5, 0, 0, time.UTC) }
	accts.Attach("backups", svc)
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

func TestManualBackups(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")
	b, err := e.svc.Create(ctx, client, user, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if b.Status != store.BackupRunning || b.Kind != store.BackupManual {
		t.Fatalf("new backup %+v", b)
	}
	if _, err := e.svc.Create(ctx, client, user, a.ID); !conflict(err, "busy") {
		t.Errorf("a second one while the first runs: %v", err)
	}
	e.waitJob(t, b.JobID)
	o, err := e.svc.Overview(ctx, user, a.ID)
	if err != nil || len(o.Backups) != 1 || o.Backups[0].Status != store.BackupOK || o.Backups[0].File == "" || o.Backups[0].Size == 0 {
		t.Fatalf("after the job: %+v %v", o, err)
	}
	files := e.fake.Backups("alice")
	content := string(files[o.Backups[0].File])
	var af backups.AccountFile
	if err := json.Unmarshal([]byte(strings.TrimLeft(content, "#")), &af); err != nil {
		t.Fatal(err)
	}
	if af.Format != 1 || af.Package != "Default" || len(af.Export.Tables["domains"]) != 1 || af.Export.Tables["accounts"][0]["username"] != "alice" {
		t.Fatalf("account.json: %+v", af)
	}

	var buf strings.Builder
	var gotName string
	if err := e.svc.Download(ctx, client, user, b.ID, func(n string, _ int64) { gotName = n }, &buf); err != nil || buf.String() != content || gotName != o.Backups[0].File {
		t.Fatalf("download: %v %q", err, gotName)
	}
	for range 2 {
		x, err := e.svc.Create(ctx, client, user, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		e.waitJob(t, x.JobID)
	}
	if _, err := e.svc.Create(ctx, client, user, a.ID); !conflict(err, "limit_reached") {
		t.Errorf("a fourth of the user's own: %v", err)
	}
	if err := e.svc.Delete(ctx, client, user, b.ID); err != nil {
		t.Fatal(err)
	}
	if len(e.fake.Backups("alice")) != 2 {
		t.Errorf("the file was not removed: %v", e.fake.Backups("alice"))
	}

	// A failed backup is recorded with its reason and leaves nothing.
	e.fake.FailBackups("disk full")
	x, err := e.svc.Create(ctx, client, user, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { bk, _ := e.db.BackupByID(ctx, x.ID); return bk.Status == store.BackupFailed })
	if bk, _ := e.db.BackupByID(ctx, x.ID); !strings.Contains(bk.Detail, "disk full") {
		t.Errorf("failure detail %q", bk.Detail)
	}
	e.fake.FailBackups("")

	_, bob := e.account(t, "bob")
	if _, err := e.svc.Overview(ctx, bob, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob lists alice's backups: %v", err)
	}
	if err := e.svc.Download(ctx, client, bob, x.ID, func(string, int64) {}, io.Discard); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob downloads alice's backup: %v", err)
	}
	if _, err := e.accts.Terminate(ctx, client, e.admin, a.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(e.fake.Backups("alice")) == 0 })
}

func TestScheduledBackups(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")
	if _, err := e.svc.SetSchedule(ctx, client, user, backups.DefaultSchedule); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a user sets the schedule: %v", err)
	}
	bad := backups.Schedule{Enabled: true, Frequency: "hourly", Hour: 2, Day: 1, Keep: 2}
	if _, err := e.svc.SetSchedule(ctx, client, e.admin, bad); !field(err, "frequency") {
		t.Errorf("hourly: %v", err)
	}
	sched := backups.Schedule{Enabled: true, Frequency: "daily", Hour: 2, Day: 1, Keep: 2}
	if _, err := e.svc.SetSchedule(ctx, client, e.admin, sched); err != nil {
		t.Fatal(err)
	}
	// Three scheduled runs, one per day: only the newest two are kept.
	for day := range 3 {
		e.svc.Now = func() time.Time { return time.Date(2026, 11, 2+day, 2, 5, 0, 0, time.UTC) }
		id, err := e.q.Enqueue(ctx, backups.JobSchedule, struct{}{}, jobs.EnqueueOptions{})
		if err != nil {
			t.Fatal(err)
		}
		e.waitJob(t, id)
		waitFor(t, func() bool {
			o, _ := e.svc.Overview(ctx, user, a.ID)
			for _, b := range o.Backups {
				if b.Status == store.BackupRunning {
					return false
				}
			}
			return true
		})
	}
	id, _ := e.q.Enqueue(ctx, backups.JobSchedule, struct{}{}, jobs.EnqueueOptions{}) // the same hour again: nothing
	e.waitJob(t, id)
	o, _ := e.svc.Overview(ctx, user, a.ID)
	if len(o.Backups) != 2 || len(e.fake.Backups("alice")) != 2 {
		t.Fatalf("kept %d records and %d files, want 2", len(o.Backups), len(e.fake.Backups("alice")))
	}
	if !sched.Due(time.Date(2026, 11, 2, 2, 59, 0, 0, time.UTC)) || sched.Due(time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC)) {
		t.Error("Due: only in the schedule's hour")
	}
	weekly := backups.Schedule{Enabled: true, Frequency: "weekly", Hour: 2, Weekday: 0, Keep: 1}
	if weekly.Due(time.Date(2026, 11, 2, 2, 0, 0, 0, time.UTC)) || !weekly.Due(time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)) {
		t.Error("weekly: only on Sundays")
	}
}
