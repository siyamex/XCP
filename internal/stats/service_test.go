package stats_test

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
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/domains"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/stats"
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
	svc   *stats.Service
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
	svc := stats.NewService(db, pl, fake)
	svc.Now = func() time.Time { return time.Date(2026, 11, 3, 10, 7, 0, 0, time.UTC) }
	w := jobs.NewWorker(q, "test", log)
	w.Poll = 10 * time.Millisecond
	for _, r := range []interface{ RegisterJobs(*jobs.Worker) }{accts, doms, zs} {
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

func field(err error, name string) bool {
	var ve *validate.Error
	return errors.As(err, &ve) && ve.Field == name
}

func TestBandwidth(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")
	for _, u := range []store.Usage{
		{Domain: "alice.example", Day: "2026-11-01", Web: 1000, Mail: 10, FTP: 1},
		{Domain: "alice.example", Day: "2026-11-03", Web: 500},
		{Domain: "blog.alice.example", Day: "2026-11-03", Web: 5000},
		{Domain: "alice.example", Day: "2026-10-31", Web: 999999}, // another month
	} {
		if err := store.AddUsage(ctx, e.db.W, a.ID, u); err != nil {
			t.Fatal(err)
		}
	}
	b, err := e.svc.Bandwidth(ctx, user, a.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if b.Month != "2026-11" || b.Total.Total != 6511 || b.Total.Mail != 10 || b.LimitMB == nil || *b.LimitMB != 100*1024 {
		t.Fatalf("month: %+v", b)
	}
	if len(b.Domains) != 2 || b.Domains[0].Domain != "blog.alice.example" || b.Domains[1].Total != 1511 {
		t.Fatalf("domains, biggest first: %+v", b.Domains)
	}
	if len(b.Days) != 3 || b.Days[0].Total != 1011 || b.Days[1].Total != 0 || b.Days[2].Total != 5500 {
		t.Fatalf("days up to today: %+v", b.Days)
	}
	if b, err = e.svc.Bandwidth(ctx, user, a.ID, "2026-10"); err != nil || b.Total.Web != 999999 || len(b.Days) != 31 {
		t.Fatalf("October: %+v %v", b.Total, err)
	}
	if _, err := e.svc.Bandwidth(ctx, user, a.ID, "2026-13"); !field(err, "month") {
		t.Errorf("a bad month: %v", err)
	}
	_, bob := e.account(t, "bob")
	if _, err := e.svc.Bandwidth(ctx, bob, a.ID, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob reads alice's bandwidth: %v", err)
	}
}

func TestLogs(t *testing.T) {
	e := newEnv(t)
	a, user := e.account(t, "alice")
	e.fake.SetSiteLog("alice", "access", "one GET /\ntwo GET /shop\nthree POST /shop\n")
	lines, err := e.svc.Tail(ctx, user, a.ID, "access", 2, "")
	if err != nil || !slices.Equal(lines, []string{"two GET /shop", "three POST /shop"}) {
		t.Fatalf("tail: %q %v", lines, err)
	}
	if lines, _ = e.svc.Tail(ctx, user, a.ID, "access", 10, "POST"); !slices.Equal(lines, []string{"three POST /shop"}) {
		t.Fatalf("search: %q", lines)
	}
	if lines, _ = e.svc.Tail(ctx, user, a.ID, "error", 10, ""); lines == nil || len(lines) != 0 {
		t.Fatalf("empty error log: %#v", lines)
	}
	for _, c := range []struct {
		kind  string
		lines int
		q     string
		field string
	}{{"secret", 10, "", "kind"}, {"access", 0, "", "lines"}, {"access", 1001, "", "lines"}, {"access", 10, "a\nb", "q"}} {
		if _, err := e.svc.Tail(ctx, user, a.ID, c.kind, c.lines, c.q); !field(err, c.field) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	big := strings.Repeat("0123456789abcdef\n", 200000) // over three parts of 1 MiB
	e.fake.SetSiteLog("alice", "error", big)
	var buf strings.Builder
	started := false
	if err := e.svc.Download(ctx, user, a.ID, "error", func() { started = true }, &buf); err != nil || !started || buf.String() != big {
		t.Fatalf("download: %v, %d of %d bytes", err, buf.Len(), len(big))
	}
	_, bob := e.account(t, "bob")
	if _, err := e.svc.Tail(ctx, bob, a.ID, "access", 10, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob reads alice's log: %v", err)
	}
}
