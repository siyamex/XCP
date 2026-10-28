package accounts

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

const pw = "correct horse battery"

var client = auth.Client{IP: "192.0.2.1"}

type env struct {
	svc   *Service
	db    *store.DB
	auth  *auth.Service
	plans *plans.Service
	fake  *agentrpc.Fake
	admin *auth.Principal
	pkgID string
	rec   *audit.Recorder
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
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
	svc := NewService(db, rec, au, pl, q, fake)

	w := jobs.NewWorker(q, "test", log)
	w.Poll = 10 * time.Millisecond
	svc.RegisterJobs(w)
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return &env{svc: svc, db: db, auth: au, plans: pl, fake: fake, admin: admin, pkgID: pkgs[0].ID, rec: rec}
}

var ctx = context.Background()

func (e *env) create(t *testing.T, user, domain string) Account {
	t.Helper()
	a, err := e.svc.Create(ctx, client, e.admin, CreateInput{Username: user, Domain: domain, PackageID: e.pkgID, Password: pw})
	if err != nil {
		t.Fatalf("create %s: %v", user, err)
	}
	return a
}

// waitStatus waits until the account's jobs have run.
func (e *env) waitStatus(t *testing.T, id, want string) Account {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a, err := e.svc.Get(ctx, e.admin, id)
		if err == nil && a.Status == want {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("account %s: status %q (%v), want %q", id, a.Status, err, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (e *env) waitJob(t *testing.T, id string) *jobs.Job {
	t.Helper()
	q := jobs.NewQueue(e.db)
	deadline := time.Now().Add(5 * time.Second)
	for {
		j, err := q.Get(ctx, id)
		if err == nil && (j.Status == jobs.StatusSucceeded || j.Status == jobs.StatusFailed) {
			return j
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s did not finish", id)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAccountLifecycle(t *testing.T) {
	e := newEnv(t)
	a := e.create(t, "Alice", "Alice-Shop.example")
	if a.Status != store.AccountCreating || a.UID != store.FirstAccountUID || a.Username != "alice" ||
		a.PrimaryDomain != "alice-shop.example" || a.JobID == "" || a.PackageName != "Default" {
		t.Fatalf("created = %+v", a)
	}
	a = e.waitStatus(t, a.ID, store.AccountActive)
	u, ok := e.fake.User("alice")
	if !ok || u.UID != 10000 || u.Shell != agentv1.Shell_SHELL_NONE || u.Limits.CPUPercent == nil || *u.Limits.CPUPercent != 100 || *u.Limits.MemoryMB != 1024 {
		t.Fatalf("linux user = %+v (%v)", u, ok)
	}
	if b := e.create(t, "bob", "bob.example"); b.UID != 10001 {
		t.Fatalf("second uid = %d", b.UID)
	}

	// The account's own login works, with the user role.
	res, err := e.auth.Login(ctx, client, "alice", pw)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := e.auth.Authenticate(ctx, res.Token)
	if p.Login.Role != store.RoleUser || p.Login.AccountID != a.ID {
		t.Fatalf("login = %+v", p.Login)
	}

	// Suspend: the login is blocked, its session ends, the Linux user is locked.
	if _, err := e.svc.Suspend(ctx, client, e.admin, a.ID, "unpaid invoice"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.Authenticate(ctx, res.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("session survived suspension: %v", err)
	}
	if _, err := e.auth.Login(ctx, client, "alice", pw); !errors.Is(err, auth.ErrLoginDisabled) {
		t.Fatalf("suspended login: %v", err)
	}
	a = e.waitStatus(t, a.ID, store.AccountSuspended)
	if a.StatusDetail != "unpaid invoice" {
		t.Fatalf("detail = %q", a.StatusDetail)
	}
	waitFor(t, func() bool { u, _ := e.fake.User("alice"); return u.Suspended })
	if _, err := e.svc.Suspend(ctx, client, e.admin, a.ID, ""); !isConflict(err, "bad_status") {
		t.Fatalf("double suspend: %v", err)
	}
	if _, err := e.svc.Unsuspend(ctx, client, e.admin, a.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { u, _ := e.fake.User("alice"); return !u.Suspended })
	if _, err := e.auth.Login(ctx, client, "alice", pw); err != nil {
		t.Fatalf("login after unsuspend: %v", err)
	}

	// Change package: limits are re-applied.
	fl, _ := e.plans.ListFeatureLists(ctx, e.admin)
	cpu := int64(50)
	big, err := e.plans.SavePackage(ctx, client, e.admin, "", plans.PackageInput{
		Name: "Half", FeatureListID: fl[0].ID,
		Limits: plans.Limits{CPUPercent: &cpu, Shell: plans.ShellFull},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Update(ctx, client, e.admin, a.ID, UpdateInput{PackageID: big.ID, Email: "Owner@Alice-Shop.example"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		u, _ := e.fake.User("alice")
		return u.Limits.CPUPercent != nil && *u.Limits.CPUPercent == 50 && u.Shell == agentv1.Shell_SHELL_FULL && u.Limits.MemoryMB == nil
	})
	if err := e.plans.DeletePackage(ctx, client, e.admin, big.ID); !isConflict(err, "in_use") {
		t.Fatalf("deleting a package in use: %v", err)
	}

	// Password reset by the admin.
	if err := e.svc.SetPassword(ctx, client, e.admin, a.ID, "a fresh password here", true); err != nil {
		t.Fatal(err)
	}
	if lr, err := e.auth.Login(ctx, client, "alice", "a fresh password here"); err != nil || !lr.MustChangePassword {
		t.Fatalf("login with reset password: %+v %v", lr, err)
	}

	// Terminate needs the username typed exactly.
	if _, err := e.svc.Terminate(ctx, client, e.admin, a.ID, "Alice"); err == nil {
		t.Fatal("terminate without exact confirmation")
	}
	tr, err := e.svc.Terminate(ctx, client, e.admin, a.ID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if j := e.waitJob(t, tr.JobID); j.Status != jobs.StatusSucceeded {
		t.Fatalf("terminate job: %+v", j)
	}
	if _, err := e.svc.Get(ctx, e.admin, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("account still there: %v", err)
	}
	if _, ok := e.fake.User("alice"); ok {
		t.Fatal("linux user still there")
	}
	if _, err := e.auth.Login(ctx, client, "alice", "a fresh password here"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("login of a terminated account: %v", err)
	}
	if n, err := e.rec.Verify(ctx); err != nil || n < 10 {
		t.Fatalf("audit: %d, %v", n, err)
	}
}

func TestCreateValidationAndConflicts(t *testing.T) {
	e := newEnv(t)
	e.create(t, "alice", "alice.example")
	cases := map[string]struct {
		in   CreateInput
		want string // field name or conflict code
	}{
		"reserved name":   {CreateInput{Username: "root", Domain: "x.example", PackageID: e.pkgID, Password: pw}, "username"},
		"bad name":        {CreateInput{Username: "a-b", Domain: "x.example", PackageID: e.pkgID, Password: pw}, "username"},
		"bad domain":      {CreateInput{Username: "carol", Domain: "not a domain", PackageID: e.pkgID, Password: pw}, "domain"},
		"weak password":   {CreateInput{Username: "carol", Domain: "x.example", PackageID: e.pkgID, Password: "short"}, "password"},
		"unknown package": {CreateInput{Username: "carol", Domain: "x.example", PackageID: "nope", Password: pw}, "package_id"},
		"bad email":       {CreateInput{Username: "carol", Domain: "x.example", PackageID: e.pkgID, Password: pw, Email: "x@"}, "email"},
		"username taken":  {CreateInput{Username: "alice", Domain: "y.example", PackageID: e.pkgID, Password: pw}, "username_taken"},
		"admin name":      {CreateInput{Username: "root", Domain: "y.example", PackageID: e.pkgID, Password: pw}, "username"},
		"domain taken":    {CreateInput{Username: "carol", Domain: "ALICE.example", PackageID: e.pkgID, Password: pw}, "domain_taken"},
	}
	for name, tc := range cases {
		_, err := e.svc.Create(ctx, client, e.admin, tc.in)
		var ve *validate.Error
		switch {
		case errors.As(err, &ve) && ve.Field == tc.want:
		case isConflict(err, tc.want):
		default:
			t.Errorf("%s: err = %v, want %s", name, err, tc.want)
		}
	}
	user := &auth.Principal{Login: &store.Login{ID: "u", Role: store.RoleUser}, Session: &store.Session{}}
	if _, err := e.svc.List(ctx, user, "", ""); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("user listing accounts: %v", err)
	}
	if list, _ := e.svc.List(ctx, e.admin, "ALI", ""); len(list) != 1 {
		t.Fatalf("search = %+v", list)
	}
}

func TestForeignLinuxUserPutsAccountInError(t *testing.T) {
	e := newEnv(t)
	// A Linux user "mallory" already exists with another UID (not created by XCP).
	if _, err := e.fake.AccountEnsure(ctx, &agentv1.AccountEnsureRequest{Username: "mallory", Uid: 20000}); err != nil {
		t.Fatal(err)
	}
	a := e.create(t, "mallory", "mallory.example")
	jobID := a.JobID
	a = e.waitStatus(t, a.ID, store.AccountError)
	if !strings.Contains(a.StatusDetail, "not created by XCP") {
		t.Fatalf("detail = %q", a.StatusDetail)
	}
	if j := e.waitJob(t, jobID); j.Attempts != 1 {
		t.Fatalf("a refused request must not be retried (attempts = %d)", j.Attempts)
	}
}

func isConflict(err error, code string) bool {
	var c *apperr.Conflict
	return errors.As(err, &c) && c.Code == code
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
