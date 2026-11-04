package serverinfo_test

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/serverinfo"
	"github.com/siyamex/XCP/internal/store"
)

var (
	ctx    = context.Background()
	client = auth.Client{IP: "192.0.2.1"}
)

type env struct {
	svc   *serverinfo.Service
	db    *store.DB
	q     *jobs.Queue
	rec   *audit.Recorder
	admin *auth.Principal
	user  *auth.Principal
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
	au, err := auth.NewService(db, rec, box, auth.Options{
		SessionIdle: time.Hour, SessionMax: time.Hour,
		Argon: auth.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := au.CreateLogin(ctx, client, nil, auth.NewLogin{Username: "root", Password: "correct horse battery", Role: store.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	h := make([]byte, 32)
	h[0] = 1
	now := time.Now().UTC()
	sess := &store.Session{IDHash: h, LoginID: l.ID, MFAPassed: true, IP: "198.51.100.7", UserAgent: "test", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := db.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	q := jobs.NewQueue(db)
	return &env{
		svc: serverinfo.NewService(db, rec, q, agentrpc.NewFake()), db: db, q: q, rec: rec,
		admin: &auth.Principal{Login: l, Session: sess},
		user:  &auth.Principal{Login: &store.Login{ID: "U", Role: store.RoleUser}, Session: &store.Session{}},
	}
}

func conflict(err error, code string) bool {
	var c *apperr.Conflict
	return errors.As(err, &c) && c.Code == code
}

func second[T any](_ T, err error) error { return err }

func TestOnlyAdminsSeeTheServer(t *testing.T) {
	e := newEnv(t)
	for name, err := range map[string]error{
		"status":   second(e.svc.Status(ctx, e.user)),
		"services": second(e.svc.Services(ctx, e.user)),
		"action":   second(e.svc.ServiceAction(ctx, client, e.user, "web", "restart")),
		"log":      second(e.svc.ServiceLog(ctx, e.user, "web", 10)),
		"jobs":     second(e.svc.Jobs(ctx, e.user, "", "", 10)),
		"sessions": second(e.svc.Sessions(ctx, e.user)),
		"logins":   second(e.svc.Logins(ctx, e.user)),
		"revoke":   e.svc.RevokeSession(ctx, client, e.user, hex.EncodeToString(make([]byte, 32))),
	} {
		if !errors.Is(err, apperr.ErrForbidden) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestStatusAndServices(t *testing.T) {
	e := newEnv(t)
	st, err := e.svc.Status(ctx, e.admin)
	if err != nil || st.Hostname != "fake-host" || st.Cores != 4 || len(st.Disks) != 1 || st.Disks[0].Used != 40<<30 || len(st.Accounts) != 1 ||
		st.AccountsAt == nil || len(st.Versions) != 1 {
		t.Fatalf("status: %+v %v", st, err)
	}
	if _, err := e.q.Enqueue(ctx, "x.kind", struct{}{}, jobs.EnqueueOptions{}); err != nil {
		t.Fatal(err)
	}
	if st, _ = e.svc.Status(ctx, e.admin); st.Jobs["queued"] != 1 {
		t.Errorf("job counts %v", st.Jobs)
	}
	list, err := e.svc.Services(ctx, e.admin)
	if err != nil || len(list) != len(serverinfo.ServiceIDs) {
		t.Fatalf("services: %d %v", len(list), err)
	}
	web := list[3]
	if web.ID != "web" || !web.Installed || web.State != "active" || web.Unit != "apache2.service" || web.Protected {
		t.Errorf("web %+v", web)
	}
	if !list[0].Protected || list[0].ID != "panel-api" {
		t.Errorf("panel-api %+v", list[0])
	}
	for _, action := range []string{"restart", "reload", "enable", "disable", "stop", "start"} {
		if _, err := e.svc.ServiceAction(ctx, client, e.admin, "web", action); err != nil {
			t.Errorf("%s: %v", action, err)
		}
	}
	for _, c := range []struct{ id, action string }{{"panel-api", "stop"}, {"panel-api", "restart"}, {"ssh", "disable"}} {
		if _, err := e.svc.ServiceAction(ctx, client, e.admin, c.id, c.action); !conflict(err, "protected") {
			t.Errorf("%v: %v", c, err)
		}
	}
	if _, err := e.svc.ServiceAction(ctx, client, e.admin, "web", "explode"); err == nil {
		t.Error("an unknown action was accepted")
	}
	if _, err := e.svc.ServiceAction(ctx, client, e.admin, "nope", "restart"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an unknown service: %v", err)
	}
	if txt, err := e.svc.ServiceLog(ctx, e.admin, "web", 3); err != nil || strings.Count(txt, "\n") != 3 {
		t.Errorf("log: %q %v", txt, err)
	}
	if _, err := e.svc.ServiceLog(ctx, e.admin, "web", 501); err == nil {
		t.Error("501 lines accepted")
	}
}

func TestJobMonitor(t *testing.T) {
	e := newEnv(t)
	id, err := e.q.Enqueue(ctx, "x.kind", struct{}{}, jobs.EnqueueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.q.Enqueue(ctx, "y.kind", struct{}{}, jobs.EnqueueOptions{}); err != nil {
		t.Fatal(err)
	}
	list, err := e.svc.Jobs(ctx, e.admin, "queued", "x.kind", 10)
	if err != nil || len(list) != 1 || list[0].ID != id {
		t.Fatalf("filtered: %+v %v", list, err)
	}
	if all, _ := e.svc.Jobs(ctx, e.admin, "", "", 10); len(all) != 2 {
		t.Fatalf("all jobs: %+v", all)
	}
	if _, err := e.svc.Jobs(ctx, e.admin, "bogus", "", 10); err == nil {
		t.Error("a bad status filter was accepted")
	}
	if _, err := e.svc.RetryJob(ctx, client, e.admin, id); !conflict(err, "bad_state") {
		t.Errorf("retry a queued job: %v", err)
	}
	if j, err := e.svc.CancelJob(ctx, client, e.admin, id); err != nil || j.Status != "canceled" {
		t.Fatalf("cancel: %+v %v", j, err)
	}
	if _, err := e.svc.CancelJob(ctx, client, e.admin, id); !conflict(err, "bad_state") {
		t.Errorf("cancel twice: %v", err)
	}
	if j, err := e.svc.RetryJob(ctx, client, e.admin, id); err != nil || j.Status != "queued" {
		t.Fatalf("retry: %+v %v", j, err)
	}
	if _, err := e.svc.CancelJob(ctx, client, e.admin, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an unknown job: %v", err)
	}
}

func TestSessionsAndLogins(t *testing.T) {
	e := newEnv(t)
	list, err := e.svc.Sessions(ctx, e.admin)
	if err != nil || len(list) != 1 || list[0].Username != "root" || !list[0].Current || list[0].Role != "admin" {
		t.Fatalf("sessions: %+v %v", list, err)
	}
	if err := e.rec.Record(ctx, audit.Event{Action: "auth.login", Result: audit.ResultDenied, IP: "203.0.113.9", Details: map[string]any{"username": "mallory", "reason": "bad_credentials"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.rec.Record(ctx, audit.Event{Action: "domain.add", Result: audit.ResultOK}); err != nil {
		t.Fatal(err)
	}
	lv, err := e.svc.Logins(ctx, e.admin)
	if err != nil || len(lv) != 1 || lv[0].Username != "mallory" || lv[0].Result != "denied" || lv[0].Reason != "bad_credentials" || lv[0].IP != "203.0.113.9" {
		t.Fatalf("logins (only sign-in events): %+v %v", lv, err)
	}
	if err := e.svc.RevokeSession(ctx, client, e.admin, "zz"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a bad id: %v", err)
	}
	if err := e.svc.RevokeSession(ctx, client, e.admin, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if list, _ = e.svc.Sessions(ctx, e.admin); len(list) != 0 {
		t.Errorf("the session is still there: %+v", list)
	}
	if err := e.svc.RevokeSession(ctx, client, e.admin, hex.EncodeToString(make([]byte, 32))); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an unknown session: %v", err)
	}
}
