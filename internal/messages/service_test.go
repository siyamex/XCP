package messages

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
)

var (
	ctx    = context.Background()
	client = auth.Client{IP: "192.0.2.1"}
)

type sent struct{ from, to, subject, body string }

type fakeMailer struct {
	mu   sync.Mutex
	out  []sent
	fail map[string]bool
}

func (f *fakeMailer) Send(_ context.Context, from, to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[to] {
		return errors.New("refused")
	}
	f.out = append(f.out, sent{from, to, subject, body})
	return nil
}

type nopReporter struct{}

func (nopReporter) Progress(int)        {}
func (nopReporter) Logf(string, ...any) {}

type env struct {
	svc   *Service
	db    *store.DB
	mail  *fakeMailer
	admin *auth.Principal
	pkgID string
	now   time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rec := audit.NewRecorder(db)
	pl := plans.NewService(db, rec)
	if err := pl.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	adminLogin := &store.Login{ID: ids.New(), Username: "root", Role: store.RoleAdmin, PasswordHash: "x"}
	if err := store.CreateLogin(ctx, db.W, adminLogin); err != nil {
		t.Fatal(err)
	}
	admin := &auth.Principal{Login: adminLogin, Session: &store.Session{}}
	pkgs, _ := pl.ListPackages(ctx, admin)
	m := &fakeMailer{fail: map[string]bool{}}
	e := &env{db: db, mail: m, admin: admin, pkgID: pkgs[0].ID, now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	e.svc = NewService(db, rec, jobs.NewQueue(db), m, Info{
		From:     func(context.Context) string { return "hosting@host.example" },
		PanelURL: func(context.Context) string { return "https://panel.host.example:2443" },
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.svc.Now = func() time.Time { return e.now }
	e.svc.Pause = 0
	return e
}

var uid = 20000

func (e *env) account(t *testing.T, name, owner, email string) *store.Account {
	t.Helper()
	uid++
	a := &store.Account{ID: ids.New(), Username: name, UID: uid, OwnerID: owner, PackageID: e.pkgID, PrimaryDomain: name + ".example", Email: email, Status: store.AccountActive}
	if err := store.InsertAccount(ctx, e.db.W, a); err != nil {
		t.Fatal(err)
	}
	return a
}

func (e *env) reseller(t *testing.T, name string) *auth.Principal {
	t.Helper()
	l := &store.Login{ID: ids.New(), Username: name, Role: store.RoleReseller, PasswordHash: "x", OwnerID: e.admin.Login.ID}
	if err := store.CreateLogin(ctx, e.db.W, l); err != nil {
		t.Fatal(err)
	}
	return &auth.Principal{Login: l, Session: &store.Session{}}
}

func TestRender(t *testing.T) {
	got := Render("Hi {{ username }} at {{DOMAIN}}: {{panel_url}} {{nope}}", map[string]string{"username": "alice", "domain": "alice.example", "panel_url": "https://p"})
	if got != "Hi alice at alice.example: https://p " {
		t.Errorf("%q", got)
	}
	// A value cannot bring template syntax with it.
	if got := Render("{{username}}", map[string]string{"username": "{{domain}}"}); got != "{{domain}}" {
		t.Errorf("values are expanded twice: %q", got)
	}
}

func TestWelcomeTemplates(t *testing.T) {
	e := newEnv(t)
	r1 := e.reseller(t, "reseller1")
	// The built-in text, then the admin text, then the reseller's own.
	tpl, err := e.svc.Welcome(ctx, r1)
	if err != nil || tpl.Custom || !strings.Contains(tpl.Subject, "{{domain}}") {
		t.Fatalf("%+v %v", tpl, err)
	}
	if _, err := e.svc.SetWelcome(ctx, client, e.admin, "Welcome to Host", "Hi {{username}}, sign in at {{panel_url}}"); err != nil {
		t.Fatal(err)
	}
	tpl, _ = e.svc.Welcome(ctx, r1)
	if tpl.Custom || tpl.Subject != "Welcome to Host" {
		t.Errorf("the reseller does not inherit the admin text: %+v", tpl)
	}
	tpl, err = e.svc.SetWelcome(ctx, client, r1, "Hello from reseller1", "Account {{username}}")
	if err != nil || !tpl.Custom || tpl.Subject != "Hello from reseller1" {
		t.Fatalf("%+v %v", tpl, err)
	}
	if adm, _ := e.svc.Welcome(ctx, e.admin); adm.Subject != "Welcome to Host" {
		t.Errorf("the reseller changed the admin text: %+v", adm)
	}
	// Reset: back to the admin text.
	if tpl, _ = e.svc.SetWelcome(ctx, client, r1, "", ""); tpl.Custom || tpl.Subject != "Welcome to Host" {
		t.Errorf("after reset: %+v", tpl)
	}
	for name, in := range map[string][2]string{
		"unknown variable": {"Hi", "{{password}}"},
		"newline":          {"Hi\nBcc: x@y.example", "body"},
		"no subject":       {"", "body"},
		"long":             {"Hi", strings.Repeat("x", MaxBody+1)},
	} {
		if _, err := e.svc.SetWelcome(ctx, client, e.admin, in[0], in[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := e.svc.Welcome(ctx, &auth.Principal{Login: &store.Login{Role: store.RoleUser}, Session: &store.Session{}}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a user reads templates: %v", err)
	}
}

func payload(t *testing.T, v any) *jobs.Job {
	t.Helper()
	b, _ := json.Marshal(v)
	return &jobs.Job{Payload: b}
}

func TestWelcomeMail(t *testing.T) {
	e := newEnv(t)
	r1 := e.reseller(t, "reseller1")
	a := e.account(t, "alice", r1.Login.ID, "alice@customer.example")
	if _, err := e.svc.welcomeJob(ctx, payload(t, map[string]string{"account_id": a.ID}), nopReporter{}); err != nil {
		t.Fatal(err)
	}
	if len(e.mail.out) != 1 {
		t.Fatalf("mails: %+v", e.mail.out)
	}
	m := e.mail.out[0]
	if m.to != "alice@customer.example" || m.from != "hosting@host.example" || !strings.Contains(m.subject, "alice.example") ||
		!strings.Contains(m.body, "https://panel.host.example:2443") || !strings.Contains(m.body, "reseller1") {
		t.Errorf("%+v", m)
	}
	// No address, no mail; a removed account, no mail.
	b := e.account(t, "bob", "", "")
	if _, err := e.svc.welcomeJob(ctx, payload(t, map[string]string{"account_id": b.ID}), nopReporter{}); err != nil || len(e.mail.out) != 1 {
		t.Errorf("mail to an account without an address: %v %d", err, len(e.mail.out))
	}
	if _, err := e.svc.welcomeJob(ctx, payload(t, map[string]string{"account_id": "gone"}), nopReporter{}); err != nil {
		t.Errorf("removed account: %v", err)
	}
}

// runBroadcast runs the broadcast job as the worker would.
func runBroadcast(t *testing.T, e *env, sender, filter string, in BroadcastInput) {
	t.Helper()
	m := map[string]string{"sender_id": sender, "filter": filter, "subject": in.Subject, "body": in.Body}
	if _, err := e.svc.broadcastJob(ctx, payload(t, m), nopReporter{}); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcast(t *testing.T) {
	e := newEnv(t)
	r1, r2 := e.reseller(t, "reseller1"), e.reseller(t, "reseller2")
	e.account(t, "alice", r1.Login.ID, "alice@customer.example")
	e.account(t, "carol", r1.Login.ID, "ALICE@customer.example") // the same address twice
	e.account(t, "dave", r1.Login.ID, "")
	e.account(t, "erin", r2.Login.ID, "erin@customer.example")
	e.account(t, "frank", "", "frank@customer.example")

	in := BroadcastInput{Subject: "Maintenance {{domain}}", Body: "Hi {{username}}"}
	if _, err := e.svc.Broadcast(ctx, client, r1, in); err != nil {
		t.Fatal(err)
	}
	runBroadcast(t, e, r1.Login.ID, r1.Login.ID, in)
	// The address that two accounts share gets one message (the newest account's).
	if len(e.mail.out) != 1 || !strings.EqualFold(e.mail.out[0].to, "alice@customer.example") || e.mail.out[0].subject != "Maintenance carol.example" || e.mail.out[0].body != "Hi carol" {
		t.Errorf("reseller1 mails: %+v", e.mail.out)
	}
	e.mail.out = nil
	e.mail.fail["erin@customer.example"] = true
	runBroadcast(t, e, e.admin.Login.ID, "*", BroadcastInput{Subject: "All", Body: "x"})
	if len(e.mail.out) != 2 { // alice and frank; erin refused; dave has none
		t.Errorf("admin mails: %+v", e.mail.out)
	}

	// Once in ten minutes; nothing to send is refused; bad text is refused.
	if _, err := e.svc.Broadcast(ctx, client, r1, BroadcastInput{Subject: "Again", Body: "x"}); err == nil {
		t.Error("two broadcasts in a row")
	}
	e.now = e.now.Add(BroadcastGap + time.Second)
	if _, err := e.svc.Broadcast(ctx, client, r1, BroadcastInput{Subject: "Later", Body: "x"}); err != nil {
		t.Errorf("after the gap: %v", err)
	}
	r3 := e.reseller(t, "reseller3")
	if _, err := e.svc.Broadcast(ctx, client, r3, BroadcastInput{Subject: "Hi", Body: "x"}); err == nil {
		t.Error("a reseller without customers broadcasts")
	}
	if _, err := e.svc.Broadcast(ctx, client, r2, BroadcastInput{Subject: "Hi {{password}}", Body: "x"}); err == nil {
		t.Error("an unknown variable")
	}
	user := &auth.Principal{Login: &store.Login{ID: "u", Role: store.RoleUser}, Session: &store.Session{}}
	if _, err := e.svc.Broadcast(ctx, client, user, BroadcastInput{Subject: "Hi", Body: "x"}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a user broadcasts: %v", err)
	}
}
