package resellers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
)

const pw = "correct horse battery"

var (
	ctx    = context.Background()
	client = auth.Client{IP: "192.0.2.1"}
)

func newEnv(t *testing.T) (*Service, *auth.Principal) {
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
	pl := plans.NewService(db, rec)
	if err := pl.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	l, err := au.CreateLogin(ctx, client, nil, auth.NewLogin{Username: "root", Password: pw, Role: store.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	return NewService(db, rec, au, pl), &auth.Principal{Login: l, Session: &store.Session{}}
}

func i64(n int64) *int64 { return &n }

func TestResellerManagement(t *testing.T) {
	s, admin := newEnv(t)
	if _, err := s.List(ctx, &auth.Principal{Login: &store.Login{Role: store.RoleUser}, Session: &store.Session{}}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a user lists resellers: %v", err)
	}
	r, err := s.Create(ctx, client, admin, CreateInput{Username: "acme", Email: "boss@acme.example", Password: pw, Limits: Limits{MaxAccounts: i64(5), DiskMB: i64(1000)}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Limits.MaxAccounts == nil || *r.Limits.MaxAccounts != 5 || r.Limits.BandwidthMB != nil || r.Usage.Accounts != 0 || r.Status != store.LoginActive {
		t.Errorf("%+v", r)
	}
	if _, err := s.Create(ctx, client, admin, CreateInput{Username: "acme", Password: pw}); err == nil {
		t.Error("a second reseller with the same name")
	}
	if _, err := s.Create(ctx, client, admin, CreateInput{Username: "bad", Password: pw, Limits: Limits{DiskMB: i64(-1)}}); err == nil {
		t.Error("a negative limit")
	}
	if _, err := s.Create(ctx, client, admin, CreateInput{Username: "weak", Password: "short"}); err == nil {
		t.Error("a weak password")
	}

	r, err = s.SetLimits(ctx, client, admin, r.ID, Limits{MaxAccounts: nil, DiskMB: i64(50), OversellDisk: true})
	if err != nil || r.Limits.MaxAccounts != nil || *r.Limits.DiskMB != 50 || !r.Limits.OversellDisk {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := s.SetLimits(ctx, client, admin, "nope", Limits{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown reseller: %v", err)
	}

	// Its own overview, and only its own.
	rp := &auth.Principal{Login: &store.Login{ID: r.ID, Role: store.RoleReseller}, Session: &store.Session{}}
	ov, err := s.Overview(ctx, rp)
	if err != nil || ov.ID != r.ID {
		t.Fatalf("%+v %v", ov, err)
	}
	if _, err := s.Overview(ctx, admin); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("an admin has no reseller overview: %v", err)
	}
	if _, err := s.SetLimits(ctx, client, rp, r.ID, Limits{}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a reseller raises its own limits: %v", err)
	}

	r, err = s.SetStatus(ctx, client, admin, r.ID, true)
	if err != nil || r.Status != store.LoginSuspended {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := s.auth.Login(ctx, client, "acme", pw); err == nil {
		t.Error("a suspended reseller signed in")
	}
	r, err = s.SetStatus(ctx, client, admin, r.ID, false)
	if err != nil || r.Status != store.LoginActive {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := s.auth.Login(ctx, client, "acme", pw); err != nil {
		t.Errorf("a reactivated reseller cannot sign in: %v", err)
	}
}
