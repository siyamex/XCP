package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func newLogin(t *testing.T, db *DB, id, username string) *Login {
	t.Helper()
	l := &Login{ID: id, Username: username, Role: RoleAdmin, PasswordHash: "$argon2id$x"}
	if err := CreateLogin(context.Background(), db.W, l); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLoginsCRUD(t *testing.T) {
	db, _ := openTemp(t)
	ctx := context.Background()
	newLogin(t, db, "L1", "alice")

	if err := CreateLogin(ctx, db.W, &Login{ID: "L2", Username: "alice", Role: RoleUser, PasswordHash: "x"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate username: err = %v", err)
	}
	if err := CreateLogin(ctx, db.W, &Login{ID: "L3", Username: "bob", Role: "god", PasswordHash: "x"}); err == nil {
		t.Fatal("invalid role accepted (CHECK constraint missing?)")
	}

	got, err := db.LoginByUsername(ctx, "alice")
	if err != nil || got.ID != "L1" || got.Status != LoginActive || got.Locale != "en" || got.TOTPEnabled() {
		t.Fatalf("LoginByUsername = %+v, %v", got, err)
	}
	if _, err := db.LoginByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if n, _ := db.CountLogins(ctx); n != 1 {
		t.Fatalf("CountLogins = %d", n)
	}

	if err := SetLoginPassword(ctx, db.W, "L1", "$argon2id$new", true); err != nil {
		t.Fatal(err)
	}
	if err := SetLoginTOTP(ctx, db.W, "L1", []byte("sealed"), nil); err != nil {
		t.Fatal(err)
	}
	got, _ = db.LoginByID(ctx, "L1")
	if got.PasswordHash != "$argon2id$new" || !got.MustChangePassword || !bytes.Equal(got.TOTPSecretEnc, []byte("sealed")) || got.TOTPPendingEnc != nil {
		t.Fatalf("after updates: %+v", got)
	}
	if err := SetLoginPassword(ctx, db.W, "missing", "x", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
}

func TestAdvanceTOTPStepIsSingleUse(t *testing.T) {
	db, _ := openTemp(t)
	ctx := context.Background()
	newLogin(t, db, "L1", "alice")
	if ok, _ := db.AdvanceTOTPStep(ctx, "L1", 100); !ok {
		t.Fatal("first use refused")
	}
	if ok, _ := db.AdvanceTOTPStep(ctx, "L1", 100); ok {
		t.Fatal("same step accepted twice")
	}
	if ok, _ := db.AdvanceTOTPStep(ctx, "L1", 99); ok {
		t.Fatal("older step accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	db, _ := openTemp(t)
	ctx := context.Background()
	newLogin(t, db, "L1", "alice")
	if err := ReplaceRecoveryCodes(ctx, db.W, "L1", [][]byte{{1}, {2}}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.UseRecoveryCode(ctx, "L1", []byte{1}); !ok {
		t.Fatal("valid code refused")
	}
	if ok, _ := db.UseRecoveryCode(ctx, "L1", []byte{1}); ok {
		t.Fatal("code used twice")
	}
	if n, _ := db.UnusedRecoveryCodes(ctx, "L1"); n != 1 {
		t.Fatalf("unused = %d", n)
	}
	if err := ReplaceRecoveryCodes(ctx, db.W, "L1", [][]byte{{9}}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.UseRecoveryCode(ctx, "L1", []byte{2}); ok {
		t.Fatal("old code still valid after replacement")
	}
}

func TestSessions(t *testing.T) {
	db, _ := openTemp(t)
	ctx := context.Background()
	newLogin(t, db, "L1", "alice")
	newLogin(t, db, "L2", "bob")
	now := time.Now().UTC()
	mk := func(hash byte, login string, expires time.Time) {
		t.Helper()
		err := db.CreateSession(ctx, &Session{IDHash: []byte{hash}, LoginID: login, IP: "192.0.2.1", UserAgent: "test",
			CreatedAt: now, LastSeenAt: now, ExpiresAt: expires})
		if err != nil {
			t.Fatal(err)
		}
	}
	mk(1, "L1", now.Add(time.Hour))
	mk(2, "L1", now.Add(time.Hour))
	mk(3, "L2", now.Add(time.Hour))
	mk(4, "L1", now.Add(-time.Minute))

	s, err := db.SessionByHash(ctx, []byte{1})
	if err != nil || s.LoginID != "L1" || s.MFAPassed || s.ReauthAt != nil {
		t.Fatalf("SessionByHash = %+v, %v", s, err)
	}
	if err := db.PassSessionMFA(ctx, []byte{1}, now, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	s, _ = db.SessionByHash(ctx, []byte{1})
	if !s.MFAPassed || s.ReauthAt == nil || !s.ExpiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("after MFA: %+v", s)
	}
	if err := db.DeleteSessionOfLogin(ctx, "L2", []byte{1}); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted another login's session")
	}
	if n, _ := db.DeleteExpiredSessions(ctx, now); n != 1 {
		t.Fatalf("expired deleted = %d", n)
	}
	if err := DeleteLoginSessions(ctx, db.W, "L1", []byte{1}); err != nil {
		t.Fatal(err)
	}
	list, _ := db.LoginSessions(ctx, "L1")
	if len(list) != 1 || list[0].IDHash[0] != 1 {
		t.Fatalf("remaining L1 sessions = %+v", list)
	}
	if other, _ := db.LoginSessions(ctx, "L2"); len(other) != 1 {
		t.Fatal("other login's sessions were deleted")
	}
	if err := DeleteLoginSessions(ctx, db.W, "L1", nil); err != nil {
		t.Fatal(err)
	}
	if list, _ := db.LoginSessions(ctx, "L1"); len(list) != 0 {
		t.Fatalf("DeleteLoginSessions(nil keep) left %d", len(list))
	}
}
