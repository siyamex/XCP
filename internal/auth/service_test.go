package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

var (
	ctx    = context.Background()
	client = Client{IP: "192.0.2.10", UserAgent: "test"}
)

type env struct {
	svc   *Service
	db    *store.DB
	audit *audit.Recorder
	now   time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, _ := secretbox.New(bytes.Repeat([]byte{1}, secretbox.KeySize))
	rec := audit.NewRecorder(db)
	svc, err := NewService(db, rec, box, Options{
		SessionIdle: 30 * time.Minute, SessionMax: 12 * time.Hour, Argon: testArgon,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{svc: svc, db: db, audit: rec, now: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	svc.now = func() time.Time { return e.now }
	return e
}

func (e *env) createAdmin(t *testing.T, username, password string) *store.Login {
	t.Helper()
	l, err := e.svc.CreateLogin(ctx, client, nil, NewLogin{Username: username, Password: password, Role: store.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (e *env) login(t *testing.T, user, pass string) LoginResult {
	t.Helper()
	res, err := e.svc.Login(ctx, client, user, pass)
	if err != nil {
		t.Fatalf("Login(%s): %v", user, err)
	}
	return res
}

func (e *env) principal(t *testing.T, token string) *Principal {
	t.Helper()
	p, err := e.svc.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return p
}

const pw = "correct horse battery"

func TestLoginAuthenticateLogout(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(t, "Root", pw)

	res := e.login(t, " ROOT ", pw)
	if res.MFARequired || len(res.Token) != tokenLen {
		t.Fatalf("result = %+v", res)
	}
	p := e.principal(t, res.Token)
	if p.Login.Username != "root" || p.Session.ReauthAt == nil {
		t.Fatalf("principal = %+v", p.Login)
	}
	csrf := CSRFToken(res.Token)
	if !CheckCSRF(res.Token, csrf) || CheckCSRF(res.Token, csrf+"x") || CheckCSRF(e.login(t, "root", pw).Token, csrf) {
		t.Fatal("CSRF token check wrong")
	}
	if err := e.svc.Logout(ctx, client, res.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, res.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("after logout: %v", err)
	}
	for _, bad := range []string{"", "short", res.Token + "x"} {
		if _, err := e.svc.Authenticate(ctx, bad); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate(%q) = %v", bad, err)
		}
	}
}

func TestBadCredentialsAreIndistinguishable(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(t, "root", pw)
	_, errWrongPass := e.svc.Login(ctx, client, "root", "wrong password!")
	_, errNoUser := e.svc.Login(ctx, client, "nobody", pw)
	if !errors.Is(errWrongPass, ErrInvalidCredentials) || errWrongPass != errNoUser {
		t.Fatalf("errors differ: %v / %v", errWrongPass, errNoUser)
	}
}

func TestUserRateLimitBlocksEvenCorrectPassword(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(t, "root", pw)
	for range 5 {
		e.svc.Login(ctx, client, "root", "wrong password!")
	}
	_, err := e.svc.Login(ctx, Client{IP: "198.51.100.1"}, "root", pw)
	var rl *RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter <= 0 {
		t.Fatalf("err = %v, want RateLimitedError", err)
	}
}

func TestSuspendedLoginIsOnlyRevealedWithCorrectPassword(t *testing.T) {
	e := newEnv(t)
	l := e.createAdmin(t, "root", pw)
	res := e.login(t, "root", pw)
	e.db.W.Exec(`UPDATE logins SET status = 'suspended' WHERE id = ?`, l.ID)

	if _, err := e.svc.Login(ctx, client, "root", "wrong password!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password on suspended login: %v", err)
	}
	if _, err := e.svc.Login(ctx, client, "root", pw); !errors.Is(err, ErrLoginDisabled) {
		t.Fatalf("right password on suspended login: %v", err)
	}
	if _, err := e.svc.Authenticate(ctx, res.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("existing session of suspended login still works: %v", err)
	}
}

func TestIdleAndAbsoluteTimeouts(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(t, "root", pw)

	idle := e.login(t, "root", pw).Token
	e.now = e.now.Add(31 * time.Minute)
	if _, err := e.svc.Authenticate(ctx, idle); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("idle session still valid: %v", err)
	}

	active := e.login(t, "root", pw).Token
	for range 26 { // stay active every 29 minutes for 12h+
		e.now = e.now.Add(29 * time.Minute)
		if _, err := e.svc.Authenticate(ctx, active); err != nil {
			if e.now.Sub(time.Date(2026, 10, 27, 12, 31, 0, 0, time.UTC)) <= 12*time.Hour {
				t.Fatalf("active session expired early at %v: %v", e.now, err)
			}
			return // expired by the absolute limit: expected
		}
	}
	t.Fatal("session outlived SessionMax")
}

func setupTOTP(t *testing.T, e *env, p *Principal) ([]byte, []string) {
	t.Helper()
	setup, err := e.svc.BeginTOTP(ctx, client, p)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := b32.DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ConfirmTOTP(ctx, client, p, "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong confirmation code: %v", err)
	}
	codes, err := e.svc.ConfirmTOTP(ctx, client, p, hotp(secret, uint64(totpStep(e.now)), totpDigits))
	if err != nil || len(codes) != recoveryCodeCount {
		t.Fatalf("ConfirmTOTP = %v, %v", codes, err)
	}
	return secret, codes
}

func TestTOTPLoginFlowReplayAndRecoveryCodes(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(t, "root", pw)
	p := e.principal(t, e.login(t, "root", pw).Token)
	secret, recovery := setupTOTP(t, e, p)

	e.now = e.now.Add(time.Minute)
	res := e.login(t, "root", pw)
	if !res.MFARequired {
		t.Fatal("2FA not required after enabling it")
	}
	if _, err := e.svc.Authenticate(ctx, res.Token); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("half-logged-in session usable: %v", err)
	}
	if err := e.svc.VerifyMFA(ctx, client, res.Token, "123456"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong code: %v", err)
	}
	code := hotp(secret, uint64(totpStep(e.now)), totpDigits)
	if err := e.svc.VerifyMFA(ctx, client, res.Token, code); err != nil {
		t.Fatal(err)
	}
	e.principal(t, res.Token)

	// The same code cannot complete a second login (replay).
	res2 := e.login(t, "root", pw)
	if err := e.svc.VerifyMFA(ctx, client, res2.Token, code); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replayed TOTP code accepted: %v", err)
	}
	// A recovery code works once, in any formatting.
	if err := e.svc.VerifyMFA(ctx, client, res2.Token, " "+recovery[0][:3]+" "+recovery[0][3:]+" "); err != nil {
		t.Fatalf("recovery code refused: %v", err)
	}
	res3 := e.login(t, "root", pw)
	if err := e.svc.VerifyMFA(ctx, client, res3.Token, recovery[0]); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("recovery code reused: %v", err)
	}

	// The pending 2FA session expires.
	e.now = e.now.Add(6 * time.Minute)
	if err := e.svc.VerifyMFA(ctx, client, res3.Token, hotp(secret, uint64(totpStep(e.now)), totpDigits)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired pending session accepted: %v", err)
	}

	p = e.principal(t, res.Token)
	if err := e.svc.DisableTOTP(ctx, client, p, "wrong password!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disable without password: %v", err)
	}
	if err := e.svc.DisableTOTP(ctx, client, p, pw); err != nil {
		t.Fatal(err)
	}
	if e.login(t, "root", pw).MFARequired {
		t.Fatal("2FA still required after disabling")
	}
}

func TestMFABruteForceIsRateLimited(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(t, "root", pw)
	setupTOTP(t, e, e.principal(t, e.login(t, "root", pw).Token))
	res := e.login(t, "root", pw)
	for range 5 {
		e.svc.VerifyMFA(ctx, client, res.Token, "000000")
	}
	var rl *RateLimitedError
	if err := e.svc.VerifyMFA(ctx, client, res.Token, "111111"); !errors.As(err, &rl) {
		t.Fatalf("err = %v, want RateLimitedError", err)
	}
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(t, "root", pw)
	other := e.login(t, "root", pw).Token
	current := e.login(t, "root", pw).Token
	p := e.principal(t, current)

	if err := e.svc.ChangePassword(ctx, client, p, "wrong password!", "a brand new password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current password: %v", err)
	}
	if err := e.svc.ChangePassword(ctx, client, p, pw, "short"); !errors.Is(err, validate.ErrValidation) {
		t.Fatalf("weak new password: %v", err)
	}
	if err := e.svc.ChangePassword(ctx, client, p, pw, "a brand new password"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, other); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("other session survived a password change")
	}
	e.principal(t, current)
	if _, err := e.svc.Login(ctx, client, "root", pw); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("old password still works")
	}
	e.login(t, "root", "a brand new password")
}

func TestReauthSessionsAndCreateLogin(t *testing.T) {
	e := newEnv(t)
	e.createAdmin(t, "root", pw)
	p := e.principal(t, e.login(t, "root", pw).Token)

	if err := e.svc.RequireReauth(p, 5*time.Minute); err != nil {
		t.Fatalf("fresh login should count as re-authenticated: %v", err)
	}
	e.now = e.now.Add(10 * time.Minute)
	if err := e.svc.RequireReauth(p, 5*time.Minute); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("stale reauth accepted: %v", err)
	}
	if err := e.svc.Reauth(ctx, client, p, pw); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RequireReauth(p, 5*time.Minute); err != nil {
		t.Fatal(err)
	}

	bob, err := e.svc.CreateLogin(ctx, client, p, NewLogin{Username: "bob", Password: pw, Role: store.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	bobP := e.principal(t, e.login(t, "bob", pw).Token)
	list, _ := e.svc.Sessions(ctx, p)
	if len(list) != 1 || !list[0].Current {
		t.Fatalf("root sessions = %+v", list)
	}
	if err := e.svc.RevokeSession(ctx, client, bobP, list[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a login revoked another login's session")
	}

	if _, err := e.svc.CreateLogin(ctx, client, p, NewLogin{Username: "bob", Password: pw, Role: store.RoleUser}); err == nil {
		t.Fatal("duplicate username accepted")
	}
	if _, err := e.svc.CreateLogin(ctx, client, p, NewLogin{Username: "test", Password: pw, Role: store.RoleUser}); err == nil {
		t.Fatal("reserved username accepted for a user login")
	}
	if _, err := e.svc.CreateLogin(ctx, client, p, NewLogin{Username: "admin", Password: pw, Role: store.RoleAdmin}); err != nil {
		t.Fatalf("reserved name refused for an admin login: %v", err)
	}
	if bob.Role != store.RoleUser {
		t.Fatalf("bob = %+v", bob)
	}

	// create root, login root, reauth, create bob, login bob, create admin.
	// Refused actions (revoke, duplicate, reserved name) change nothing and are not logged here.
	if n, err := e.audit.Verify(ctx); err != nil || n != 6 {
		t.Fatalf("audit chain: %d entries, %v", n, err)
	}
}
