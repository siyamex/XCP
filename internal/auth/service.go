package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Errors returned to the HTTP layer. Messages are safe to show to users.
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrLoginDisabled      = errors.New("this login is suspended or locked")
	ErrUnauthenticated    = errors.New("not logged in or session expired")
	ErrMFARequired        = errors.New("second factor required")
	ErrInvalidCode        = errors.New("invalid or already used code")
	ErrReauthRequired     = errors.New("please confirm your password to continue")
	ErrTOTPState          = errors.New("two-factor authentication is not in the right state for this")
)

// RateLimitedError: too many failures; try again after RetryAfter.
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("too many attempts, try again in %s", e.RetryAfter.Round(time.Second))
}

// Options configure the service.
type Options struct {
	SessionIdle   time.Duration // logout after this much inactivity
	SessionMax    time.Duration // absolute session lifetime
	MFAPendingTTL time.Duration // time to enter the 2FA code after the password
	Issuer        string        // shown in authenticator apps
	Argon         Argon2Params
	HashParallel  int // concurrent password hashes
	Log           *slog.Logger
}

// Client describes where a request comes from, for audit and rate limits.
type Client struct {
	IP        string
	UserAgent string
	RequestID string
}

// Principal is an authenticated caller.
type Principal struct {
	Login   *store.Login
	Session *store.Session
}

// Service implements login, sessions and 2FA.
type Service struct {
	db        *store.DB
	audit     *audit.Recorder
	box       *secretbox.Box
	hasher    *Hasher
	ipLimit   *Limiter
	userLimit *Limiter
	opt       Options
	now       func() time.Time
	dummyHash string
}

// NewService returns an auth service.
func NewService(db *store.DB, rec *audit.Recorder, box *secretbox.Box, opt Options) (*Service, error) {
	if opt.MFAPendingTTL == 0 {
		opt.MFAPendingTTL = 5 * time.Minute
	}
	if opt.Issuer == "" {
		opt.Issuer = "XCP"
	}
	if opt.Argon == (Argon2Params{}) {
		opt.Argon = DefaultArgon2
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	s := &Service{
		db: db, audit: rec, box: box, opt: opt, now: time.Now,
		hasher:    NewHasher(opt.Argon, max(opt.HashParallel, 2)),
		ipLimit:   NewLimiter(20, 15*time.Minute, 15*time.Minute),
		userLimit: NewLimiter(5, 15*time.Minute, 15*time.Minute),
	}
	// Verifying against a dummy hash for unknown usernames makes the reply
	// take as long as for real ones, so timing does not reveal valid names.
	var err error
	s.dummyHash, err = s.hasher.Hash(context.Background(), ids.New())
	return s, err
}

// LoginResult is returned by a successful first factor.
type LoginResult struct {
	Token              string // session token for the cookie
	MFARequired        bool   // call VerifyMFA before the session is usable
	MustChangePassword bool
}

func (s *Service) record(ctx context.Context, c Client, l *store.Login, action, result string, details map[string]any) {
	e := audit.Event{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: result, Details: details}
	if l != nil {
		e.ActorID, e.Role, e.TargetType, e.TargetID, e.AccountID = l.ID, l.Role, "login", l.ID, l.AccountID
	}
	// Login outcomes are recorded best-effort: a full disk must not lock
	// every admin out. State changes (password, 2FA) use RecordTx instead.
	if err := s.audit.Record(ctx, e); err != nil {
		s.opt.Log.Error("audit record failed", "action", action, "err", err)
	}
}

// Login checks a username and password and starts a session.
func (s *Service) Login(ctx context.Context, c Client, username, password string) (LoginResult, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	ipKey, userKey := "ip:"+c.IP, "user:"+username
	for _, key := range []string{ipKey, userKey} {
		if ok, wait := s.limiterFor(key).Allowed(key); !ok {
			s.record(ctx, c, nil, "auth.login", audit.ResultDenied, map[string]any{"username": username, "reason": "rate_limited"})
			return LoginResult{}, &RateLimitedError{RetryAfter: wait}
		}
	}

	l, err := s.db.LoginByUsername(ctx, username)
	hash := s.dummyHash
	if err == nil {
		hash = l.PasswordHash
	} else if !errors.Is(err, store.ErrNotFound) {
		return LoginResult{}, err
	}
	ok, rehash, verr := s.hasher.Verify(ctx, password, hash)
	if l == nil || !ok || verr != nil || len(username) > 64 {
		s.ipLimit.Fail(ipKey)
		s.userLimit.Fail(userKey)
		s.record(ctx, c, l, "auth.login", audit.ResultDenied, map[string]any{"username": username, "reason": "bad_credentials"})
		return LoginResult{}, ErrInvalidCredentials
	}
	if l.Status != store.LoginActive {
		s.record(ctx, c, l, "auth.login", audit.ResultDenied, map[string]any{"reason": "login_" + l.Status})
		return LoginResult{}, ErrLoginDisabled
	}
	s.userLimit.Reset(userKey) // not the IP: one valid account must not reset an attacker's IP counter
	if rehash {
		if h, err := s.hasher.Hash(ctx, password); err == nil {
			_ = store.SetLoginPassword(ctx, s.db.W, l.ID, h, l.MustChangePassword)
		}
	}

	now := s.now()
	mfa := l.TOTPEnabled()
	token, idHash := newToken()
	sess := &store.Session{
		IDHash: idHash, LoginID: l.ID, MFAPassed: !mfa, IP: c.IP, UserAgent: truncate(c.UserAgent, 512),
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(s.opt.SessionMax),
	}
	if mfa {
		sess.ExpiresAt = now.Add(s.opt.MFAPendingTTL)
	} else {
		sess.ReauthAt = &now
	}
	if err := s.db.CreateSession(ctx, sess); err != nil {
		return LoginResult{}, err
	}
	if mfa {
		s.record(ctx, c, l, "auth.login.password", audit.ResultOK, nil)
	} else {
		_ = s.db.TouchLastLogin(ctx, l.ID, now)
		s.record(ctx, c, l, "auth.login", audit.ResultOK, map[string]any{"mfa": "none"})
	}
	return LoginResult{Token: token, MFARequired: mfa, MustChangePassword: l.MustChangePassword}, nil
}

func (s *Service) limiterFor(key string) *Limiter {
	if strings.HasPrefix(key, "ip:") {
		return s.ipLimit
	}
	return s.userLimit
}

// VerifyMFA completes a login with a TOTP code or a recovery code.
func (s *Service) VerifyMFA(ctx context.Context, c Client, token, code string) error {
	sess, err := s.sessionFor(ctx, token)
	if err != nil {
		return err
	}
	if sess.MFAPassed {
		return nil
	}
	key := "mfa:" + sess.LoginID
	if ok, wait := s.userLimit.Allowed(key); !ok {
		return &RateLimitedError{RetryAfter: wait}
	}
	l, err := s.db.LoginByID(ctx, sess.LoginID)
	if err != nil {
		return err
	}
	method, ok, err := s.checkSecondFactor(ctx, l, code)
	if err != nil {
		return err
	}
	if !ok {
		s.userLimit.Fail(key)
		s.record(ctx, c, l, "auth.login", audit.ResultDenied, map[string]any{"reason": "bad_mfa_code"})
		return ErrInvalidCode
	}
	s.userLimit.Reset(key)
	now := s.now()
	if err := s.db.PassSessionMFA(ctx, sess.IDHash, now, now.Add(s.opt.SessionMax)); err != nil {
		return err
	}
	_ = s.db.TouchLastLogin(ctx, l.ID, now)
	s.record(ctx, c, l, "auth.login", audit.ResultOK, map[string]any{"mfa": method})
	return nil
}

// checkSecondFactor accepts a current TOTP code or an unused recovery code.
func (s *Service) checkSecondFactor(ctx context.Context, l *store.Login, code string) (method string, ok bool, err error) {
	if !l.TOTPEnabled() {
		return "", false, ErrTOTPState
	}
	secret, err := s.box.Open(l.TOTPSecretEnc, totpAD(l.ID))
	if err != nil {
		return "", false, err
	}
	if step, ok := verifyTOTP(secret, code, s.now(), l.TOTPLastStep); ok {
		// The conditional update makes the code single-use even under concurrent requests.
		advanced, err := s.db.AdvanceTOTPStep(ctx, l.ID, step)
		return "totp", advanced, err
	}
	if norm := normalizeRecoveryCode(code); len(norm) == recoveryCodeLen {
		used, err := s.db.UseRecoveryCode(ctx, l.ID, hashRecoveryCode(norm))
		return "recovery_code", used, err
	}
	return "", false, nil
}

// Authenticate resolves a session token to a principal, enforcing idle and
// absolute timeouts and the login's status.
func (s *Service) Authenticate(ctx context.Context, token string) (*Principal, error) {
	sess, err := s.sessionFor(ctx, token)
	if err != nil {
		return nil, err
	}
	if !sess.MFAPassed {
		return nil, ErrMFARequired
	}
	l, err := s.db.LoginByID(ctx, sess.LoginID)
	if err != nil || l.Status != store.LoginActive {
		_ = s.db.DeleteSession(ctx, sess.IDHash)
		return nil, ErrUnauthenticated
	}
	if now := s.now(); now.Sub(sess.LastSeenAt) > time.Minute { // limit DB writes to one per minute
		_ = s.db.TouchSession(ctx, sess.IDHash, now)
		sess.LastSeenAt = now
	}
	return &Principal{Login: l, Session: sess}, nil
}

// sessionFor loads a live session (expired ones are deleted).
func (s *Service) sessionFor(ctx context.Context, token string) (*store.Session, error) {
	if len(token) != tokenLen {
		return nil, ErrUnauthenticated
	}
	sess, err := s.db.SessionByHash(ctx, hashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > s.opt.SessionIdle {
		_ = s.db.DeleteSession(ctx, sess.IDHash)
		return nil, ErrUnauthenticated
	}
	return sess, nil
}

// Logout ends the session for token.
func (s *Service) Logout(ctx context.Context, c Client, token string) error {
	if len(token) != tokenLen {
		return nil
	}
	sess, err := s.db.SessionByHash(ctx, hashToken(token))
	if err != nil {
		return nil // already gone
	}
	if err := s.db.DeleteSession(ctx, sess.IDHash); err != nil {
		return err
	}
	if l, err := s.db.LoginByID(ctx, sess.LoginID); err == nil {
		s.record(ctx, c, l, "auth.logout", audit.ResultOK, nil)
	}
	return nil
}

// Reauth confirms the password again before a sensitive action.
func (s *Service) Reauth(ctx context.Context, c Client, p *Principal, password string) error {
	if err := s.checkPassword(ctx, c, p.Login, password, "auth.reauth"); err != nil {
		return err
	}
	now := s.now()
	p.Session.ReauthAt = &now
	if err := s.db.SetSessionReauth(ctx, p.Session.IDHash, now); err != nil {
		return err
	}
	return s.audit.Record(ctx, s.event(c, p, "auth.reauth", nil))
}

// RequireReauth fails unless the password was confirmed within the last `within`.
func (s *Service) RequireReauth(p *Principal, within time.Duration) error {
	if p.Session.ReauthAt == nil || s.now().Sub(*p.Session.ReauthAt) > within {
		return ErrReauthRequired
	}
	return nil
}

func (s *Service) checkPassword(ctx context.Context, c Client, l *store.Login, password, action string) error {
	key := "user:" + l.Username
	if ok, wait := s.userLimit.Allowed(key); !ok {
		return &RateLimitedError{RetryAfter: wait}
	}
	ok, _, err := s.hasher.Verify(ctx, password, l.PasswordHash)
	if err != nil {
		return err
	}
	if !ok {
		s.userLimit.Fail(key)
		s.record(ctx, c, l, action, audit.ResultDenied, map[string]any{"reason": "bad_password"})
		return ErrInvalidCredentials
	}
	return nil
}

// ChangePassword sets a new password and logs out all other sessions.
func (s *Service) ChangePassword(ctx context.Context, c Client, p *Principal, current, next string) error {
	if err := validate.WithField(validate.Password(next), "new_password"); err != nil {
		return err
	}
	if next == current {
		return &validate.Error{Field: "new_password", Code: validate.CodeFormat, Message: "new password must differ from the current one"}
	}
	if err := s.checkPassword(ctx, c, p.Login, current, "auth.password.change"); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(ctx, next)
	if err != nil {
		return err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetLoginPassword(ctx, tx, p.Login.ID, hash, false); err != nil {
			return err
		}
		if err := store.DeleteLoginSessions(ctx, tx, p.Login.ID, p.Session.IDHash); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, s.event(c, p, "auth.password.change", nil))
	})
	if err != nil {
		return err
	}
	now := s.now()
	p.Login.MustChangePassword = false
	p.Session.ReauthAt = &now
	return s.db.SetSessionReauth(ctx, p.Session.IDHash, now)
}

func (s *Service) event(c Client, p *Principal, action string, details map[string]any) audit.Event {
	return audit.Event{
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: "login", TargetID: p.Login.ID, AccountID: p.Login.AccountID, Details: details,
	}
}

// CSRFToken derives the CSRF token for a session token. The browser gets it
// in a response body and sends it back in a header; a cross-site attacker
// can neither read it nor compute it.
func CSRFToken(sessionToken string) string {
	mac := hmac.New(sha256.New, []byte(sessionToken))
	mac.Write([]byte("xcp-csrf-v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// CheckCSRF compares a received CSRF token in constant time.
func CheckCSRF(sessionToken, got string) bool {
	return hmac.Equal([]byte(CSRFToken(sessionToken)), []byte(got))
}

// SessionInfo describes a session for the "active sessions" page.
type SessionInfo struct {
	ID         string // hex of the token hash; safe to show, cannot be used to log in
	IP         string
	UserAgent  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	Current    bool
}

// Sessions lists the principal's sessions.
func (s *Service) Sessions(ctx context.Context, p *Principal) ([]SessionInfo, error) {
	list, err := s.db.LoginSessions(ctx, p.Login.ID)
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, 0, len(list))
	for _, x := range list {
		out = append(out, SessionInfo{
			ID: hex.EncodeToString(x.IDHash), IP: x.IP, UserAgent: x.UserAgent,
			CreatedAt: x.CreatedAt, LastSeenAt: x.LastSeenAt, Current: hmac.Equal(x.IDHash, p.Session.IDHash),
		})
	}
	return out, nil
}

// RevokeSession ends one of the principal's own sessions.
func (s *Service) RevokeSession(ctx context.Context, c Client, p *Principal, id string) error {
	h, err := hex.DecodeString(id)
	if err != nil || len(h) != sha256.Size {
		return store.ErrNotFound
	}
	if err := s.db.DeleteSessionOfLogin(ctx, p.Login.ID, h); err != nil {
		return err
	}
	return s.audit.Record(ctx, s.event(c, p, "auth.session.revoke", map[string]any{"session": id[:12]}))
}

const tokenLen = 43 // base64url of 32 bytes

func newToken() (token string, hash []byte) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("auth: crypto/rand failed: " + err.Error())
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token)
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
