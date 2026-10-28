package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"

	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

func totpAD(loginID string) []byte        { return []byte("login:" + loginID + ":totp") }
func totpPendingAD(loginID string) []byte { return []byte("login:" + loginID + ":totp-pending") }

// TOTPSetup is shown once while enabling 2FA (as text and as a QR code).
type TOTPSetup struct {
	Secret string // base32, for manual entry
	URI    string // otpauth:// URI for the QR code
}

// BeginTOTP creates a pending secret. 2FA is not active until ConfirmTOTP.
func (s *Service) BeginTOTP(ctx context.Context, _ Client, p *Principal) (TOTPSetup, error) {
	if p.Login.TOTPEnabled() {
		return TOTPSetup{}, ErrTOTPState
	}
	secret := newTOTPSecret()
	pending := s.box.Seal(secret, totpPendingAD(p.Login.ID))
	if err := store.SetLoginTOTP(ctx, s.db.W, p.Login.ID, nil, pending); err != nil {
		return TOTPSetup{}, err
	}
	p.Login.TOTPPendingEnc = pending
	return TOTPSetup{Secret: b32.EncodeToString(secret), URI: otpauthURI(s.opt.Issuer, p.Login.Username, secret)}, nil
}

// ConfirmTOTP activates 2FA if code matches the pending secret, and returns
// one-time recovery codes to show the user once.
func (s *Service) ConfirmTOTP(ctx context.Context, c Client, p *Principal, code string) ([]string, error) {
	l, err := s.db.LoginByID(ctx, p.Login.ID)
	if err != nil {
		return nil, err
	}
	if l.TOTPEnabled() || len(l.TOTPPendingEnc) == 0 {
		return nil, ErrTOTPState
	}
	secret, err := s.box.Open(l.TOTPPendingEnc, totpPendingAD(l.ID))
	if err != nil {
		return nil, err
	}
	step, ok := verifyTOTP(secret, code, s.now(), 0)
	if !ok {
		return nil, ErrInvalidCode
	}
	codes, hashes := newRecoveryCodes()
	sealed := s.box.Seal(secret, totpAD(l.ID))
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetLoginTOTP(ctx, tx, l.ID, sealed, nil); err != nil {
			return err
		}
		if err := store.ReplaceRecoveryCodes(ctx, tx, l.ID, hashes); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, s.event(c, p, "auth.2fa.enable", nil))
	})
	if err != nil {
		return nil, err
	}
	// The confirmation code must not also work for a login.
	if _, err := s.db.AdvanceTOTPStep(ctx, l.ID, step); err != nil {
		return nil, err
	}
	p.Login.TOTPSecretEnc, p.Login.TOTPPendingEnc = sealed, nil
	return codes, nil
}

// DisableTOTP turns 2FA off after confirming the password.
func (s *Service) DisableTOTP(ctx context.Context, c Client, p *Principal, password string) error {
	if !p.Login.TOTPEnabled() {
		return ErrTOTPState
	}
	if err := s.checkPassword(ctx, c, p.Login, password, "auth.2fa.disable"); err != nil {
		return err
	}
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetLoginTOTP(ctx, tx, p.Login.ID, nil, nil); err != nil {
			return err
		}
		if err := store.ReplaceRecoveryCodes(ctx, tx, p.Login.ID, nil); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, s.event(c, p, "auth.2fa.disable", nil))
	})
	if err == nil {
		p.Login.TOTPSecretEnc = nil
	}
	return err
}

const (
	recoveryCodeCount = 10
	recoveryCodeLen   = 10 // base32 chars = 50 bits
)

// newRecoveryCodes returns codes formatted "ABCDE-FGHIJ" and their hashes.
func newRecoveryCodes() ([]string, [][]byte) {
	codes := make([]string, recoveryCodeCount)
	hashes := make([][]byte, recoveryCodeCount)
	for i := range codes {
		b := make([]byte, 7)
		if _, err := rand.Read(b); err != nil {
			panic("auth: crypto/rand failed: " + err.Error())
		}
		raw := b32.EncodeToString(b)[:recoveryCodeLen]
		codes[i] = raw[:5] + "-" + raw[5:]
		hashes[i] = hashRecoveryCode(raw)
	}
	return codes, hashes
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
}

func hashRecoveryCode(normalized string) []byte {
	h := sha256.Sum256([]byte("xcp-recovery-v1:" + normalized))
	return h[:]
}

// HashPassword validates a new password against the policy and hashes it,
// for callers that create logins inside their own transaction.
func (s *Service) HashPassword(ctx context.Context, password string) (string, error) {
	if err := validate.WithField(validate.Password(password), "password"); err != nil {
		return "", err
	}
	return s.hasher.Hash(ctx, password)
}

// NewLogin describes a login to create.
type NewLogin struct {
	Username           string
	Password           string
	Role               string
	Email              string
	OwnerID            string
	AccountID          string
	MustChangePassword bool
}

// CreateLogin validates and creates a login. actor is nil for the installer
// creating the first admin.
func (s *Service) CreateLogin(ctx context.Context, c Client, actor *Principal, in NewLogin) (*store.Login, error) {
	username := strings.ToLower(strings.TrimSpace(in.Username))
	if err := validate.Username(username); err != nil {
		var ve *validate.Error
		// Admin logins are not Linux users, so names like "admin" or "root" are fine for them.
		if in.Role != store.RoleAdmin || !errors.As(err, &ve) || ve.Code != validate.CodeReserved {
			return nil, validate.WithField(err, "username")
		}
	}
	switch in.Role {
	case store.RoleAdmin, store.RoleReseller, store.RoleUser, store.RoleSubuser:
	default:
		return nil, &validate.Error{Field: "role", Code: validate.CodeFormat, Message: "unknown role"}
	}
	if err := validate.WithField(validate.Password(in.Password), "password"); err != nil {
		return nil, err
	}
	email := ""
	if in.Email != "" {
		var err error
		if email, err = validate.Email(in.Email); err != nil {
			return nil, validate.WithField(err, "email")
		}
	}
	hash, err := s.hasher.Hash(ctx, in.Password)
	if err != nil {
		return nil, err
	}
	l := &store.Login{
		ID: ids.New(), Username: username, Role: in.Role, PasswordHash: hash, Email: email,
		OwnerID: in.OwnerID, AccountID: in.AccountID, MustChangePassword: in.MustChangePassword,
	}
	ev := audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: "login.create",
		Result: audit.ResultOK, TargetType: "login", TargetID: l.ID, AccountID: l.AccountID,
		Details: map[string]any{"username": username, "role": in.Role},
	}
	if actor != nil {
		ev.ActorID, ev.ImpersonatorID, ev.Role = actor.Login.ID, actor.Session.ImpersonatorID, actor.Login.Role
	} else {
		ev.Role = "system"
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.CreateLogin(ctx, tx, l); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, ev)
	})
	if errors.Is(err, store.ErrConflict) {
		return nil, &validate.Error{Field: "username", Code: "taken", Message: "username is already taken"}
	}
	return l, err
}
