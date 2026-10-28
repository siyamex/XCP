package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrConflict is returned when a unique value (like a username) is taken.
var ErrConflict = errors.New("store: already exists")

// Login roles.
const (
	RoleAdmin    = "admin"
	RoleReseller = "reseller"
	RoleUser     = "user"
	RoleSubuser  = "subuser"
)

// Login statuses.
const (
	LoginActive    = "active"
	LoginSuspended = "suspended"
	LoginLocked    = "locked"
)

// Login is a panel identity (admin, reseller, user or sub-user).
type Login struct {
	ID                 string
	Username           string
	Role               string
	PasswordHash       string
	TOTPSecretEnc      []byte
	TOTPPendingEnc     []byte
	TOTPLastStep       int64
	Status             string
	Email              string
	Locale             string
	MustChangePassword bool
	OwnerID            string
	AccountID          string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastLoginAt        *time.Time
}

// TOTPEnabled reports whether 2FA is active for the login.
func (l *Login) TOTPEnabled() bool { return len(l.TOTPSecretEnc) > 0 }

const loginColumns = `id, username, role, password_hash, totp_secret_enc, totp_pending_enc, totp_last_step,
	status, email, locale, must_change_password, COALESCE(owner_id, ''), COALESCE(account_id, ''),
	created_at, updated_at, last_login_at`

func scanLogin(s scanner) (*Login, error) {
	var (
		l                Login
		created, updated string
		lastLogin        sql.NullString
	)
	err := s.Scan(&l.ID, &l.Username, &l.Role, &l.PasswordHash, &l.TOTPSecretEnc, &l.TOTPPendingEnc, &l.TOTPLastStep,
		&l.Status, &l.Email, &l.Locale, &l.MustChangePassword, &l.OwnerID, &l.AccountID, &created, &updated, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [3]error
	l.CreatedAt, errs[0] = ParseTime(created)
	l.UpdatedAt, errs[1] = ParseTime(updated)
	l.LastLoginAt, errs[2] = NullTime(lastLogin)
	return &l, errors.Join(errs[:]...)
}

type scanner interface{ Scan(...any) error }

// querier is satisfied by *sql.DB and *sql.Tx.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// CreateLogin inserts l (ID, Username, Role, PasswordHash must be set).
// q may be db.W or a transaction.
func CreateLogin(ctx context.Context, q querier, l *Login) error {
	now := time.Now().UTC()
	if l.Status == "" {
		l.Status = LoginActive
	}
	if l.Locale == "" {
		l.Locale = "en"
	}
	l.CreatedAt, l.UpdatedAt = now, now
	_, err := q.ExecContext(ctx, `INSERT INTO logins (id, username, role, password_hash, status, email, locale,
		must_change_password, owner_id, account_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.Username, l.Role, l.PasswordHash, l.Status, l.Email, l.Locale, l.MustChangePassword,
		nullIfEmpty(l.OwnerID), nullIfEmpty(l.AccountID), FormatTime(now), FormatTime(now))
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: logins.username") {
		return ErrConflict
	}
	return err
}

// LoginByUsername returns the login with that username.
func (db *DB) LoginByUsername(ctx context.Context, username string) (*Login, error) {
	return scanLogin(db.R.QueryRowContext(ctx, `SELECT `+loginColumns+` FROM logins WHERE username = ?`, username))
}

// LoginByID returns the login with that ID.
func (db *DB) LoginByID(ctx context.Context, id string) (*Login, error) {
	return scanLogin(db.R.QueryRowContext(ctx, `SELECT `+loginColumns+` FROM logins WHERE id = ?`, id))
}

// CountLogins returns how many logins exist (0 means the panel needs its first admin).
func (db *DB) CountLogins(ctx context.Context) (int, error) {
	var n int
	err := db.R.QueryRowContext(ctx, `SELECT COUNT(*) FROM logins`).Scan(&n)
	return n, err
}

func execOne(ctx context.Context, q querier, query string, args ...any) error {
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetLoginPassword replaces the password hash.
func SetLoginPassword(ctx context.Context, q querier, id, hash string, mustChange bool) error {
	return execOne(ctx, q, `UPDATE logins SET password_hash = ?, must_change_password = ?, updated_at = ? WHERE id = ?`,
		hash, mustChange, FormatTime(time.Now()), id)
}

// SetLoginTOTP sets the active and pending TOTP secrets (nil clears) and resets the replay counter.
func SetLoginTOTP(ctx context.Context, q querier, id string, secretEnc, pendingEnc []byte) error {
	return execOne(ctx, q, `UPDATE logins SET totp_secret_enc = ?, totp_pending_enc = ?, totp_last_step = 0,
		updated_at = ? WHERE id = ?`, secretEnc, pendingEnc, FormatTime(time.Now()), id)
}

// AdvanceTOTPStep records a used TOTP step. It returns false if the step was
// already used (or an earlier one is newer), which makes code replay
// impossible even with two concurrent logins.
func (db *DB) AdvanceTOTPStep(ctx context.Context, id string, step int64) (bool, error) {
	res, err := db.W.ExecContext(ctx, `UPDATE logins SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, id, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// TouchLastLogin records a successful login time.
func (db *DB) TouchLastLogin(ctx context.Context, id string, t time.Time) error {
	return execOne(ctx, db.W, `UPDATE logins SET last_login_at = ? WHERE id = ?`, FormatTime(t), id)
}

// ReplaceRecoveryCodes deletes old recovery codes and stores new hashes.
func ReplaceRecoveryCodes(ctx context.Context, q querier, loginID string, hashes [][]byte) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM recovery_codes WHERE login_id = ?`, loginID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := q.ExecContext(ctx, `INSERT INTO recovery_codes (login_id, code_hash) VALUES (?, ?)`, loginID, h); err != nil {
			return err
		}
	}
	return nil
}

// UseRecoveryCode marks an unused code as used. It returns false if no
// unused code matches.
func (db *DB) UseRecoveryCode(ctx context.Context, loginID string, hash []byte) (bool, error) {
	res, err := db.W.ExecContext(ctx, `UPDATE recovery_codes SET used_at = ? WHERE login_id = ? AND code_hash = ? AND used_at IS NULL`,
		FormatTime(time.Now()), loginID, hash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// UnusedRecoveryCodes counts the login's remaining recovery codes.
func (db *DB) UnusedRecoveryCodes(ctx context.Context, loginID string) (int, error) {
	var n int
	err := db.R.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE login_id = ? AND used_at IS NULL`, loginID).Scan(&n)
	return n, err
}
