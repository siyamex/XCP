package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Session is a logged-in browser session. Only the SHA-256 of the token is
// stored, so a leaked database does not leak usable sessions.
type Session struct {
	IDHash         []byte
	LoginID        string
	ImpersonatorID string
	MFAPassed      bool
	IP             string
	UserAgent      string
	CreatedAt      time.Time
	LastSeenAt     time.Time
	ExpiresAt      time.Time
	ReauthAt       *time.Time
}

const sessionColumns = `id_hash, login_id, COALESCE(impersonator_id, ''), mfa_passed, ip, user_agent,
	created_at, last_seen_at, expires_at, reauth_at`

func scanSession(s scanner) (*Session, error) {
	var (
		x                      Session
		created, seen, expires string
		reauth                 sql.NullString
	)
	err := s.Scan(&x.IDHash, &x.LoginID, &x.ImpersonatorID, &x.MFAPassed, &x.IP, &x.UserAgent, &created, &seen, &expires, &reauth)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [4]error
	x.CreatedAt, errs[0] = ParseTime(created)
	x.LastSeenAt, errs[1] = ParseTime(seen)
	x.ExpiresAt, errs[2] = ParseTime(expires)
	x.ReauthAt, errs[3] = NullTime(reauth)
	return &x, errors.Join(errs[:]...)
}

// CreateSession inserts s.
func (db *DB) CreateSession(ctx context.Context, s *Session) error {
	var reauth any
	if s.ReauthAt != nil {
		reauth = FormatTime(*s.ReauthAt)
	}
	_, err := db.W.ExecContext(ctx, `INSERT INTO sessions (id_hash, login_id, impersonator_id, mfa_passed, ip, user_agent,
		created_at, last_seen_at, expires_at, reauth_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.IDHash, s.LoginID, nullIfEmpty(s.ImpersonatorID), s.MFAPassed, s.IP, s.UserAgent,
		FormatTime(s.CreatedAt), FormatTime(s.LastSeenAt), FormatTime(s.ExpiresAt), reauth)
	return err
}

// SessionByHash returns the session with that token hash.
func (db *DB) SessionByHash(ctx context.Context, idHash []byte) (*Session, error) {
	return scanSession(db.R.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id_hash = ?`, idHash))
}

// TouchSession updates the last-seen time.
func (db *DB) TouchSession(ctx context.Context, idHash []byte, t time.Time) error {
	return execOne(ctx, db.W, `UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?`, FormatTime(t), idHash)
}

// PassSessionMFA marks the second factor as done and sets the full expiry.
func (db *DB) PassSessionMFA(ctx context.Context, idHash []byte, now, expires time.Time) error {
	return execOne(ctx, db.W, `UPDATE sessions SET mfa_passed = 1, last_seen_at = ?, reauth_at = ?, expires_at = ?
		WHERE id_hash = ?`, FormatTime(now), FormatTime(now), FormatTime(expires), idHash)
}

// SetSessionReauth records a successful re-authentication.
func (db *DB) SetSessionReauth(ctx context.Context, idHash []byte, t time.Time) error {
	return execOne(ctx, db.W, `UPDATE sessions SET reauth_at = ? WHERE id_hash = ?`, FormatTime(t), idHash)
}

// DeleteSession removes one session (logout).
func (db *DB) DeleteSession(ctx context.Context, idHash []byte) error {
	_, err := db.W.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteSessionOfLogin removes one session only if it belongs to loginID.
func (db *DB) DeleteSessionOfLogin(ctx context.Context, loginID string, idHash []byte) error {
	return execOne(ctx, db.W, `DELETE FROM sessions WHERE id_hash = ? AND login_id = ?`, idHash, loginID)
}

// DeleteLoginSessions removes all sessions of a login except keep (may be nil).
func DeleteLoginSessions(ctx context.Context, q querier, loginID string, keep []byte) error {
	_, err := q.ExecContext(ctx, `DELETE FROM sessions WHERE login_id = ? AND id_hash IS NOT ?`, loginID, keep)
	return err
}

// LoginSessions lists a login's sessions, newest first.
func (db *DB) LoginSessions(ctx context.Context, loginID string) ([]Session, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE login_id = ?
		ORDER BY last_seen_at DESC`, loginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// DeleteExpiredSessions removes sessions past their absolute expiry.
func (db *DB) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := db.W.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, FormatTime(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
