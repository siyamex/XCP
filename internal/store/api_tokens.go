package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Scopes of an API token.
const (
	TokenRead  = "read"  // GET requests only
	TokenWrite = "write" // everything the login may do through the API, except the pages that need a session
)

// APIToken is a stored token (never its secret).
type APIToken struct {
	ID, LoginID, Name, Prefix string
	Hash                      []byte
	Scope                     string
	IPAllow                   string // JSON array of networks; empty array: from anywhere
	CreatedAt                 time.Time
	ExpiresAt, LastUsedAt     *time.Time
	LastUsedIP                string
}

const apiRowColumns = `id, login_id, name, prefix, hash, scope, ip_allow, created_at, expires_at, last_used_at, last_used_ip` //nolint:gosec // G101: column names

func scanToken(s scanner) (*APIToken, error) {
	var t APIToken
	var created string
	var expires, used sql.NullString
	err := s.Scan(&t.ID, &t.LoginID, &t.Name, &t.Prefix, &t.Hash, &t.Scope, &t.IPAllow, &created, &expires, &used, &t.LastUsedIP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [3]error
	t.CreatedAt, errs[0] = ParseTime(created)
	t.ExpiresAt, errs[1] = NullTime(expires)
	t.LastUsedAt, errs[2] = NullTime(used)
	return &t, errors.Join(errs[:]...)
}

// InsertToken adds a token.
func InsertToken(ctx context.Context, q querier, t *APIToken) error {
	var expires any
	if t.ExpiresAt != nil {
		expires = FormatTime(*t.ExpiresAt)
	}
	_, err := q.ExecContext(ctx, `INSERT INTO api_tokens (`+apiRowColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '')`,
		t.ID, t.LoginID, t.Name, t.Prefix, t.Hash, t.Scope, t.IPAllow, FormatTime(t.CreatedAt), expires)
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// TokensOf lists a login's tokens, newest first.
func (db *DB) TokensOf(ctx context.Context, loginID string) ([]APIToken, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT `+apiRowColumns+` FROM api_tokens WHERE login_id = ? ORDER BY created_at DESC, id DESC`, loginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// TokenByPrefix finds a token by its public prefix.
func (db *DB) TokenByPrefix(ctx context.Context, prefix string) (*APIToken, error) {
	return scanToken(db.R.QueryRowContext(ctx, `SELECT `+apiRowColumns+` FROM api_tokens WHERE prefix = ?`, prefix))
}

// TokenByID finds a token.
func (db *DB) TokenByID(ctx context.Context, id string) (*APIToken, error) {
	return scanToken(db.R.QueryRowContext(ctx, `SELECT `+apiRowColumns+` FROM api_tokens WHERE id = ?`, id))
}

// CountTokens counts a login's tokens.
func CountTokens(ctx context.Context, q querier, loginID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_tokens WHERE login_id = ?`, loginID).Scan(&n)
	return n, err
}

// TouchToken records a use.
func (db *DB) TouchToken(ctx context.Context, id, ip string, t time.Time) error {
	_, err := db.W.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?`, FormatTime(t), ip, id)
	return err
}

// DeleteToken removes a token.
func DeleteToken(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM api_tokens WHERE id = ?`, id)
}
