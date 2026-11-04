package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Ban sources.
const (
	BanSSH    = "ssh"
	BanMail   = "mail"
	BanFTP    = "ftp"
	BanPanel  = "panel"
	BanManual = "manual"
)

// FWBan is a banned address.
type FWBan struct {
	ID         string
	IP         string
	Reason     string
	Source     string
	CreatedAt  time.Time
	ExpiresAt  *time.Time // nil: permanent
	ReleasedAt *time.Time
	ReleasedBy string
}

// Active reports whether the ban holds at t.
func (b FWBan) Active(t time.Time) bool {
	return b.ReleasedAt == nil && (b.ExpiresAt == nil || b.ExpiresAt.After(t))
}

const banColumns = `id, ip, reason, source, created_at, expires_at, released_at, released_by`

func scanBan(s scanner) (*FWBan, error) {
	var b FWBan
	var created string
	var expires, released sql.NullString
	err := s.Scan(&b.ID, &b.IP, &b.Reason, &b.Source, &created, &expires, &released, &b.ReleasedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [3]error
	b.CreatedAt, errs[0] = ParseTime(created)
	b.ExpiresAt, errs[1] = NullTime(expires)
	b.ReleasedAt, errs[2] = NullTime(released)
	return &b, errors.Join(errs[:]...)
}

func queryBans(ctx context.Context, q querier, where string, args ...any) ([]FWBan, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+banColumns+` FROM fw_bans WHERE `+where, args...) //nolint:gosec // G202: fixed conditions
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FWBan
	for rows.Next() {
		b, err := scanBan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// ActiveBans returns the bans in force at t, newest first.
func ActiveBans(ctx context.Context, q querier, t time.Time) ([]FWBan, error) {
	return queryBans(ctx, q, `released_at IS NULL AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC, id DESC`, FormatTime(t))
}

// RecentBans returns the latest bans, active or not.
func RecentBans(ctx context.Context, q querier, limit int) ([]FWBan, error) {
	return queryBans(ctx, q, `1 = 1 ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
}

// BanByID returns a ban.
func (db *DB) BanByID(ctx context.Context, id string) (*FWBan, error) {
	return scanBan(db.R.QueryRowContext(ctx, `SELECT `+banColumns+` FROM fw_bans WHERE id = ?`, id))
}

// InsertBan adds a ban.
func InsertBan(ctx context.Context, q querier, b *FWBan) error {
	var expires any
	if b.ExpiresAt != nil {
		expires = FormatTime(*b.ExpiresAt)
	}
	_, err := q.ExecContext(ctx, `INSERT INTO fw_bans (`+banColumns+`) VALUES (?, ?, ?, ?, ?, ?, NULL, '')`,
		b.ID, b.IP, b.Reason, b.Source, FormatTime(b.CreatedAt), expires)
	return err
}

// ReleaseBan lifts a ban.
func ReleaseBan(ctx context.Context, q querier, id, by string, t time.Time) error {
	return execOne(ctx, q, `UPDATE fw_bans SET released_at = ?, released_by = ? WHERE id = ? AND released_at IS NULL`, FormatTime(t), by, id)
}

// ExpireBans marks the bans whose time has passed as released.
func ExpireBans(ctx context.Context, q querier, t time.Time) (int64, error) {
	res, err := q.ExecContext(ctx, `UPDATE fw_bans SET released_at = expires_at, released_by = 'expired' WHERE released_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?`, FormatTime(t))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountBans counts all bans an address ever had.
func CountBans(ctx context.Context, q querier, ip string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM fw_bans WHERE ip = ?`, ip).Scan(&n)
	return n, err
}

// LoginFailure is a refused panel sign-in, from the audit log.
type LoginFailure struct {
	ID int64
	At time.Time
	IP string
}

// MaxAuditID returns the newest audit event's id (0: none).
func MaxAuditID(ctx context.Context, q querier) (int64, error) {
	var id int64
	err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM audit_events`).Scan(&id)
	return id, err
}

// LoginFailuresAfter returns refused panel sign-ins after an audit event id.
func LoginFailuresAfter(ctx context.Context, q querier, after int64) ([]LoginFailure, int64, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, at, ip FROM audit_events WHERE id > ? AND action IN ('auth.login', 'auth.login.password')
		AND result = 'denied' AND ip != '' ORDER BY id LIMIT 5000`, after)
	if err != nil {
		return nil, after, err
	}
	defer rows.Close()
	var out []LoginFailure
	last := after
	for rows.Next() {
		var f LoginFailure
		var at string
		if err := rows.Scan(&f.ID, &at, &f.IP); err != nil {
			return nil, after, err
		}
		if f.At, err = ParseTime(at); err != nil {
			return nil, after, err
		}
		last = f.ID
		out = append(out, f)
	}
	return out, last, rows.Err()
}

// IsBanned reports whether an address has a ban in force at t.
func IsBanned(ctx context.Context, q querier, ip string, t time.Time) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM fw_bans WHERE ip = ? AND released_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`, ip, FormatTime(t)).Scan(&n)
	return n > 0, err
}
