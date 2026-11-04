package store

import (
	"context"
	"encoding/json"
	"time"
)

// SessionRow is a session with its login, for the admin's session list.
type SessionRow struct {
	Session
	Username string
	Role     string
}

// AllSessions returns every session, most recently used first.
func (db *DB) AllSessions(ctx context.Context) ([]SessionRow, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT s.id_hash, s.login_id, COALESCE(s.impersonator_id, ''), s.mfa_passed, s.ip, s.user_agent,
		s.created_at, s.last_seen_at, s.expires_at, s.reauth_at, l.username, l.role
		FROM sessions s JOIN logins l ON l.id = s.login_id ORDER BY s.last_seen_at DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var x SessionRow
		var created, seen, expires string
		var reauthS *string
		err := rows.Scan(&x.IDHash, &x.LoginID, &x.ImpersonatorID, &x.MFAPassed, &x.IP, &x.UserAgent, &created, &seen, &expires, &reauthS, &x.Username, &x.Role)
		if err != nil {
			return nil, err
		}
		if x.CreatedAt, err = ParseTime(created); err != nil {
			return nil, err
		}
		if x.LastSeenAt, err = ParseTime(seen); err != nil {
			return nil, err
		}
		if x.ExpiresAt, err = ParseTime(expires); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// LoginEvent is one sign-in attempt from the audit log.
type LoginEvent struct {
	At        time.Time
	Action    string
	Result    string
	IP        string
	UserAgent string
	Username  string // the login, when the attempt named a known one
	Detail    map[string]any
}

// LoginEvents returns the latest sign-in attempts, newest first.
func (db *DB) LoginEvents(ctx context.Context, limit int) ([]LoginEvent, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT a.at, a.action, a.result, a.ip, a.user_agent, COALESCE(l.username, ''), a.details
		FROM audit_events a LEFT JOIN logins l ON l.id = a.actor_id
		WHERE a.action IN ('auth.login', 'auth.login.password', 'auth.2fa.verify') ORDER BY a.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginEvent
	for rows.Next() {
		var e LoginEvent
		var at, details string
		if err := rows.Scan(&at, &e.Action, &e.Result, &e.IP, &e.UserAgent, &e.Username, &details); err != nil {
			return nil, err
		}
		if e.At, err = ParseTime(at); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(details), &e.Detail)
		if n, ok := e.Detail["username"].(string); ok && e.Username == "" {
			e.Username = n
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
