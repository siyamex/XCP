package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// MessageTemplate returns the welcome message of an owner ("" = the admins).
func (db *DB) MessageTemplate(ctx context.Context, ownerID string) (subject, body string, found bool, err error) {
	err = db.R.QueryRowContext(ctx, `SELECT subject, body FROM message_templates WHERE owner_id = ?`, ownerID).Scan(&subject, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	return subject, body, err == nil, err
}

// SetMessageTemplate saves an owner's welcome message.
func (db *DB) SetMessageTemplate(ctx context.Context, ownerID, subject, body string, t time.Time) error {
	_, err := db.W.ExecContext(ctx, `INSERT INTO message_templates (owner_id, subject, body, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (owner_id) DO UPDATE SET subject = excluded.subject, body = excluded.body, updated_at = excluded.updated_at`,
		ownerID, subject, body, FormatTime(t))
	return err
}

// DeleteMessageTemplate removes an owner's welcome message (the default applies again).
func (db *DB) DeleteMessageTemplate(ctx context.Context, ownerID string) error {
	_, err := db.W.ExecContext(ctx, `DELETE FROM message_templates WHERE owner_id = ?`, ownerID)
	return err
}
