package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// NoticeTemplate returns an owner's text for a notice.
func (db *DB) NoticeTemplate(ctx context.Context, ownerID, kind string) (subject, body string, found bool, err error) {
	err = db.R.QueryRowContext(ctx, `SELECT subject, body FROM notice_templates WHERE owner_id = ? AND kind = ?`, ownerID, kind).Scan(&subject, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	return subject, body, err == nil, err
}

// SetNoticeTemplate saves an owner's text for a notice.
func (db *DB) SetNoticeTemplate(ctx context.Context, ownerID, kind, subject, body string, t time.Time) error {
	_, err := db.W.ExecContext(ctx, `INSERT INTO notice_templates (owner_id, kind, subject, body, updated_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (owner_id, kind) DO UPDATE SET subject = excluded.subject, body = excluded.body, updated_at = excluded.updated_at`,
		ownerID, kind, subject, body, FormatTime(t))
	return err
}

// DeleteNoticeTemplate removes an owner's text (the default applies again).
func (db *DB) DeleteNoticeTemplate(ctx context.Context, ownerID, kind string) error {
	_, err := db.W.ExecContext(ctx, `DELETE FROM notice_templates WHERE owner_id = ? AND kind = ?`, ownerID, kind)
	return err
}

// NoticeSent reports whether a notice went out for the period.
func (db *DB) NoticeSent(ctx context.Context, accountID, kind, period string) (bool, error) {
	var n int
	err := db.R.QueryRowContext(ctx, `SELECT COUNT(*) FROM notices_sent WHERE account_id = ? AND kind = ? AND period = ?`, accountID, kind, period).Scan(&n)
	return n > 0, err
}

// MarkNoticeSent records that a notice went out.
func (db *DB) MarkNoticeSent(ctx context.Context, accountID, kind, period string, t time.Time) error {
	_, err := db.W.ExecContext(ctx, `INSERT OR IGNORE INTO notices_sent (account_id, kind, period, sent_at) VALUES (?, ?, ?, ?)`, accountID, kind, period, FormatTime(t))
	return err
}

// ClearNoticeSent forgets a notice, so it can be sent again.
func (db *DB) ClearNoticeSent(ctx context.Context, accountID, kind string) error {
	_, err := db.W.ExecContext(ctx, `DELETE FROM notices_sent WHERE account_id = ? AND kind = ?`, accountID, kind)
	return err
}
