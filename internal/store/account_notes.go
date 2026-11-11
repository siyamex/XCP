package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// AccountNote is the admins' internal note and tags on an account.
type AccountNote struct {
	AccountID string
	Note      string
	Tags      []string
	UpdatedBy string
	UpdatedAt time.Time // zero: never written
}

// AccountNoteByID returns an account's note; an empty one if none was written.
func (db *DB) AccountNoteByID(ctx context.Context, accountID string) (AccountNote, error) {
	n := AccountNote{AccountID: accountID, Tags: []string{}}
	var tags, updated string
	err := db.R.QueryRowContext(ctx, `SELECT note, tags, updated_by, updated_at FROM account_notes WHERE account_id = ?`, accountID).
		Scan(&n.Note, &tags, &n.UpdatedBy, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return n, nil
	}
	if err != nil {
		return n, err
	}
	if err := json.Unmarshal([]byte(tags), &n.Tags); err != nil {
		return n, err
	}
	n.UpdatedAt, err = ParseTime(updated)
	return n, err
}

// SetAccountNote saves an account's note and tags.
func SetAccountNote(ctx context.Context, q querier, n AccountNote) error {
	tags, err := json.Marshal(n.Tags)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO account_notes (account_id, note, tags, updated_by, updated_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (account_id) DO UPDATE SET note = excluded.note, tags = excluded.tags,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		n.AccountID, n.Note, string(tags), n.UpdatedBy, FormatTime(n.UpdatedAt))
	return err
}

// AccountTags returns the tags of every account that has some, by account ID.
func (db *DB) AccountTags(ctx context.Context) (map[string][]string, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT account_id, tags FROM account_notes WHERE tags <> '[]'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id, tags string
		if err := rows.Scan(&id, &tags); err != nil {
			return nil, err
		}
		var l []string
		if err := json.Unmarshal([]byte(tags), &l); err != nil {
			return nil, err
		}
		out[id] = l
	}
	return out, rows.Err()
}
