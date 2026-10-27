package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// GetSetting decodes the JSON value stored under key into dst.
// It returns ErrNotFound if the key is not set.
func (db *DB) GetSetting(ctx context.Context, key string, dst any) error {
	var raw string
	err := db.R.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		return fmt.Errorf("store: setting %q: %w", key, err)
	}
	return nil
}

// SetSetting stores v as JSON under key, replacing any previous value.
func (db *DB) SetSetting(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("store: setting %q: %w", key, err)
	}
	_, err = db.W.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, string(b), FormatTime(time.Now()))
	return err
}
