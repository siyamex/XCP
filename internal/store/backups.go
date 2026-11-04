package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Backup statuses and kinds.
const (
	BackupRunning   = "running"
	BackupOK        = "ok"
	BackupFailed    = "failed"
	BackupManual    = "manual"
	BackupScheduled = "scheduled"
)

// Backup is the panel's record of an account backup. AccountID is empty
// once the account was removed (the backup is then only for an admin).
type Backup struct {
	ID         string
	AccountID  string
	Username   string
	Kind       string
	Status     string
	File       string
	Size       int64
	SHA256     string
	Detail     string
	JobID      string
	CreatedAt  time.Time
	FinishedAt *time.Time
}

const backupColumns = `id, COALESCE(account_id, ''), username, kind, status, file, size, sha256, detail, job_id, created_at, finished_at`

func scanBackup(s scanner) (*Backup, error) {
	var b Backup
	var created string
	var finished sql.NullString
	err := s.Scan(&b.ID, &b.AccountID, &b.Username, &b.Kind, &b.Status, &b.File, &b.Size, &b.SHA256, &b.Detail, &b.JobID, &created, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if b.CreatedAt, err = ParseTime(created); err != nil {
		return nil, err
	}
	if finished.Valid {
		t, err := ParseTime(finished.String)
		if err != nil {
			return nil, err
		}
		b.FinishedAt = &t
	}
	return &b, nil
}

func queryBackups(ctx context.Context, q querier, where string, args ...any) ([]Backup, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+backupColumns+` FROM backups WHERE `+where+` ORDER BY created_at DESC, id DESC`, args...) //nolint:gosec // G202: fixed conditions
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Backup
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// AccountBackups returns an account's backups, newest first.
func AccountBackups(ctx context.Context, q querier, accountID string) ([]Backup, error) {
	return queryBackups(ctx, q, `account_id = ?`, accountID)
}

// OrphanBackups returns the finished backups of removed accounts, newest first.
func OrphanBackups(ctx context.Context, q querier) ([]Backup, error) {
	return queryBackups(ctx, q, `account_id IS NULL AND status = 'ok'`)
}

// AdoptBackups gives a restored account its old backups back.
func AdoptBackups(ctx context.Context, q querier, username, accountID string) error {
	_, err := q.ExecContext(ctx, `UPDATE backups SET account_id = ? WHERE account_id IS NULL AND username = ?`, accountID, username)
	return err
}

// BackupByID returns a backup.
func (db *DB) BackupByID(ctx context.Context, id string) (*Backup, error) {
	return scanBackup(db.R.QueryRowContext(ctx, `SELECT `+backupColumns+` FROM backups WHERE id = ?`, id))
}

// InsertBackup records a backup that is starting.
func InsertBackup(ctx context.Context, q querier, b *Backup) error {
	b.CreatedAt = time.Now().UTC()
	_, err := q.ExecContext(ctx, `INSERT INTO backups (id, account_id, username, kind, status, file, size, sha256, detail, job_id, created_at, finished_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		b.ID, nullIfEmpty(b.AccountID), b.Username, b.Kind, b.Status, b.File, b.Size, b.SHA256, b.Detail, b.JobID, FormatTime(b.CreatedAt))
	return err
}

// FinishBackup records how a backup ended.
func FinishBackup(ctx context.Context, q querier, b *Backup) error {
	now := time.Now().UTC()
	b.FinishedAt = &now
	return execOne(ctx, q, `UPDATE backups SET status = ?, file = ?, size = ?, sha256 = ?, detail = ?, finished_at = ? WHERE id = ?`,
		b.Status, b.File, b.Size, b.SHA256, b.Detail, FormatTime(now), b.ID)
}

// DeleteBackup removes a backup's record.
func DeleteBackup(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM backups WHERE id = ?`, id)
}
