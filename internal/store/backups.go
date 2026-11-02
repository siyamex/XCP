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

// Backup is the panel's record of an account backup.
type Backup struct {
	ID         string
	AccountID  string
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

const backupColumns = `id, account_id, kind, status, file, size, sha256, detail, job_id, created_at, finished_at`

func scanBackup(s scanner) (*Backup, error) {
	var b Backup
	var created string
	var finished sql.NullString
	err := s.Scan(&b.ID, &b.AccountID, &b.Kind, &b.Status, &b.File, &b.Size, &b.SHA256, &b.Detail, &b.JobID, &created, &finished)
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

// AccountBackups returns an account's backups, newest first.
func AccountBackups(ctx context.Context, q querier, accountID string) ([]Backup, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+backupColumns+` FROM backups WHERE account_id = ? ORDER BY created_at DESC, id DESC`, accountID)
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

// BackupByID returns a backup.
func (db *DB) BackupByID(ctx context.Context, id string) (*Backup, error) {
	return scanBackup(db.R.QueryRowContext(ctx, `SELECT `+backupColumns+` FROM backups WHERE id = ?`, id))
}

// InsertBackup records a backup that is starting.
func InsertBackup(ctx context.Context, q querier, b *Backup) error {
	b.CreatedAt = time.Now().UTC()
	_, err := q.ExecContext(ctx, `INSERT INTO backups (`+backupColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		b.ID, b.AccountID, b.Kind, b.Status, b.File, b.Size, b.SHA256, b.Detail, b.JobID, FormatTime(b.CreatedAt))
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
