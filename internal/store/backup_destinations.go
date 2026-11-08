package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// BackupDestination is a place where copies of backups are kept (ADR-0031).
// Config is JSON without secrets; SecretsEnc is the sealed JSON of the secrets.
type BackupDestination struct {
	ID         string
	Name       string
	Kind       string
	Config     string
	SecretsEnc []byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

const destColumns = `id, name, kind, config, secrets_enc, created_at, updated_at`

func scanDest(s scanner) (*BackupDestination, error) {
	var d BackupDestination
	var created, updated string
	err := s.Scan(&d.ID, &d.Name, &d.Kind, &d.Config, &d.SecretsEnc, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [2]error
	d.CreatedAt, errs[0] = ParseTime(created)
	d.UpdatedAt, errs[1] = ParseTime(updated)
	return &d, errors.Join(errs[:]...)
}

// BackupDestinations lists the destinations by name.
func (db *DB) BackupDestinations(ctx context.Context) ([]BackupDestination, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT `+destColumns+` FROM backup_destinations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackupDestination
	for rows.Next() {
		d, err := scanDest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// BackupDestinationByID returns a destination.
func (db *DB) BackupDestinationByID(ctx context.Context, id string) (*BackupDestination, error) {
	return scanDest(db.R.QueryRowContext(ctx, `SELECT `+destColumns+` FROM backup_destinations WHERE id = ?`, id))
}

// InsertBackupDestination adds a destination; ErrConflict when the name is taken.
func InsertBackupDestination(ctx context.Context, q querier, d *BackupDestination) error {
	now := time.Now().UTC()
	d.CreatedAt, d.UpdatedAt = now, now
	_, err := q.ExecContext(ctx, `INSERT INTO backup_destinations (`+destColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.Name, d.Kind, d.Config, d.SecretsEnc, FormatTime(now), FormatTime(now))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// UpdateBackupDestination replaces a destination's name, settings and secrets.
func UpdateBackupDestination(ctx context.Context, q querier, d *BackupDestination) error {
	d.UpdatedAt = time.Now().UTC()
	err := execOne(ctx, q, `UPDATE backup_destinations SET name = ?, kind = ?, config = ?, secrets_enc = ?, updated_at = ? WHERE id = ?`,
		d.Name, d.Kind, d.Config, d.SecretsEnc, FormatTime(d.UpdatedAt), d.ID)
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// DeleteBackupDestination removes a destination and what is known of its copies.
func DeleteBackupDestination(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM backup_destinations WHERE id = ?`, id)
}

// Remote copy statuses.
const (
	RemoteRunning = "running"
	RemoteOK      = "ok"
	RemoteFailed  = "failed"
)

// BackupRemote is what is known of one backup's copy at a destination.
type BackupRemote struct {
	BackupID        string
	DestinationID   string
	DestinationName string
	Status          string
	Detail          string
	Size            int64
	At              time.Time
}

// SetBackupRemote records the state of a backup's copy at a destination.
func SetBackupRemote(ctx context.Context, q querier, r BackupRemote) error {
	_, err := q.ExecContext(ctx, `INSERT INTO backup_remote (backup_id, destination_id, status, detail, size, at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (backup_id, destination_id) DO UPDATE SET status = excluded.status, detail = excluded.detail, size = excluded.size, at = excluded.at`,
		r.BackupID, r.DestinationID, r.Status, r.Detail, r.Size, FormatTime(r.At))
	return err
}

// DeleteBackupRemote forgets a backup's copy at a destination.
func DeleteBackupRemote(ctx context.Context, q querier, backupID, destinationID string) error {
	_, err := q.ExecContext(ctx, `DELETE FROM backup_remote WHERE backup_id = ? AND destination_id = ?`, backupID, destinationID)
	return err
}

// BackupRemotes returns the copies of the given backups, by backup ID.
func (db *DB) BackupRemotes(ctx context.Context, backupIDs []string) (map[string][]BackupRemote, error) {
	out := map[string][]BackupRemote{}
	if len(backupIDs) == 0 {
		return out, nil
	}
	args := make([]any, len(backupIDs))
	marks := ""
	for i, id := range backupIDs {
		args[i] = id
		marks += ",?"
	}
	rows, err := db.R.QueryContext(ctx, `SELECT r.backup_id, r.destination_id, d.name, r.status, r.detail, r.size, r.at
		FROM backup_remote r JOIN backup_destinations d ON d.id = r.destination_id
		WHERE r.backup_id IN (`+marks[1:]+`) ORDER BY d.name`, args...) //nolint:gosec // G202: only placeholders
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r BackupRemote
		var at string
		if err := rows.Scan(&r.BackupID, &r.DestinationID, &r.DestinationName, &r.Status, &r.Detail, &r.Size, &at); err != nil {
			return nil, err
		}
		if r.At, err = ParseTime(at); err != nil {
			return nil, err
		}
		out[r.BackupID] = append(out[r.BackupID], r)
	}
	return out, rows.Err()
}

// BackupByFile finds the record of an account's backup file.
func (db *DB) BackupByFile(ctx context.Context, username, file string) (*Backup, error) {
	return scanBackup(db.R.QueryRowContext(ctx, `SELECT `+backupColumns+` FROM backups WHERE username = ? AND file = ?`, username, file))
}
