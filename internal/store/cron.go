package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// CronJob is a cron job of an account.
type CronJob struct {
	ID        string
	AccountID string
	Schedule  string
	Command   string
	Email     string // "" = output kept only
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

const cronColumns = `id, account_id, schedule, command, email, enabled, created_at, updated_at`

func scanCronJob(s scanner) (*CronJob, error) {
	var j CronJob
	var created, updated string
	err := s.Scan(&j.ID, &j.AccountID, &j.Schedule, &j.Command, &j.Email, &j.Enabled, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [2]error
	j.CreatedAt, errs[0] = ParseTime(created)
	j.UpdatedAt, errs[1] = ParseTime(updated)
	return &j, errors.Join(errs[:]...)
}

// AccountCronJobs returns an account's cron jobs, oldest first.
func AccountCronJobs(ctx context.Context, q querier, accountID string) ([]CronJob, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+cronColumns+` FROM cron_jobs WHERE account_id = ? ORDER BY created_at, id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CronJob
	for rows.Next() {
		j, err := scanCronJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

// CronJobByID returns a cron job.
func (db *DB) CronJobByID(ctx context.Context, id string) (*CronJob, error) {
	return scanCronJob(db.R.QueryRowContext(ctx, `SELECT `+cronColumns+` FROM cron_jobs WHERE id = ?`, id))
}

// InsertCronJob adds a cron job.
func InsertCronJob(ctx context.Context, q querier, j *CronJob) error {
	j.CreatedAt = time.Now().UTC()
	j.UpdatedAt = j.CreatedAt
	_, err := q.ExecContext(ctx, `INSERT INTO cron_jobs (`+cronColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		j.ID, j.AccountID, j.Schedule, j.Command, j.Email, j.Enabled, FormatTime(j.CreatedAt), FormatTime(j.UpdatedAt))
	return err
}

// UpdateCronJob stores a cron job's schedule, command, email and switch.
func UpdateCronJob(ctx context.Context, q querier, j *CronJob) error {
	j.UpdatedAt = time.Now().UTC()
	return execOne(ctx, q, `UPDATE cron_jobs SET schedule = ?, command = ?, email = ?, enabled = ?, updated_at = ? WHERE id = ?`,
		j.Schedule, j.Command, j.Email, j.Enabled, FormatTime(j.UpdatedAt), j.ID)
}

// DeleteCronJob removes a cron job.
func DeleteCronJob(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM cron_jobs WHERE id = ?`, id)
}

// CountCronJobs counts an account's cron jobs.
func CountCronJobs(ctx context.Context, q querier, accountID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM cron_jobs WHERE account_id = ?`, accountID).Scan(&n)
	return n, err
}
