// Package jobs is the persistent job queue and worker (01-architecture.md §5).
// Anything that may take longer than ~2 seconds runs as a job.
package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/store"
)

// Status of a job.
type Status string

// Job statuses.
const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCanceled  Status = "canceled"
)

var (
	// ErrLeaseLost means the job was canceled or its lease expired and another worker took it.
	ErrLeaseLost = errors.New("jobs: lease lost")
	// ErrDuplicate means Enqueue with Unique found a queued or running job of the same kind and lock key.
	ErrDuplicate = errors.New("jobs: duplicate job already queued or running")
	// ErrBadState means the job is not in a state that allows the operation.
	ErrBadState = errors.New("jobs: operation not allowed in current state")
)

// Job is one row of the queue.
type Job struct {
	ID          string
	Kind        string
	Payload     json.RawMessage
	Status      Status
	Progress    int
	Attempts    int
	MaxAttempts int
	RunAfter    time.Time
	LockKey     string
	AccountID   string
	CreatedBy   string
	Result      json.RawMessage
	Error       string
	CreatedAt   time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
}

// EnqueueOptions are optional settings for a new job.
type EnqueueOptions struct {
	AccountID string
	CreatedBy string
	// LockKey: jobs with the same key run one at a time, in enqueue order.
	// A job waiting for a retry blocks later jobs with the same key, so
	// "create account" always finishes before "add domain" starts.
	LockKey     string
	MaxAttempts int       // 0 means 3
	RunAfter    time.Time // zero means now
	Unique      bool      // refuse if a queued/running job has the same kind and LockKey
}

// Queue reads and writes jobs.
type Queue struct {
	db  *store.DB
	now func() time.Time
}

// NewQueue returns a queue backed by db.
func NewQueue(db *store.DB) *Queue { return &Queue{db: db, now: time.Now} }

const jobColumns = `id, kind, payload, status, progress, attempts, max_attempts, run_after,
	COALESCE(lock_key, ''), COALESCE(account_id, ''), COALESCE(created_by, ''),
	result, COALESCE(error, ''), created_at, started_at, finished_at`

type scanner interface{ Scan(...any) error }

func scanJob(s scanner) (*Job, error) {
	var (
		j                          Job
		payload, runAfter, created string
		result, started, finished  sql.NullString
	)
	err := s.Scan(&j.ID, &j.Kind, &payload, &j.Status, &j.Progress, &j.Attempts, &j.MaxAttempts, &runAfter,
		&j.LockKey, &j.AccountID, &j.CreatedBy, &result, &j.Error, &created, &started, &finished)
	if err != nil {
		return nil, err
	}
	j.Payload = json.RawMessage(payload)
	if result.Valid {
		j.Result = json.RawMessage(result.String)
	}
	var errs [5]error
	j.RunAfter, errs[0] = store.ParseTime(runAfter)
	j.CreatedAt, errs[1] = store.ParseTime(created)
	j.StartedAt, errs[2] = store.NullTime(started)
	j.FinishedAt, errs[3] = store.NullTime(finished)
	return &j, errors.Join(errs[:]...)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Enqueue adds a job and returns its ID.
func (q *Queue) Enqueue(ctx context.Context, kind string, payload any, opt EnqueueOptions) (string, error) {
	if kind == "" {
		return "", errors.New("jobs: kind is required")
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("jobs: encode payload: %w", err)
	}
	now := q.now()
	if opt.MaxAttempts <= 0 {
		opt.MaxAttempts = 3
	}
	if opt.RunAfter.IsZero() {
		opt.RunAfter = now
	}
	id := ids.At(now)
	err = q.db.Tx(ctx, func(tx *sql.Tx) error {
		if opt.Unique {
			var n int
			err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE kind = ? AND COALESCE(lock_key, '') = ?
				AND status IN ('queued', 'running')`, kind, opt.LockKey).Scan(&n)
			if err != nil {
				return err
			}
			if n > 0 {
				return ErrDuplicate
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO jobs (id, kind, payload, status, max_attempts, run_after,
			lock_key, account_id, created_by, created_at) VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?)`,
			id, kind, string(b), opt.MaxAttempts, store.FormatTime(opt.RunAfter),
			nullable(opt.LockKey), nullable(opt.AccountID), nullable(opt.CreatedBy), store.FormatTime(now))
		return err
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// Get returns one job.
func (q *Queue) Get(ctx context.Context, id string) (*Job, error) {
	j, err := scanJob(q.db.R.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return j, err
}

// Claim takes the next runnable job of one of kinds for workerID, holding it
// for lease. It returns (nil, nil) when nothing is runnable. A running job
// whose lease expired (its worker died) is claimable again.
func (q *Queue) Claim(ctx context.Context, workerID string, kinds []string, lease time.Duration) (*Job, error) {
	if len(kinds) == 0 {
		return nil, nil
	}
	now := store.FormatTime(q.now())
	until := store.FormatTime(q.now().Add(lease))
	var job *Job
	err := q.db.Tx(ctx, func(tx *sql.Tx) error {
		// Jobs whose worker died on the last allowed attempt fail instead of running again.
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'failed', finished_at = ?, locked_by = NULL,
			locked_until = NULL, error = 'worker lease expired on the last attempt'
			WHERE status = 'running' AND locked_until < ? AND attempts >= max_attempts`, now, now); err != nil {
			return err
		}
		ph := strings.Repeat("?,", len(kinds))
		args := []any{workerID, until, now, now, now}
		for _, k := range kinds {
			args = append(args, k)
		}
		args = append(args, now)
		//nolint:gosec // G202: only "?" placeholders are concatenated; values are bound
		row := tx.QueryRowContext(ctx, `UPDATE jobs SET status = 'running', locked_by = ?, locked_until = ?,
			attempts = attempts + 1, started_at = COALESCE(started_at, ?)
			WHERE id = (
				SELECT j.id FROM jobs j
				WHERE ((j.status = 'queued' AND j.run_after <= ?) OR (j.status = 'running' AND j.locked_until < ?))
				  AND j.kind IN (`+ph[:len(ph)-1]+`)
				  AND (j.lock_key IS NULL OR NOT EXISTS (
					SELECT 1 FROM jobs o WHERE o.lock_key = j.lock_key AND o.id != j.id
					  AND ((o.status = 'running' AND o.locked_until >= ?)
					    OR (o.status = 'queued' AND o.rowid < j.rowid))))
				ORDER BY j.run_after, j.rowid LIMIT 1)
			RETURNING `+jobColumns, args...)
		var err error
		job, err = scanJob(row)
		if errors.Is(err, sql.ErrNoRows) {
			job, err = nil, nil
		}
		return err
	})
	return job, err
}

// owned runs an UPDATE that only applies while workerID still holds the job.
func (q *Queue) owned(ctx context.Context, id, workerID, set string, args ...any) error {
	args = append(args, id, workerID)
	// set is always a constant from this file; values are bound as args.
	res, err := q.db.W.ExecContext(ctx, `UPDATE jobs SET `+set+` WHERE id = ? AND locked_by = ? AND status = 'running'`, args...) //nolint:gosec // G202
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrLeaseLost
	}
	return nil
}

// Heartbeat extends the lease. ErrLeaseLost means the worker must stop.
func (q *Queue) Heartbeat(ctx context.Context, id, workerID string, lease time.Duration) error {
	return q.owned(ctx, id, workerID, `locked_until = ?`, store.FormatTime(q.now().Add(lease)))
}

// SetProgress records progress in percent (clamped to 0..100).
func (q *Queue) SetProgress(ctx context.Context, id, workerID string, pct int) error {
	return q.owned(ctx, id, workerID, `progress = ?`, min(max(pct, 0), 100))
}

// Complete marks the job succeeded with an optional JSON result.
func (q *Queue) Complete(ctx context.Context, id, workerID string, result any) error {
	b, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("jobs: encode result: %w", err)
	}
	return q.owned(ctx, id, workerID, `status = 'succeeded', progress = 100, result = ?, error = NULL,
		finished_at = ?, locked_by = NULL, locked_until = NULL`, string(b), store.FormatTime(q.now()))
}

// Fail records an error. The job is retried with back-off unless it used all
// attempts or the error is Permanent.
func (q *Queue) Fail(ctx context.Context, id, workerID string, jobErr error, attempts, maxAttempts int) error {
	msg := jobErr.Error()
	if attempts >= maxAttempts || IsPermanent(jobErr) {
		return q.owned(ctx, id, workerID, `status = 'failed', error = ?, finished_at = ?, locked_by = NULL,
			locked_until = NULL`, msg, store.FormatTime(q.now()))
	}
	return q.owned(ctx, id, workerID, `status = 'queued', error = ?, run_after = ?, locked_by = NULL,
		locked_until = NULL`, msg, store.FormatTime(q.now().Add(Backoff(attempts))))
}

// Backoff is the delay before retry number attempt+1: 10s, 40s, 90s, ... capped at 10 minutes.
func Backoff(attempt int) time.Duration {
	return min(time.Duration(attempt*attempt)*10*time.Second, 10*time.Minute)
}

// Cancel stops a queued or running job. A running job's worker notices on
// its next heartbeat.
func (q *Queue) Cancel(ctx context.Context, id string) error {
	res, err := q.db.W.ExecContext(ctx, `UPDATE jobs SET status = 'canceled', finished_at = ?, locked_by = NULL,
		locked_until = NULL WHERE id = ? AND status IN ('queued', 'running')`, store.FormatTime(q.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrBadState
	}
	return nil
}

// Retry re-queues a failed or canceled job with a fresh set of attempts.
func (q *Queue) Retry(ctx context.Context, id string) error {
	res, err := q.db.W.ExecContext(ctx, `UPDATE jobs SET status = 'queued', attempts = 0, progress = 0, error = NULL,
		run_after = ?, finished_at = NULL WHERE id = ? AND status IN ('failed', 'canceled')`, store.FormatTime(q.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrBadState
	}
	return nil
}

// Log appends a line to the job's log.
func (q *Queue) Log(ctx context.Context, id, level, msg string) error {
	_, err := q.db.W.ExecContext(ctx, `INSERT INTO job_logs (job_id, seq, at, level, message)
		VALUES (?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM job_logs WHERE job_id = ?), ?, ?, ?)`,
		id, id, store.FormatTime(q.now()), level, msg)
	return err
}

// LogLine is one job log entry.
type LogLine struct {
	Seq     int
	At      time.Time
	Level   string
	Message string
}

// Logs returns log lines with seq > after, for streaming.
func (q *Queue) Logs(ctx context.Context, id string, after int) ([]LogLine, error) {
	rows, err := q.db.R.QueryContext(ctx, `SELECT seq, at, level, message FROM job_logs
		WHERE job_id = ? AND seq > ? ORDER BY seq`, id, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogLine
	for rows.Next() {
		var l LogLine
		var at string
		if err := rows.Scan(&l.Seq, &at, &l.Level, &l.Message); err != nil {
			return nil, err
		}
		if l.At, err = store.ParseTime(at); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// Permanent marks an error as not worth retrying (e.g. invalid input).
func Permanent(err error) error { return permanentError{err} }

// IsPermanent reports whether err was wrapped with Permanent.
func IsPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}
