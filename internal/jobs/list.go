package jobs

import (
	"context"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/store"
)

// ListFilter selects jobs for the monitor; empty fields match all.
type ListFilter struct {
	Status Status
	Kind   string
	Limit  int // 0: 50; at most 200
}

// List returns jobs, newest first.
func (q *Queue) List(ctx context.Context, f ListFilter) ([]Job, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 200)
	where, args := []string{"1 = 1"}, []any{}
	if f.Status != "" {
		where, args = append(where, "status = ?"), append(args, string(f.Status))
	}
	if f.Kind != "" {
		where, args = append(where, "kind = ?"), append(args, f.Kind)
	}
	//nolint:gosec // G202: fixed column list and fixed conditions; the values are bound with ?
	rows, err := q.db.R.QueryContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE `+strings.Join(where, " AND ")+` ORDER BY created_at DESC, id DESC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

// Counts returns how many jobs are in each status: those created since
// the given time, and every queued or running one.
func (q *Queue) Counts(ctx context.Context, since time.Time) (map[Status]int, error) {
	rows, err := q.db.R.QueryContext(ctx, `SELECT status, COUNT(*) FROM jobs WHERE created_at >= ? OR status IN ('queued', 'running') GROUP BY status`,
		store.FormatTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Status]int{}
	for rows.Next() {
		var s Status
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}
