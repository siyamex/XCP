package store

import (
	"context"
	"time"
)

// DBRemoteHosts returns the hosts an account's database users may connect
// from besides the server, in the order they were added.
func DBRemoteHosts(ctx context.Context, q querier, accountID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT host FROM db_remote_hosts WHERE account_id = ? ORDER BY created_at, host`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetDBRemoteHosts replaces an account's remote hosts; hosts it had keep
// their place.
func SetDBRemoteHosts(ctx context.Context, q querier, accountID string, hosts []string) error {
	have, err := DBRemoteHosts(ctx, q, accountID)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, h := range hosts {
		keep[h] = true
	}
	for _, h := range have {
		if !keep[h] {
			if _, err := q.ExecContext(ctx, `DELETE FROM db_remote_hosts WHERE account_id = ? AND host = ?`, accountID, h); err != nil {
				return err
			}
		}
	}
	now := time.Now()
	for i, h := range hosts {
		// One step apart, so the order of a new list stays.
		at := FormatTime(now.Add(time.Duration(i) * time.Microsecond))
		if _, err := q.ExecContext(ctx, `INSERT OR IGNORE INTO db_remote_hosts (account_id, host, created_at) VALUES (?, ?, ?)`, accountID, h, at); err != nil {
			return err
		}
	}
	return nil
}
