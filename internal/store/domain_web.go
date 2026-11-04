package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// DomainWeb returns the JSON web settings of a domain ("" = none saved).
func (db *DB) DomainWeb(ctx context.Context, domainID string) (string, error) {
	var o string
	err := db.R.QueryRowContext(ctx, `SELECT options FROM domain_web WHERE domain_id = ?`, domainID).Scan(&o)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return o, err
}

// SetDomainWeb saves the JSON web settings of a domain.
func SetDomainWeb(ctx context.Context, q querier, domainID, options string, t time.Time) error {
	_, err := q.ExecContext(ctx, `INSERT INTO domain_web (domain_id, options, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (domain_id) DO UPDATE SET options = excluded.options, updated_at = excluded.updated_at`, domainID, options, FormatTime(t))
	return err
}

// AccountDomainWeb returns the JSON web settings of an account's domains, by domain id.
func (db *DB) AccountDomainWeb(ctx context.Context, accountID string) (map[string]string, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT w.domain_id, w.options FROM domain_web w
		JOIN domains d ON d.id = w.domain_id WHERE d.account_id = ?`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, o string
		if err := rows.Scan(&id, &o); err != nil {
			return nil, err
		}
		out[id] = o
	}
	return out, rows.Err()
}
