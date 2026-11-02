package store

import (
	"context"
	"fmt"
)

// AccountTables lists every table that holds an account's state, with the
// condition that picks the account's rows (? is the account's id). A
// backup's account.json is these rows (ADR-0013); a new table that holds
// account state must be added here.
var AccountTables = []struct {
	Table, Where string
}{
	{"accounts", `id = ?`},
	{"logins", `account_id = ?`},
	{"recovery_codes", `login_id IN (SELECT id FROM logins WHERE account_id = ?)`},
	{"domains", `account_id = ?`},
	{"redirects", `domain_id IN (SELECT id FROM domains WHERE account_id = ?)`},
	{"dns_zones", `account_id = ?`},
	{"dns_records", `zone_id IN (SELECT id FROM dns_zones WHERE account_id = ?)`},
	{"certificates", `domain_id IN (SELECT id FROM domains WHERE account_id = ?)`},
	{"databases", `account_id = ?`},
	{"db_users", `account_id = ?`},
	{"db_grants", `db_user_id IN (SELECT id FROM db_users WHERE account_id = ?)`},
	{"mail_domains", `domain_id IN (SELECT id FROM domains WHERE account_id = ?)`},
	{"mailboxes", `domain_id IN (SELECT id FROM domains WHERE account_id = ?)`},
	{"mail_forwarders", `domain_id IN (SELECT id FROM domains WHERE account_id = ?)`},
	{"mail_autoresponders", `mailbox_id IN (SELECT m.id FROM mailboxes m JOIN domains d ON d.id = m.domain_id WHERE d.account_id = ?)`},
	{"ftp_accounts", `domain_id IN (SELECT id FROM domains WHERE account_id = ?)`},
	{"cron_jobs", `account_id = ?`},
}

// AccountExport is an account's rows, by table, each row by column. BLOB
// columns (secrets encrypted with the master key) come as []byte.
type AccountExport struct {
	SchemaVersion int                         `json:"schema_version"`
	Tables        map[string][]map[string]any `json:"tables"`
}

// ExportAccount reads all rows of an account's state, in one read
// transaction so they agree with each other.
func (db *DB) ExportAccount(ctx context.Context, accountID string) (AccountExport, error) {
	out := AccountExport{Tables: map[string][]map[string]any{}}
	tx, err := db.R.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&out.SchemaVersion); err != nil {
		return out, err
	}
	for _, t := range AccountTables {
		rows, err := tx.QueryContext(ctx, `SELECT * FROM `+t.Table+` WHERE `+t.Where, accountID) //nolint:gosec // G202: fixed table names and conditions
		if err != nil {
			return out, fmt.Errorf("export %s: %w", t.Table, err)
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			return out, err
		}
		list := []map[string]any{}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return out, err
			}
			row := make(map[string]any, len(cols))
			for i, c := range cols {
				row[c] = vals[i]
			}
			list = append(list, row)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
		out.Tables[t.Table] = list
	}
	return out, nil
}
