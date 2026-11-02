package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportAccountHasEveryTableAndOnlyTheAccountsRows(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.Tx(ctx, func(tx *sql.Tx) error {
		seedAccount(t, tx, "A1", "alice", "alice.example")
		seedAccount(t, tx, "B12", "bob", "bob.example")
		for _, d := range []*Domain{
			{ID: "DA", AccountID: "A1", Name: "alice.example", Kind: DomainPrimary, DocRoot: "public_html"},
			{ID: "DB", AccountID: "B12", Name: "bob.example", Kind: DomainPrimary, DocRoot: "public_html"},
		} {
			if err := InsertDomain(ctx, tx, d); err != nil {
				return err
			}
		}
		return InsertCronJob(ctx, tx, &CronJob{ID: "C1", AccountID: "A1", Schedule: "* * * * *", Command: "true", Enabled: true})
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err := db.ExportAccount(ctx, "A1")
	if err != nil {
		t.Fatal(err)
	}
	if e.SchemaVersion < 15 || len(e.Tables) != len(AccountTables) {
		t.Fatalf("schema v%d, %d tables", e.SchemaVersion, len(e.Tables))
	}
	if len(e.Tables["accounts"]) != 1 || len(e.Tables["domains"]) != 1 || e.Tables["domains"][0]["name"] != "alice.example" ||
		len(e.Tables["cron_jobs"]) != 1 {
		t.Fatalf("rows: %+v", e.Tables)
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), "bob") {
		t.Error("bob's rows are in alice's export")
	}

	// Every table with an account's state is exported: a table referencing
	// accounts, domains, zones, logins, mailboxes or db_users must be listed.
	rows, err := db.R.QueryContext(ctx, `SELECT name, sql FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	listed := map[string]bool{}
	for _, t := range AccountTables {
		listed[t.Table] = true
	}
	notState := map[string]bool{"sessions": true, "usage_bandwidth": true, "jobs": true, "job_logs": true, "audit_events": true, "backups": true}
	for rows.Next() {
		var name, ddl string
		if err := rows.Scan(&name, &ddl); err != nil {
			t.Fatal(err)
		}
		for _, ref := range []string{"accounts (id)", "domains (id)", "dns_zones (id)", "logins (id)", "mailboxes (id)", "db_users (id)"} {
			if strings.Contains(ddl, "REFERENCES "+ref) && !listed[name] && !notState[name] && name != "packages" && name != "feature_lists" {
				t.Errorf("table %s holds account state but is not in AccountTables", name)
			}
		}
	}
}
