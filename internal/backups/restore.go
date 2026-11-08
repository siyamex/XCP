package backups

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// JobRestore rebuilds a removed account from one of its backups (ADR-0015).
const JobRestore = "backup.restore"

// Applier makes the server match an account's rows: the accounts service.
type Applier interface {
	ApplyNow(ctx context.Context, accountID string) error
}

// ZoneQueuer queues the DNS apply of zones: the zones service.
type ZoneQueuer interface {
	Enqueue(ctx context.Context, tx *sql.Tx, createdBy string, remove, apply []store.Zone) error
}

// SetRestoreDeps connects what restoring needs from other services.
func (s *Service) SetRestoreDeps(a Applier, z ZoneQueuer) { s.applier, s.zones = a, z }

// Orphan is the backup of a removed account, as the admin sees it.
type Orphan struct {
	ID        string       `json:"id"`
	Username  string       `json:"username"`
	Kind      string       `json:"kind"`
	File      string       `json:"file"`
	Size      int64        `json:"size"`
	CreatedAt time.Time    `json:"created_at"`
	Remote    []RemoteCopy `json:"remote"` // copies at destinations
}

// RestoreInput chooses the package of the restored account; empty: the
// package of the same name as in the backup.
type RestoreInput struct {
	PackageID string `json:"package_id"`
}

type restorePayload struct {
	BackupID  string `json:"backup_id"`
	PackageID string `json:"package_id"`
}

func adminOnly(p *auth.Principal) error {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return apperr.ErrForbidden
	}
	return nil
}

// Orphans lists the backups of removed accounts (admins).
func (s *Service) Orphans(ctx context.Context, p *auth.Principal) ([]Orphan, error) {
	if err := adminOnly(p); err != nil {
		return nil, err
	}
	bs, err := store.OrphanBackups(ctx, s.db.R)
	if err != nil {
		return nil, err
	}
	out := make([]Orphan, 0, len(bs))
	for _, b := range bs {
		out = append(out, Orphan{ID: b.ID, Username: b.Username, Kind: b.Kind, File: b.File, Size: b.Size, CreatedAt: b.CreatedAt, Remote: []RemoteCopy{}})
	}
	s.attachOrphanRemote(ctx, out)
	return out, nil
}

// Restore starts rebuilding a removed account from its backup (admins).
func (s *Service) Restore(ctx context.Context, c auth.Client, p *auth.Principal, id string, in RestoreInput) (string, error) {
	if err := adminOnly(p); err != nil {
		return "", err
	}
	b, err := s.db.BackupByID(ctx, id)
	if err != nil {
		return "", err
	}
	switch {
	case b.AccountID != "":
		return "", apperr.NewConflict("account_exists", "this backup belongs to an account that exists: restoring over an account is not available yet")
	case b.Status != store.BackupOK:
		return "", apperr.NewConflict("not_ready", "the backup is not finished")
	}
	as, err := s.db.ListAccounts(ctx, store.AccountFilter{OwnerID: "*", Search: b.Username})
	if err != nil {
		return "", err
	}
	if slices.ContainsFunc(as, func(a store.Account) bool { return a.Username == b.Username }) {
		return "", apperr.NewConflict("username_taken", "an account named "+b.Username+" exists already")
	}
	if in.PackageID != "" {
		if _, err := s.db.PackageByID(ctx, in.PackageID); err != nil {
			return "", &validate.Error{Field: "package_id", Code: validate.CodeFormat, Message: "choose one of the packages"}
		}
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		jobID, err = s.jobs.EnqueueTx(ctx, tx, JobRestore, restorePayload{BackupID: b.ID, PackageID: in.PackageID}, jobs.EnqueueOptions{
			LockKey: "restore:" + b.Username, MaxAttempts: 1, CreatedBy: p.Login.ID,
		})
		if err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "backup.restore.start", "", b.ID, map[string]any{"username": b.Username, "file": b.File}))
	})
	return jobID, err
}

// packageFor finds the package of the restored account: the chosen one, or
// the one with the backup's package name.
func (s *Service) packageFor(ctx context.Context, name, chosen string) (string, error) {
	if chosen != "" {
		return chosen, nil
	}
	pks, err := s.db.Packages(ctx, "")
	if err != nil {
		return "", err
	}
	for _, pk := range pks {
		if pk.Name == name {
			return pk.ID, nil
		}
	}
	return "", fmt.Errorf("this server has no package named %q: choose one to restore with", name)
}

func (s *Service) restoreJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p restorePayload
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.BackupID == "" {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	if s.applier == nil || s.zones == nil {
		return nil, jobs.Permanent(errors.New("restore is not set up"))
	}
	b, err := s.db.BackupByID(ctx, p.BackupID)
	if err != nil {
		return nil, jobs.Permanent(err)
	}
	r.Logf("reading and checking %s", b.File)
	plan, err := s.agent.BackupInspect(ctx, &agentv1.BackupInspectRequest{Username: b.Username, File: b.File})
	if err != nil {
		return nil, jobs.Permanent(err)
	}
	r.Progress(15)
	var af AccountFile
	dec := json.NewDecoder(bytes.NewReader(plan.GetAccountJson()))
	dec.UseNumber()
	if err := dec.Decode(&af); err != nil {
		return nil, jobs.Permanent(fmt.Errorf("account.json: %w", err))
	}
	if af.Format != 1 {
		return nil, jobs.Permanent(fmt.Errorf("account.json is format %d, not 1", af.Format))
	}
	pkgID, err := s.packageFor(ctx, af.Package, p.PackageID)
	if err != nil {
		return nil, jobs.Permanent(err)
	}
	accountID, err := s.importRows(ctx, &af, b.Username, pkgID)
	if err != nil {
		return nil, jobs.Permanent(err)
	}
	r.Logf("the account's settings are back; creating it on the server")
	r.Progress(30)
	if err := s.applier.ApplyNow(ctx, accountID); err != nil {
		return nil, fmt.Errorf("create the account: %w", err)
	}
	r.Progress(50)
	r.Logf("restoring the home folder (%d files)", plan.GetFiles())
	home, err := s.agent.BackupRestoreHome(ctx, &agentv1.BackupRestoreRequest{Username: b.Username, File: b.File})
	if err != nil {
		return nil, fmt.Errorf("restore the files: %w", err)
	}
	r.Progress(75)
	var dbs []string
	if len(plan.GetDatabases()) > 0 {
		r.Logf("restoring %d database(s)", len(plan.GetDatabases()))
		res, err := s.agent.BackupRestoreDatabases(ctx, &agentv1.BackupRestoreRequest{Username: b.Username, File: b.File})
		if err != nil {
			return nil, fmt.Errorf("restore the databases: %w", err)
		}
		dbs = res.GetDatabases()
	}
	r.Progress(90)
	zs, err := store.AccountZones(ctx, s.db.R, accountID)
	if err != nil {
		return nil, err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.zones.Enqueue(ctx, tx, "restore", nil, zs); err != nil {
			return err
		}
		if err := store.AdoptBackups(ctx, tx, b.Username, accountID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(clientNone, nil, "backup.restore", accountID, b.ID, map[string]any{
			"username": b.Username, "file": b.File, "files": plan.GetFiles(), "databases": dbs,
		}))
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"account_id": accountID, "files": plan.GetFiles(), "entries": home.GetEntries(), "databases": dbs}, nil
}

// tableColumns returns the columns of a table with their declared types.
func tableColumns(ctx context.Context, tx *sql.Tx, table string) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name, type FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]string{}
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			return nil, err
		}
		cols[name] = typ
	}
	return cols, rows.Err()
}

// sqlValue turns a value of account.json into one SQLite takes; BLOB
// columns come as base64.
func sqlValue(v any, colType string) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i, nil
		}
		return x.Float64()
	case bool:
		if x {
			return int64(1), nil
		}
		return int64(0), nil
	case string:
		if strings.EqualFold(colType, "BLOB") {
			return base64.StdEncoding.DecodeString(x)
		}
		return x, nil
	}
	return nil, fmt.Errorf("a value of type %T", v)
}

// importRows puts the rows of account.json back, in one transaction, as
// a new account with a fresh uid, the chosen package and no reseller
// owner. Table and column names come from the server's own schema, never
// from the archive: a column the schema lacks stops the restore.
func (s *Service) importRows(ctx context.Context, af *AccountFile, username, pkgID string) (string, error) {
	accounts := af.Export.Tables["accounts"]
	if len(accounts) != 1 {
		return "", errors.New("account.json must hold exactly one account")
	}
	if u, _ := accounts[0]["username"].(string); u != username {
		return "", fmt.Errorf("account.json is of account %q, not %q", u, username)
	}
	id, _ := accounts[0]["id"].(string)
	if id == "" {
		return "", errors.New("the account has no id")
	}
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
			return err
		}
		var version int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
			return err
		}
		if af.Export.SchemaVersion > version {
			return fmt.Errorf("the backup is from a newer panel (schema v%d, this one is v%d): update first", af.Export.SchemaVersion, version)
		}
		taken := func(query, what string, v any) error {
			var n int
			if err := tx.QueryRowContext(ctx, query, v).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return fmt.Errorf("%s is in use on this server already", what)
			}
			return nil
		}
		if err := taken(`SELECT COUNT(*) FROM accounts WHERE username = ?`, "the account name "+username, username); err != nil {
			return err
		}
		for _, d := range af.Export.Tables["domains"] {
			name, _ := d["name"].(string)
			if err := taken(`SELECT COUNT(*) FROM domains WHERE name = ?`, "the domain "+name, name); err != nil {
				return err
			}
		}
		for _, l := range af.Export.Tables["logins"] {
			name, _ := l["username"].(string)
			if err := taken(`SELECT COUNT(*) FROM logins WHERE username = ?`, "the login "+name, name); err != nil {
				return err
			}
		}
		uid, err := store.NextAccountUID(ctx, tx)
		if err != nil {
			return err
		}
		overrides := map[string]map[string]any{
			"accounts": {"uid": int64(uid), "package_id": pkgID, "owner_id": nil, "status": store.AccountCreating, "status_detail": ""},
			"logins":   {"owner_id": nil},
		}
		for _, t := range store.AccountTables {
			rows := af.Export.Tables[t.Table]
			if len(rows) == 0 {
				continue
			}
			cols, err := tableColumns(ctx, tx, t.Table)
			if err != nil {
				return err
			}
			for _, row := range rows {
				if err := insertRow(ctx, tx, t.Table, cols, row, overrides[t.Table]); err != nil {
					return fmt.Errorf("restore %s: %w", t.Table, err)
				}
			}
		}
		return nil
	})
	return id, err
}

func insertRow(ctx context.Context, tx *sql.Tx, table string, cols map[string]string, row, override map[string]any) error {
	keys := make([]string, 0, len(row))
	for k := range row {
		if _, ok := cols[k]; !ok {
			return fmt.Errorf("the column %q is not in this server's schema", k)
		}
		keys = append(keys, k)
	}
	for k := range override {
		if _, ok := row[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	args := make([]any, 0, len(keys))
	quoted := make([]string, len(keys))
	for i, k := range keys {
		var v any
		if o, ok := override[k]; ok {
			v = o
		} else {
			var err error
			if v, err = sqlValue(row[k], cols[k]); err != nil {
				return fmt.Errorf("column %s: %w", k, err)
			}
		}
		args = append(args, v)
		quoted[i] = `"` + k + `"`
	}
	q := `INSERT INTO "` + table + `" (` + strings.Join(quoted, ", ") + `) VALUES (?` + strings.Repeat(", ?", len(keys)-1) + `)` //nolint:gosec // G202: names are the server's own schema's
	_, err := tx.ExecContext(ctx, q, args...)
	return err
}
