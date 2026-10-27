package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads migrations/NNNN_name.sql in version order.
// Migrations are forward-only; the pre-migration backup is the rollback.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		num, name, ok := strings.Cut(strings.TrimSuffix(e.Name(), ".sql"), "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("store: bad migration file name %q (want NNNN_name.sql)", e.Name())
		}
		b, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: name, sql: string(b)})
	}
	slices.SortFunc(out, func(a, b migration) int { return a.version - b.version })
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, fmt.Errorf("store: duplicate migration version %d", out[i].version)
		}
	}
	return out, nil
}

func migrate(ctx context.Context, db *sql.DB, path string) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	return runMigrations(ctx, db, path, ms)
}

func runMigrations(ctx context.Context, db *sql.DB, path string, ms []migration) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TEXT NOT NULL
	) STRICT`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	var current int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	if latest := ms[len(ms)-1].version; current > latest {
		return fmt.Errorf("store: database schema v%d is newer than this binary (v%d); refusing to run", current, latest)
	}
	var pending []migration
	for _, m := range ms {
		if m.version > current {
			pending = append(pending, m)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	if current > 0 && path != ":memory:" {
		if err := backupBeforeMigrate(ctx, db, path, current); err != nil {
			return err
		}
	}
	for _, m := range pending {
		if err := apply(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

func apply(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("store: migration %04d_%s: %w", m.version, m.name, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.version, m.name, FormatTime(time.Now())); err != nil {
		return err
	}
	return tx.Commit()
}

// backupBeforeMigrate writes a consistent copy with VACUUM INTO.
func backupBeforeMigrate(ctx context.Context, db *sql.DB, path string, version int) error {
	dst := fmt.Sprintf("%s.pre-v%d-%s.bak", path, version+1, time.Now().UTC().Format("20060102T150405Z"))
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("store: backup %s already exists", dst)
	}
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return fmt.Errorf("store: backup before migration: %w", err)
	}
	return os.Chmod(dst, 0o600)
}
