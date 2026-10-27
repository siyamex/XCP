// Package store owns the panel database (SQLite, WAL mode).
// See 01-architecture.md §6 and ADR-0001.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// DB holds one writer connection and a read-only pool. SQLite allows one
// writer at a time; funnelling writes through one connection avoids
// SQLITE_BUSY errors, while readers run in parallel thanks to WAL.
type DB struct {
	W *sql.DB
	R *sql.DB
}

// Open opens (creating if needed) the database at path and applies pending
// migrations. Before migrating an existing database it writes a copy next to
// it (see migrate.go).
func Open(ctx context.Context, path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("store: create db dir: %w", err)
	}
	w, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	w.SetConnMaxIdleTime(0)
	if err := w.PingContext(ctx); err != nil {
		w.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := migrate(ctx, w, path); err != nil {
		w.Close()
		return nil, err
	}
	r, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(max(4, runtime.NumCPU()))
	return &DB{W: w, R: r}, nil
}

func dsn(path string, readOnly bool) string {
	q := url.Values{}
	for _, p := range []string{"journal_mode(WAL)", "busy_timeout(5000)", "foreign_keys(1)", "synchronous(NORMAL)"} {
		q.Add("_pragma", p)
	}
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	} else {
		// Take the write lock at BEGIN, so a transaction never fails half-way
		// when it upgrades from read to write.
		q.Set("_txlock", "immediate")
	}
	return "file:" + filepath.ToSlash(path) + "?" + q.Encode()
}

// Close closes both pools.
func (db *DB) Close() error {
	return errors.Join(db.R.Close(), db.W.Close())
}

// Tx runs fn in a write transaction, committing if fn returns nil.
func (db *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	return tx.Commit()
}

// timeLayout is fixed-width so that timestamps sort correctly as TEXT.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// FormatTime converts t to the stored form (UTC, fixed width).
func FormatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// ParseTime reads a stored timestamp.
func ParseTime(s string) (time.Time, error) { return time.Parse(timeLayout, s) }

// NullTime converts a nullable column to a pointer.
func NullTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := ParseTime(ns.String)
	return &t, err
}
