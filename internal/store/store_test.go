package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTemp(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xcp.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

func schemaVersion(t *testing.T, db *DB) int {
	t.Helper()
	var v int
	if err := db.R.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestOpenMigratesAndIsIdempotent(t *testing.T) {
	db, path := openTemp(t)
	ms, _ := loadMigrations()
	want := ms[len(ms)-1].version
	if got := schemaVersion(t, db); got != want {
		t.Fatalf("schema version = %d, want %d", got, want)
	}
	db.Close()

	db2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	if got := schemaVersion(t, db2); got != want {
		t.Fatalf("schema version after reopen = %d", got)
	}
	if bak, _ := filepath.Glob(path + ".pre-*.bak"); len(bak) != 0 {
		t.Fatalf("backup written although nothing was migrated: %v", bak)
	}
}

func TestBackupBeforeMigrateAndRefuseNewerSchema(t *testing.T) {
	db, path := openTemp(t)
	ctx := context.Background()
	ms, _ := loadMigrations()
	next := ms[len(ms)-1].version + 1
	extra := append(ms, migration{version: next, name: "extra", sql: `CREATE TABLE extra (x INTEGER) STRICT;`})

	if err := runMigrations(ctx, db.W, path, extra); err != nil {
		t.Fatal(err)
	}
	if bak, _ := filepath.Glob(path + ".pre-*.bak"); len(bak) != 1 {
		t.Fatalf("want exactly one pre-migration backup, got %v", bak)
	}
	// The real binary (without "extra") must refuse the newer schema.
	if err := runMigrations(ctx, db.W, path, ms); err == nil || !strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("err = %v, want refusal", err)
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	db, path := openTemp(t)
	ms, _ := loadMigrations()
	next := ms[len(ms)-1].version + 1
	bad := append(ms, migration{version: next, name: "bad", sql: `CREATE TABLE half (x INTEGER); SELECT nope FROM missing;`})
	if err := runMigrations(context.Background(), db.W, path, bad); err == nil {
		t.Fatal("bad migration succeeded")
	}
	var n int
	db.R.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'half'`).Scan(&n)
	if n != 0 || schemaVersion(t, db) != next-1 {
		t.Fatal("failed migration left partial changes")
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	db, _ := openTemp(t)
	ctx := context.Background()
	type ns struct{ NS1, NS2 string }

	var got ns
	if err := db.GetSetting(ctx, "dns.nameservers", &got); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if err := db.SetSetting(ctx, "dns.nameservers", ns{"ns1.example.com", "ns2.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, "dns.nameservers", ns{"a.example.net", "b.example.net"}); err != nil {
		t.Fatal(err)
	}
	if err := db.GetSetting(ctx, "dns.nameservers", &got); err != nil || got.NS1 != "a.example.net" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestAuditEventsAreAppendOnly(t *testing.T) {
	db, _ := openTemp(t)
	_, err := db.W.Exec(`INSERT INTO audit_events (at, action, result, hash) VALUES (?, 'test', 'ok', x'00')`, FormatTime(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.W.Exec(`UPDATE audit_events SET action = 'tampered'`); err == nil {
		t.Error("UPDATE on audit_events allowed")
	}
	if _, err := db.W.Exec(`DELETE FROM audit_events`); err == nil {
		t.Error("DELETE on audit_events allowed")
	}
}

func TestReadPoolIsReadOnlyAndForeignKeysOn(t *testing.T) {
	db, _ := openTemp(t)
	if _, err := db.R.Exec(`INSERT INTO settings (key, value, updated_at) VALUES ('x', '1', 'now')`); err == nil {
		t.Error("write through read pool succeeded")
	}
	now := FormatTime(time.Now())
	_, err := db.W.Exec(`INSERT INTO sessions (id_hash, login_id, ip, user_agent, created_at, last_seen_at, expires_at)
		VALUES (x'01', 'missing-login', '', '', ?, ?, ?)`, now, now, now)
	if err == nil {
		t.Error("foreign keys are not enforced")
	}
}

func TestTimeFormatSortsAsText(t *testing.T) {
	a := FormatTime(time.Date(2026, 1, 2, 3, 4, 5, 6, time.FixedZone("x", 3600)))
	b := FormatTime(time.Date(2026, 1, 2, 3, 4, 5, 7, time.FixedZone("x", 3600)))
	if a >= b || len(a) != len(b) {
		t.Fatalf("%s / %s do not sort", a, b)
	}
	got, err := ParseTime(a)
	if err != nil || got.Nanosecond() != 6 || got.Hour() != 2 {
		t.Fatalf("ParseTime = %v, %v", got, err)
	}
}
