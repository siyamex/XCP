package logd

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/siyamex/XCP/internal/store"
)

func TestIngesterCountsOnlyNewBytesOnce(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SaveFeatureList(ctx, tx, &store.FeatureList{ID: "F", Name: "f"}, true); err != nil {
			return err
		}
		if err := store.SavePackage(ctx, tx, &store.Package{ID: "P", Name: "p", FeatureListID: "F", Limits: []byte("{}")}, true); err != nil {
			return err
		}
		a := &store.Account{ID: "A", Username: "alice", UID: 10001, PackageID: "P", PrimaryDomain: "alice.example", Status: store.AccountActive}
		if err := store.InsertAccount(ctx, tx, a); err != nil {
			return err
		}
		return store.InsertDomain(ctx, tx, &store.Domain{ID: "D", AccountID: "A", Name: "alice.example", Kind: store.DomainPrimary, DocRoot: "public_html"})
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	web := filepath.Join(dir, "alice.access.log")
	ftp := filepath.Join(dir, "xferlog")
	appendTo(t, web, `alice.example:80 192.0.2.1 - - [02/Nov/2026:10:00:00 +0000] "GET /old HTTP/1.1" 200 999999 "-" "-"`+"\n")
	in := &Ingester{DB: db, WebLogs: filepath.Join(dir, "*.access.log"), FTPLog: ftp, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// The first tick only marks where the logs are.
	if err := in.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	appendTo(t, web, `alice.example:443 192.0.2.1 - - [02/Nov/2026:10:01:00 +0000] "GET / HTTP/1.1" 200 1000 "-" "-"`+"\n"+
		`other.example:80 192.0.2.1 - - [02/Nov/2026:10:01:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"`+"\n")
	appendTo(t, ftp, "Mon Nov 02 10:00:23 2026 0 127.0.0.1 250 /home/alice/a.txt b _ i r web@alice.example ftp 1 * c\n")
	for range 2 { // the second tick finds nothing new
		if err := in.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	u, err := store.AccountUsage(ctx, db.R, "A", "2026-11-01", "2026-11-30")
	if err != nil {
		t.Fatal(err)
	}
	if len(u) != 1 || u[0].Domain != "alice.example" || u[0].Web != 1000 || u[0].FTP != 250 {
		t.Fatalf("usage: %+v", u)
	}

	// A restarted xcp-logd goes on from the stored offsets.
	in2 := &Ingester{DB: db, WebLogs: in.WebLogs, FTPLog: ftp, Log: in.Log}
	appendTo(t, web, `alice.example:443 192.0.2.1 - - [02/Nov/2026:10:02:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`+"\n")
	if err := in2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if u, _ = store.AccountUsage(ctx, db.R, "A", "2026-11-01", "2026-11-30"); u[0].Web != 1001 {
		t.Fatalf("after a restart: %+v", u)
	}
}
