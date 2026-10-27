package audit

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/siyamex/XCP/internal/store"
)

func newRecorder(t *testing.T) (*Recorder, *store.DB) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewRecorder(db), db
}

func TestRecordAndVerifyChain(t *testing.T) {
	r, db := newRecorder(t)
	ctx := context.Background()
	for i, action := range []string{"auth.login", "account.create", "auth.logout"} {
		err := r.Record(ctx, Event{ActorID: "L1", Action: action, Result: ResultOK, IP: "192.0.2.1",
			Details: map[string]any{"n": i, "new_password": "hunter2", "nested": map[string]any{"api_token": "xcp_x"}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	n, err := r.Verify(ctx)
	if err != nil || n != 3 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	var details string
	db.R.QueryRow(`SELECT details FROM audit_events WHERE id = 1`).Scan(&details)
	if strings.Contains(details, "hunter2") || strings.Contains(details, "xcp_x") || !strings.Contains(details, `"n":0`) {
		t.Fatalf("details not masked correctly: %s", details)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	r, db := newRecorder(t)
	ctx := context.Background()
	for _, a := range []string{"a", "b", "c"} {
		if err := r.Record(ctx, Event{Action: a, Result: ResultOK}); err != nil {
			t.Fatal(err)
		}
	}
	// An attacker with raw DB access drops the append-only trigger and edits a row.
	if _, err := db.W.Exec(`DROP TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.W.Exec(`UPDATE audit_events SET action = 'harmless' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	n, err := r.Verify(ctx)
	if !errors.Is(err, ErrChainBroken) || n != 1 || !strings.Contains(err.Error(), "entry 2") {
		t.Fatalf("Verify = %d, %v; want break at entry 2", n, err)
	}
}

func TestVerifyDetectsDeletion(t *testing.T) {
	r, db := newRecorder(t)
	ctx := context.Background()
	for _, a := range []string{"a", "b", "c"} {
		r.Record(ctx, Event{Action: a, Result: ResultOK})
	}
	db.W.Exec(`DROP TRIGGER audit_no_delete`)
	db.W.Exec(`DELETE FROM audit_events WHERE id = 2`)
	if _, err := r.Verify(ctx); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("deletion not detected: %v", err)
	}
}

func TestRecordRejectsIncompleteEvents(t *testing.T) {
	r, _ := newRecorder(t)
	for _, e := range []Event{{Result: ResultOK}, {Action: "x"}, {Action: "x", Result: "maybe"}} {
		if err := r.Record(context.Background(), e); err == nil {
			t.Errorf("accepted %+v", e)
		}
	}
}
