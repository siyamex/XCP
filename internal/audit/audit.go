// Package audit writes the append-only, hash-chained audit log
// (07-security.md §9). Every state change records who did what, as whom,
// from where, and with what result.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/siyamex/XCP/internal/logging"
	"github.com/siyamex/XCP/internal/store"
)

// Results.
const (
	ResultOK     = "ok"
	ResultDenied = "denied"
	ResultError  = "error"
)

// Event is one audit entry.
type Event struct {
	ActorID        string
	ImpersonatorID string
	Role           string
	IP             string
	UserAgent      string
	Action         string // e.g. "auth.login", "account.create"
	TargetType     string
	TargetID       string
	AccountID      string
	RequestID      string
	Result         string
	Details        map[string]any // secret-looking keys are masked before storing
}

// Recorder appends events.
type Recorder struct {
	db  *store.DB
	now func() time.Time
}

// NewRecorder returns a recorder writing to db.
func NewRecorder(db *store.DB) *Recorder { return &Recorder{db: db, now: time.Now} }

// Record appends e in its own transaction.
func (r *Recorder) Record(ctx context.Context, e Event) error {
	return r.db.Tx(ctx, func(tx *sql.Tx) error { return r.RecordTx(ctx, tx, e) })
}

// RecordTx appends e inside tx, so the audit entry commits or rolls back
// together with the change it describes.
func (r *Recorder) RecordTx(ctx context.Context, tx *sql.Tx, e Event) error {
	if e.Action == "" || (e.Result != ResultOK && e.Result != ResultDenied && e.Result != ResultError) {
		return fmt.Errorf("audit: action and a valid result are required (got %q, %q)", e.Action, e.Result)
	}
	details, err := json.Marshal(mask(e.Details))
	if err != nil {
		return fmt.Errorf("audit: details: %w", err)
	}
	var prev []byte
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	row := chainRow{
		At: store.FormatTime(r.now()), ActorID: e.ActorID, ImpersonatorID: e.ImpersonatorID, Role: e.Role,
		IP: e.IP, UserAgent: e.UserAgent, Action: e.Action, TargetType: e.TargetType, TargetID: e.TargetID,
		AccountID: e.AccountID, RequestID: e.RequestID, Result: e.Result, Details: string(details),
	}
	hash := row.hash(prev)
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events (at, actor_id, impersonator_id, role, ip, user_agent,
		action, target_type, target_id, account_id, request_id, result, details, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.At, nullIfEmpty(row.ActorID), nullIfEmpty(row.ImpersonatorID), row.Role, row.IP, row.UserAgent,
		row.Action, row.TargetType, row.TargetID, nullIfEmpty(row.AccountID), row.RequestID, row.Result,
		row.Details, prev, hash)
	return err
}

// chainRow is exactly what the hash covers. Field order is fixed by the
// struct, so the JSON encoding (and the hash) is deterministic.
type chainRow struct {
	At             string `json:"at"`
	ActorID        string `json:"actor_id"`
	ImpersonatorID string `json:"impersonator_id"`
	Role           string `json:"role"`
	IP             string `json:"ip"`
	UserAgent      string `json:"user_agent"`
	Action         string `json:"action"`
	TargetType     string `json:"target_type"`
	TargetID       string `json:"target_id"`
	AccountID      string `json:"account_id"`
	RequestID      string `json:"request_id"`
	Result         string `json:"result"`
	Details        string `json:"details"`
}

func (c chainRow) hash(prev []byte) []byte {
	b, _ := json.Marshal(c) // only strings: cannot fail
	h := sha256.New()
	h.Write(prev)
	h.Write([]byte{0})
	h.Write(b)
	return h.Sum(nil)
}

// ErrChainBroken means an entry was changed, removed or inserted outside Record.
var ErrChainBroken = errors.New("audit: hash chain broken")

// Verify recomputes the whole chain. It returns the number of entries checked,
// or ErrChainBroken naming the first bad entry.
//
// Limitation: deleting the newest entries leaves a valid (shorter) chain, so
// it cannot be detected from the table alone. The daily export of the chain
// head to a file and the notification log (P2) anchor it.
func (r *Recorder) Verify(ctx context.Context) (int, error) {
	rows, err := r.db.R.QueryContext(ctx, `SELECT id, at, COALESCE(actor_id, ''), COALESCE(impersonator_id, ''), role,
		ip, user_agent, action, target_type, target_id, COALESCE(account_id, ''), request_id, result, details,
		prev_hash, hash FROM audit_events ORDER BY id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var prev []byte
	n := 0
	for rows.Next() {
		var (
			id         int64
			c          chainRow
			prevH, got []byte
		)
		if err := rows.Scan(&id, &c.At, &c.ActorID, &c.ImpersonatorID, &c.Role, &c.IP, &c.UserAgent, &c.Action,
			&c.TargetType, &c.TargetID, &c.AccountID, &c.RequestID, &c.Result, &c.Details, &prevH, &got); err != nil {
			return n, err
		}
		if !bytes.Equal(prevH, prev) || !bytes.Equal(c.hash(prev), got) {
			return n, fmt.Errorf("%w at entry %d", ErrChainBroken, id)
		}
		prev = got
		n++
	}
	return n, rows.Err()
}

// mask replaces values of secret-looking keys, at any depth.
func mask(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch {
		case logging.IsSecretKey(k):
			out[k] = logging.Redacted
		default:
			if inner, ok := v.(map[string]any); ok {
				v = mask(inner)
			}
			out[k] = v
		}
	}
	return out
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
