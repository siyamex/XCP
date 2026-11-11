package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// Delivery statuses.
const (
	DeliverySent     = "sent"
	DeliveryDeferred = "deferred"
	DeliveryBounced  = "bounced"
	DeliveryExpired  = "expired"
	DeliveryRejected = "rejected" // refused when it came in
)

// MailDelivery is what Postfix did with a message for one recipient.
type MailDelivery struct {
	ID        int64
	At        time.Time
	QueueID   string
	Sender    string
	Recipient string
	OrigTo    string
	Status    string
	Relay     string
	Detail    string
	Size      int64
}

func domainOf(addr string) string {
	_, d, _ := strings.Cut(strings.ToLower(addr), "@")
	return d
}

// AddMailDeliveries stores deliveries.
func AddMailDeliveries(ctx context.Context, q querier, list []MailDelivery) error {
	for _, d := range list {
		if _, err := q.ExecContext(ctx, `INSERT INTO mail_deliveries
			(at, queue_id, sender, recipient, orig_to, sender_domain, rcpt_domain, orig_domain, status, relay, detail, size)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			FormatTime(d.At), d.QueueID, d.Sender, d.Recipient, d.OrigTo, domainOf(d.Sender), domainOf(d.Recipient), domainOf(d.OrigTo),
			d.Status, d.Relay, d.Detail, d.Size); err != nil {
			return err
		}
	}
	return nil
}

// PruneMailDeliveries removes the deliveries before a time.
func PruneMailDeliveries(ctx context.Context, q querier, before time.Time) error {
	_, err := q.ExecContext(ctx, `DELETE FROM mail_deliveries WHERE at < ?`, FormatTime(before))
	return err
}

// DeliveryFilter selects deliveries.
type DeliveryFilter struct {
	Domains []string // of the sender or a recipient; nil: every delivery
	Search  string   // part of an address, or a queue ID
	Status  string
	Limit   int
}

// MailDeliveries returns deliveries, newest first.
func (db *DB) MailDeliveries(ctx context.Context, f DeliveryFilter) ([]MailDelivery, error) {
	q := `SELECT id, at, queue_id, sender, recipient, orig_to, status, relay, detail, size FROM mail_deliveries WHERE 1 = 1`
	var args []any
	if f.Domains != nil {
		js, err := json.Marshal(f.Domains)
		if err != nil {
			return nil, err
		}
		in := ` IN (SELECT value FROM json_each(?))`
		q += ` AND (sender_domain` + in + ` OR rcpt_domain` + in + ` OR (orig_domain <> '' AND orig_domain` + in + `))`
		args = append(args, string(js), string(js), string(js))
	}
	if s := strings.ToLower(strings.TrimSpace(f.Search)); s != "" {
		q += ` AND (instr(lower(sender), ?) > 0 OR instr(lower(recipient), ?) > 0 OR instr(lower(orig_to), ?) > 0 OR lower(queue_id) = ?)`
		args = append(args, s, s, s, s)
	}
	if f.Status != "" {
		q += ` AND status = ?`
		args = append(args, f.Status)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := db.R.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MailDelivery{}
	for rows.Next() {
		var (
			d  MailDelivery
			at string
		)
		if err := rows.Scan(&d.ID, &at, &d.QueueID, &d.Sender, &d.Recipient, &d.OrigTo, &d.Status, &d.Relay, &d.Detail, &d.Size); err != nil {
			return nil, err
		}
		if d.At, err = ParseTime(at); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// CountRefused counts the deliveries refused since a time whose sender is
// at one of the domains and whose answer contains text.
func (db *DB) CountRefused(ctx context.Context, domains []string, text string, since time.Time) (int, error) {
	js, err := json.Marshal(domains)
	if err != nil {
		return 0, err
	}
	var n int
	err = db.R.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_deliveries
		WHERE status = ? AND at >= ? AND instr(detail, ?) > 0 AND sender_domain IN (SELECT value FROM json_each(?))`,
		DeliveryRejected, FormatTime(since), text, string(js)).Scan(&n)
	return n, err
}
