package store

import (
	"context"
	"encoding/json"
	"time"
)

// MailboxSpam is a mailbox's spam filter.
type MailboxSpam struct {
	MailboxID string
	Enabled   bool
	Threshold int      // stars of X-Spam-Level (about the score) from which mail is spam
	Action    string   // junk or delete
	Allow     []string // senders whose mail is never treated as spam
	Block     []string // senders whose mail always is
}

// DefaultSpam is the filter of a mailbox that never changed it.
func DefaultSpam(mailboxID string) MailboxSpam {
	return MailboxSpam{MailboxID: mailboxID, Enabled: true, Threshold: 6, Action: "junk", Allow: []string{}, Block: []string{}}
}

// AccountSpam returns the spam filters of an account's mailboxes, by mailbox ID
// (mailboxes without a row are not in the map).
func AccountSpam(ctx context.Context, q querier, accountID string) (map[string]MailboxSpam, error) {
	rows, err := q.QueryContext(ctx, `SELECT s.mailbox_id, s.enabled, s.threshold, s.action, s.allow_list, s.block_list
		FROM mailbox_spam s JOIN mailboxes m ON m.id = s.mailbox_id JOIN domains d ON d.id = m.domain_id WHERE d.account_id = ?`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]MailboxSpam{}
	for rows.Next() {
		var s MailboxSpam
		var allow, block string
		if err := rows.Scan(&s.MailboxID, &s.Enabled, &s.Threshold, &s.Action, &allow, &block); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(allow), &s.Allow) != nil || s.Allow == nil {
			s.Allow = []string{}
		}
		if json.Unmarshal([]byte(block), &s.Block) != nil || s.Block == nil {
			s.Block = []string{}
		}
		out[s.MailboxID] = s
	}
	return out, rows.Err()
}

// MailboxSpamOf returns one mailbox's filter (the default if it has none).
func (db *DB) MailboxSpamOf(ctx context.Context, mailboxID string) (MailboxSpam, error) {
	s := DefaultSpam(mailboxID)
	var allow, block string
	err := db.R.QueryRowContext(ctx, `SELECT enabled, threshold, action, allow_list, block_list FROM mailbox_spam WHERE mailbox_id = ?`, mailboxID).
		Scan(&s.Enabled, &s.Threshold, &s.Action, &allow, &block)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return DefaultSpam(mailboxID), nil
		}
		return s, err
	}
	if json.Unmarshal([]byte(allow), &s.Allow) != nil || s.Allow == nil {
		s.Allow = []string{}
	}
	if json.Unmarshal([]byte(block), &s.Block) != nil || s.Block == nil {
		s.Block = []string{}
	}
	return s, nil
}

// SetMailboxSpam stores a mailbox's filter.
func SetMailboxSpam(ctx context.Context, q querier, s MailboxSpam, t time.Time) error {
	allow, _ := json.Marshal(s.Allow)
	block, _ := json.Marshal(s.Block)
	_, err := q.ExecContext(ctx, `INSERT INTO mailbox_spam (mailbox_id, enabled, threshold, action, allow_list, block_list, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (mailbox_id) DO UPDATE SET enabled = excluded.enabled, threshold = excluded.threshold, action = excluded.action,
			allow_list = excluded.allow_list, block_list = excluded.block_list, updated_at = excluded.updated_at`,
		s.MailboxID, s.Enabled, s.Threshold, s.Action, string(allow), string(block), FormatTime(t))
	return err
}
