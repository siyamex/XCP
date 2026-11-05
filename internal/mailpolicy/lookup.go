package mailpolicy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/siyamex/XCP/internal/store"
)

// DBDecider finds the sending limit of a mailbox login in the panel database:
// the mail_per_hour of its account's package.
type DBDecider struct {
	DB  *store.DB
	TTL time.Duration // how long an answer is kept; 0: a minute
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	key   string
	limit int64
	until time.Time
}

// Limit implements Decider.
func (d *DBDecider) Limit(ctx context.Context, login string) (string, int64, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	d.mu.Lock()
	if c, ok := d.cache[login]; ok && now.Before(c.until) {
		d.mu.Unlock()
		return c.key, c.limit, nil
	}
	d.mu.Unlock()

	var accountID, limitsJSON string
	err := d.DB.R.QueryRowContext(ctx, `SELECT a.id, p.limits FROM mailboxes m
		JOIN domains dm ON dm.id = m.domain_id
		JOIN accounts a ON a.id = dm.account_id
		JOIN packages p ON p.id = a.package_id
		WHERE lower(m.local_part) || '@' || lower(dm.name) = ?`, login).Scan(&accountID, &limitsJSON)
	var key string
	var limit int64
	switch {
	case errors.Is(err, sql.ErrNoRows):
		key = "login:" + login // not a mailbox of ours: no limit
	case err != nil:
		return "", 0, err
	default:
		var l struct {
			MailPerHour *int64 `json:"mail_per_hour"`
		}
		if err := json.Unmarshal([]byte(limitsJSON), &l); err != nil {
			return "", 0, err
		}
		key = "account:" + accountID
		if l.MailPerHour != nil {
			limit = *l.MailPerHour
		}
	}
	ttl := d.TTL
	if ttl == 0 {
		ttl = time.Minute
	}
	d.mu.Lock()
	if d.cache == nil || len(d.cache) > 10000 {
		d.cache = map[string]cached{}
	}
	d.cache[login] = cached{key, limit, now.Add(ttl)}
	d.mu.Unlock()
	return key, limit, nil
}
