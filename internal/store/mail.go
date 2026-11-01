package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// MailDomain is a domain's mail settings; a domain without a row has the
// defaults (no DKIM key yet, unknown addresses rejected).
type MailDomain struct {
	DomainID   string
	DKIMKeyEnc []byte
	CatchAll   []string
	UpdatedAt  time.Time
}

// Mailbox is a mailbox of a domain.
type Mailbox struct {
	ID           string
	DomainID     string
	LocalPart    string
	PasswordHash string
	QuotaMB      int64
	CanLogin     bool
	CanReceive   bool
	CanSend      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Forwarder forwards or rejects mail for an address of a domain.
type Forwarder struct {
	ID           string
	DomainID     string
	LocalPart    string
	Destinations []string
	FailMessage  string
	CreatedAt    time.Time
}

// AccountMailDomains returns the mail settings of an account's domains, by domain ID.
func AccountMailDomains(ctx context.Context, q querier, accountID string) (map[string]MailDomain, error) {
	rows, err := q.QueryContext(ctx, `SELECT m.domain_id, m.dkim_key_enc, m.catch_all, m.updated_at FROM mail_domains m
		JOIN domains d ON d.id = m.domain_id WHERE d.account_id = ?`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]MailDomain{}
	for rows.Next() {
		var m MailDomain
		var catchAll, updated string
		if err := rows.Scan(&m.DomainID, &m.DKIMKeyEnc, &catchAll, &updated); err != nil {
			return nil, err
		}
		var errs [2]error
		errs[0] = json.Unmarshal([]byte(catchAll), &m.CatchAll)
		m.UpdatedAt, errs[1] = ParseTime(updated)
		if err := errors.Join(errs[:]...); err != nil {
			return nil, err
		}
		out[m.DomainID] = m
	}
	return out, rows.Err()
}

// SetMailDomain stores a domain's mail settings.
func SetMailDomain(ctx context.Context, q querier, m MailDomain) error {
	if m.CatchAll == nil {
		m.CatchAll = []string{}
	}
	ca, err := json.Marshal(m.CatchAll)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO mail_domains (domain_id, dkim_key_enc, catch_all, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (domain_id) DO UPDATE SET dkim_key_enc = excluded.dkim_key_enc, catch_all = excluded.catch_all,
		updated_at = excluded.updated_at`, m.DomainID, m.DKIMKeyEnc, string(ca), FormatTime(time.Now()))
	return err
}

const mailboxColumns = `id, domain_id, local_part, password_hash, quota_mb, can_login, can_receive, can_send, created_at, updated_at`

func scanMailbox(s scanner) (*Mailbox, error) {
	var m Mailbox
	var created, updated string
	err := s.Scan(&m.ID, &m.DomainID, &m.LocalPart, &m.PasswordHash, &m.QuotaMB, &m.CanLogin, &m.CanReceive, &m.CanSend, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [2]error
	m.CreatedAt, errs[0] = ParseTime(created)
	m.UpdatedAt, errs[1] = ParseTime(updated)
	return &m, errors.Join(errs[:]...)
}

// AccountMailboxes returns the mailboxes of an account's domains.
func AccountMailboxes(ctx context.Context, q querier, accountID string) ([]Mailbox, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+prefixed("m.", mailboxColumns)+` FROM mailboxes m JOIN domains d ON d.id = m.domain_id
		WHERE d.account_id = ? ORDER BY d.name, m.local_part`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Mailbox
	for rows.Next() {
		m, err := scanMailbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// MailboxByID returns a mailbox.
func (db *DB) MailboxByID(ctx context.Context, id string) (*Mailbox, error) {
	return scanMailbox(db.R.QueryRowContext(ctx, `SELECT `+mailboxColumns+` FROM mailboxes WHERE id = ?`, id))
}

// InsertMailbox adds a mailbox. ErrConflict means the address exists.
func InsertMailbox(ctx context.Context, q querier, m *Mailbox) error {
	m.CreatedAt = time.Now().UTC()
	m.UpdatedAt = m.CreatedAt
	_, err := q.ExecContext(ctx, `INSERT INTO mailboxes (`+mailboxColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.DomainID, m.LocalPart, m.PasswordHash, m.QuotaMB, m.CanLogin, m.CanReceive, m.CanSend,
		FormatTime(m.CreatedAt), FormatTime(m.UpdatedAt))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// UpdateMailbox stores a mailbox's quota, switches and password hash.
func UpdateMailbox(ctx context.Context, q querier, m *Mailbox) error {
	m.UpdatedAt = time.Now().UTC()
	return execOne(ctx, q, `UPDATE mailboxes SET password_hash = ?, quota_mb = ?, can_login = ?, can_receive = ?, can_send = ?,
		updated_at = ? WHERE id = ?`, m.PasswordHash, m.QuotaMB, m.CanLogin, m.CanReceive, m.CanSend, FormatTime(m.UpdatedAt), m.ID)
}

// DeleteMailbox removes a mailbox.
func DeleteMailbox(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM mailboxes WHERE id = ?`, id)
}

// CountMailboxes counts an account's mailboxes.
func CountMailboxes(ctx context.Context, q querier, accountID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM mailboxes m JOIN domains d ON d.id = m.domain_id WHERE d.account_id = ?`, accountID).Scan(&n)
	return n, err
}

const forwarderColumns = `id, domain_id, local_part, destinations, fail_message, created_at`

func scanForwarder(s scanner) (*Forwarder, error) {
	var f Forwarder
	var dest, created string
	err := s.Scan(&f.ID, &f.DomainID, &f.LocalPart, &dest, &f.FailMessage, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [2]error
	errs[0] = json.Unmarshal([]byte(dest), &f.Destinations)
	f.CreatedAt, errs[1] = ParseTime(created)
	return &f, errors.Join(errs[:]...)
}

// AccountForwarders returns the forwarders of an account's domains.
func AccountForwarders(ctx context.Context, q querier, accountID string) ([]Forwarder, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+prefixed("f.", forwarderColumns)+` FROM mail_forwarders f JOIN domains d ON d.id = f.domain_id
		WHERE d.account_id = ? ORDER BY d.name, f.local_part`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Forwarder
	for rows.Next() {
		f, err := scanForwarder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// ForwarderByID returns a forwarder.
func (db *DB) ForwarderByID(ctx context.Context, id string) (*Forwarder, error) {
	return scanForwarder(db.R.QueryRowContext(ctx, `SELECT `+forwarderColumns+` FROM mail_forwarders WHERE id = ?`, id))
}

// InsertForwarder adds a forwarder. ErrConflict means the address has one.
func InsertForwarder(ctx context.Context, q querier, f *Forwarder) error {
	f.CreatedAt = time.Now().UTC()
	if f.Destinations == nil {
		f.Destinations = []string{}
	}
	dest, err := json.Marshal(f.Destinations)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO mail_forwarders (`+forwarderColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
		f.ID, f.DomainID, f.LocalPart, string(dest), f.FailMessage, FormatTime(f.CreatedAt))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// DeleteForwarder removes a forwarder.
func DeleteForwarder(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM mail_forwarders WHERE id = ?`, id)
}

// CountForwarders counts an account's forwarders.
func CountForwarders(ctx context.Context, q querier, accountID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_forwarders f JOIN domains d ON d.id = f.domain_id WHERE d.account_id = ?`, accountID).Scan(&n)
	return n, err
}

// prefixed qualifies a column list with a table alias ("m." + each column).
func prefixed(alias, columns string) string {
	cols := strings.Split(columns, ", ")
	for i, c := range cols {
		cols[i] = alias + c
	}
	return strings.Join(cols, ", ")
}
