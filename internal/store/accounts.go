package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Account statuses.
const (
	AccountCreating    = "creating"
	AccountActive      = "active"
	AccountSuspended   = "suspended"
	AccountTerminating = "terminating"
	AccountError       = "error"
)

// UID range for hosting accounts (system users stay below 10000).
const (
	FirstAccountUID = 10000
	LastAccountUID  = 59999
)

// Account is a hosting account.
type Account struct {
	ID            string
	Username      string
	UID           int
	OwnerID       string
	PackageID     string
	PrimaryDomain string
	Email         string
	Status        string
	StatusDetail  string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

const accountColumns = `id, username, uid, COALESCE(owner_id, ''), package_id, primary_domain, email,
	status, status_detail, created_at, updated_at`

func scanAccount(s scanner) (*Account, error) {
	var (
		a                Account
		created, updated string
	)
	err := s.Scan(&a.ID, &a.Username, &a.UID, &a.OwnerID, &a.PackageID, &a.PrimaryDomain, &a.Email,
		&a.Status, &a.StatusDetail, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [2]error
	a.CreatedAt, errs[0] = ParseTime(created)
	a.UpdatedAt, errs[1] = ParseTime(updated)
	return &a, errors.Join(errs[:]...)
}

// AccountFilter narrows ListAccounts.
type AccountFilter struct {
	OwnerID string // "" = admin-owned accounts only; "*" = all owners
	Search  string // matches username or primary domain
	Status  string
}

// ListAccounts returns accounts, newest first.
func (db *DB) ListAccounts(ctx context.Context, f AccountFilter) ([]Account, error) {
	q := `SELECT ` + accountColumns + ` FROM accounts WHERE 1 = 1`
	var args []any
	if f.OwnerID != "*" {
		q += ` AND COALESCE(owner_id, '') = ?`
		args = append(args, f.OwnerID)
	}
	if s := strings.TrimSpace(f.Search); s != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(s)) + "%"
		q += ` AND (username LIKE ? ESCAPE '\' OR primary_domain LIKE ? ESCAPE '\')`
		args = append(args, like, like)
	}
	if f.Status != "" {
		q += ` AND status = ?`
		args = append(args, f.Status)
	}
	rows, err := db.R.QueryContext(ctx, q+` ORDER BY created_at DESC, id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// AccountByID returns one account.
func (db *DB) AccountByID(ctx context.Context, id string) (*Account, error) {
	return scanAccount(db.R.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM accounts WHERE id = ?`, id))
}

// NextAccountUID returns the lowest free UID above the highest one in use.
// Call it inside the transaction that inserts the account.
func NextAccountUID(ctx context.Context, q querier) (int, error) {
	var maxUID sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT MAX(uid) FROM accounts`).Scan(&maxUID); err != nil {
		return 0, err
	}
	next := FirstAccountUID
	if maxUID.Valid {
		next = int(maxUID.Int64) + 1
	}
	if next > LastAccountUID {
		return 0, errors.New("store: no account UIDs left")
	}
	return next, nil
}

// InsertAccount adds a new account. ErrConflict means the username or primary domain is taken.
func InsertAccount(ctx context.Context, q querier, a *Account) error {
	now := time.Now().UTC()
	a.CreatedAt, a.UpdatedAt = now, now
	_, err := q.ExecContext(ctx, `INSERT INTO accounts (id, username, uid, owner_id, package_id, primary_domain,
		email, status, status_detail, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Username, a.UID, nullIfEmpty(a.OwnerID), a.PackageID, a.PrimaryDomain, a.Email,
		a.Status, a.StatusDetail, FormatTime(now), FormatTime(now))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// UpdateAccount saves package, email, status and detail.
func UpdateAccount(ctx context.Context, q querier, a *Account) error {
	a.UpdatedAt = time.Now().UTC()
	return execOne(ctx, q, `UPDATE accounts SET package_id = ?, email = ?, status = ?, status_detail = ?,
		updated_at = ? WHERE id = ?`, a.PackageID, a.Email, a.Status, a.StatusDetail, FormatTime(a.UpdatedAt), a.ID)
}

// SetAccountStatus changes only the status fields.
func (db *DB) SetAccountStatus(ctx context.Context, id, status, detail string) error {
	return execOne(ctx, db.W, `UPDATE accounts SET status = ?, status_detail = ?, updated_at = ? WHERE id = ?`,
		status, detail, FormatTime(time.Now()), id)
}

// DeleteAccount removes the account row and its logins.
func DeleteAccount(ctx context.Context, q querier, id string) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM logins WHERE account_id = ?`, id); err != nil {
		return err
	}
	return execOne(ctx, q, `DELETE FROM accounts WHERE id = ?`, id)
}

// AccountLogin returns the account's own panel login (role user).
func (db *DB) AccountLogin(ctx context.Context, accountID string) (*Login, error) {
	return scanLogin(db.R.QueryRowContext(ctx, `SELECT `+loginColumns+` FROM logins
		WHERE account_id = ? AND role = 'user'`, accountID))
}

// SetLoginStatus sets a login's status (active, suspended, locked).
func SetLoginStatus(ctx context.Context, q querier, id, status string) error {
	return execOne(ctx, q, `UPDATE logins SET status = ?, updated_at = ? WHERE id = ?`, status, FormatTime(time.Now()), id)
}

// UsernameTaken reports whether a login or an account already uses name.
func UsernameTaken(ctx context.Context, q querier, name string) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM logins WHERE username = ?) +
		(SELECT COUNT(*) FROM accounts WHERE username = ?)`, name, name).Scan(&n)
	return n > 0, err
}

// PackageInUse reports how many accounts use a package.
func PackageInUse(ctx context.Context, q querier, packageID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts WHERE package_id = ?`, packageID).Scan(&n)
	return n, err
}
