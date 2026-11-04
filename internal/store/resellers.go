package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// ResellerLimits are a reseller's caps; nil is unlimited.
type ResellerLimits struct {
	LoginID           string
	MaxAccounts       *int64
	DiskMB            *int64
	BandwidthMB       *int64
	OversellDisk      bool
	OversellBandwidth bool
	Privileges        []string // see Privileges in this package
}

// Reseller privileges (ADM-RSL-03).
const (
	PrivCreate      = "create"      // make accounts
	PrivModify      = "modify"      // change an account's package and contact details
	PrivSuspend     = "suspend"     // suspend and reactivate accounts
	PrivPassword    = "password"    // set a customer's password
	PrivTerminate   = "terminate"   // remove accounts for good
	PrivImpersonate = "impersonate" // sign in as a customer
)

// AllPrivileges lists every privilege, in display order.
var AllPrivileges = []string{PrivCreate, PrivModify, PrivSuspend, PrivPassword, PrivTerminate, PrivImpersonate}

func nullInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// ResellerLimitsOf returns a reseller's limits (all unlimited if never set).
func (db *DB) ResellerLimitsOf(ctx context.Context, loginID string) (ResellerLimits, error) {
	l := ResellerLimits{LoginID: loginID, Privileges: slices.Clone(AllPrivileges)}
	var privs string
	var maxAcc, disk, bw sql.NullInt64
	err := db.R.QueryRowContext(ctx, `SELECT max_accounts, disk_mb, bandwidth_mb, oversell_disk, oversell_bandwidth, privileges
		FROM reseller_limits WHERE login_id = ?`, loginID).Scan(&maxAcc, &disk, &bw, &l.OversellDisk, &l.OversellBandwidth, &privs)
	if errors.Is(err, sql.ErrNoRows) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	var list []string
	if json.Unmarshal([]byte(privs), &list) == nil {
		l.Privileges = list
	}
	for _, x := range []struct {
		n sql.NullInt64
		p **int64
	}{{maxAcc, &l.MaxAccounts}, {disk, &l.DiskMB}, {bw, &l.BandwidthMB}} {
		if x.n.Valid {
			v := x.n.Int64
			*x.p = &v
		}
	}
	return l, nil
}

// SetResellerLimits saves a reseller's limits.
func SetResellerLimits(ctx context.Context, q querier, l ResellerLimits, t time.Time) error {
	if l.Privileges == nil {
		l.Privileges = slices.Clone(AllPrivileges)
	}
	privs, err := json.Marshal(l.Privileges)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO reseller_limits (login_id, max_accounts, disk_mb, bandwidth_mb, oversell_disk, oversell_bandwidth, privileges, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (login_id) DO UPDATE SET max_accounts = excluded.max_accounts, disk_mb = excluded.disk_mb, bandwidth_mb = excluded.bandwidth_mb,
			oversell_disk = excluded.oversell_disk, oversell_bandwidth = excluded.oversell_bandwidth, privileges = excluded.privileges, updated_at = excluded.updated_at`,
		l.LoginID, nullInt(l.MaxAccounts), nullInt(l.DiskMB), nullInt(l.BandwidthMB), l.OversellDisk, l.OversellBandwidth, string(privs), FormatTime(t))
	return err
}

// ResellerRow is a reseller login for the admin's list.
type ResellerRow struct {
	ID, Username, Email, Status string
	CreatedAt                   time.Time
	Accounts                    int
}

// ListResellers returns the reseller logins with their number of accounts.
func (db *DB) ListResellers(ctx context.Context) ([]ResellerRow, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT l.id, l.username, l.email, l.status, l.created_at,
		(SELECT COUNT(*) FROM accounts a WHERE a.owner_id = l.id)
		FROM logins l WHERE l.role = 'reseller' ORDER BY l.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResellerRow
	for rows.Next() {
		var r ResellerRow
		var created string
		if err := rows.Scan(&r.ID, &r.Username, &r.Email, &r.Status, &created, &r.Accounts); err != nil {
			return nil, err
		}
		if r.CreatedAt, err = ParseTime(created); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// OwnedAccounts returns a reseller's accounts (removed ones are gone).
func (db *DB) OwnedAccounts(ctx context.Context, ownerID string) ([]Account, error) {
	return db.ListAccounts(ctx, AccountFilter{OwnerID: ownerID})
}
