package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// FTPAccount is an FTP login of an account: Name@<its domain>.
type FTPAccount struct {
	ID           string
	DomainID     string
	Name         string
	PasswordHash string
	HomeRel      string // "." is the home
	QuotaMB      int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

const ftpColumns = `id, domain_id, name, password_hash, home_rel, quota_mb, created_at, updated_at`

func scanFTPAccount(s scanner) (*FTPAccount, error) {
	var f FTPAccount
	var created, updated string
	err := s.Scan(&f.ID, &f.DomainID, &f.Name, &f.PasswordHash, &f.HomeRel, &f.QuotaMB, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [2]error
	f.CreatedAt, errs[0] = ParseTime(created)
	f.UpdatedAt, errs[1] = ParseTime(updated)
	return &f, errors.Join(errs[:]...)
}

// AccountFTPAccounts returns the FTP logins of an account's domains.
func AccountFTPAccounts(ctx context.Context, q querier, accountID string) ([]FTPAccount, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+prefixed("f.", ftpColumns)+` FROM ftp_accounts f JOIN domains d ON d.id = f.domain_id
		WHERE d.account_id = ? ORDER BY d.name, f.name`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FTPAccount
	for rows.Next() {
		f, err := scanFTPAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// FTPAccountByID returns an FTP login.
func (db *DB) FTPAccountByID(ctx context.Context, id string) (*FTPAccount, error) {
	return scanFTPAccount(db.R.QueryRowContext(ctx, `SELECT `+ftpColumns+` FROM ftp_accounts WHERE id = ?`, id))
}

// InsertFTPAccount adds an FTP login. ErrConflict means the login exists.
func InsertFTPAccount(ctx context.Context, q querier, f *FTPAccount) error {
	f.CreatedAt = time.Now().UTC()
	f.UpdatedAt = f.CreatedAt
	_, err := q.ExecContext(ctx, `INSERT INTO ftp_accounts (`+ftpColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.DomainID, f.Name, f.PasswordHash, f.HomeRel, f.QuotaMB, FormatTime(f.CreatedAt), FormatTime(f.UpdatedAt))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// UpdateFTPAccount stores an FTP login's password hash, folder and quota.
func UpdateFTPAccount(ctx context.Context, q querier, f *FTPAccount) error {
	f.UpdatedAt = time.Now().UTC()
	return execOne(ctx, q, `UPDATE ftp_accounts SET password_hash = ?, home_rel = ?, quota_mb = ?, updated_at = ? WHERE id = ?`,
		f.PasswordHash, f.HomeRel, f.QuotaMB, FormatTime(f.UpdatedAt), f.ID)
}

// DeleteFTPAccount removes an FTP login.
func DeleteFTPAccount(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM ftp_accounts WHERE id = ?`, id)
}

// CountFTPAccounts counts an account's FTP logins.
func CountFTPAccounts(ctx context.Context, q querier, accountID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM ftp_accounts f JOIN domains d ON d.id = f.domain_id WHERE d.account_id = ?`, accountID).Scan(&n)
	return n, err
}
