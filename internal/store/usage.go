package store

import (
	"context"
	"strings"
)

// Usage is one domain's bytes on one day.
type Usage struct {
	Domain string
	Day    string // 2006-01-02, UTC
	Web    int64
	Mail   int64
	FTP    int64
}

// LogOffset is where xcp-logd is in one log.
type LogOffset struct {
	Source string
	Inode  uint64
	Offset int64
	Cursor string
}

// DomainAccounts maps every domain name to its account.
func DomainAccounts(ctx context.Context, q querier) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT name, account_id FROM domains`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, account string
		if err := rows.Scan(&name, &account); err != nil {
			return nil, err
		}
		out[strings.ToLower(name)] = account
	}
	return out, rows.Err()
}

// AddUsage adds bytes to an account's domain on a day.
func AddUsage(ctx context.Context, q querier, accountID string, u Usage) error {
	_, err := q.ExecContext(ctx, `INSERT INTO usage_bandwidth (account_id, domain, day, bytes_web, bytes_mail, bytes_ftp)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (account_id, domain, day) DO UPDATE SET bytes_web = bytes_web + excluded.bytes_web,
			bytes_mail = bytes_mail + excluded.bytes_mail, bytes_ftp = bytes_ftp + excluded.bytes_ftp`,
		accountID, u.Domain, u.Day, u.Web, u.Mail, u.FTP)
	return err
}

// AccountUsage returns an account's usage on days from first to last (inclusive).
func AccountUsage(ctx context.Context, q querier, accountID, first, last string) ([]Usage, error) {
	rows, err := q.QueryContext(ctx, `SELECT domain, day, bytes_web, bytes_mail, bytes_ftp FROM usage_bandwidth
		WHERE account_id = ? AND day >= ? AND day <= ? ORDER BY day, domain`, accountID, first, last)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Usage
	for rows.Next() {
		var u Usage
		if err := rows.Scan(&u.Domain, &u.Day, &u.Web, &u.Mail, &u.FTP); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// LogOffsets returns where xcp-logd is in each log.
func LogOffsets(ctx context.Context, q querier) (map[string]LogOffset, error) {
	rows, err := q.QueryContext(ctx, `SELECT source, inode, offset, cursor FROM log_offsets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]LogOffset{}
	for rows.Next() {
		var o LogOffset
		var ino int64
		if err := rows.Scan(&o.Source, &ino, &o.Offset, &o.Cursor); err != nil {
			return nil, err
		}
		o.Inode = uint64(ino) //nolint:gosec // G115: stored from a uint64
		out[o.Source] = o
	}
	return out, rows.Err()
}

// SetLogOffset stores where xcp-logd is in one log.
func SetLogOffset(ctx context.Context, q querier, o LogOffset) error {
	_, err := q.ExecContext(ctx, `INSERT INTO log_offsets (source, inode, offset, cursor) VALUES (?, ?, ?, ?)
		ON CONFLICT (source) DO UPDATE SET inode = excluded.inode, offset = excluded.offset, cursor = excluded.cursor`,
		o.Source, int64(o.Inode), o.Offset, o.Cursor) //nolint:gosec // G115: inodes fit
	return err
}
