package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Database is a MariaDB database of an account; Name is its full name on
// the server ("<username>_<name>").
type Database struct {
	ID        string
	AccountID string
	Name      string
	CreatedAt time.Time
}

// DBUser is a MariaDB user of an account. PasswordEnc is MariaDB's own
// password hash, encrypted with the master key.
type DBUser struct {
	ID          string
	AccountID   string
	Name        string
	PasswordEnc []byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// DBGrant gives a user privileges on a database of the same account.
type DBGrant struct {
	UserID     string
	DatabaseID string
	Privileges []string
}

const databaseColumns = `id, account_id, name, created_at`

func scanDatabase(s scanner) (*Database, error) {
	var d Database
	var created string
	err := s.Scan(&d.ID, &d.AccountID, &d.Name, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.CreatedAt, err = ParseTime(created)
	return &d, err
}

// ListDatabases returns an account's databases by name.
func (db *DB) ListDatabases(ctx context.Context, accountID string) ([]Database, error) {
	rows, err := db.R.QueryContext(ctx, `SELECT `+databaseColumns+` FROM databases WHERE account_id = ? ORDER BY name`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Database
	for rows.Next() {
		d, err := scanDatabase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// DatabaseByID returns a database.
func (db *DB) DatabaseByID(ctx context.Context, id string) (*Database, error) {
	return scanDatabase(db.R.QueryRowContext(ctx, `SELECT `+databaseColumns+` FROM databases WHERE id = ?`, id))
}

// DatabaseByName returns a database by its full name.
func (db *DB) DatabaseByName(ctx context.Context, name string) (*Database, error) {
	return scanDatabase(db.R.QueryRowContext(ctx, `SELECT `+databaseColumns+` FROM databases WHERE engine = 'mysql' AND name = ?`, name))
}

// InsertDatabase adds a database. ErrConflict means the name is taken.
func InsertDatabase(ctx context.Context, q querier, d *Database) error {
	d.CreatedAt = time.Now().UTC()
	_, err := q.ExecContext(ctx, `INSERT INTO databases (id, account_id, name, created_at) VALUES (?, ?, ?, ?)`,
		d.ID, d.AccountID, d.Name, FormatTime(d.CreatedAt))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// RenameDatabase changes a database's name. ErrConflict means the name is taken.
func RenameDatabase(ctx context.Context, q querier, id, name string) error {
	err := execOne(ctx, q, `UPDATE databases SET name = ? WHERE id = ?`, name, id)
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// DeleteDatabase removes a database and the grants on it.
func DeleteDatabase(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM databases WHERE id = ?`, id)
}

// CountDatabases counts an account's databases.
func CountDatabases(ctx context.Context, q querier, accountID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM databases WHERE account_id = ?`, accountID).Scan(&n)
	return n, err
}

const dbUserColumns = `id, account_id, name, password_enc, created_at, updated_at`

func scanDBUser(s scanner) (*DBUser, error) {
	var u DBUser
	var created, updated string
	err := s.Scan(&u.ID, &u.AccountID, &u.Name, &u.PasswordEnc, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var errs [2]error
	u.CreatedAt, errs[0] = ParseTime(created)
	u.UpdatedAt, errs[1] = ParseTime(updated)
	return &u, errors.Join(errs[:]...)
}

// ListDBUsers returns an account's database users by name.
func ListDBUsers(ctx context.Context, q querier, accountID string) ([]DBUser, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+dbUserColumns+` FROM db_users WHERE account_id = ? ORDER BY name`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DBUser
	for rows.Next() {
		u, err := scanDBUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// DBUserByID returns a database user.
func (db *DB) DBUserByID(ctx context.Context, id string) (*DBUser, error) {
	return scanDBUser(db.R.QueryRowContext(ctx, `SELECT `+dbUserColumns+` FROM db_users WHERE id = ?`, id))
}

// InsertDBUser adds a database user. ErrConflict means the name is taken.
func InsertDBUser(ctx context.Context, q querier, u *DBUser) error {
	u.CreatedAt = time.Now().UTC()
	u.UpdatedAt = u.CreatedAt
	_, err := q.ExecContext(ctx, `INSERT INTO db_users (id, account_id, name, password_enc, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`, u.ID, u.AccountID, u.Name, u.PasswordEnc, FormatTime(u.CreatedAt), FormatTime(u.UpdatedAt))
	if uniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// SetDBUserPassword replaces a database user's encrypted password hash.
func SetDBUserPassword(ctx context.Context, q querier, id string, enc []byte) error {
	return execOne(ctx, q, `UPDATE db_users SET password_enc = ?, updated_at = ? WHERE id = ?`, enc, FormatTime(time.Now()), id)
}

// DeleteDBUser removes a database user and its grants.
func DeleteDBUser(ctx context.Context, q querier, id string) error {
	return execOne(ctx, q, `DELETE FROM db_users WHERE id = ?`, id)
}

// CountDBUsers counts an account's database users.
func CountDBUsers(ctx context.Context, q querier, accountID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM db_users WHERE account_id = ?`, accountID).Scan(&n)
	return n, err
}

// AccountGrants returns the grants of an account's database users.
func AccountGrants(ctx context.Context, q querier, accountID string) ([]DBGrant, error) {
	rows, err := q.QueryContext(ctx, `SELECT g.db_user_id, g.database_id, g.privileges FROM db_grants g
		JOIN db_users u ON u.id = g.db_user_id WHERE u.account_id = ? ORDER BY g.db_user_id, g.database_id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DBGrant
	for rows.Next() {
		var g DBGrant
		var privs string
		if err := rows.Scan(&g.UserID, &g.DatabaseID, &privs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(privs), &g.Privileges); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetGrant gives a user privileges on a database, replacing what it had there.
func SetGrant(ctx context.Context, q querier, g DBGrant) error {
	privs, err := json.Marshal(g.Privileges)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO db_grants (db_user_id, database_id, privileges) VALUES (?, ?, ?)
		ON CONFLICT (db_user_id, database_id) DO UPDATE SET privileges = excluded.privileges`, g.UserID, g.DatabaseID, string(privs))
	return err
}

// DeleteGrant takes a user's privileges on a database away.
func DeleteGrant(ctx context.Context, q querier, userID, databaseID string) error {
	return execOne(ctx, q, `DELETE FROM db_grants WHERE db_user_id = ? AND database_id = ?`, userID, databaseID)
}
