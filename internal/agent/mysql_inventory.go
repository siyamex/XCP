package agent

import (
	"context"
	"slices"
	"strings"
)

// MariaDB's own databases and users, and the prefixes of XCP's temporary
// users (sign-on, restore): never listed, never dropped as orphans.
var (
	systemDatabases = []string{"information_schema", "mysql", "performance_schema", "sys"}
	systemUsers     = []string{"", "root", "mariadb.sys", "mysql", "debian-sys-maint", "PUBLIC"}
	tempUserPrefix  = []string{ssoPrefix, "xcprestore"}
)

// MaxInventory bounds the databases and users one inventory returns.
const MaxInventory = 20000

// IsSystemDatabase reports whether a database is MariaDB's own.
func IsSystemDatabase(name string) bool {
	return slices.Contains(systemDatabases, strings.ToLower(name))
}

// IsSystemUser reports whether a user is MariaDB's own or one of XCP's
// temporary ones.
func IsSystemUser(name string) bool {
	if slices.Contains(systemUsers, name) {
		return true
	}
	for _, p := range tempUserPrefix {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// MySQLInventory is every database (with its size) and user of MariaDB but
// the system's.
type MySQLInventory struct {
	Databases map[string]int64
	Users     map[string][]string // name -> hosts
}

// Inventory lists MariaDB's databases and users for the admin's map
// (ADM-DB-02).
func (m *MySQL) Inventory(ctx context.Context) (MySQLInventory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return MySQLInventory{}, err
	}
	defer c.Close()
	dbs, err := databasesLike(ctx, c, "")
	if err != nil {
		return MySQLInventory{}, err
	}
	inv := MySQLInventory{Databases: map[string]int64{}, Users: map[string][]string{}}
	for n, size := range dbs {
		if !IsSystemDatabase(n) {
			inv.Databases[n] = size
		}
	}
	rows, err := c.QueryContext(ctx, `SELECT User, Host FROM mysql.global_priv ORDER BY User, Host LIMIT ?`, MaxInventory)
	if err != nil {
		return MySQLInventory{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var name, host string
		if err := rows.Scan(&name, &host); err != nil {
			return MySQLInventory{}, err
		}
		if !IsSystemUser(name) {
			inv.Users[name] = append(inv.Users[name], host)
		}
	}
	if len(inv.Databases) > MaxInventory {
		return MySQLInventory{}, invalid("MariaDB has more than %d databases", MaxInventory)
	}
	return inv, rows.Err()
}

// DropOrphan drops a database, or a user on every host, by name. The panel
// has checked that no account owns it; the agent refuses MariaDB's own and
// XCP's temporary ones. It reports whether there was anything.
func (m *MySQL) DropOrphan(ctx context.Context, database, user string) (bool, error) {
	switch {
	case (database == "") == (user == ""):
		return false, invalid("give one of a database and a user")
	case database != "" && (IsSystemDatabase(database) || len(database) > MaxDatabaseName || strings.ContainsAny(database, "`/\\.\x00")):
		return false, invalid("%q cannot be dropped here", database)
	case user != "" && (IsSystemUser(user) || len(user) > 80 || strings.ContainsRune(user, 0)):
		return false, invalid("%q cannot be dropped here", user)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return false, err
	}
	defer c.Close()
	if database != "" {
		var n int
		if err := c.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?`, database).Scan(&n); err != nil || n == 0 {
			return false, err
		}
		return true, exec(ctx, c, "DROP DATABASE IF EXISTS "+ident(database))
	}
	rows, err := c.QueryContext(ctx, `SELECT Host FROM mysql.global_priv WHERE User = ?`, user)
	if err != nil {
		return false, err
	}
	var hosts []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return false, err
		}
		hosts = append(hosts, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, h := range hosts {
		if err := exec(ctx, c, "DROP USER IF EXISTS "+userAt(user, h)); err != nil {
			return false, err
		}
	}
	return len(hosts) > 0, nil
}
