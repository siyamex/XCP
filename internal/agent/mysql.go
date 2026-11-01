package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: MariaDB's mysql_native_password format, not our choice of hash
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/validate"
)

// MySQL manages the databases and users of accounts in MariaDB (ADR-0006).
// It connects to the server's socket as MariaDB's root, which lets the
// agent in through unix_socket authentication because it runs as root.
type MySQL struct {
	Server      string // /usr/sbin/mariadbd; missing means MariaDB is not installed
	Socket      string // /run/mysqld/mysqld.sock
	TicketDir   string // phpMyAdmin sign-on tickets; missing means phpMyAdmin is not installed
	TicketUser  string // the user phpMyAdmin runs as, who reads and deletes tickets
	VersionFile string // the installed phpMyAdmin version
	Now         func() time.Time
	mu          sync.Mutex
	db          *sql.DB
}

// Paths of the Ubuntu setup made by xcp-install.
const (
	MariaDBServer  = "/usr/sbin/mariadbd"
	MySQLSocket    = "/run/mysqld/mysqld.sock"
	PMATicketDir   = "/var/lib/xcp-phpmyadmin/tickets"
	PMAUser        = "xcp-pma"
	PMAVersionFile = "/usr/share/xcp/phpmyadmin/.xcp-version"
)

// Limits of names and sign-on.
const (
	MaxDatabaseName = 64 // MariaDB's limit
	MaxDBUserName   = 32 // MySQL's limit, which some tools keep
	SignonTTL       = 4 * time.Hour
	ticketTTL       = 2 * time.Minute
	ssoPrefix       = "xcp_sso_"
)

// MySQLAccount is everything of one account in MariaDB.
type MySQLAccount struct {
	Username  string
	Databases []string // full names: <username>_<name>
	Users     []MySQLUser
	Locked    bool // the account is suspended
}

// MySQLUser is a database user of an account.
type MySQLUser struct {
	Name         string
	PasswordHash string // mysql_native_password: "*" and 40 hex digits
	Grants       []MySQLGrant
}

// MySQLGrant gives a user privileges on one of the account's databases.
type MySQLGrant struct {
	Database   string
	Privileges []string // from MySQLPrivileges, or just PrivilegeAll
}

// PrivilegeAll stands for every privilege in MySQLPrivileges.
const PrivilegeAll = "ALL"

// privColumns maps the privileges an account may grant to their columns in
// mysql.db, in the order the UI lists them.
var privColumns = []struct{ col, priv string }{
	{"Select_priv", "SELECT"},
	{"Insert_priv", "INSERT"},
	{"Update_priv", "UPDATE"},
	{"Delete_priv", "DELETE"},
	{"Create_priv", "CREATE"},
	{"Drop_priv", "DROP"},
	{"Alter_priv", "ALTER"},
	{"Index_priv", "INDEX"},
	{"References_priv", "REFERENCES"},
	{"Create_tmp_table_priv", "CREATE TEMPORARY TABLES"},
	{"Lock_tables_priv", "LOCK TABLES"},
	{"Create_view_priv", "CREATE VIEW"},
	{"Show_view_priv", "SHOW VIEW"},
	{"Create_routine_priv", "CREATE ROUTINE"},
	{"Alter_routine_priv", "ALTER ROUTINE"},
	{"Execute_priv", "EXECUTE"},
	{"Event_priv", "EVENT"},
	{"Trigger_priv", "TRIGGER"},
	{"Delete_history_priv", "DELETE HISTORY"},
}

// grantOption is never given, but taken away if someone gave it.
const grantOption = "GRANT OPTION"

// MySQLPrivileges returns the privileges an account may grant on its databases.
func MySQLPrivileges() []string {
	out := make([]string, len(privColumns))
	for i, c := range privColumns {
		out[i] = c.priv
	}
	return out
}

var (
	mysqlNameRe  = regexp.MustCompile(`^[a-z0-9_]+$`)
	nativeHashRe = regexp.MustCompile(`^\*[0-9A-F]{40}$`)
)

// CheckMySQLName checks that name is a database (max = MaxDatabaseName) or
// user (MaxDBUserName) name of the account username: "<username>_<rest>".
func CheckMySQLName(username, name string, maxLen int) error {
	if validate.Username(username) != nil {
		return invalid("%q is not an account name", username)
	}
	rest, ok := strings.CutPrefix(name, username+"_")
	if !ok || rest == "" || len(name) > maxLen || !mysqlNameRe.MatchString(name) {
		return invalid("%q is not a name of account %s: <username>_ and a-z, 0-9 or _, at most %d characters", name, username, maxLen)
	}
	return nil
}

// NativePasswordHash returns MariaDB's mysql_native_password hash of password.
func NativePasswordHash(password string) string {
	a := sha1.Sum([]byte(password)) //nolint:gosec // G401: see the import
	b := sha1.Sum(a[:])             //nolint:gosec // G401: see the import
	return "*" + strings.ToUpper(hex.EncodeToString(b[:]))
}

// CheckNativeHash checks a mysql_native_password hash: "*" and 40 hex digits.
func CheckNativeHash(h string) error {
	if !nativeHashRe.MatchString(h) {
		return invalid("the password hash is not a mysql_native_password hash")
	}
	return nil
}

// CheckMySQLAccount validates an account request. The fake agent uses it too.
func CheckMySQLAccount(a MySQLAccount) error {
	dbs := map[string]bool{}
	for _, d := range a.Databases {
		if err := CheckMySQLName(a.Username, d, MaxDatabaseName); err != nil {
			return err
		}
		dbs[d] = true
	}
	seen := map[string]bool{}
	for _, u := range a.Users {
		if err := CheckMySQLName(a.Username, u.Name, MaxDBUserName); err != nil {
			return err
		}
		if seen[u.Name] {
			return invalid("user %s is listed twice", u.Name)
		}
		seen[u.Name] = true
		if err := CheckNativeHash(u.PasswordHash); err != nil {
			return fmt.Errorf("user %s: %w", u.Name, err)
		}
		granted := map[string]bool{}
		for _, g := range u.Grants {
			if !dbs[g.Database] {
				return invalid("user %s: %s is not one of the account's databases", u.Name, g.Database)
			}
			if granted[g.Database] {
				return invalid("user %s: %s is granted twice", u.Name, g.Database)
			}
			granted[g.Database] = true
			if _, err := privSet(g.Privileges); err != nil {
				return invalid("user %s on %s: %v", u.Name, g.Database, err)
			}
		}
	}
	return nil
}

// privSet turns a privilege list into a set, expanding PrivilegeAll.
func privSet(privs []string) (map[string]bool, error) {
	if len(privs) == 0 {
		return nil, errors.New("no privileges")
	}
	all := MySQLPrivileges()
	set := map[string]bool{}
	for _, p := range privs {
		switch {
		case p == PrivilegeAll && len(privs) == 1:
			for _, a := range all {
				set[a] = true
			}
		case slices.Contains(all, p):
			set[p] = true
		default:
			return nil, fmt.Errorf("unknown privilege %q", p)
		}
	}
	return set, nil
}

// quote makes a string literal.
func quote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, "'", `\'`).Replace(s) + "'"
}

// ident quotes an identifier.
func ident(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

// grantPattern is a database name as GRANT and mysql.db read it: there _
// and % are wildcards, so "alice_shop" would also match "alice5shop".
func grantPattern(db string) string {
	return strings.NewReplacer(`\`, `\\`, "_", `\_`, "%", `\%`).Replace(db)
}

// likePrefix matches names that start with prefix, in LIKE.
func likePrefix(prefix string) string { return grantPattern(prefix) + "%" }

func userAt(name, host string) string { return quote(name) + "@" + quote(host) }

// grantChanges returns the statements that turn a user's database
// privileges from have into want (both keyed by grant pattern). It only
// adds and removes what differs, so the user never loses a privilege it
// keeps, not even for a moment.
func grantChanges(user string, have, want map[string]map[string]bool) []string {
	order := append(MySQLPrivileges(), grantOption)
	list := func(set map[string]bool, not map[string]bool) string {
		var out []string
		for _, p := range order {
			if set[p] && !not[p] {
				out = append(out, p)
			}
		}
		return strings.Join(out, ", ")
	}
	var stmts []string
	for _, db := range sortedKeys(have) {
		if l := list(have[db], want[db]); l != "" {
			stmts = append(stmts, "REVOKE "+l+" ON "+ident(db)+".* FROM "+userAt(user, "localhost"))
		}
	}
	for _, db := range sortedKeys(want) {
		if l := list(want[db], have[db]); l != "" {
			stmts = append(stmts, "GRANT "+l+" ON "+ident(db)+".* TO "+userAt(user, "localhost"))
		}
	}
	return stmts
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (m *MySQL) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// conn returns a connection as MariaDB's root. Callers hold m.mu.
func (m *MySQL) conn(ctx context.Context) (*sql.Conn, error) {
	if _, err := os.Stat(m.Server); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("MariaDB is not installed: %w", ErrNotInstalled)
	}
	if m.db == nil {
		cfg := mysql.NewConfig()
		cfg.User, cfg.Net, cfg.Addr = "root", "unix", m.Socket
		cfg.InterpolateParams = true
		cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Minute, 10*time.Minute
		connector, err := mysql.NewConnector(cfg)
		if err != nil {
			return nil, err
		}
		m.db = sql.OpenDB(connector)
		m.db.SetMaxOpenConns(1)
		m.db.SetConnMaxIdleTime(time.Minute)
	}
	return m.db.Conn(ctx)
}

// mysqlUser is a user as MariaDB has it.
type mysqlUser struct {
	hosts  []string
	local  bool // has 'localhost', the host XCP manages
	plugin string
	auth   string
	locked bool
}

// usersLike returns the users whose names start with prefix.
func usersLike(ctx context.Context, c *sql.Conn, prefix string) (map[string]*mysqlUser, error) {
	rows, err := c.QueryContext(ctx, `SELECT User, Host,
		COALESCE(JSON_VALUE(Priv, '$.plugin'), ''), COALESCE(JSON_VALUE(Priv, '$.authentication_string'), ''),
		COALESCE(JSON_VALUE(Priv, '$.account_locked'), 'false')
		FROM mysql.global_priv WHERE User LIKE ?`, likePrefix(prefix))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := map[string]*mysqlUser{}
	for rows.Next() {
		var name, host, plugin, auth, locked string
		if err := rows.Scan(&name, &host, &plugin, &auth, &locked); err != nil {
			return nil, err
		}
		u := users[name]
		if u == nil {
			u = &mysqlUser{}
			users[name] = u
		}
		u.hosts = append(u.hosts, host)
		if host == "localhost" {
			// JSON_VALUE gives a JSON true as "1".
			u.local, u.plugin, u.auth, u.locked = true, plugin, auth, locked == "1" || locked == "true"
		}
	}
	return users, rows.Err()
}

// databasesLike returns the databases whose names start with prefix, with their sizes.
func databasesLike(ctx context.Context, c *sql.Conn, prefix string) (map[string]int64, error) {
	rows, err := c.QueryContext(ctx, `SELECT s.SCHEMA_NAME, COALESCE(SUM(t.DATA_LENGTH + t.INDEX_LENGTH), 0)
		FROM information_schema.SCHEMATA s LEFT JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = s.SCHEMA_NAME
		WHERE s.SCHEMA_NAME LIKE ? GROUP BY s.SCHEMA_NAME`, likePrefix(prefix))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dbs := map[string]int64{}
	for rows.Next() {
		var name string
		var size int64
		if err := rows.Scan(&name, &size); err != nil {
			return nil, err
		}
		dbs[name] = size
	}
	return dbs, rows.Err()
}

// grantsOf returns a user's database privileges, keyed by grant pattern.
func grantsOf(ctx context.Context, c *sql.Conn, name string) (map[string]map[string]bool, error) {
	cols := make([]string, 0, len(privColumns)+2)
	cols = append(cols, "Db")
	for _, p := range privColumns {
		cols = append(cols, p.col)
	}
	cols = append(cols, "Grant_priv")
	rows, err := c.QueryContext(ctx, "SELECT "+strings.Join(cols, ", ")+ //nolint:gosec // G202: column names from privColumns
		" FROM mysql.db WHERE Host = 'localhost' AND User = ?", name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]bool{}
	for rows.Next() {
		vals := make([]string, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		set := map[string]bool{}
		for i, p := range privColumns {
			if vals[i+1] == "Y" {
				set[p.priv] = true
			}
		}
		if vals[len(vals)-1] == "Y" {
			set[grantOption] = true
		}
		out[vals[0]] = set
	}
	return out, rows.Err()
}

func exec(ctx context.Context, c *sql.Conn, stmts ...string) error {
	for _, s := range stmts {
		if _, err := c.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("%s: %w", strings.SplitN(s, " IDENTIFIED", 2)[0], err)
		}
	}
	return nil
}

// dropUsers drops every user (on every host) whose name starts with prefix
// and for which keep returns false.
func dropUsers(ctx context.Context, c *sql.Conn, prefix string, keep func(string) bool) (int, error) {
	users, err := usersLike(ctx, c, prefix)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range sortedKeys(users) {
		if keep(name) {
			continue
		}
		for _, h := range users[name].hosts {
			if err := exec(ctx, c, "DROP USER IF EXISTS "+userAt(name, h)); err != nil {
				return n, err
			}
		}
		n++
	}
	return n, nil
}

// ApplyAccount makes MariaDB hold the account's users, passwords, grants
// and lock state exactly as given, and creates missing databases. It never
// drops a database. It reports whether anything changed.
func (m *MySQL) ApplyAccount(ctx context.Context, a MySQLAccount) (bool, error) {
	if err := CheckMySQLAccount(a); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return false, err
	}
	defer c.Close()
	prefix := a.Username + "_"
	have, err := databasesLike(ctx, c, prefix)
	if err != nil {
		return false, err
	}
	changed := false
	for _, d := range a.Databases {
		if _, ok := have[d]; !ok {
			if err := exec(ctx, c, "CREATE DATABASE IF NOT EXISTS "+ident(d)+" CHARACTER SET utf8mb4"); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	want := map[string]bool{}
	for _, u := range a.Users {
		want[u.Name] = true
	}
	n, err := dropUsers(ctx, c, prefix, func(name string) bool { return want[name] })
	if err != nil {
		return changed, err
	}
	changed = changed || n > 0
	users, err := usersLike(ctx, c, prefix)
	if err != nil {
		return changed, err
	}
	lock := " ACCOUNT UNLOCK"
	if a.Locked {
		lock = " ACCOUNT LOCK"
	}
	for _, u := range a.Users {
		auth := " IDENTIFIED BY PASSWORD " + quote(u.PasswordHash)
		switch st := users[u.Name]; {
		case st == nil || !st.local:
			create := "CREATE USER " + userAt(u.Name, "localhost") + auth
			if a.Locked {
				create += lock
			}
			if err := exec(ctx, c, create); err != nil {
				return changed, err
			}
			changed = true
		case st.plugin != "mysql_native_password" || st.auth != u.PasswordHash || st.locked != a.Locked:
			if err := exec(ctx, c, "ALTER USER "+userAt(u.Name, "localhost")+auth+lock); err != nil {
				return changed, err
			}
			changed = true
		}
		hasGrants, err := grantsOf(ctx, c, u.Name)
		if err != nil {
			return changed, err
		}
		wantGrants := map[string]map[string]bool{}
		for _, g := range u.Grants {
			wantGrants[grantPattern(g.Database)], _ = privSet(g.Privileges) // checked above
		}
		stmts := grantChanges(u.Name, hasGrants, wantGrants)
		if err := exec(ctx, c, stmts...); err != nil {
			return changed, err
		}
		changed = changed || len(stmts) > 0
	}
	if a.Locked {
		// A suspended account signs in nowhere, phpMyAdmin included.
		n, err := dropUsers(ctx, c, ssoPrefix+prefix, func(string) bool { return false })
		if err != nil {
			return changed, err
		}
		changed = changed || n > 0
	}
	return changed, nil
}

// DatabaseSizes returns the account's databases in MariaDB with their size
// in bytes (data and indexes).
func (m *MySQL) DatabaseSizes(ctx context.Context, username string) (map[string]int64, error) {
	if validate.Username(username) != nil {
		return nil, invalid("%q is not an account name", username)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return databasesLike(ctx, c, username+"_")
}

// DropDatabase drops one of the account's databases with all its data. It
// reports whether it existed. Grants on it go with the next ApplyAccount.
func (m *MySQL) DropDatabase(ctx context.Context, username, name string) (bool, error) {
	if err := CheckMySQLName(username, name, MaxDatabaseName); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return false, err
	}
	defer c.Close()
	have, err := databasesLike(ctx, c, name)
	if err != nil {
		return false, err
	}
	if _, ok := have[name]; !ok {
		return false, nil
	}
	return true, exec(ctx, c, "DROP DATABASE IF EXISTS "+ident(name))
}

var charsetRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// RenameDatabase moves all tables of one of the account's databases to a
// new database and drops the old one. Views, triggers, routines and events
// cannot move with RENAME TABLE, so a database with any of them is refused.
func (m *MySQL) RenameDatabase(ctx context.Context, username, from, to string) error {
	if err := CheckMySQLName(username, from, MaxDatabaseName); err != nil {
		return err
	}
	if err := CheckMySQLName(username, to, MaxDatabaseName); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	var charset, collation string
	err = c.QueryRowContext(ctx, `SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME
		FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?`, from).Scan(&charset, &collation)
	if errors.Is(err, sql.ErrNoRows) {
		return invalid("database %s does not exist", from)
	}
	if err != nil {
		return err
	}
	if !charsetRe.MatchString(charset) || !charsetRe.MatchString(collation) {
		return fmt.Errorf("database %s has an unexpected character set %q/%q", from, charset, collation)
	}
	var exists int
	if err := c.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?`, to).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return invalid("database %s exists already", to)
	}
	var objects int
	if err := c.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM information_schema.VIEWS WHERE TABLE_SCHEMA = ?) +
		(SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ?) +
		(SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ?) +
		(SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = ?)`, from, from, from, from).Scan(&objects); err != nil {
		return err
	}
	if objects > 0 {
		return invalid("%s has views, triggers, stored routines or events, which cannot be renamed with it; "+
			"export it, import it under the new name and remove the old one instead", from)
	}
	rows, err := c.QueryContext(ctx, `SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME`, from)
	if err != nil {
		return err
	}
	var pairs []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		pairs = append(pairs, ident(from)+"."+ident(t)+" TO "+ident(to)+"."+ident(t))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := exec(ctx, c, "CREATE DATABASE "+ident(to)+" CHARACTER SET "+charset+" COLLATE "+collation); err != nil {
		return err
	}
	if len(pairs) > 0 {
		// One statement: MariaDB moves all tables or none.
		if err := exec(ctx, c, "RENAME TABLE "+strings.Join(pairs, ", ")); err != nil {
			_ = exec(ctx, c, "DROP DATABASE "+ident(to))
			return err
		}
	}
	return exec(ctx, c, "DROP DATABASE "+ident(from))
}

// RemoveAccount drops all databases and users of an account, sign-on users included.
func (m *MySQL) RemoveAccount(ctx context.Context, username string) (dbs, users int, err error) {
	if validate.Username(username) != nil {
		return 0, 0, invalid("%q is not an account name", username)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer c.Close()
	prefix := username + "_"
	have, err := databasesLike(ctx, c, prefix)
	if err != nil {
		return 0, 0, err
	}
	for _, d := range sortedKeys(have) {
		if err := exec(ctx, c, "DROP DATABASE IF EXISTS "+ident(d)); err != nil {
			return dbs, 0, err
		}
		dbs++
	}
	none := func(string) bool { return false }
	if users, err = dropUsers(ctx, c, prefix, none); err != nil {
		return dbs, users, err
	}
	n, err := dropUsers(ctx, c, ssoPrefix+prefix, none)
	return dbs, users + n, err
}

// SetRootPassword lets root in with this password too (mysql_native_password
// hash), next to unix_socket for root on the server, which the agent uses.
func (m *MySQL) SetRootPassword(ctx context.Context, hash string) error {
	if err := CheckNativeHash(hash); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	return exec(ctx, c, "ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket OR mysql_native_password USING "+quote(hash))
}

// MySQLStatus describes the database server.
type MySQLStatus struct {
	Version    string // MariaDB's
	PHPMyAdmin string // installed phpMyAdmin version, "" if none
}

// Status reports MariaDB's version and the installed phpMyAdmin.
func (m *MySQL) Status(ctx context.Context) (MySQLStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return MySQLStatus{}, err
	}
	defer c.Close()
	var st MySQLStatus
	if err := c.QueryRowContext(ctx, "SELECT VERSION()").Scan(&st.Version); err != nil {
		return st, err
	}
	if b, err := os.ReadFile(m.VersionFile); err == nil && len(b) < 100 {
		st.PHPMyAdmin = strings.TrimSpace(string(b))
	}
	return st, nil
}

// signonName is the name of a sign-on user: the account, when it expires
// (Unix time in base 36) and a random part. The expiry in the name lets
// ExpireSignons work without any stored state.
func signonName(username string, expires time.Time, random string) string {
	return ssoPrefix + username + "_" + strconv.FormatInt(expires.Unix(), 36) + "_" + random
}

// signonExpiry reads the expiry from a sign-on user's name; ok is false for
// a name in the sign-on namespace that XCP did not make.
func signonExpiry(name string) (time.Time, bool) {
	parts := strings.Split(strings.TrimPrefix(name, ssoPrefix), "_")
	if !strings.HasPrefix(name, ssoPrefix) || len(parts) != 3 {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(parts[1], 36, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

const lowerAlnum = "abcdefghijklmnopqrstuvwxyz0123456789"

// randomString returns n random characters from alphabet.
func randomString(n int, alphabet string) string {
	limit := 256 - 256%len(alphabet) // 256 itself when len divides it
	out := make([]byte, 0, n)
	buf := make([]byte, 2*n)
	for len(out) < n {
		_, _ = rand.Read(buf) // never fails (crypto/rand)
		for _, b := range buf {
			if int(b) < limit && len(out) < n {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out)
}

// signonTicket is what phpMyAdmin's xcp-signon.php reads.
type signonTicket struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Expires  int64  `json:"expires"`
}

var ticketRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Signon creates a temporary user with all privileges on the given
// databases of the account, valid for SignonTTL, and a one-time ticket
// for phpMyAdmin to sign in as it. It returns the ticket's ID.
func (m *MySQL) Signon(ctx context.Context, username string, databases []string) (string, error) {
	if validate.Username(username) != nil {
		return "", invalid("%q is not an account name", username)
	}
	for _, d := range databases {
		if err := CheckMySQLName(username, d, MaxDatabaseName); err != nil {
			return "", err
		}
	}
	if fi, err := os.Stat(m.TicketDir); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("phpMyAdmin is not installed: %w", ErrNotInstalled)
	}
	u, err := user.Lookup(m.TicketUser)
	if err != nil {
		return "", fmt.Errorf("phpMyAdmin's user: %w", err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := m.expireSignons(ctx, c); err != nil {
		return "", err
	}
	now := m.now()
	name := signonName(username, now.Add(SignonTTL), randomString(6, lowerAlnum))
	password := randomString(32, lowerAlnum+"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	stmts := []string{"CREATE USER " + userAt(name, "localhost") + " IDENTIFIED BY PASSWORD " + quote(NativePasswordHash(password))}
	for _, d := range databases {
		stmts = append(stmts, "GRANT ALL PRIVILEGES ON "+ident(grantPattern(d))+".* TO "+userAt(name, "localhost"))
	}
	if err := exec(ctx, c, stmts...); err != nil {
		_ = exec(ctx, c, "DROP USER IF EXISTS "+userAt(name, "localhost"))
		return "", err
	}
	id := randomString(64, "0123456789abcdef")
	// The ticket's job is to carry the password to phpMyAdmin, readable by it alone.
	data, _ := json.Marshal(signonTicket{User: name, Password: password, Expires: now.Add(ticketTTL).Unix()}) //nolint:gosec // G117: see above
	root, err := fsx.OpenRoot(m.TicketDir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := root.WriteFileAtomic(id, data, 0o600); err != nil {
		return "", err
	}
	if err := root.Chown(id, uid, gid); err != nil {
		_ = root.Remove(id)
		return "", err
	}
	return id, nil
}

// ExpireSignons drops the sign-on users that have expired and removes
// unused tickets. It reports how many users it dropped.
func (m *MySQL) ExpireSignons(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return m.expireSignons(ctx, c)
}

func (m *MySQL) expireSignons(ctx context.Context, c *sql.Conn) (int, error) {
	now := m.now()
	n, err := dropUsers(ctx, c, ssoPrefix, func(name string) bool {
		exp, ok := signonExpiry(name)
		return ok && exp.After(now)
	})
	if err != nil {
		return n, err
	}
	root, err := fsx.OpenRoot(m.TicketDir)
	if errors.Is(err, fs.ErrNotExist) {
		return n, nil
	}
	if err != nil {
		return n, err
	}
	defer root.Close()
	ents, err := root.ReadDir(".")
	if err != nil {
		return n, err
	}
	for _, e := range ents {
		info, err := e.Info()
		if err == nil && ticketRe.MatchString(e.Name()) && now.Sub(info.ModTime()) > ticketTTL {
			_ = root.Remove(e.Name())
		}
	}
	return n, nil
}
