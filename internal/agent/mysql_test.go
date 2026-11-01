package agent

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCheckMySQLName(t *testing.T) {
	for _, ok := range []string{"alice_shop", "alice_a", "alice_2024_backup", "alice_" + strings.Repeat("x", 58)} {
		if err := CheckMySQLName("alice", ok, MaxDatabaseName); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"alice_", "alice", "bob_shop", "alice-shop", "alice_Shop", "alice_shop;", "alice_`x", "alice_x y",
		"alice_" + strings.Repeat("x", 59), // 65 characters
		"alicebob_shop",
	} {
		if err := CheckMySQLName("alice", bad, MaxDatabaseName); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%q: want invalid, got %v", bad, err)
		}
	}
	if err := CheckMySQLName("alice", "alice_"+strings.Repeat("u", 27), MaxDBUserName); !errors.Is(err, ErrInvalidRequest) {
		t.Error("a 33-character user name passed")
	}
	if err := CheckMySQLName("Bad_x", "Bad_x_y", MaxDatabaseName); !errors.Is(err, ErrInvalidRequest) {
		t.Error("a bad account name passed")
	}
}

func TestNativePasswordHash(t *testing.T) {
	// SELECT PASSWORD('password') in MariaDB.
	if got := NativePasswordHash("password"); got != "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19" {
		t.Fatalf("got %s", got)
	}
}

func TestCheckMySQLAccount(t *testing.T) {
	hash := NativePasswordHash("x")
	good := MySQLAccount{
		Username: "alice", Databases: []string{"alice_shop", "alice_blog"},
		Users: []MySQLUser{{Name: "alice_app", PasswordHash: hash, Grants: []MySQLGrant{
			{Database: "alice_shop", Privileges: []string{PrivilegeAll}},
			{Database: "alice_blog", Privileges: []string{"SELECT", "INSERT"}},
		}}},
	}
	if err := CheckMySQLAccount(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*MySQLAccount){
		"foreign database":   func(a *MySQLAccount) { a.Databases = append(a.Databases, "bob_shop") },
		"foreign user":       func(a *MySQLAccount) { a.Users[0].Name = "bob_app" },
		"grant elsewhere":    func(a *MySQLAccount) { a.Users[0].Grants[0].Database = "alice_other" },
		"unknown privilege":  func(a *MySQLAccount) { a.Users[0].Grants[1].Privileges = []string{"SUPER"} },
		"ALL with others":    func(a *MySQLAccount) { a.Users[0].Grants[1].Privileges = []string{PrivilegeAll, "SELECT"} },
		"no privileges":      func(a *MySQLAccount) { a.Users[0].Grants[1].Privileges = nil },
		"plain password":     func(a *MySQLAccount) { a.Users[0].PasswordHash = "secret" },
		"user twice":         func(a *MySQLAccount) { a.Users = append(a.Users, a.Users[0]) },
		"database granted 2": func(a *MySQLAccount) { a.Users[0].Grants[1].Database = "alice_shop" },
	} {
		a := good
		a.Databases = slices.Clone(good.Databases)
		u := good.Users[0]
		u.Grants = slices.Clone(u.Grants)
		a.Users = []MySQLUser{u}
		mutate(&a)
		if err := CheckMySQLAccount(a); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: want invalid, got %v", name, err)
		}
	}
}

func TestQuoting(t *testing.T) {
	if got := grantPattern("alice_my_db"); got != `alice\_my\_db` {
		t.Errorf("grant pattern: %s", got)
	}
	if got := likePrefix("xcp_sso_alice_"); got != `xcp\_sso\_alice\_%` {
		t.Errorf("like prefix: %s", got)
	}
	if got := quote(`a'b\c`); got != `'a\'b\\c'` {
		t.Errorf("quote: %s", got)
	}
	if got := ident("a`b"); got != "`a``b`" {
		t.Errorf("ident: %s", got)
	}
}

func TestGrantChanges(t *testing.T) {
	all, _ := privSet([]string{PrivilegeAll})
	set := func(p ...string) map[string]bool {
		m := map[string]bool{}
		for _, x := range p {
			m[x] = true
		}
		return m
	}
	have := map[string]map[string]bool{
		`alice\_shop`: set("SELECT", "INSERT", "UPDATE"),
		`alice\_old`:  set("SELECT", grantOption),
		`alice\_same`: all,
	}
	want := map[string]map[string]bool{
		`alice\_shop`: set("SELECT", "DELETE"),
		`alice\_same`: all,
		`alice\_new`:  set("SELECT"),
	}
	got := grantChanges("alice_app", have, want)
	exp := []string{
		"REVOKE SELECT, GRANT OPTION ON `alice\\_old`.* FROM 'alice_app'@'localhost'",
		"REVOKE INSERT, UPDATE ON `alice\\_shop`.* FROM 'alice_app'@'localhost'",
		"GRANT SELECT ON `alice\\_new`.* TO 'alice_app'@'localhost'",
		"GRANT DELETE ON `alice\\_shop`.* TO 'alice_app'@'localhost'",
	}
	if !slices.Equal(got, exp) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(exp, "\n"))
	}
	if n := grantChanges("alice_app", want, want); len(n) != 0 {
		t.Fatalf("no change expected, got %v", n)
	}
}

func TestSignonNames(t *testing.T) {
	exp := time.Unix(1_800_000_000, 0)
	name := signonName("alice", exp, "ab12cd")
	if !strings.HasPrefix(name, "xcp_sso_alice_") || len(name) > 80 {
		t.Fatalf("name %s", name)
	}
	if got, ok := signonExpiry(name); !ok || !got.Equal(exp) {
		t.Fatalf("expiry of %s: %v %v", name, got, ok)
	}
	for _, bad := range []string{"xcp_sso_alice", "xcp_sso_alice_zz!_x", "alice_shop", "xcp_sso_a_b_c_d"} {
		if _, ok := signonExpiry(bad); ok {
			t.Errorf("%s parsed", bad)
		}
	}
	for _, alphabet := range []string{lowerAlnum, "0123456789abcdef"} { // 16 divides 256
		if s := randomString(40, alphabet); len(s) != 40 || strings.Trim(s, alphabet) != "" {
			t.Fatalf("random %q", s)
		}
	}
}
