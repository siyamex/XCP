package install

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // the PowerDNS zone database is created with XCP's own SQLite
)

// PowerDNS files (06-service-drivers.md §5).
const (
	PDNSConf     = "/etc/powerdns/pdns.d/xcp.conf"
	PDNSDatabase = "/var/lib/powerdns/xcp.sqlite3"
	PDNSKeyFile  = SecretsDir + "/pdns-api-key" //nolint:gosec // G101: a file path, not a credential
)

// pdnsConf is PowerDNS's configuration. It listens on this server's own
// addresses rather than on every address, because systemd-resolved holds
// 127.0.0.53:53; the API is reachable from localhost only.
func pdnsConf(key string, ips []string) string {
	addrs := append([]string{"127.0.0.1", "::1"}, ips...)
	return "# Managed by XCP (xcp-install); changes are overwritten.\n" +
		"# Zones are kept in the database and changed only through the API by xcp-agent.\n" +
		"launch=gsqlite3\n" +
		"gsqlite3-database=" + PDNSDatabase + "\n" +
		"gsqlite3-dnssec=yes\n" +
		"local-address=" + strings.Join(addrs, ", ") + "\n" +
		"local-address-nonexist-fail=no\n" +
		"api=yes\n" +
		"api-key=" + key + "\n" +
		"webserver=yes\n" +
		"webserver-address=127.0.0.1\n" +
		"webserver-port=8081\n" +
		"webserver-allow-from=127.0.0.1/32\n"
}

func (in *installer) dns(ctx context.Context) error {
	if in.o.NoDNS {
		in.logf("    skipped (--no-dns)")
		return nil
	}
	if in.o.DryRun {
		in.logf("    would install pdns-server and pdns-backend-sqlite3, write %s and create %s", PDNSConf, PDNSDatabase)
		return nil
	}
	installed, err := in.o.Sys.InstallDNSServer(ctx)
	if err != nil {
		return err
	}
	if installed {
		in.changed("installed pdns-server and pdns-backend-sqlite3")
	}
	uid, gid, err := in.o.Sys.LookupIDs("pdns")
	if err != nil {
		return err
	}
	in.pdnsGID = gid
	key, err := in.pdnsKey()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(in.path(filepath.ToSlash(filepath.Dir(PDNSConf))), 0o755); err != nil { //nolint:gosec // G301: like the rest of /etc
		return err
	}
	wrote, err := in.writeFile(PDNSConf, []byte(pdnsConf(key, in.o.IPs)), 0o640, rootPDNS, false)
	if err != nil {
		return err
	}
	created, err := in.pdnsDatabase(uid, gid)
	if err != nil {
		return err
	}
	if err := in.o.Sys.Systemctl(ctx, "enable", "--now", "pdns.service"); err != nil {
		return err
	}
	if installed || wrote || created {
		return in.o.Sys.Systemctl(ctx, "restart", "pdns.service")
	}
	return nil
}

// pdnsKey returns the PowerDNS API key, made once and then kept. Only root
// (xcp-agent) reads it.
func (in *installer) pdnsKey() (string, error) {
	if b, err := os.ReadFile(in.path(PDNSKeyFile)); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		_, err := in.writeFile(PDNSKeyFile, nil, 0o600, rootRoot, true) // fix mode/owner only
		return strings.TrimSpace(string(b)), err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	key := hex.EncodeToString(b)
	_, err := in.writeFile(PDNSKeyFile, []byte(key+"\n"), 0o600, rootRoot, false)
	return key, err
}

// pdnsDatabase creates PowerDNS's SQLite database from the schema that
// comes with it, owned by PowerDNS. An existing database is kept.
func (in *installer) pdnsDatabase(uid, gid int) (bool, error) {
	p := in.path(PDNSDatabase)
	if _, err := os.Stat(p); err == nil {
		return false, in.o.Sys.Chown(p, uid, gid)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	schema, err := in.o.Sys.PDNSSchema()
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // G301: owned by the package normally
		return false, err
	}
	tmp := p + ".new"
	_ = os.Remove(tmp)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(tmp))
	if err != nil {
		return false, err
	}
	_, err = db.Exec(string(schema))
	if cerr := db.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.Chmod(tmp, 0o600); err != nil { // PowerDNS owns it
		return false, err
	}
	if err := in.o.Sys.Chown(tmp, uid, gid); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, p); err != nil {
		return false, err
	}
	in.changed("file " + PDNSDatabase)
	return true, nil
}
