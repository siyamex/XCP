package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/siyamex/XCP/internal/agent"
)

// MariaDB and phpMyAdmin files (ADR-0006).
const (
	MariaDBConf  = "/etc/mysql/mariadb.conf.d/90-xcp.cnf"
	PMADir       = "/usr/share/xcp/phpmyadmin"
	PMAStateDir  = "/var/lib/xcp-phpmyadmin" // tickets/, sessions/, tmp/
	PMAConfigDir = "/etc/xcp/phpmyadmin"
	PMASocket    = "/run/php/xcp_phpmyadmin.sock"
	// The pool's name has an underscore, which account names never have, so
	// it cannot meet an account's pool (xcp-<username>.conf).
	pmaPool      = "xcp_phpmyadmin"
	pmaSecret    = SecretsDir + "/phpmyadmin-blowfish" //nolint:gosec // G101: a file path, not a credential
	pmaMaxPHP    = "8.3"                               // the newest PHP the release below supports
	pmaMaxBytes  = 64 << 20
	signonScript = "xcp-signon.php"
)

// phpMyAdmin is the release xcp-install installs, pinned by version and
// SHA-256 (07-security.md §10). Tests swap it for a small tarball.
var phpMyAdmin = release{
	Name:    "phpMyAdmin",
	Version: "5.2.3",
	URL:     "https://files.phpmyadmin.net/phpMyAdmin/5.2.3/phpMyAdmin-5.2.3-all-languages.tar.gz",
	SHA256:  "12ba1c425fa4071abbd4e7668c9ebdeac0b0755a467a6d6d5026122bb47c102b",
}

// pmaDropped are folders of the release that are not needed and must not
// be reachable: the setup wizard and the example scripts (one of them
// signs in with whatever credentials it is given).
var pmaDropped = []string{"setup", "examples", "test", "doc"}

const mariadbConf = `# Managed by XCP (xcp-install); changes are overwritten.
# Databases are for applications on this server; remote access comes later (USR-DB-05).
[mysqld]
bind-address = 127.0.0.1
`

// pmaConfig is phpMyAdmin's configuration: sign-on through the panel only.
func pmaConfig(secret string) string {
	return `<?php
// Managed by XCP (xcp-install); changes are overwritten. ADR-0006.
declare(strict_types=1);

$cfg['blowfish_secret'] = sodium_hex2bin('` + secret + `');
$cfg['TempDir'] = '` + PMAStateDir + `/tmp';
$cfg['VersionCheck'] = false;
$cfg['SendErrorReports'] = 'never';
$cfg['ShowCreateDb'] = false;    // databases are made in the panel
$cfg['ShowChgPassword'] = false; // sign-on users are temporary
$cfg['ShowServerInfo'] = false;
$cfg['ShowPhpInfo'] = false;
$cfg['ZeroConf'] = false;
$cfg['PmaNoRelation_DisableWarning'] = true;

$i = 1;
$cfg['Servers'][$i]['auth_type'] = 'signon';
$cfg['Servers'][$i]['SignonSession'] = 'XCPSignon';
$cfg['Servers'][$i]['SignonCookieParams'] = [
    'lifetime' => 0, 'path' => '/phpmyadmin/', 'domain' => '', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax',
];
$cfg['Servers'][$i]['SignonURL'] = '/phpmyadmin/` + signonScript + `';
$cfg['Servers'][$i]['LogoutURL'] = '/phpmyadmin/` + signonScript + `?signed_out=1';
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['socket'] = '` + agent.MySQLSocket + `';
$cfg['Servers'][$i]['AllowRoot'] = false;
$cfg['Servers'][$i]['AllowNoPassword'] = false;
`
}

// pmaSignon exchanges a one-time ticket from the agent for phpMyAdmin's
// sign-on session. Without a valid ticket it only points to the panel.
const pmaSignon = `<?php
// Managed by XCP (xcp-install); changes are overwritten. ADR-0006:
// exchanges a one-time ticket from the panel for a phpMyAdmin session.
declare(strict_types=1);

function xcp_page(int $code, string $message): void
{
    http_response_code($code);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    echo '<!doctype html><meta charset="utf-8"><title>phpMyAdmin</title><p>', htmlspecialchars($message), "</p>\n";
    exit;
}

header('Referrer-Policy: no-referrer');
$ticket = $_GET['ticket'] ?? '';
if (!is_string($ticket) || preg_match('/^[0-9a-f]{64}$/', $ticket) !== 1) {
    xcp_page(200, 'Open phpMyAdmin from your control panel.');
}
// Claim the ticket first, so it works once even if two requests race.
$path = '` + agent.PMATicketDir + `/' . $ticket;
$claimed = $path . '.used-' . bin2hex(random_bytes(8));
if (!@rename($path, $claimed)) {
    xcp_page(403, 'This sign-in link was used already or has expired. Open phpMyAdmin from your control panel again.');
}
$raw = @file_get_contents($claimed);
@unlink($claimed);
$t = is_string($raw) ? json_decode($raw, true) : null;
if (!is_array($t) || !is_string($t['user'] ?? null) || !is_string($t['password'] ?? null) || (int) ($t['expires'] ?? 0) < time()) {
    xcp_page(403, 'This sign-in link has expired. Open phpMyAdmin from your control panel again.');
}
session_set_cookie_params(['lifetime' => 0, 'path' => '/phpmyadmin/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
session_name('XCPSignon');
session_start();
session_regenerate_id(true);
$_SESSION['PMA_single_signon_user'] = $t['user'];
$_SESSION['PMA_single_signon_password'] = $t['password'];
$_SESSION['PMA_single_signon_HMAC_secret'] = bin2hex(random_bytes(16));
session_write_close();
header('Location: index.php');
`

// pmaPoolConf is phpMyAdmin's PHP-FPM pool, as its own system user.
func pmaPoolConf() string {
	return "; Managed by XCP (xcp-install); changes are overwritten. phpMyAdmin (ADR-0006).\n" +
		"[" + pmaPool + "]\n" +
		"user = " + agent.PMAUser + "\n" +
		"group = " + agent.PMAUser + "\n" +
		"listen = " + PMASocket + "\n" +
		"listen.owner = www-data\n" +
		"listen.group = www-data\n" +
		"listen.mode = 0660\n" +
		"pm = ondemand\n" +
		"pm.max_children = 8\n" +
		"pm.process_idle_timeout = 30s\n" +
		"pm.max_requests = 500\n" +
		"php_admin_value[open_basedir] = " + PMADir + "/:" + PMAStateDir + "/:" + PMAConfigDir + "/\n" +
		"php_admin_value[session.save_path] = " + PMAStateDir + "/sessions\n" +
		"php_admin_value[session.gc_probability] = 1\n" +
		"php_admin_value[session.gc_divisor] = 100\n" +
		"php_admin_value[upload_tmp_dir] = " + PMAStateDir + "/tmp\n" +
		"php_admin_value[sys_temp_dir] = " + PMAStateDir + "/tmp\n" +
		"php_admin_value[upload_max_filesize] = 64M\n" +
		"php_admin_value[post_max_size] = 64M\n" +
		"php_admin_value[memory_limit] = 256M\n" +
		"php_admin_value[max_execution_time] = 300\n" +
		"php_admin_flag[display_errors] = off\n"
}

// pmaPHP picks the PHP version for phpMyAdmin: the newest one it
// supports, or the newest installed if none is old enough.
func pmaPHP(versions []string) string {
	key := func(v string) [2]int {
		major, minor, _ := strings.Cut(v, ".")
		a, _ := strconv.Atoi(major)
		b, _ := strconv.Atoi(minor)
		return [2]int{a, b}
	}
	less := func(x, y [2]int) bool { return x[0] < y[0] || x[0] == y[0] && x[1] < y[1] }
	sorted := slices.Clone(versions)
	slices.SortFunc(sorted, func(x, y string) int {
		switch {
		case less(key(x), key(y)):
			return -1
		case less(key(y), key(x)):
			return 1
		}
		return 0
	})
	best := ""
	for _, v := range sorted {
		if !less(key(pmaMaxPHP), key(v)) {
			best = v
		}
	}
	if best == "" && len(sorted) > 0 {
		best = sorted[len(sorted)-1]
	}
	return best
}

func (in *installer) database(ctx context.Context) error {
	if in.o.NoDB {
		in.logf("    skipped (--no-db)")
		return nil
	}
	if in.o.DryRun {
		in.logf("    would install mariadb-server and PHP's MySQL extension, write %s and install phpMyAdmin %s in %s",
			MariaDBConf, phpMyAdmin.Version, PMADir)
		return nil
	}
	installed, err := in.o.Sys.InstallDatabaseServer(ctx)
	if err != nil {
		return err
	}
	if installed {
		in.changed("installed mariadb-server and PHP's MySQL extension")
	}
	if err := os.MkdirAll(in.path(path.Dir(MariaDBConf)), 0o755); err != nil { //nolint:gosec // G301: like the rest of /etc
		return err
	}
	wrote, err := in.writeFile(MariaDBConf, []byte(mariadbConf), 0o644, rootRoot, false)
	if err != nil {
		return err
	}
	if wrote {
		if err := in.o.Sys.Systemctl(ctx, "restart", "mariadb.service"); err != nil {
			return err
		}
	}
	if in.o.NoWeb {
		in.logf("    phpMyAdmin skipped: it needs the web server (--no-web)")
		return nil
	}
	return in.phpMyAdmin(ctx)
}

func (in *installer) phpMyAdmin(ctx context.Context) error {
	created, err := in.o.Sys.EnsureSystemUser(ctx, agent.PMAUser, PMAStateDir)
	if err != nil {
		return err
	}
	if created {
		in.changed("created system user " + agent.PMAUser)
	}
	if in.pmaUID, in.pmaGID, err = in.o.Sys.LookupIDs(agent.PMAUser); err != nil {
		return err
	}
	if err := in.makeDirs([]dirSpec{
		{"/usr/share/xcp", 0o755, rootRoot},
		{PMAStateDir, 0o750, rootPMA},
		{agent.PMATicketDir, 0o700, pmaPMA},
		{PMAStateDir + "/sessions", 0o700, pmaPMA},
		{PMAStateDir + "/tmp", 0o700, pmaPMA},
		{PMAConfigDir, 0o750, rootPMA},
	}); err != nil {
		return err
	}
	tree, err := in.pmaTree(ctx)
	if err != nil {
		return fmt.Errorf("phpMyAdmin %s: %w", phpMyAdmin.Version, err)
	}
	secret, err := in.secretHex(pmaSecret)
	if err != nil {
		return err
	}
	if _, err := in.writeFile(PMAConfigDir+"/config.inc.php", []byte(pmaConfig(secret)), 0o640, rootPMA, false); err != nil {
		return err
	}
	if _, err := in.writeFile(PMADir+"/config.inc.php", []byte("<?php\nrequire '"+PMAConfigDir+"/config.inc.php';\n"), 0o644, rootRoot, false); err != nil {
		return err
	}
	if _, err := in.writeFile(PMADir+"/"+signonScript, []byte(pmaSignon), 0o644, rootRoot, false); err != nil {
		return err
	}
	ver := pmaPHP(in.o.Sys.PHPFPMVersions())
	if ver == "" {
		return errors.New("no PHP-FPM installed for phpMyAdmin")
	}
	pool := "/etc/php/" + ver + "/fpm/pool.d/" + pmaPool + ".conf"
	if err := os.MkdirAll(in.path(path.Dir(pool)), 0o755); err != nil { //nolint:gosec // G301: like the rest of /etc
		return err
	}
	wrotePool, err := in.writeFile(pool, []byte(pmaPoolConf()), 0o644, rootRoot, false)
	if err != nil {
		return err
	}
	if wrotePool {
		if err := in.o.Sys.Systemctl(ctx, "reload-or-restart", "php"+ver+"-fpm.service"); err != nil {
			return err
		}
	}
	if tree || wrotePool {
		// Apache serves phpMyAdmin only once its files exist (<IfFile>).
		return in.o.Sys.Systemctl(ctx, "reload-or-restart", "apache2.service")
	}
	return nil
}

// secretHex returns a 32-byte secret as hex, made once and then kept (root only).
func (in *installer) secretHex(p string) (string, error) {
	if b, err := os.ReadFile(in.path(p)); err == nil && len(strings.TrimSpace(string(b))) == 64 {
		_, err := in.writeFile(p, nil, 0o600, rootRoot, true)
		return strings.TrimSpace(string(b)), err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := hex.EncodeToString(b)
	_, err := in.writeFile(p, []byte(s+"\n"), 0o600, rootRoot, false)
	return s, err
}

// release is a third-party web application xcp-install installs, pinned
// by version and SHA-256 (07-security.md §10).
type release struct {
	Name, Version, URL, SHA256 string
}

// releaseVersionFile names the file in a tree that records its version.
const releaseVersionFile = ".xcp-version"

// pmaTree installs the pinned phpMyAdmin release in PMADir.
func (in *installer) pmaTree(ctx context.Context) (bool, error) {
	return in.installRelease(ctx, phpMyAdmin, PMADir, pmaDropped)
}

// installRelease installs a release in dir, unless that version is there
// already, without the folders in dropped. It replaces the whole tree, so
// files the installer adds to it are written again afterwards. It reports
// whether it installed it.
func (in *installer) installRelease(ctx context.Context, rel release, dir string, dropped []string) (bool, error) {
	versionFile := dir + "/" + releaseVersionFile
	if b, err := os.ReadFile(in.path(versionFile)); err == nil && strings.TrimSpace(string(b)) == rel.Version {
		return false, nil
	}
	in.logf("    downloading %s %s", rel.Name, rel.Version)
	data, err := in.o.Sys.Download(ctx, rel.URL, pmaMaxBytes)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != rel.SHA256 {
		return false, fmt.Errorf("download has SHA-256 %s, want %s", got, rel.SHA256)
	}
	dst := in.path(dir)
	tmp, old := dst+".new", dst+".old"
	if err := errors.Join(os.RemoveAll(tmp), os.RemoveAll(old)); err != nil {
		return false, err
	}
	if err := extractTarGz(data, tmp); err != nil {
		return false, err
	}
	for _, d := range dropped {
		if err := os.RemoveAll(filepath.Join(tmp, d)); err != nil {
			return false, err
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, releaseVersionFile), []byte(rel.Version+"\n"), 0o644); err != nil { //nolint:forbidigo,gosec // installer, see writeFile
		return false, err
	}
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, old); err != nil {
			return false, err
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		return false, err
	}
	in.changed(rel.Name + " " + rel.Version + " in " + dir)
	return true, os.RemoveAll(old)
}

// extractTarGz unpacks a release tarball into dir, without its top folder.
// The archive is checked against a pinned hash first; this still refuses
// anything but plain files and folders inside dir.
func extractTarGz(data []byte, dir string) error {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		_, rel, _ := strings.Cut(h.Name, "/") // the release's top folder
		rel = strings.TrimSuffix(rel, "/")
		if rel == "" {
			continue
		}
		if !fs.ValidPath(rel) {
			return fmt.Errorf("archive entry %q leaves the folder", h.Name)
		}
		p := filepath.Join(dir, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o755); err != nil { //nolint:gosec // G301: web files, read by PHP-FPM
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if total > 4*pmaMaxBytes {
				return errors.New("archive unpacks too large")
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // G301: see above
				return err
			}
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G302,G304: see above
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(tr, h.Size))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			// Links and devices have no place in the release.
		}
	}
}
