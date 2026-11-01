package install

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/siyamex/XCP/internal/agent"
)

// Roundcube files (ADR-0008).
const (
	RCDir       = "/usr/share/xcp/roundcube"
	RCStateDir  = "/var/lib/xcp-roundcube" // db/, tmp/, logs/, sessions/, tickets/
	RCSocket    = "/run/php/xcp_roundcube.sock"
	rcPool      = "xcp_roundcube" // an underscore: never an account's pool
	rcDatabase  = RCStateDir + "/db/roundcube.db"
	rcDESSecret = SecretsDir + "/roundcube-des-key" //nolint:gosec // G101: a file path, not a credential
)

// roundcube is the release xcp-install installs, pinned like phpMyAdmin.
var roundcube = release{
	Name:    "Roundcube",
	Version: "1.7.5",
	URL:     "https://github.com/roundcube/roundcubemail/releases/download/1.7.5/roundcubemail-1.7.5-complete.tar.gz",
	SHA256:  "93a66c94e3efff7db93187c1c9d7f35546647a3e1e7b9327cc87911564edf9d1",
}

// rcDropped are folders of the release that must not be there: its web
// installer, and the sample plugin that signs anyone in from localhost.
var rcDropped = []string{"installer", "public_html/installer.php", "plugins/autologon", "docs"}

func rcConfig(desKey string) string {
	return `<?php
// Managed by XCP (xcp-install; ADR-0008). Changes are overwritten.
$config = [];
$config['db_dsnw'] = 'sqlite:///` + rcDatabase + `?mode=0600';
$config['imap_host'] = 'ssl://localhost:993';
$config['smtp_host'] = 'tls://localhost:587';
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
// Mail is on this server: its certificate is for the host name, not "localhost".
$config['imap_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];
$config['smtp_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];
$config['des_key'] = '` + desKey + `';
$config['product_name'] = 'Webmail';
$config['support_url'] = '';
$config['skin'] = 'elastic';
$config['plugins'] = ['xcp_sso', 'archive', 'zipdownload'];
$config['temp_dir'] = '` + RCStateDir + `/tmp/';
$config['log_dir'] = '` + RCStateDir + `/logs/';
$config['enable_installer'] = false;
$config['use_https'] = true;
$config['ip_check'] = true;
$config['login_autocomplete'] = 0;
$config['session_lifetime'] = 60;
`
}

// rcPlugin signs in with a one-time ticket from the agent (ADR-0008).
const rcPlugin = `<?php
// Managed by XCP (xcp-install; ADR-0008). Changes are overwritten.
// Signs in with a one-time ticket from the panel: /webmail/?_xcp_ticket=<id>.
class xcp_sso extends rcube_plugin
{
    private $ticket = null;

    public function init()
    {
        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('authenticate', [$this, 'authenticate']);
    }

    public function startup($args)
    {
        $t = $_GET['_xcp_ticket'] ?? '';
        if (is_string($t) && preg_match('/^[0-9a-f]{64}$/', $t) === 1) {
            $this->ticket = $t;
            $args['task'] = 'login';
            $args['action'] = 'login';
        }
        return $args;
    }

    public function authenticate($args)
    {
        if ($this->ticket === null) {
            return $args;
        }
        // Claim the ticket first, so it works once even if two requests race.
        $path = '` + agent.WebmailTicketDir + `/' . $this->ticket;
        $claimed = $path . '.used-' . bin2hex(random_bytes(8));
        $this->ticket = null;
        if (!@rename($path, $claimed)) {
            return $args;
        }
        $raw = @file_get_contents($claimed);
        @unlink($claimed);
        $t = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($t) || !is_string($t['user'] ?? null) || !is_string($t['password'] ?? null) || (int) ($t['expires'] ?? 0) < time()) {
            return $args;
        }
        $args['user'] = $t['user'];
        $args['pass'] = $t['password'];
        $args['host'] = 'ssl://localhost:993';
        $args['cookiecheck'] = false;
        $args['valid'] = true;
        return $args;
    }
}
`

func rcPoolConf(maxMB int64) string {
	return "; Managed by XCP (xcp-install); changes are overwritten. Roundcube (ADR-0008).\n" +
		"[" + rcPool + "]\n" +
		"user = " + agent.WebmailUser + "\n" +
		"group = " + agent.WebmailUser + "\n" +
		"listen = " + RCSocket + "\n" +
		"listen.owner = www-data\n" +
		"listen.group = www-data\n" +
		"listen.mode = 0660\n" +
		"pm = ondemand\n" +
		"pm.max_children = 16\n" +
		"pm.process_idle_timeout = 30s\n" +
		"pm.max_requests = 500\n" +
		"php_admin_value[open_basedir] = " + RCDir + "/:" + RCStateDir + "/\n" +
		"php_admin_value[session.save_path] = " + RCStateDir + "/sessions\n" +
		"php_admin_value[upload_tmp_dir] = " + RCStateDir + "/tmp\n" +
		"php_admin_value[sys_temp_dir] = " + RCStateDir + "/tmp\n" +
		fmt.Sprintf("php_admin_value[upload_max_filesize] = %dM\n", maxMB) +
		fmt.Sprintf("php_admin_value[post_max_size] = %dM\n", maxMB+10) +
		"php_admin_value[memory_limit] = 256M\n" +
		"php_admin_flag[display_errors] = off\n"
}

// webmail installs Roundcube and its PHP-FPM pool. Apache serves it once
// its files exist (<IfFile> in the host name's virtual host).
func (in *installer) webmail(ctx context.Context, maxMB int64) error {
	created, err := in.o.Sys.EnsureSystemUser(ctx, agent.WebmailUser, RCStateDir)
	if err != nil {
		return err
	}
	if created {
		in.changed("created system user " + agent.WebmailUser)
	}
	if in.rcUID, in.rcGID, err = in.o.Sys.LookupIDs(agent.WebmailUser); err != nil {
		return err
	}
	if err := in.makeDirs([]dirSpec{
		{"/usr/share/xcp", 0o755, rootRoot},
		{RCStateDir, 0o750, rootRC},
		{RCStateDir + "/db", 0o700, rcRC},
		{RCStateDir + "/tmp", 0o700, rcRC},
		{RCStateDir + "/logs", 0o700, rcRC},
		{RCStateDir + "/sessions", 0o700, rcRC},
		{agent.WebmailTicketDir, 0o700, rcRC},
	}); err != nil {
		return err
	}
	tree, err := in.installRelease(ctx, roundcube, RCDir, rcDropped)
	if err != nil {
		return fmt.Errorf("installing webmail (Roundcube %s): %w", roundcube.Version, err)
	}
	des, err := in.secretHex(rcDESSecret)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(in.path(RCDir+"/config"), 0o755); err != nil { //nolint:gosec // G301: the release's own folder
		return err
	}
	if _, err := in.writeFile(RCDir+"/config/config.inc.php", []byte(rcConfig(des[:24])), 0o640, rootRC, false); err != nil {
		return err
	}
	if err := os.MkdirAll(in.path(RCDir+"/plugins/xcp_sso"), 0o755); err != nil { //nolint:gosec // G301: code, read by PHP-FPM
		return err
	}
	if _, err := in.writeFile(RCDir+"/plugins/xcp_sso/xcp_sso.php", []byte(rcPlugin), 0o644, rootRoot, false); err != nil {
		return err
	}
	if err := in.rcDatabase(); err != nil {
		return err
	}
	ver := pmaPHP(in.o.Sys.PHPFPMVersions())
	if ver == "" {
		return errors.New("no PHP-FPM installed for Roundcube")
	}
	pool := "/etc/php/" + ver + "/fpm/pool.d/" + rcPool + ".conf"
	if err := os.MkdirAll(in.path(path.Dir(pool)), 0o755); err != nil { //nolint:gosec // G301: like the rest of /etc
		return err
	}
	wrotePool, err := in.writeFile(pool, []byte(rcPoolConf(maxMB)), 0o644, rootRoot, false)
	if err != nil {
		return err
	}
	if wrotePool {
		if err := in.o.Sys.Systemctl(ctx, "reload-or-restart", "php"+ver+"-fpm.service"); err != nil {
			return err
		}
	}
	if tree || wrotePool {
		return in.o.Sys.Systemctl(ctx, "reload-or-restart", "apache2.service")
	}
	return nil
}

// rcDatabase creates Roundcube's SQLite database from the schema that
// comes with it, owned by Roundcube. An existing database is kept.
func (in *installer) rcDatabase() error {
	p := in.path(rcDatabase)
	if _, err := os.Stat(p); err == nil {
		return in.chown(p, rcRC)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	schema, err := os.ReadFile(in.path(RCDir + "/SQL/sqlite.initial.sql"))
	if err != nil {
		return err
	}
	tmp := p + ".new"
	_ = os.Remove(tmp)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(tmp))
	if err != nil {
		return err
	}
	_, err = db.Exec(string(schema))
	if cerr := db.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("webmail database: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := in.chown(tmp, rcRC); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	in.changed("file " + rcDatabase)
	return nil
}
