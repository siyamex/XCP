package install

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/siyamex/XCP/internal/agent"
)

// Mail files that are not rendered from settings (ADR-0007).
const (
	PostfixMasterCF = agent.PostfixConfDir + "/master.cf"
	DovecotConf     = "/etc/dovecot/dovecot.conf"
	mailMaps        = agent.PostfixConfDir + "/xcp"
	rspamdLocal     = agent.RspamdConfDir + "/local.d"
)

// The maps the agent writes; empty files let Postfix start before any
// account has mail.
var postfixMaps = []string{
	"domains", "alias_domains", "relay_domains", "mailboxes", "aliases", "recipient_access", "sender_logins", "sasl_access",
	"transport",
}

const dovecotConf = `# Managed by XCP (xcp-install; ADR-0007). Changes are overwritten.
protocols = imap pop3 lmtp
listen = *, ::
log_path = syslog
mail_location = maildir:~/Maildir
mail_plugins = $mail_plugins quota
# Mailboxes belong to account users (UID 10000 and up).
first_valid_uid = 10000
first_valid_gid = 10000
auth_mechanisms = plain login
disable_plaintext_auth = yes
auth_cache_size = 10M
auth_cache_ttl = 1 hour
auth_cache_negative_ttl = 1 min

passdb {
  driver = passwd-file
  args = scheme=ARGON2ID username_format=%Lu /etc/dovecot/xcp/passwd
}
# Temporary passwords for webmail sign-on (ADR-0008), tried after the real one.
passdb {
  driver = passwd-file
  args = scheme=SHA256 username_format=%Lu /etc/dovecot/xcp/tokens
}
userdb {
  driver = passwd-file
  args = username_format=%Lu /etc/dovecot/xcp/passwd
}

namespace inbox {
  inbox = yes
  separator = /
  mailbox Drafts {
    special_use = \Drafts
    auto = subscribe
  }
  mailbox Junk {
    special_use = \Junk
    auto = subscribe
  }
  mailbox Sent {
    special_use = \Sent
    auto = subscribe
  }
  mailbox Trash {
    special_use = \Trash
    auto = subscribe
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

plugin {
  quota = count:User quota
  quota_vsizes = yes
  # Autoresponders (ADR-0008), written by xcp-agent; then the user's own filters.
  sieve_before = /etc/dovecot/xcp/sieve/%d/%n.sieve
  sieve = file:~/sieve;active=~/.dovecot.sieve
}
protocol lmtp {
  mail_plugins = $mail_plugins sieve
}
protocol imap {
  mail_plugins = $mail_plugins imap_quota
}

ssl = required
ssl_min_protocol = TLSv1.2
!include /etc/dovecot/xcp/ssl.conf
`

const rspamdDKIM = `# Managed by XCP (xcp-install; ADR-0007). Changes are overwritten.
# Keys per domain, written by xcp-agent; domains not in the map are not signed.
enabled = true;
path = "` + agent.RspamdDKIMDir + `/$domain.$selector.key";
selector_map = "` + agent.RspamdConfDir + `/xcp/dkim_selectors.map";
allow_username_mismatch = true;
try_fallback = false;
use_esld = false;
sign_authenticated = true;
sign_local = true;
`

const rspamdRedis = `# Managed by XCP (xcp-install; ADR-0007). Greylisting keeps its state here.
servers = "127.0.0.1";
`

// mailSettings returns the mail settings the agent last applied, or the
// defaults for a new server.
func (in *installer) mailSettings() (agent.MailSettings, bool, error) {
	s := agent.MailSettings{Hostname: strings.ToLower(in.o.Hostname), MaxMessageMB: 50, RBLs: []string{}, HeloChecks: true}
	b, err := os.ReadFile(in.path(agent.MailSettingsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return s, false, nil
	}
	if err != nil {
		return s, false, err
	}
	var stored agent.MailSettings
	if err := json.Unmarshal(b, &stored); err != nil {
		return s, false, err
	}
	return stored, true, nil
}

func (in *installer) mail(ctx context.Context) error {
	if in.o.NoMail {
		in.logf("    skipped (--no-mail)")
		return nil
	}
	if in.o.DryRun {
		in.logf("    would install postfix, dovecot, rspamd and redis-server, and write their configuration")
		return nil
	}
	installed, err := in.o.Sys.InstallMailServer(ctx)
	if err != nil {
		return err
	}
	if installed {
		in.changed("installed postfix, dovecot, rspamd and redis-server")
	}
	_, dovecotGID, err := in.o.Sys.LookupIDs("dovecot")
	if err != nil {
		return err
	}
	_, rspamdGID, err := in.o.Sys.LookupIDs("_rspamd")
	if err != nil {
		return err
	}
	in.mailGIDs = map[owner]int{rootDovecot: dovecotGID, rootRspamd: rspamdGID}
	if err := in.makeDirs([]dirSpec{
		{path.Dir(agent.MailFragmentDir), 0o700, rootRoot},
		{agent.MailFragmentDir, 0o700, rootRoot},
		{mailMaps, 0o755, rootRoot},
		{agent.DovecotXCPDir, 0o755, rootDovecot},
		{agent.DovecotSieveDir, 0o755, rootRoot},
		{rspamdLocal, 0o755, rootRoot},
		{agent.RspamdConfDir + "/xcp", 0o755, rootRoot},
		{agent.RspamdDKIMDir, 0o750, rootRspamd},
	}); err != nil {
		return err
	}
	for _, m := range postfixMaps {
		if _, err := in.writeFile(mailMaps+"/"+m, nil, 0o644, rootRoot, true); err != nil {
			return err
		}
	}
	if _, err := in.writeFile(mailMaps+"/relay_password", nil, 0o600, rootRoot, true); err != nil {
		return err
	}
	for _, f := range []string{"passwd", "tokens"} {
		if _, err := in.writeFile(agent.DovecotXCPDir+"/"+f, nil, 0o640, rootDovecot, true); err != nil {
			return err
		}
	}
	if _, err := in.writeFile(agent.RspamdConfDir+"/xcp/dkim_selectors.map", nil, 0o644, rootRoot, true); err != nil {
		return err
	}
	set, ok, err := in.mailSettings()
	if err != nil {
		return err
	}
	if !ok {
		b, _ := json.Marshal(set)
		if _, err := in.writeFile(agent.MailSettingsFile, b, 0o600, rootRoot, false); err != nil {
			return err
		}
	}
	cert, key := CertFile, KeyFile
	if _, err := os.Stat(in.path(HostCertFile)); err == nil {
		cert, key = HostCertFile, HostKeyFile
	}
	mainCF, sslConf, greylist := agent.MailRenderDefaults(set, cert, key)
	masterCF, err := agent.MailMasterCF(in.path(agent.MailFragmentDir), "/home")
	if err != nil {
		return err
	}
	changed := map[string]bool{}
	for _, f := range []struct {
		path, content, unit string
		mode                os.FileMode
		own                 owner
	}{
		{agent.PostfixConfDir + "/main.cf", mainCF, "postfix.service", 0o644, rootRoot},
		{PostfixMasterCF, masterCF, "postfix.service", 0o644, rootRoot},
		{DovecotConf, dovecotConf, "dovecot.service", 0o644, rootRoot},
		{agent.DovecotXCPDir + "/ssl.conf", sslConf, "dovecot.service", 0o644, rootRoot},
		{rspamdLocal + "/dkim_signing.conf", rspamdDKIM, "rspamd.service", 0o644, rootRoot},
		{rspamdLocal + "/redis.conf", rspamdRedis, "rspamd.service", 0o644, rootRoot},
		{rspamdLocal + "/greylist.conf", greylist, "rspamd.service", 0o644, rootRoot},
	} {
		wrote, err := in.writeFile(f.path, []byte(f.content), f.mode, f.own, false)
		if err != nil {
			return err
		}
		changed[f.unit] = changed[f.unit] || wrote || installed
	}
	if err := in.o.Sys.Systemctl(ctx, "enable", "--now", "redis-server.service", "rspamd.service", "dovecot.service", "xcp-mailpolicy.service", "postfix.service"); err != nil {
		return err
	}
	for _, unit := range []string{"rspamd.service", "dovecot.service", "postfix.service"} {
		if changed[unit] {
			if err := in.o.Sys.Systemctl(ctx, "restart", unit); err != nil {
				return err
			}
		}
	}
	if in.o.NoWeb {
		in.logf("    webmail skipped: it needs the web server (--no-web)")
		return nil
	}
	return in.webmail(ctx, set.MaxMessageMB)
}
