package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/validate"
)

// Paths of mail part 2 (ADR-0008).
const (
	SievecPath        = "/usr/bin/sievec"
	DoveadmPath       = "/usr/bin/doveadm"
	DovecotSieveDir   = DovecotXCPDir + "/sieve"
	WebmailStateFile  = "/etc/xcp/mail/webmail.json"
	WebmailTicketDir  = "/var/lib/xcp-roundcube/tickets"
	WebmailUser       = "xcp-rc"
	WebmailTokenTTL   = 8 * time.Hour
	webmailTicketTTL  = 2 * time.Minute
	maxReplySubject   = 200
	maxReplyBody      = 4000
	pipeServicePrefix = "xcppipe-"
)

var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// checkReply validates an autoresponder.
func checkReply(r Autoresponder) error {
	if r.Subject == "" || len(r.Subject) > maxReplySubject || strings.ContainsAny(r.Subject, "\r\n\x00") {
		return invalid("the subject is one line of at most %d characters", maxReplySubject)
	}
	if r.Body == "" || len(r.Body) > maxReplyBody || strings.ContainsRune(r.Body, 0) {
		return invalid("the message has 1 to %d characters", maxReplyBody)
	}
	for _, d := range []string{r.Start, r.End} {
		if d == "" {
			continue
		}
		if _, err := time.Parse(time.DateOnly, d); err != nil || !dateRe.MatchString(d) {
			return invalid("dates are YYYY-MM-DD")
		}
	}
	if r.Start != "" && r.End != "" && r.End < r.Start {
		return invalid("the end date is before the start date")
	}
	if r.Days < 1 || r.Days > 30 {
		return invalid("reply at most once in 1 to 30 days")
	}
	return nil
}

// sieveString quotes a string for Sieve (RFC 5228 quoted-string).
func sieveString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(strings.ReplaceAll(s, "\r\n", "\n")) + `"`
}

// renderSieve renders an autoresponder as a vacation script; the dates are
// checked by the script, so it starts and stops on its own.
func renderSieve(address string, r Autoresponder) string {
	var conds []string
	if r.Start != "" {
		conds = append(conds, `currentdate :value "ge" "date" `+sieveString(r.Start))
	}
	if r.End != "" {
		conds = append(conds, `currentdate :value "le" "date" `+sieveString(r.End))
	}
	vacation := "vacation :days " + strconv.Itoa(r.Days) + " :subject " + sieveString(r.Subject) +
		" :addresses [" + sieveString(address) + "] " + sieveString(r.Body) + ";\n"
	head := "# Managed by XCP (ADR-0008): the autoresponder of " + address + ". Do not edit.\n" +
		`require ["vacation", "date", "relational"];` + "\n"
	if len(conds) == 0 {
		return head + vacation
	}
	return head + "if allof(" + strings.Join(conds, ", ") + ") {\n  " + vacation + "}\n"
}

// pipeService is a Postfix pipe transport that runs a script as an account user.
type pipeService struct {
	name, user, path string
}

const masterCFBase = `# Managed by XCP (ADR-0007, ADR-0008): written by xcp-install and xcp-agent. Do not edit.
# service type  private unpriv  chroot  wakeup  maxproc command + args
smtp      inet  n       -       n       -       -       smtpd
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=$mua_client_restrictions
  -o smtpd_sender_restrictions=$mua_sender_restrictions
  -o smtpd_relay_restrictions=$mua_relay_restrictions
  -o smtpd_recipient_restrictions=
  -o smtpd_end_of_data_restrictions=$mua_data_restrictions
  -o smtpd_policy_service_default_action=DUNNO
  -o smtpd_policy_service_timeout=10s
  -o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=$mua_client_restrictions
  -o smtpd_sender_restrictions=$mua_sender_restrictions
  -o smtpd_relay_restrictions=$mua_relay_restrictions
  -o smtpd_recipient_restrictions=
  -o smtpd_end_of_data_restrictions=$mua_data_restrictions
  -o smtpd_policy_service_default_action=DUNNO
  -o smtpd_policy_service_timeout=10s
  -o milter_macro_daemon_name=ORIGINATING
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
  -o syslog_name=postfix/$service_name
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
`

// renderMasterCF renders master.cf: Postfix's services and one pipe
// transport per pipe forwarder, run as the account's user.
func renderMasterCF(pipes []pipeService) string {
	var b strings.Builder
	b.WriteString(masterCFBase)
	if len(pipes) > 0 {
		b.WriteString("# Pipe forwarders: each script runs as its account's user.\n")
	}
	for _, p := range pipes {
		fmt.Fprintf(&b, "%s unix  -       n       n       -       -       pipe\n  flags=Rq user=%s argv=%s ${sender} ${recipient}\n", p.name, p.user, p.path)
	}
	return b.String()
}

// MailMasterCF renders master.cf from the fragments in dir, for xcp-install.
func MailMasterCF(dir, homesRoot string) (string, error) {
	m := &Mail{FragmentDir: dir}
	all, err := m.fragments("", nil)
	if errors.Is(err, fs.ErrNotExist) {
		return renderMasterCF(nil), nil
	}
	if err != nil {
		return "", err
	}
	return renderMasterCF(renderMail(all, homesRoot).pipes), nil
}

// writeSieve writes the autoresponder scripts, compiles them, and removes
// the ones no mailbox has any more. Each is readable by its account's group
// only, which Dovecot's delivery runs as.
func (m *Mail) writeSieve(ctx context.Context, f mailFiles) (bool, error) {
	changed := false
	keep := map[string]bool{}
	for _, rel := range sortedKeys(f.sieve) {
		s := f.sieve[rel]
		dir, name := filepath.Dir(rel), filepath.Base(rel)
		keep[rel] = true
		keep[strings.TrimSuffix(rel, ".sieve")+".svbin"] = true
		root, err := fsx.OpenRoot(m.SieveDir)
		if err != nil {
			return false, err
		}
		err = root.MkdirAll(dir, 0o755)
		root.Close()
		if err != nil {
			return false, err
		}
		c, err := writeFileGID(filepath.Join(m.SieveDir, dir), name, s.script, 0o640, s.gid)
		if err != nil {
			return false, err
		}
		bin := strings.TrimSuffix(name, ".sieve") + ".svbin"
		if _, err := os.Stat(filepath.Join(m.SieveDir, dir, bin)); c || err != nil {
			if err := m.compileSieve(ctx, filepath.Join(m.SieveDir, rel), s.gid); err != nil {
				return false, err
			}
		}
		changed = changed || c
	}
	removed, err := m.pruneSieve(keep)
	return changed || removed, err
}

func (m *Mail) compileSieve(ctx context.Context, path string, gid int) error {
	if m.Run == nil {
		return nil // tests
	}
	if _, err := m.Run.Run(ctx, execx.Cmd{Path: SievecPath, Args: []string{"--", path}}); err != nil {
		return fmt.Errorf("compile %s: %w", path, err)
	}
	root, err := fsx.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	bin := strings.TrimSuffix(filepath.Base(path), ".sieve") + ".svbin"
	if err := root.Chmod(bin, 0o640); err != nil {
		return err
	}
	return root.Chown(bin, 0, gid)
}

// pruneSieve removes script files not in keep (paths relative to SieveDir).
func (m *Mail) pruneSieve(keep map[string]bool) (bool, error) {
	root, err := fsx.OpenRoot(m.SieveDir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	domains, err := root.ReadDir(".")
	if err != nil {
		return false, err
	}
	removed := false
	for _, d := range domains {
		if !d.IsDir() {
			continue
		}
		files, err := root.ReadDir(d.Name())
		if err != nil {
			return removed, err
		}
		left := 0
		for _, f := range files {
			rel := d.Name() + "/" + f.Name()
			if keep[rel] {
				left++
				continue
			}
			if err := root.Remove(rel); err != nil {
				return removed, err
			}
			removed = true
		}
		if left == 0 {
			_ = root.Remove(d.Name())
		}
	}
	return removed, nil
}

// writeFileGID is writeFile with a numeric group.
func writeFileGID(dir, name, content string, mode fs.FileMode, gid int) (bool, error) {
	root, err := fsx.OpenRoot(dir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	if old, err := root.ReadFile(name, 16<<20); err == nil && string(old) == content {
		return false, root.Chown(name, 0, gid)
	}
	if err := root.WriteFileAtomic(name, []byte(content), mode); err != nil {
		return false, err
	}
	return true, root.Chown(name, 0, gid)
}

// webmailToken is a temporary IMAP password for webmail sign-on.
type webmailToken struct {
	Address string    `json:"address"`
	Hash    string    `json:"hash"` // {SHA256}: base64 of the SHA-256 of the token
	Expires time.Time `json:"expires"`
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "{SHA256}" + base64.StdEncoding.EncodeToString(sum[:])
}

func (m *Mail) loadTokens() ([]webmailToken, error) {
	b, err := os.ReadFile(m.WebmailState)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ts []webmailToken
	return ts, json.Unmarshal(b, &ts)
}

// writeTokens keeps the tokens that are not expired and whose mailbox may
// log in, and writes Dovecot's second passdb from them. Callers hold m.mu.
func (m *Mail) writeTokens(all []MailAccount, ts []webmailToken) (bool, error) {
	may := map[string]bool{}
	for _, a := range all {
		for _, d := range a.Domains {
			for _, b := range d.Mailboxes {
				if b.Login {
					may[b.Local+"@"+d.Name] = true
				}
			}
		}
	}
	now := m.now()
	ts = slices.DeleteFunc(slices.Clone(ts), func(t webmailToken) bool { return !may[t.Address] || !t.Expires.After(now) })
	b, err := json.Marshal(ts)
	if err != nil {
		return false, err
	}
	if _, err := writeFile(filepath.Dir(m.WebmailState), filepath.Base(m.WebmailState), string(b), 0o600, ""); err != nil {
		return false, err
	}
	var passdb strings.Builder
	for _, t := range ts {
		fmt.Fprintf(&passdb, "%s:%s\n", t.Address, t.Hash)
	}
	return writeFile(m.DovecotDir, "tokens", passdb.String(), 0o640, dovecotGroup)
}

// flushAuthCache empties Dovecot's login cache, so a new password, login
// switched off or a dropped webmail password counts at once rather than
// when the cached login expires.
func (m *Mail) flushAuthCache(ctx context.Context) error {
	if m.Run == nil {
		return nil // tests
	}
	if _, err := m.Run.Run(ctx, execx.Cmd{Path: DoveadmPath, Args: []string{"auth", "cache", "flush"}}); err != nil {
		return fmt.Errorf("flush Dovecot's login cache: %w", err)
	}
	return nil
}

func (m *Mail) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// WebmailSignon makes a temporary password for a mailbox of the account
// (which must be allowed to log in) and a one-time ticket for Roundcube to
// sign in with it. It returns the ticket's ID.
func (m *Mail) WebmailSignon(_ context.Context, username, address string) (string, error) {
	if validate.Username(username) != nil {
		return "", invalid("%q is not an account name", username)
	}
	if err := CheckAddress(address); err != nil {
		return "", err
	}
	if err := m.installed(); err != nil {
		return "", err
	}
	if fi, err := os.Stat(m.WebmailTickets); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("webmail is not installed: %w", ErrNotInstalled)
	}
	u, err := user.Lookup(m.WebmailUser)
	if err != nil {
		return "", fmt.Errorf("webmail's user: %w", err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	m.mu.Lock()
	defer m.mu.Unlock()
	all, err := m.fragments("", nil)
	if err != nil {
		return "", err
	}
	ok := false
	for _, a := range all {
		if a.Username != username {
			continue
		}
		for _, d := range a.Domains {
			for _, b := range d.Mailboxes {
				ok = ok || (b.Local+"@"+d.Name == address && b.Login)
			}
		}
	}
	if !ok {
		return "", invalid("%s is not a mailbox of %s that may log in", address, username)
	}
	ts, err := m.loadTokens()
	if err != nil {
		return "", err
	}
	token := randomString(32, lowerAlnum+"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	now := m.now()
	ts = append(ts, webmailToken{Address: address, Hash: tokenHash(token), Expires: now.Add(WebmailTokenTTL)})
	if _, err := m.writeTokens(all, ts); err != nil {
		return "", err
	}
	id := randomString(64, "0123456789abcdef")
	data, _ := json.Marshal(signonTicket{User: address, Password: token, Expires: now.Add(webmailTicketTTL).Unix()}) //nolint:gosec // G117: the ticket carries the temporary password to Roundcube
	root, err := fsx.OpenRoot(m.WebmailTickets)
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
	m.pruneTickets(root, now)
	return id, nil
}

// ExpireWebmail drops expired temporary passwords and unused tickets.
func (m *Mail) ExpireWebmail(ctx context.Context) error {
	if m.installed() != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	all, err := m.fragments("", nil)
	if err != nil {
		return err
	}
	ts, err := m.loadTokens()
	if err != nil {
		return err
	}
	changed, err := m.writeTokens(all, ts)
	if err != nil {
		return err
	}
	if changed {
		if err := m.flushAuthCache(ctx); err != nil {
			return err
		}
	}
	if root, err := fsx.OpenRoot(m.WebmailTickets); err == nil {
		m.pruneTickets(root, m.now())
		root.Close()
	}
	return nil
}

func (m *Mail) pruneTickets(root *fsx.Root, now time.Time) {
	ents, err := root.ReadDir(".")
	if err != nil {
		return
	}
	for _, e := range ents {
		if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > webmailTicketTTL {
			_ = root.Remove(e.Name())
		}
	}
}

// CheckAutoresponder validates an autoresponder; the panel uses it too.
func CheckAutoresponder(r Autoresponder) error { return checkReply(r) }
