package agent

import (
	"bytes"
	"context"
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
	"sync"
	"time"

	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/tlsx"
	"github.com/siyamex/XCP/internal/validate"
)

// Mail runs the mail of all accounts with Postfix, Dovecot and Rspamd
// (ADR-0007). Each account's mail is kept as a fragment; the global maps
// are rebuilt from all fragments on every change.
type Mail struct {
	Postfix      string // /usr/sbin/postfix; missing means mail is not installed
	FragmentDir  string // /etc/xcp/mail/accounts, root only
	SettingsFile string // /etc/xcp/mail/settings.json: the last MailSettings
	PostfixDir   string // /etc/postfix: main.cf and xcp/ with the maps
	DovecotDir   string // /etc/dovecot/xcp: passwd and ssl.conf
	DKIMDir      string // /var/lib/rspamd/dkim
	RspamdDir    string // /etc/rspamd: local.d/ and xcp/
	HomesRoot    string // /home
	HostCert     *HostCert
	PanelCert    string // the self-signed pair, until the host name has a certificate
	PanelKey     string
	Services     ServiceManager
	// Mail part 2 (ADR-0008).
	Run            *execx.Runner // runs sievec; nil in tests
	SieveDir       string        // /etc/dovecot/xcp/sieve
	WebmailState   string        // /etc/xcp/mail/webmail.json
	WebmailTickets string        // /var/lib/xcp-roundcube/tickets; missing means no webmail
	WebmailUser    string        // the user Roundcube runs as
	Now            func() time.Time
	mu             sync.Mutex
}

// Paths of the Ubuntu setup made by xcp-install.
const (
	PostfixBinary     = "/usr/sbin/postfix"
	MailFragmentDir   = "/etc/xcp/mail/accounts"
	MailSettingsFile  = "/etc/xcp/mail/settings.json"
	PostfixConfDir    = "/etc/postfix"
	DovecotXCPDir     = "/etc/dovecot/xcp"
	RspamdDKIMDir     = "/var/lib/rspamd/dkim"
	RspamdConfDir     = "/etc/rspamd"
	DKIMSelector      = "xcp"
	MailMaxForwardTo  = 20
	MailMaxDomains    = 1000
	mailMaxMessage    = 200 // characters of a rejection message
	dovecotGroup      = "dovecot"
	rspamdGroup       = "_rspamd"
	postfixMilter     = "inet:127.0.0.1:11332"
	dovecotLMTPSocket = "private/dovecot-lmtp"
	dovecotAuthSocket = "private/auth"
)

// Mail routing of a domain (the zone's email routing).
const (
	MailLocal  = "local"  // mailboxes here
	MailBackup = "backup" // accept and pass on to the primary MX
)

// MailAccount is all mail of one account.
type MailAccount struct {
	Username string
	UID, GID int
	Domains  []MailDomain
}

// MailDomain is one domain's mail.
type MailDomain struct {
	Name       string
	Routing    string // MailLocal or MailBackup
	AliasOf    string // set: all mail goes to the same address at this domain
	Mailboxes  []Mailbox
	Forwarders []Forwarder
	CatchAll   []string // where mail to unknown addresses goes; empty rejects it
	DKIMKey    string   // PKCS #8 PEM private key; empty: no signing
}

// Mailbox is one mailbox.
type Mailbox struct {
	Local        string
	PasswordHash string // {ARGON2ID}$argon2id$...
	QuotaMB      int64  // 0: no limit
	Login        bool
	Receive      bool
	Send         bool
	Reply        *Autoresponder // nil: none
}

// Autoresponder answers mail to a mailbox between two dates (ADR-0008).
type Autoresponder struct {
	Subject string
	Body    string
	Start   string // YYYY-MM-DD; "" = from now
	End     string // YYYY-MM-DD, inclusive; "" = until removed
	Days    int    // reply to the same sender at most once in this many days
}

// Forwarder sends mail for an address to other addresses, or rejects it.
type Forwarder struct {
	Local string
	To    []string // full addresses
	Fail  string   // set: reject with this message instead
	Pipe  string   // set: hand the mail to this script, relative to the account's home
}

var (
	argonHashRe = regexp.MustCompile(`^\{ARGON2ID\}\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)
	messageRe   = regexp.MustCompile(`^[\x20-\x7e]+$`)
)

// CheckLocalPart checks the part of a hosted address before the @, normalised.
func CheckLocalPart(s string) error {
	if n, err := validate.MailboxName(s); err != nil || n != s {
		return invalid("%q is not a valid address name: a-z, 0-9, '.', '_' and '-', at most 64", s)
	}
	return nil
}

// CheckAddress checks a full address, normalised (lower case, punycode).
func CheckAddress(s string) error {
	if n, err := validate.Email(s); err != nil || n != s {
		return invalid("%q is not a valid email address", s)
	}
	return nil
}

// CheckMailAccount validates an account's mail. The fake agent uses it too.
func CheckMailAccount(a MailAccount) error {
	if validate.Username(a.Username) != nil {
		return invalid("%q is not an account name", a.Username)
	}
	if a.UID < 10000 || a.GID < 1 {
		return invalid("account %s: bad uid/gid %d/%d", a.Username, a.UID, a.GID)
	}
	if len(a.Domains) > MailMaxDomains {
		return invalid("too many mail domains")
	}
	seen := map[string]bool{}
	for _, d := range a.Domains {
		if n, err := validate.Domain(d.Name); err != nil || n != d.Name {
			return invalid("%q is not a domain name", d.Name)
		}
		if seen[d.Name] {
			return invalid("domain %s is listed twice", d.Name)
		}
		seen[d.Name] = true
		if d.Routing != MailLocal && d.Routing != MailBackup {
			return invalid("domain %s: routing must be local or backup", d.Name)
		}
		if d.AliasOf != "" {
			if n, err := validate.Domain(d.AliasOf); err != nil || n != d.AliasOf || d.AliasOf == d.Name {
				return invalid("domain %s: bad alias target %q", d.Name, d.AliasOf)
			}
			if len(d.Mailboxes)+len(d.Forwarders)+len(d.CatchAll) > 0 {
				return invalid("alias domain %s has its own addresses", d.Name)
			}
		}
		if d.DKIMKey != "" {
			if _, err := tlsx.ParseRSAKey(d.DKIMKey); err != nil {
				return invalid("domain %s: DKIM key: %v", d.Name, err)
			}
		}
		addrs := map[string]string{}
		for _, m := range d.Mailboxes {
			if err := CheckLocalPart(m.Local); err != nil {
				return err
			}
			if addrs[m.Local] != "" {
				return invalid("%s@%s is listed twice", m.Local, d.Name)
			}
			addrs[m.Local] = "mailbox"
			if !argonHashRe.MatchString(m.PasswordHash) {
				return invalid("%s@%s: the password hash is not {ARGON2ID}", m.Local, d.Name)
			}
			if m.QuotaMB < 0 || m.QuotaMB > 10<<20 {
				return invalid("%s@%s: bad quota", m.Local, d.Name)
			}
			if m.Reply != nil {
				if err := checkReply(*m.Reply); err != nil {
					return fmt.Errorf("autoresponder of %s@%s: %w", m.Local, d.Name, err)
				}
			}
		}
		for _, f := range d.Forwarders {
			if err := CheckLocalPart(f.Local); err != nil {
				return err
			}
			if addrs[f.Local] == "forwarder" {
				return invalid("forwarder %s@%s is listed twice", f.Local, d.Name)
			}
			if f.Pipe != "" {
				if addrs[f.Local] == "mailbox" || len(f.To) > 0 || f.Fail != "" {
					return invalid("pipe %s@%s: a pipe is the address's only destination", f.Local, d.Name)
				}
				if p, err := validate.RelPath(f.Pipe); err != nil || p != f.Pipe || strings.ContainsAny(f.Pipe, " \t$") {
					return invalid("pipe %s@%s: %q is not a path inside the account's home", f.Local, d.Name, f.Pipe)
				}
				addrs[f.Local] = "forwarder"
				continue
			}
			if f.Fail != "" {
				if addrs[f.Local] == "mailbox" {
					return invalid("%s@%s is a mailbox; it cannot also reject its mail", f.Local, d.Name)
				}
				if len(f.To) > 0 || len(f.Fail) > mailMaxMessage || !messageRe.MatchString(f.Fail) {
					return invalid("forwarder %s@%s: a rejection has a one-line message of at most %d characters and no addresses", f.Local, d.Name, mailMaxMessage)
				}
			} else if err := checkTargets(f.To); err != nil {
				return fmt.Errorf("forwarder %s@%s: %w", f.Local, d.Name, err)
			}
			addrs[f.Local] = "forwarder"
		}
		if len(d.CatchAll) > 0 {
			if err := checkTargets(d.CatchAll); err != nil {
				return fmt.Errorf("default address of %s: %w", d.Name, err)
			}
		}
	}
	return nil
}

func checkTargets(to []string) error {
	if len(to) == 0 || len(to) > MailMaxForwardTo {
		return invalid("give 1 to %d addresses", MailMaxForwardTo)
	}
	for _, t := range to {
		if err := CheckAddress(t); err != nil {
			return err
		}
	}
	return nil
}

// mailFiles is what the agent writes from all fragments.
type mailFiles struct {
	maps    map[string]string // file in PostfixDir/xcp -> content
	passwd  string
	dkim    map[string]string // file in DKIMDir -> key
	dkimMap string            // domain -> selector, for Rspamd
	sieve   map[string]sieveFile
	pipes   []pipeService
}

// sieveFile is an autoresponder script, readable by its account's group.
type sieveFile struct {
	script string
	gid    int
}

// renderMail builds the global maps from all accounts' fragments.
func renderMail(accounts []MailAccount, homesRoot string) mailFiles {
	slices.SortFunc(accounts, func(a, b MailAccount) int { return strings.Compare(a.Username, b.Username) })
	var domains, aliasDomains, relayDomains, mailboxes, aliases, access, senders, sasl, passwd, dkimMap, transport strings.Builder
	dkim := map[string]string{}
	sieve := map[string]sieveFile{}
	var pipes []pipeService
	for _, a := range accounts {
		ds := slices.Clone(a.Domains)
		slices.SortFunc(ds, func(x, y MailDomain) int { return strings.Compare(x.Name, y.Name) })
		for _, d := range ds {
			if d.DKIMKey != "" {
				dkim[d.Name+"."+DKIMSelector+".key"] = d.DKIMKey
				fmt.Fprintf(&dkimMap, "%s %s\n", d.Name, DKIMSelector)
			}
			switch {
			case d.Routing == MailBackup:
				fmt.Fprintf(&relayDomains, "%s OK\n", d.Name)
				continue
			case d.AliasOf != "":
				fmt.Fprintf(&aliasDomains, "%s OK\n", d.Name)
				fmt.Fprintf(&aliases, "@%s @%s\n", d.Name, d.AliasOf)
				continue
			}
			fmt.Fprintf(&domains, "%s OK\n", d.Name)
			forwards := map[string][]string{}
			fws := slices.Clone(d.Forwarders)
			slices.SortFunc(fws, func(x, y Forwarder) int { return strings.Compare(x.Local, y.Local) })
			for _, f := range fws {
				addr := f.Local + "@" + d.Name
				if f.Pipe != "" {
					name := pipeServicePrefix + a.Username + "-" + strconv.Itoa(len(pipes)+1)
					path := filepath.ToSlash(filepath.Join(homesRoot, a.Username, f.Pipe))
					pipes = append(pipes, pipeService{name: name, user: a.Username, path: path})
					fmt.Fprintf(&mailboxes, "%s OK\n", addr)
					fmt.Fprintf(&transport, "%s %s:\n", addr, name)
					// Like a mailbox, the address maps to itself, so the default
					// address does not take its mail before the transport sees it.
					fmt.Fprintf(&aliases, "%s %s\n", addr, addr)
					continue
				}
				if f.Fail != "" {
					fmt.Fprintf(&access, "%s REJECT %s\n", addr, f.Fail)
					continue
				}
				forwards[addr] = f.To
			}
			boxes := slices.Clone(d.Mailboxes)
			slices.SortFunc(boxes, func(x, y Mailbox) int { return strings.Compare(x.Local, y.Local) })
			for _, m := range boxes {
				addr := m.Local + "@" + d.Name
				home := filepath.ToSlash(filepath.Join(homesRoot, a.Username, "mail", d.Name, m.Local))
				extra := ""
				if m.QuotaMB > 0 {
					extra += " userdb_quota_rule=*:storage=" + strconv.FormatInt(m.QuotaMB, 10) + "M"
				}
				if !m.Login {
					extra += " nologin=y"
				}
				fmt.Fprintf(&passwd, "%s:%s:%d:%d::%s::%s\n", addr, m.PasswordHash, a.UID, a.GID, home, strings.TrimSpace(extra))
				if m.Reply != nil {
					sieve[d.Name+"/"+m.Local+".sieve"] = sieveFile{script: renderSieve(addr, *m.Reply), gid: a.GID}
				}
				if m.Send {
					fmt.Fprintf(&senders, "%s %s\n", addr, addr)
				} else {
					fmt.Fprintf(&sasl, "%s REJECT Sending is switched off for this mailbox\n", addr)
				}
				if !m.Receive {
					fmt.Fprintf(&access, "%s REJECT This mailbox does not receive mail\n", addr)
					continue
				}
				fmt.Fprintf(&mailboxes, "%s OK\n", addr)
				// The address maps to itself, so the default address never takes
				// its mail; a forwarder on it keeps a copy here.
				fmt.Fprintf(&aliases, "%s %s\n", addr, strings.Join(append([]string{addr}, forwards[addr]...), ", "))
				delete(forwards, addr)
			}
			for _, addr := range sortedKeys(forwards) {
				fmt.Fprintf(&aliases, "%s %s\n", addr, strings.Join(forwards[addr], ", "))
			}
			if len(d.CatchAll) > 0 {
				fmt.Fprintf(&aliases, "@%s %s\n", d.Name, strings.Join(d.CatchAll, ", "))
			}
		}
	}
	const head = "# Managed by XCP (ADR-0007): built from every account's mail. Do not edit.\n"
	return mailFiles{
		maps: map[string]string{
			"domains": head + domains.String(), "alias_domains": head + aliasDomains.String(),
			"relay_domains": head + relayDomains.String(), "mailboxes": head + mailboxes.String(),
			"aliases": head + aliases.String(), "recipient_access": head + access.String(),
			"sender_logins": head + senders.String(), "sasl_access": head + sasl.String(),
			"transport": head + transport.String(),
		},
		passwd: passwd.String(), dkim: dkim, dkimMap: head + dkimMap.String(), sieve: sieve, pipes: pipes,
	}
}

// MailSettings are the server's mail settings (ADM-MAIL-01).
type MailSettings struct {
	Hostname      string   `json:"hostname"`       // HELO name, should match the PTR record
	MaxMessageMB  int64    `json:"max_message_mb"` // largest message accepted
	RelayHost     string   `json:"relay_host"`     // "host" or "host:port"; empty: deliver directly
	RelayUser     string   `json:"relay_user"`     // SASL login at the relay
	RelayPassword string   `json:"relay_password"` // kept root-only in a Postfix map
	RBLs          []string `json:"rbls"`           // DNS block lists checked for incoming mail
	HeloChecks    bool     `json:"helo_checks"`    // refuse senders without a valid HELO name
	Greylisting   bool     `json:"greylisting"`    // Rspamd greylisting of unknown senders
}

var relayRe = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]{1,5})?$`)

// CheckMailSettings validates mail settings.
func CheckMailSettings(s MailSettings) error {
	if n, err := validate.Domain(s.Hostname); err != nil || n != s.Hostname {
		return invalid("mail host name %q is not a host name", s.Hostname)
	}
	if s.MaxMessageMB < 1 || s.MaxMessageMB > 1024 {
		return invalid("the largest message must be 1 to 1024 MB")
	}
	if s.RelayHost != "" {
		host, _, _ := strings.Cut(s.RelayHost, ":")
		d, domErr := validate.Domain(host)
		_, ipErr := validate.IP(host)
		if !relayRe.MatchString(s.RelayHost) || (domErr != nil || d != host) && ipErr != nil {
			return invalid("relay host %q is not host or host:port", s.RelayHost)
		}
	}
	for _, v := range []string{s.RelayUser, s.RelayPassword} {
		if v != "" && (len(v) > 255 || !messageRe.MatchString(v) || strings.ContainsAny(v, " \t")) {
			return invalid("relay login and password are printable characters without spaces")
		}
	}
	if (s.RelayUser == "") != (s.RelayPassword == "") || (s.RelayUser != "" && s.RelayHost == "") {
		return invalid("a relay login needs a relay host, a user and a password")
	}
	if len(s.RBLs) > 10 {
		return invalid("at most 10 block lists")
	}
	for _, r := range s.RBLs {
		if n, err := validate.Domain(r); err != nil || n != r {
			return invalid("block list %q is not a DNS name", r)
		}
	}
	return nil
}

// relayTarget is the relay host in Postfix's form: [host]:port, no MX lookup.
func relayTarget(r string) string {
	host, port, ok := strings.Cut(r, ":")
	if !ok {
		port = "587"
	}
	return "[" + host + "]:" + port
}

// renderMainCF renders Postfix's main.cf.
func renderMainCF(s MailSettings, cert, key string) string {
	m := func(name string) string { return "texthash:" + PostfixConfDir + "/xcp/" + name }
	var b strings.Builder
	w := func(k, v string) { fmt.Fprintf(&b, "%s = %s\n", k, v) }
	b.WriteString("# Managed by XCP (ADR-0007): rendered from the panel's mail settings. Do not edit.\n")
	w("compatibility_level", "3.6")
	w("myhostname", s.Hostname)
	w("myorigin", "$myhostname")
	w("mydestination", "localhost")
	w("inet_interfaces", "all")
	w("inet_protocols", "all")
	w("mynetworks", "127.0.0.0/8 [::1]/128")
	w("alias_maps", "")
	w("alias_database", "")
	w("biff", "no")
	w("append_dot_mydomain", "no")
	w("smtpd_banner", "$myhostname ESMTP")
	w("message_size_limit", strconv.FormatInt(s.MaxMessageMB<<20, 10))
	w("mailbox_size_limit", "0")
	w("virtual_mailbox_domains", m("domains"))
	w("virtual_mailbox_maps", m("mailboxes"))
	w("virtual_alias_domains", m("alias_domains"))
	w("virtual_alias_maps", m("aliases"))
	w("relay_domains", m("relay_domains"))
	w("virtual_transport", "lmtp:unix:"+dovecotLMTPSocket)
	w("transport_maps", m("transport"))
	w("smtpd_sasl_type", "dovecot")
	w("smtpd_sasl_path", dovecotAuthSocket)
	w("smtpd_sasl_auth_enable", "no")
	w("smtpd_sender_login_maps", m("sender_logins"))
	w("smtpd_helo_required", "yes")
	if s.HeloChecks {
		w("smtpd_helo_restrictions", "permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname")
	}
	w("smtpd_relay_restrictions", "permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination")
	// For mail clients on submission (587) and smtps (465), named in master.cf:
	// log in, and send only as your own address unless sending is switched off.
	w("mua_client_restrictions", "permit_sasl_authenticated, reject")
	w("mua_sender_restrictions", "check_sasl_access "+m("sasl_access")+", reject_authenticated_sender_login_mismatch, permit")
	w("mua_relay_restrictions", "permit_sasl_authenticated, reject")
	w("smtpd_sasl_authenticated_header", "no")
	rcpt := []string{"check_recipient_access " + m("recipient_access"), "permit_mynetworks", "permit_sasl_authenticated", "reject_unauth_destination"}
	for _, r := range s.RBLs {
		rcpt = append(rcpt, "reject_rbl_client "+r)
	}
	w("smtpd_recipient_restrictions", strings.Join(rcpt, ", "))
	w("smtpd_tls_cert_file", cert)
	w("smtpd_tls_key_file", key)
	w("smtpd_tls_security_level", "may")
	w("smtpd_tls_auth_only", "yes")
	w("smtpd_tls_mandatory_protocols", ">=TLSv1.2")
	w("smtpd_tls_protocols", ">=TLSv1.2")
	w("smtp_tls_security_level", "may")
	w("smtpd_milters", postfixMilter)
	w("non_smtpd_milters", postfixMilter)
	w("milter_default_action", "accept")
	w("milter_protocol", "6")
	if s.RelayHost != "" {
		w("relayhost", relayTarget(s.RelayHost))
		if s.RelayUser != "" {
			w("smtp_sasl_auth_enable", "yes")
			w("smtp_sasl_password_maps", m("relay_password"))
			w("smtp_sasl_security_options", "noanonymous")
			w("smtp_tls_security_level", "encrypt")
		}
	}
	return b.String()
}

func renderDovecotSSL(cert, key string) string {
	return "# Managed by XCP (ADR-0007). Do not edit.\nssl_cert = <" + cert + "\nssl_key = <" + key + "\n"
}

func renderGreylist(on bool) string {
	return "# Managed by XCP (ADR-0007). Do not edit.\nenabled = " + strconv.FormatBool(on) + ";\n"
}

// tls returns the certificate mail serves: the host name's once AutoSSL
// installed it, the panel's self-signed one before.
func (m *Mail) tls() (cert, key string) {
	if m.HostCert != nil {
		if _, err := os.Stat(m.HostCert.CertFile); err == nil {
			return m.HostCert.CertFile, m.HostCert.KeyFile
		}
	}
	return m.PanelCert, m.PanelKey
}

func (m *Mail) installed() error {
	if _, err := os.Stat(m.Postfix); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the mail server is not installed: %w", ErrNotInstalled)
	}
	return nil
}

// writeFile writes a file through fsx if its content differs, with mode
// and group. It reports whether it wrote.
func writeFile(dir, name, content string, mode fs.FileMode, group string) (bool, error) {
	root, err := fsx.OpenRoot(dir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	gid := 0
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return false, fmt.Errorf("group %s: %w", group, err)
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	if old, err := root.ReadFile(name, 16<<20); err == nil && bytes.Equal(old, []byte(content)) {
		return false, nil
	}
	if err := root.WriteFileAtomic(name, []byte(content), mode); err != nil {
		return false, err
	}
	return true, root.Chown(name, 0, gid)
}

// fragments reads all accounts' fragments, with the given one replaced
// (nil: removed).
func (m *Mail) fragments(username string, replace *MailAccount) ([]MailAccount, error) {
	root, err := fsx.OpenRoot(m.FragmentDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	ents, err := root.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var out []MailAccount
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || name == username {
			continue
		}
		b, err := root.ReadFile(e.Name(), 64<<20)
		if err != nil {
			return nil, err
		}
		var a MailAccount
		if err := json.Unmarshal(b, &a); err != nil {
			return nil, fmt.Errorf("mail fragment %s: %w", e.Name(), err)
		}
		out = append(out, a)
	}
	if replace != nil {
		out = append(out, *replace)
	}
	return out, nil
}

// ApplyAccount stores an account's mail and rebuilds the maps. It refuses
// a domain another account's mail has. It reports whether anything changed.
func (m *Mail) ApplyAccount(ctx context.Context, a MailAccount) (bool, error) {
	if validate.Username(a.Username) != nil {
		return false, invalid("%q is not an account name", a.Username)
	}
	// The mailboxes belong to the account's Linux user, found here rather
	// than taken from the request.
	u, err := lookup(a.Username)
	if err != nil {
		return false, err
	}
	if u == nil || u.Name != AccountMarker {
		return false, ErrNotOurUser
	}
	a.UID, _ = strconv.Atoi(u.Uid)
	a.GID, _ = strconv.Atoi(u.Gid)
	if err := CheckMailAccount(a); err != nil {
		return false, err
	}
	if err := m.installed(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	all, err := m.fragments(a.Username, nil)
	if err != nil {
		return false, err
	}
	owner := map[string]string{}
	for _, o := range all {
		for _, d := range o.Domains {
			owner[d.Name] = o.Username
		}
	}
	for _, d := range a.Domains {
		if o := owner[d.Name]; o != "" {
			return false, invalid("domain %s has mail in account %s already", d.Name, o)
		}
	}
	b, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	changed, err := writeFile(m.FragmentDir, a.Username+".json", string(b), 0o600, "")
	if err != nil {
		return false, err
	}
	rebuilt, err := m.rebuild(ctx, append(all, a))
	return changed || rebuilt, err
}

// RemoveAccount drops an account's mail from the maps. Its mail files stay
// in its home (removed with the account).
func (m *Mail) RemoveAccount(ctx context.Context, username string) (bool, error) {
	if validate.Username(username) != nil {
		return false, invalid("%q is not an account name", username)
	}
	if err := m.installed(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	root, err := fsx.OpenRoot(m.FragmentDir)
	if err != nil {
		return false, err
	}
	err = root.Remove(username + ".json")
	root.Close()
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	all, err := m.fragments(username, nil)
	if err != nil {
		return false, err
	}
	_, err = m.rebuild(ctx, all)
	return true, err
}

// rebuild writes the maps from all fragments and reloads what changed.
func (m *Mail) rebuild(ctx context.Context, all []MailAccount) (bool, error) {
	f := renderMail(all, m.HomesRoot)
	postfixChanged := false
	for _, name := range sortedKeys(f.maps) {
		c, err := writeFile(filepath.Join(m.PostfixDir, "xcp"), name, f.maps[name], 0o644, "")
		if err != nil {
			return false, err
		}
		postfixChanged = postfixChanged || c
	}
	// Dovecot reads its passwd-file again when it changes.
	passwdChanged, err := writeFile(m.DovecotDir, "passwd", f.passwd, 0o640, dovecotGroup)
	if err != nil {
		return false, err
	}
	dkimChanged, err := m.writeDKIM(f)
	if err != nil {
		return false, err
	}
	masterChanged, err := writeFile(m.PostfixDir, "master.cf", renderMasterCF(f.pipes), 0o644, "")
	if err != nil {
		return false, err
	}
	postfixChanged = postfixChanged || masterChanged
	sieveChanged, err := m.writeSieve(ctx, f)
	if err != nil {
		return false, err
	}
	tokens, err := m.loadTokens()
	if err != nil {
		return false, err
	}
	tokensChanged, err := m.writeTokens(all, tokens)
	if err != nil {
		return false, err
	}
	if passwdChanged || tokensChanged {
		if err := m.flushAuthCache(ctx); err != nil {
			return true, err
		}
	}
	if postfixChanged {
		if err := m.Services.Do(ctx, "postfix.service", ActionReload); err != nil {
			return true, err
		}
	}
	return postfixChanged || passwdChanged || dkimChanged || sieveChanged, nil
}

// writeDKIM writes the signing keys and Rspamd's selector map, and removes
// keys no domain has any more. Rspamd reads both when it signs.
func (m *Mail) writeDKIM(f mailFiles) (bool, error) {
	changed := false
	for _, name := range sortedKeys(f.dkim) {
		c, err := writeFile(m.DKIMDir, name, f.dkim[name], 0o640, rspamdGroup)
		if err != nil {
			return false, err
		}
		changed = changed || c
	}
	root, err := fsx.OpenRoot(m.DKIMDir)
	if err != nil {
		return false, err
	}
	ents, err := root.ReadDir(".")
	if err != nil {
		root.Close()
		return false, err
	}
	for _, e := range ents {
		if _, keep := f.dkim[e.Name()]; !keep && strings.HasSuffix(e.Name(), "."+DKIMSelector+".key") {
			if err := root.Remove(e.Name()); err != nil {
				root.Close()
				return false, err
			}
			changed = true
		}
	}
	root.Close()
	c, err := writeFile(filepath.Join(m.RspamdDir, "xcp"), "dkim_selectors.map", f.dkimMap, 0o644, "")
	return changed || c, err
}

// ApplySettings renders the server's mail configuration from settings and
// reloads the services whose files changed.
func (m *Mail) ApplySettings(ctx context.Context, s MailSettings) (bool, error) {
	s.Hostname = strings.ToLower(s.Hostname)
	if err := CheckMailSettings(s); err != nil {
		return false, err
	}
	if err := m.installed(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := json.Marshal(s)
	if err != nil {
		return false, err
	}
	if _, err := writeFile(filepath.Dir(m.SettingsFile), filepath.Base(m.SettingsFile), string(b), 0o600, ""); err != nil {
		return false, err
	}
	return m.render(ctx, s)
}

// RefreshTLS renders the configs again with the current certificate
// (after the host name got one).
func (m *Mail) RefreshTLS(ctx context.Context) (bool, error) {
	if m.installed() != nil {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	root, err := fsx.OpenRoot(filepath.Dir(m.SettingsFile))
	if err != nil {
		return false, err
	}
	b, err := root.ReadFile(filepath.Base(m.SettingsFile), 1<<20)
	root.Close()
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil // not set up yet
	}
	if err != nil {
		return false, err
	}
	var s MailSettings
	if err := json.Unmarshal(b, &s); err != nil {
		return false, err
	}
	return m.render(ctx, s)
}

func (m *Mail) render(ctx context.Context, s MailSettings) (bool, error) {
	cert, key := m.tls()
	relay := "# Managed by XCP (ADR-0007). Do not edit.\n"
	if s.RelayUser != "" {
		relay += relayTarget(s.RelayHost) + " " + s.RelayUser + ":" + s.RelayPassword + "\n"
	}
	pRelay, err := writeFile(filepath.Join(m.PostfixDir, "xcp"), "relay_password", relay, 0o600, "")
	if err != nil {
		return false, err
	}
	pMain, err := writeFile(m.PostfixDir, "main.cf", renderMainCF(s, cert, key), 0o644, "")
	if err != nil {
		return false, err
	}
	dSSL, err := writeFile(m.DovecotDir, "ssl.conf", renderDovecotSSL(cert, key), 0o644, "")
	if err != nil {
		return false, err
	}
	rGrey, err := writeFile(filepath.Join(m.RspamdDir, "local.d"), "greylist.conf", renderGreylist(s.Greylisting), 0o644, "")
	if err != nil {
		return false, err
	}
	for _, r := range []struct {
		changed bool
		unit    string
	}{{pMain || pRelay, "postfix.service"}, {dSSL, "dovecot.service"}, {rGrey, "rspamd.service"}} {
		if r.changed {
			if err := m.Services.Do(ctx, r.unit, ActionReloadOrRestart); err != nil {
				return true, err
			}
		}
	}
	return pMain || pRelay || dSSL || rGrey, nil
}

// MailRenderDefaults returns the files xcp-install writes before the panel
// has applied any settings, so the installer and the agent agree.
func MailRenderDefaults(s MailSettings, cert, key string) (mainCF, dovecotSSL, greylist string) {
	return renderMainCF(s, cert, key), renderDovecotSSL(cert, key), renderGreylist(s.Greylisting)
}
