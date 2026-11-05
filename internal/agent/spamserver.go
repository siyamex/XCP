package agent

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/siyamex/XCP/internal/validate"
)

// Server-wide spam settings (ADM-MAIL-05, ADR-0030).
const (
	// DefaultSpamReject is Rspamd's own limit for refusing a message.
	DefaultSpamReject = 15
	// MaxServerSpamList bounds the global allow and block lists.
	MaxServerSpamList = 1000
)

var spamSenderRe = regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+$`)

// CleanSpamSender checks a global block-list entry: an address or a domain,
// returned in lower case.
func CleanSpamSender(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if spamSenderRe.MatchString(s) && len(s) <= 254 {
		return s, nil
	}
	if d, err := validate.Domain(s); err == nil && d == s {
		return s, nil
	}
	return "", fmt.Errorf("%q is not an address or a domain", s)
}

func checkSpamSettings(s MailSettings) error {
	if s.SpamReject != 0 && (s.SpamReject < 8 || s.SpamReject > 100) {
		return invalid("the score from which mail is refused is 8 to 100 (15 is usual)")
	}
	for name, l := range map[string][]string{"allow": s.SpamAllow, "block": s.SpamBlock} {
		if len(l) > MaxServerSpamList {
			return invalid("the spam %s list has at most %d entries", name, MaxServerSpamList)
		}
		for _, e := range l {
			if name == "allow" {
				if d, err := validate.Domain(e); err != nil || d != e {
					return invalid("spam allow list: %q is not a domain", e)
				}
			} else if c, err := CleanSpamSender(e); err != nil || c != e {
				return invalid("spam block list: %q is not an address or a domain", e)
			}
		}
	}
	return nil
}

// RspamdActions renders the score from which Rspamd refuses a message.
func RspamdActions(reject int) string {
	if reject == 0 {
		reject = DefaultSpamReject
	}
	return fmt.Sprintf("# Managed by XCP (ADR-0030). Changes are overwritten.\nreject = %d;\n", reject)
}

// rspamdMultimap puts the block list into Rspamd: senders on it get a score
// above the usual refusal limit.
func rspamdMultimap(blockMap string) string {
	return "# Managed by XCP (ADR-0030). Changes are overwritten.\n" +
		"XCP_BLOCKED_SENDER {\n  type = \"from\";\n  map = \"" + blockMap + "\";\n  score = 20.0;\n  description = \"Sender on the server block list\";\n}\n"
}

// rspamdWhitelist trusts mail of the allowed domains, but only when it is
// signed (DKIM) or passes SPF: a forged sender gets no credit.
func rspamdWhitelist(allowMap string) string {
	return "# Managed by XCP (ADR-0030). Changes are overwritten.\n" +
		"rules {\n  \"XCP_ALLOWED_DOMAIN\" {\n    domains = \"" + allowMap + "\";\n    valid_dkim = true;\n    valid_spf = true;\n    score = -6.0;\n  }\n}\n"
}

func mapFile(l []string) string {
	l = slices.Clone(l)
	slices.Sort(l)
	if len(l) == 0 {
		return "# empty\n"
	}
	return strings.Join(l, "\n") + "\n"
}

// writeSpamServer writes Rspamd's refusal score and the global lists.
func (m *Mail) writeSpamServer(s MailSettings) (bool, error) {
	local := filepath.Join(m.RspamdDir, "local.d")
	xcp := filepath.Join(m.RspamdDir, "xcp")
	allowMap, blockMap := filepath.Join(xcp, "allow_domains.map"), filepath.Join(xcp, "block_senders.map")
	changed := false
	for _, f := range []struct{ dir, name, content string }{
		{xcp, "allow_domains.map", mapFile(s.SpamAllow)},
		{xcp, "block_senders.map", mapFile(s.SpamBlock)},
		{local, "actions.conf", RspamdActions(s.SpamReject)},
		{local, "multimap.conf", rspamdMultimap(blockMap)},
		{local, "whitelist.conf", rspamdWhitelist(allowMap)},
	} {
		c, err := writeFile(f.dir, f.name, f.content, 0o644, "")
		if err != nil {
			return false, err
		}
		changed = changed || c
	}
	return changed, nil
}
