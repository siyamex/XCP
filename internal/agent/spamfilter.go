package agent

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// SpamFilter is a mailbox's spam rules (USR-MAIL-08, ADR-0029). Rspamd scores
// every message and adds an X-Spam-Level header with one star per point; the
// mailbox's Sieve script reads it.
type SpamFilter struct {
	Enabled   bool
	Threshold int      // stars from which mail is spam: 1 to 50
	Action    string   // SpamJunk or SpamDelete
	Allow     []string // sender addresses; "*" matches any characters, like *@example.com
	Block     []string
}

// Spam actions.
const (
	SpamJunk   = "junk"
	SpamDelete = "delete"
)

// MaxSpamList is the most entries an allow or block list can have.
const MaxSpamList = 200

var spamPatternRe = regexp.MustCompile(`^[A-Za-z0-9._%+@*-]{3,100}$`)

// CleanSpamPattern checks a sender pattern and returns it in lower case.
func CleanSpamPattern(p string) (string, error) {
	p = strings.ToLower(strings.TrimSpace(p))
	if !spamPatternRe.MatchString(p) || !strings.Contains(p, "@") && !strings.Contains(p, "*") {
		return "", fmt.Errorf("%q is not an address or a pattern like *@example.com", p)
	}
	if strings.Trim(p, "*") == "" {
		return "", fmt.Errorf("%q would match everyone", p)
	}
	return p, nil
}

// CheckSpamFilter validates a filter.
func CheckSpamFilter(s SpamFilter) error {
	if s.Threshold < 1 || s.Threshold > 50 {
		return invalid("the spam threshold is 1 to 50")
	}
	if s.Action != SpamJunk && s.Action != SpamDelete {
		return invalid("spam is moved to Junk or deleted")
	}
	for name, l := range map[string][]string{"allow": s.Allow, "block": s.Block} {
		if len(l) > MaxSpamList {
			return invalid("the %s list has at most %d entries", name, MaxSpamList)
		}
		for _, p := range l {
			if c, err := CleanSpamPattern(p); err != nil || c != p {
				return invalid("%s list: %q is not an address or a pattern like *@example.com", name, p)
			}
		}
	}
	return nil
}

func sieveList(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = sieveString(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// spamBlock renders the filter as Sieve: allowed senders pass, blocked ones
// and mail above the threshold are moved to Junk or deleted.
func spamBlock(s SpamFilter) string {
	if !s.Enabled {
		return ""
	}
	act := "  fileinto :create \"Junk\";\n  stop;\n"
	if s.Action == SpamDelete {
		act = "  discard;\n  stop;\n"
	}
	allow, block := slices.Clone(s.Allow), slices.Clone(s.Block)
	slices.Sort(allow)
	slices.Sort(block)
	var b strings.Builder
	first := true
	branch := func(cond string) {
		kw := "if"
		if !first {
			kw = "elsif"
		}
		first = false
		b.WriteString(kw + " " + cond + " {\n")
	}
	if len(allow) > 0 {
		branch("address :matches :all \"from\" " + sieveList(allow))
		b.WriteString("  # allowed sender\n}\n")
	}
	if len(block) > 0 {
		branch("address :matches :all \"from\" " + sieveList(block))
		b.WriteString(act + "}\n")
	}
	branch("header :contains \"X-Spam-Level\" " + sieveString(strings.Repeat("*", s.Threshold)))
	b.WriteString(act + "}\n")
	return b.String()
}

// renderMailboxSieve renders the spam filter and the autoresponder of a
// mailbox as one script. Without a spam filter it is the autoresponder alone.
func renderMailboxSieve(address string, r *Autoresponder, s *SpamFilter) string {
	if s == nil {
		return renderSieve(address, *r)
	}
	req := []string{`"fileinto"`, `"mailbox"`}
	if r != nil {
		req = append(req, `"vacation"`, `"date"`, `"relational"`)
	}
	var b strings.Builder
	b.WriteString("# Managed by XCP (ADR-0008, ADR-0029): the spam filter and autoresponder of " + address + ". Do not edit.\n")
	b.WriteString("require [" + strings.Join(req, ", ") + "];\n")
	b.WriteString(spamBlock(*s))
	if r != nil {
		// The autoresponder part of renderSieve, without its header lines.
		_, body, _ := strings.Cut(renderSieve(address, *r), "\"relational\"];\n")
		b.WriteString(body)
	}
	return b.String()
}
