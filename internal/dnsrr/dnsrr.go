// Package dnsrr validates and normalises the records of hosted DNS zones.
// The API and the agent both use it, so a record the API accepts is one the
// agent accepts (07-security.md §7). Parsing is done by miekg/dns.
package dnsrr

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/miekg/dns"

	"github.com/siyamex/XCP/internal/validate"
)

// Types users may create. The SOA record and the zone's own NS records are
// kept by XCP itself.
var Types = []string{"A", "AAAA", "CAA", "CNAME", "HTTPS", "MX", "NS", "SRV", "SVCB", "TLSA", "TXT"}

// Bounds of records and zones.
const (
	MinTTL     = 60
	MaxTTL     = 604800 // one week
	MaxRecords = 2000   // per zone
	maxContent = 4000
)

// Record is a record of a zone in the form the agent receives it.
type Record struct {
	Name    string // fully qualified, lower case, without the final dot: "www.example.com", "*.example.com"
	Type    string
	TTL     uint32
	Content string // presentation format; names absolute with a final dot; TXT as quoted strings
}

func fail(code, format string, args ...any) error {
	return &validate.Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

var labelRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// Name turns what a user typed for a record's name ("@", "www",
// "www.example.com.") into its fully qualified name in zone.
func Name(input, zone string) (string, error) {
	s := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(input), "."))
	if s == "" || s == "@" || s == zone {
		return zone, nil
	}
	s = strings.TrimSuffix(s, "."+zone)
	for i, l := range strings.Split(s, ".") {
		if l == "*" && i == 0 {
			continue // a wildcard is only the leftmost label
		}
		if !labelRe.MatchString(l) {
			return "", fail(validate.CodeFormat, "%q is not a valid record name (letters, digits, '-', '_'; * only first)", input)
		}
	}
	full := s + "." + zone
	if len(full) > validate.MaxDomainLen {
		return "", fail(validate.CodeTooLong, "record name is longer than %d characters", validate.MaxDomainLen)
	}
	return full, nil
}

// Relative is the name as users see it: "@" for the zone itself, else the
// part before the zone.
func Relative(name, zone string) string {
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

// hostField is the field that holds a host name, for the types that have one.
var hostField = map[string]int{"CNAME": 0, "NS": 0, "MX": 1, "SRV": 3, "HTTPS": 1, "SVCB": 1}

// Content checks a record's data and returns the form that is stored and
// served. TXT takes plain text. The other types take their zone-file form;
// for the host name in it, "@" is the zone itself, a single label is a name
// in the zone ("mail" is mail.example.com) and a name with dots is complete
// ("mail.google.com"), with or without the final dot.
func Content(typ, input, zone string) (string, error) {
	if !slices.Contains(Types, typ) {
		return "", fail(validate.CodeFormat, "type must be one of %s", strings.Join(Types, ", "))
	}
	if typ == "TXT" {
		return txt(input)
	}
	s := strings.TrimSpace(input)
	switch {
	case s == "":
		return "", fail(validate.CodeRequired, "the record's value is required")
	case len(s) > maxContent:
		return "", fail(validate.CodeTooLong, "the value is longer than %d characters", maxContent)
	case strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || strings.ContainsRune(";()$\\", r) }):
		return "", fail(validate.CodeFormat, "the value must not contain control characters or ; ( ) $ \\")
	}
	fields := strings.Fields(s)
	if i, ok := hostField[typ]; ok && i < len(fields) {
		switch f := fields[i]; {
		case f == "@":
			fields[i] = zone + "."
		case f != "." && !strings.Contains(f, "."):
			fields[i] = f + "." + zone + "."
		}
	}
	rr, err := parse(zone, typ, strings.Join(fields, " "))
	if err != nil {
		return "", err
	}
	if err := checkData(rr); err != nil {
		return "", err
	}
	return rdata(rr), nil
}

// txt stores plain text as TXT strings of at most 255 bytes, split between characters.
func txt(s string) (string, error) {
	switch {
	case s == "":
		return "", fail(validate.CodeRequired, "the text is required")
	case len(s) > maxContent:
		return "", fail(validate.CodeTooLong, "the text is longer than %d characters", maxContent)
	case !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl):
		return "", fail(validate.CodeFormat, "the text must be valid UTF-8 without control characters")
	}
	var chunks []string
	for len(s) > 255 {
		cut := 255
		for !utf8.RuneStart(s[cut]) {
			cut--
		}
		chunks = append(chunks, s[:cut])
		s = s[cut:]
	}
	chunks = append(chunks, s)
	return rdata(&dns.TXT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: chunks}), nil
}

// Plain is a stored value as users enter it: the text of a TXT record, else unchanged.
func Plain(typ, content string) string {
	if typ != "TXT" {
		return content
	}
	rr, err := parse("plain.invalid", "TXT", content)
	if err != nil {
		return content
	}
	return unescape(strings.Join(rr.(*dns.TXT).Txt, ""))
}

// unescape turns TXT data from presentation form (\" \\ \DDD), which is how
// miekg/dns keeps it, back into its bytes.
func unescape(s string) string {
	digit := func(c byte) bool { return c >= '0' && c <= '9' }
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		if i+3 < len(s) && digit(s[i+1]) && digit(s[i+2]) && digit(s[i+3]) {
			if n := int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0'); n <= 255 {
				b.WriteByte(byte(n)) //nolint:gosec // G115: n <= 255 above
				i += 3
				continue
			}
		}
		b.WriteByte(s[i+1])
		i++
	}
	return b.String()
}

// parse reads one record of type typ for name with the given data. Names in
// the data without a final dot are taken as complete (origin ".").
func parse(name, typ, data string) (dns.RR, error) {
	zp := dns.NewZoneParser(strings.NewReader(fmt.Sprintf("%s. 3600 IN %s %s\n", name, typ, data)), ".", "")
	rr, ok := zp.Next()
	if !ok {
		msg := "not a valid " + typ + " value"
		if err := zp.Err(); err != nil {
			msg += ": " + err.Error()
		}
		return nil, fail(validate.CodeFormat, "%s", msg)
	}
	if _, more := zp.Next(); more || dns.TypeToString[rr.Header().Rrtype] != typ {
		return nil, fail(validate.CodeFormat, "not a single %s value", typ)
	}
	return rr, nil
}

// Normalize returns record data in the form miekg/dns prints it, to compare
// data written by others (a DNS server's API); unparsable data is returned as it is.
func Normalize(name, typ, content string) string {
	rr, err := parse(strings.TrimSuffix(name, "."), typ, content)
	if err != nil {
		return content
	}
	return rdata(rr)
}

// rdata is the record's data in presentation format (the record without its header).
func rdata(rr dns.RR) string { return strings.TrimPrefix(rr.String(), rr.Header().String()) }

var caaTags = []string{"issue", "issuewild", "iodef"}

// checkData applies rules the parser does not: host names where a host is
// expected, known CAA tags.
func checkData(rr dns.RR) error {
	host := func(what, name string, rootOK bool) error {
		if name == "." && !rootOK {
			return fail(validate.CodeFormat, "%s cannot be the root", what)
		}
		if net.ParseIP(strings.TrimSuffix(name, ".")) != nil {
			return fail(validate.CodeFormat, "%s must be a host name, not an IP address", what)
		}
		return nil
	}
	switch r := rr.(type) {
	case *dns.CNAME:
		return host("the target", r.Target, false)
	case *dns.NS:
		return host("the name server", r.Ns, false)
	case *dns.MX:
		return host("the mail server", r.Mx, r.Preference == 0) // "0 ." is a null MX (RFC 7505)
	case *dns.SRV:
		return host("the target", r.Target, true) // "." = service not available
	case *dns.CAA:
		if !slices.Contains(caaTags, r.Tag) {
			return fail(validate.CodeFormat, "CAA tag must be one of %s", strings.Join(caaTags, ", "))
		}
	}
	return nil
}

// Check validates a record the agent receives: its stored form must parse
// and come out unchanged.
func Check(zone string, r Record) error {
	if n, err := Name(r.Name, zone); err != nil || n != r.Name {
		return fail(validate.CodeFormat, "record name %q is not a normalised name in %s", r.Name, zone)
	}
	if r.TTL < MinTTL || r.TTL > MaxTTL {
		return fail(validate.CodeOutOfRange, "TTL of %s %s must be %d to %d seconds", r.Name, r.Type, MinTTL, MaxTTL)
	}
	if r.Type == "TXT" {
		if len(r.Content) > 2*maxContent {
			return fail(validate.CodeTooLong, "TXT value of %s is too long", r.Name)
		}
		rr, err := parse(r.Name, "TXT", r.Content)
		if err != nil || rdata(rr) != r.Content {
			return fail(validate.CodeFormat, "TXT value of %s is not in normalised form", r.Name)
		}
		return nil
	}
	if c, err := Content(r.Type, r.Content, zone); err != nil || c != r.Content {
		return fail(validate.CodeFormat, "%s value %q of %s is not in normalised form", r.Type, r.Content, r.Name)
	}
	return nil
}

// CheckZone validates a zone's records together: each one, then that a
// CNAME stands alone and not at the zone's top, and that the zone's own NS
// records are not among them.
func CheckZone(zone string, records []Record) error {
	if n, err := validate.Domain(zone); err != nil || n != zone {
		return fail(validate.CodeFormat, "zone %q is not a normalised domain name", zone)
	}
	if len(records) > MaxRecords {
		return fail(validate.CodeOutOfRange, "a zone can have at most %d records", MaxRecords)
	}
	types := map[string][]string{}
	seen := map[Record]bool{}
	for _, r := range records {
		if err := Check(zone, r); err != nil {
			return err
		}
		key := Record{Name: r.Name, Type: r.Type, Content: r.Content}
		if seen[key] {
			return fail(validate.CodeFormat, "%s %s %s is there twice", r.Name, r.Type, r.Content)
		}
		seen[key] = true
		types[r.Name] = append(types[r.Name], r.Type)
	}
	for name, ts := range types {
		if slices.Contains(ts, "CNAME") && (name == zone || len(ts) > 1) {
			return fail(validate.CodeFormat, "%s: a CNAME must be the only record of its name and cannot be at the zone's top", name)
		}
		if name == zone && slices.Contains(ts, "NS") {
			return fail(validate.CodeFormat, "the NS records of the zone itself come from the server's DNS settings")
		}
	}
	return nil
}
