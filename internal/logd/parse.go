// Package logd turns web, FTP and mail logs into bandwidth per domain and
// day (ADR-0012). The parsers here are pure; xcp-logd feeds them.
package logd

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/store"
)

// Key is one domain on one UTC day.
type Key struct {
	Domain string
	Day    string // 2006-01-02, UTC
}

// Counts are bytes by kind.
type Counts struct {
	Web, Mail, FTP int64
}

// Sums adds up bytes.
type Sums map[Key]*Counts

func (s Sums) add(domain string, at time.Time, web, mail, ftp int64) {
	k := Key{Domain: strings.ToLower(strings.TrimSuffix(domain, ".")), Day: at.UTC().Format(time.DateOnly)}
	c := s[k]
	if c == nil {
		c = &Counts{}
		s[k] = c
	}
	c.Web += web
	c.Mail += mail
	c.FTP += ftp
}

// AddWeb adds an access log line in vhost_combined format:
//
//	example.com:443 192.0.2.1 - - [02/Nov/2026:10:00:00 +0500] "GET / HTTP/1.1" 200 510 "-" "agent"
func (s Sums) AddWeb(line []byte) bool {
	host, rest, ok := bytes.Cut(line, []byte(" "))
	if !ok {
		return false
	}
	if i := bytes.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	open := bytes.IndexByte(rest, '[')
	end := bytes.IndexByte(rest, ']')
	if open < 0 || end < open {
		return false
	}
	at, err := time.Parse("02/Jan/2006:15:04:05 -0700", string(rest[open+1:end]))
	if err != nil {
		return false
	}
	// The request line is quoted, with \" inside it escaped.
	rest = rest[end+1:]
	q := bytes.IndexByte(rest, '"')
	if q < 0 {
		return false
	}
	i := q + 1
	for ; i < len(rest); i++ {
		if rest[i] == '\\' {
			i++
			continue
		}
		if rest[i] == '"' {
			break
		}
	}
	if i >= len(rest) {
		return false
	}
	fields := bytes.Fields(rest[i+1:])
	if len(fields) < 2 {
		return false
	}
	n, err := strconv.ParseInt(string(fields[1]), 10, 64)
	if err != nil || n < 0 {
		return false // "-": nothing sent
	}
	s.add(string(host), at, n, 0, 0)
	return true
}

// AddFTP adds an xferlog line:
//
//	Mon Nov 02 10:00:23 2026 0 127.0.0.1 15 /home/u/a b.txt b _ i r web@example.com ftp 1 * c
//
// The file name may hold spaces, so the fields after it are taken from the end.
func (s Sums) AddFTP(line []byte, loc *time.Location) bool {
	f := strings.Fields(string(line))
	if len(f) < 18 {
		return false
	}
	at, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(f[:5], " "), loc)
	if err != nil {
		return false
	}
	n, err := strconv.ParseInt(f[7], 10, 64)
	if err != nil || n < 0 {
		return false
	}
	user := f[len(f)-5]
	_, domain, ok := strings.Cut(user, "@")
	if !ok || domain == "" {
		return false
	}
	s.add(domain, at, 0, 0, n)
	return true
}

// Mail follows Postfix's log lines of each message, by queue ID, and adds
// the message's size to a domain on each delivery.
type Mail struct {
	q map[string]*message
	// Deliveries collects what happened to each message for each recipient
	// ("track delivery"); the caller takes them and empties the list.
	Deliveries []store.MailDelivery
}

type message struct {
	size       int64
	from, auth string // domains
	sender     string // the envelope sender
}

// maxDetail bounds the other server's answer kept with a delivery.
const maxDetail = 300

func short(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxDetail {
		s = strings.ToValidUTF8(s[:maxDetail], "") + "..."
	}
	return s
}

// refusal reads Postfix's line about mail it refused when it came in:
// "reject: RCPT from host[ip]: 554 5.7.1 why; from=<a> to=<b> proto=..."
// and the milter's "milter-reject: END-OF-MESSAGE from host[ip]: 5.7.1 why; from=...".
func refusal(qid, rest string, at time.Time) (store.MailDelivery, bool) {
	why, addrs, ok := strings.Cut(rest, "; from=<")
	if !ok {
		return store.MailDelivery{}, false
	}
	addrs = " from=<" + addrs
	to := field(addrs, "to")
	if to == "" {
		return store.MailDelivery{}, false
	}
	if _, after, ok := strings.Cut(why, "]: "); ok {
		why = after
	}
	if qid == "NOQUEUE" {
		qid = ""
	}
	return store.MailDelivery{At: at, QueueID: qid, Sender: field(addrs, "from"), Recipient: to, Status: store.DeliveryRejected, Detail: short(why)}, true
}

func domainOf(addr string) string {
	_, d, ok := strings.Cut(addr, "@")
	if !ok {
		return ""
	}
	return d
}

// field returns the value of "name=<v>" or "name=v," in a Postfix line.
func field(msg, name string) string {
	i := strings.Index(msg, " "+name+"=")
	if i < 0 {
		return ""
	}
	v := msg[i+len(name)+2:]
	if strings.HasPrefix(v, "<") {
		v, _, _ = strings.Cut(v[1:], ">")
		return v
	}
	if j := strings.IndexAny(v, ", "); j >= 0 {
		v = v[:j]
	}
	return v
}

// Line takes one Postfix journal message (its MESSAGE field).
func (m *Mail) Line(s Sums, msg string, at time.Time) {
	if m.q == nil {
		m.q = map[string]*message{}
	}
	qid, rest, ok := strings.Cut(msg, ": ")
	if !ok || qid == "" || strings.ContainsAny(qid, " =") || len(m.q) > 100000 {
		if len(m.q) > 100000 {
			m.q = map[string]*message{} // bounded: drop what never got "removed"
		}
		return
	}
	rest = " " + rest
	get := func() *message {
		e := m.q[qid]
		if e == nil {
			e = &message{}
			m.q[qid] = e
		}
		return e
	}
	switch {
	case strings.HasPrefix(rest, " reject: "), strings.HasPrefix(rest, " milter-reject: "):
		if d, ok := refusal(qid, rest, at); ok {
			m.Deliveries = append(m.Deliveries, d)
		}
	case strings.HasPrefix(rest, " removed"):
		delete(m.q, qid)
	case strings.Contains(rest, " sasl_username="):
		get().auth = domainOf(field(rest, "sasl_username"))
	case strings.HasPrefix(rest, " from=") && strings.Contains(rest, " size="):
		e := get()
		e.sender = field(rest, "from")
		e.from = domainOf(e.sender)
		e.size, _ = strconv.ParseInt(field(rest, "size"), 10, 64)
	case strings.HasPrefix(rest, " to=") && field(rest, "status") != "":
		e := m.q[qid]
		d := store.MailDelivery{
			At: at, QueueID: qid, Recipient: field(rest, "to"), OrigTo: field(rest, "orig_to"),
			Status: field(rest, "status"), Relay: field(rest, "relay"),
		}
		if i := strings.Index(rest, " status="+d.Status+" ("); i >= 0 {
			d.Detail = short(strings.TrimSuffix(rest[i+len(" status="+d.Status+" ("):], ")"))
		}
		if e != nil {
			d.Sender, d.Size = e.sender, e.size
		}
		m.Deliveries = append(m.Deliveries, d)
		if d.Status != "sent" || e == nil || e.size <= 0 {
			return
		}
		if strings.Contains(field(rest, "relay"), "dovecot-lmtp") {
			s.add(domainOf(field(rest, "to")), at, 0, e.size, 0)
			return
		}
		for _, d := range []string{e.auth, domainOf(field(rest, "orig_to")), e.from} {
			if d != "" {
				s.add(d, at, 0, e.size, 0)
				return
			}
		}
	}
}
