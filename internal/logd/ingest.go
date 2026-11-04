package logd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/execx"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
)

// Paths of the Ubuntu setup made by xcp-install.
const (
	WebLogs        = "/var/log/apache2/xcp/*.access.log"
	FTPLog         = "/var/log/pure-ftpd/xferlog"
	JournalctlPath = "/usr/bin/journalctl"
	MailUnit       = "postfix@-.service"
	maxJournal     = 32 << 20
)

// Ingester reads the logs and adds their bytes to the database, once per Tick.
type Ingester struct {
	DB      *store.DB
	Run     *execx.Runner // runs journalctl; nil: no mail
	WebLogs string        // glob of the access logs
	FTPLog  string
	Unit    string // Postfix's unit in the journal
	Log     *slog.Logger
	Queue   *jobs.Queue     // for queueing the firewall; nil: no brute-force bans
	Audit   *audit.Recorder // optional
	det     Detector
	mail    Mail
}

const (
	sourceInit    = "init" // marks that xcp-logd ran before
	sourceJournal = "journal:mail"
	sourceAudit   = "audit:logins" // the panel's refused sign-ins: the last audit event read
)

// Tick reads what the logs gained since the last tick and stores the bytes
// together with the new offsets. On the very first tick the logs are only
// marked, not counted: their past is not this server's panel's business.
func (in *Ingester) Tick(ctx context.Context) error {
	offs, err := store.LogOffsets(ctx, in.DB.R)
	if err != nil {
		return err
	}
	_, ran := offs[sourceInit]
	sums := Sums{}
	var next []store.LogOffset
	files, err := filepath.Glob(in.WebLogs)
	if err != nil {
		return err
	}
	read := func(path string, add func([]byte)) {
		key := "file:" + path
		o := offs[key]
		b, no, err := ReadNew(path, Offset{Inode: o.Inode, Offset: o.Offset}, !ran)
		if err != nil {
			in.Log.Warn("read a log", "path", path, "err", err)
		}
		for line := range bytes.Lines(b) {
			add(bytes.TrimRight(line, "\r\n"))
		}
		if no != (Offset{Inode: o.Inode, Offset: o.Offset}) {
			next = append(next, store.LogOffset{Source: key, Inode: no.Inode, Offset: no.Offset})
		}
	}
	for _, f := range files {
		read(f, func(l []byte) { sums.AddWeb(l) })
	}
	if in.FTPLog != "" {
		read(in.FTPLog, func(l []byte) { sums.AddFTP(l, time.Local) })
	}
	var fails []Failure
	if in.Run != nil {
		cursor, jf, err := in.journal(ctx, offs[sourceJournal].Cursor, ran, sums)
		if err != nil {
			in.Log.Warn("read the mail log", "err", err)
		} else {
			fails = append(fails, jf...)
			if cursor != offs[sourceJournal].Cursor {
				next = append(next, store.LogOffset{Source: sourceJournal, Cursor: cursor})
			}
		}
	}
	if pf, off, err := in.panelFailures(ctx, offs[sourceAudit], ran); err != nil {
		in.Log.Warn("read the panel's sign-in failures", "err", err)
	} else {
		fails = append(fails, pf...)
		if off != offs[sourceAudit].Offset {
			next = append(next, store.LogOffset{Source: sourceAudit, Offset: off})
		}
	}
	in.bruteForce(ctx, fails)
	if !ran {
		next = append(next, store.LogOffset{Source: sourceInit})
	}
	if len(next) == 0 && len(sums) == 0 {
		return nil
	}
	stored := 0
	err = in.DB.Tx(ctx, func(tx *sql.Tx) error {
		accounts, err := store.DomainAccounts(ctx, tx)
		if err != nil {
			return err
		}
		for k, c := range sums {
			acct := accounts[k.Domain]
			if acct == "" {
				continue // not a domain of an account (the host name, a removed domain)
			}
			if err := store.AddUsage(ctx, tx, acct, store.Usage{Domain: k.Domain, Day: k.Day, Web: c.Web, Mail: c.Mail, FTP: c.FTP}); err != nil {
				return err
			}
			stored++
		}
		for _, o := range next {
			if err := store.SetLogOffset(ctx, tx, o); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil && stored > 0 {
		in.Log.Info("counted", "domains", stored, "sources", len(next))
	}
	return err
}

type journalEntry struct {
	Cursor   string          `json:"__CURSOR"`
	Realtime string          `json:"__REALTIME_TIMESTAMP"` // microseconds
	Message  json.RawMessage `json:"MESSAGE"`
	Unit     string          `json:"_SYSTEMD_UNIT"`
}

// journal reads the entries of Postfix and the services whose failed
// logins are counted, after cursor, and returns the new cursor and the
// failures. Postfix's feed the bandwidth sums. Without a cursor it starts
// from now ("since:<unix>" until an entry comes).
func (in *Ingester) journal(ctx context.Context, cursor string, ran bool, sums Sums) (string, []Failure, error) {
	if cursor == "" || !ran {
		return "since:" + strconv.FormatInt(time.Now().Unix(), 10), nil, nil
	}
	args := []string{"--no-pager", "--output=json", "--unit=" + in.Unit}
	for _, u := range BruteUnits {
		args = append(args, "--unit="+u)
	}
	if since, ok := strings.CutPrefix(cursor, "since:"); ok {
		args = append(args, "--since=@"+since)
	} else {
		args = append(args, "--after-cursor="+cursor)
	}
	res, err := in.Run.Run(ctx, execx.Cmd{Path: JournalctlPath, Args: args, Timeout: 2 * time.Minute, MaxOutput: maxJournal})
	var ee *execx.ExitError
	if err != nil && (!errors.As(err, &ee) || len(res.Stdout) != 0) {
		return cursor, nil, err
	}
	out := res.Stdout
	if res.Truncated {
		out = out[:bytes.LastIndexByte(out, '\n')+1] // the rest comes next time
	}
	var fails []Failure
	for line := range bytes.Lines(out) {
		var e journalEntry
		if json.Unmarshal(line, &e) != nil || e.Cursor == "" {
			continue
		}
		cursor = e.Cursor
		var msg string
		if json.Unmarshal(e.Message, &msg) != nil {
			continue // not text
		}
		us, _ := strconv.ParseInt(e.Realtime, 10, 64)
		at := time.UnixMicro(us)
		if e.Unit == in.Unit || e.Unit == "" {
			in.mail.Line(sums, msg, at)
		}
		if f, ok := ParseFailure(e.Unit, msg); ok {
			f.At = at
			fails = append(fails, f)
		}
	}
	return cursor, fails, nil
}

// panelFailures returns the panel's refused sign-ins after the last audit
// event read (the first time: none, only where to start).
func (in *Ingester) panelFailures(ctx context.Context, off store.LogOffset, ran bool) ([]Failure, int64, error) {
	if !ran || off.Source == "" {
		id, err := store.MaxAuditID(ctx, in.DB.R)
		return nil, id, err
	}
	list, last, err := store.LoginFailuresAfter(ctx, in.DB.R, off.Offset)
	if err != nil {
		return nil, off.Offset, err
	}
	var out []Failure
	for _, f := range list {
		if ip, err := netip.ParseAddr(f.IP); err == nil {
			out = append(out, Failure{IP: ip.Unmap(), Source: store.BanPanel, At: f.At})
		}
	}
	return out, last, nil
}

// Loop ticks once a minute until ctx ends.
func (in *Ingester) Loop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if err := in.Tick(ctx); err != nil && ctx.Err() == nil {
			in.Log.Error("count the logs", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
