package logd

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/fwcfg"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/store"
)

// Journal units whose failed logins xcp-logd counts (ADR-0017). Postfix's is
// read for bandwidth too (Ingester.Unit).
var BruteUnits = []string{"ssh.service", "dovecot.service", "pure-ftpd.service"}

// Failure is one refused login.
type Failure struct {
	IP     netip.Addr
	Source string // ssh, mail, ftp or panel
	At     time.Time
}

var (
	sshFailures = []*regexp.Regexp{
		regexp.MustCompile(`^Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?\S+ from (\S+) port \d+`),
		regexp.MustCompile(`^Invalid user \S* from (\S+) port \d+`),
		regexp.MustCompile(`^Disconnecting authenticating user \S+ (\S+) port \d+: Too many authentication failures`),
	}
	postfixFailure = regexp.MustCompile(`^warning: \S+\[(\S+)\]: SASL \S+ authentication failed`)
	dovecotFailure = regexp.MustCompile(`auth failed, \d+ attempts? in \d+ secs\).*?rip=([0-9a-fA-F:.]+)`)
	ftpFailure     = regexp.MustCompile(`^\([^@)]*@([0-9a-fA-F:.]+)\) \[WARNING\] Authentication failed for user`)
)

// ParseFailure recognises a refused login in a journal message of a unit.
// The time is the caller's.
func ParseFailure(unit, msg string) (Failure, bool) {
	var res []*regexp.Regexp
	source := ""
	switch {
	case unit == "ssh.service" || unit == "sshd.service":
		res, source = sshFailures, store.BanSSH
	case strings.HasPrefix(unit, "postfix"):
		res, source = []*regexp.Regexp{postfixFailure}, store.BanMail
	case unit == "dovecot.service":
		res, source = []*regexp.Regexp{dovecotFailure}, store.BanMail
	case unit == "pure-ftpd.service":
		res, source = []*regexp.Regexp{ftpFailure}, store.BanFTP
	default:
		return Failure{}, false
	}
	for _, re := range res {
		if m := re.FindStringSubmatch(msg); m != nil {
			ip, err := netip.ParseAddr(m[1])
			if err != nil {
				return Failure{}, false
			}
			return Failure{IP: ip.Unmap(), Source: source}, true
		}
	}
	return Failure{}, false
}

// Detector counts failures per address in a sliding window.
type Detector struct {
	hits map[netip.Addr][]time.Time
}

const maxTracked = 100000

// Add records a failure and reports whether the address reached the
// threshold within the window; its count then starts again.
func (d *Detector) Add(ip netip.Addr, at time.Time, threshold int, window time.Duration) bool {
	if d.hits == nil || len(d.hits) > maxTracked {
		d.hits = map[netip.Addr][]time.Time{}
	}
	list := d.hits[ip]
	cut := 0
	for cut < len(list) && at.Sub(list[cut]) > window {
		cut++
	}
	list = append(slices.Clone(list[cut:]), at)
	if len(list) >= threshold {
		delete(d.hits, ip)
		return true
	}
	d.hits[ip] = list
	return false
}

// bruteForce bans the addresses that failed too often. Nothing happens
// while the firewall or the protection is off, for allowed addresses or
// for this server itself.
func (in *Ingester) bruteForce(ctx context.Context, fails []Failure) {
	if len(fails) == 0 || in.Queue == nil {
		return
	}
	cfg, err := fwcfg.Load(ctx, in.DB, 0)
	if err != nil {
		in.Log.Warn("read the firewall settings", "err", err)
		return
	}
	if !cfg.Enabled || !cfg.Brute.Enabled {
		return
	}
	window := time.Duration(cfg.Brute.WindowMinutes) * time.Minute
	allow := fwcfg.Cidrs(cfg.Allow)
	banned := false
	for _, f := range fails {
		if !slices.Contains(cfg.Brute.Sources, f.Source) || f.IP.IsLoopback() || f.IP.IsUnspecified() || fwcfg.Contains(allow, f.IP) {
			continue
		}
		if !in.det.Add(f.IP, f.At, cfg.Brute.Threshold, window) {
			continue
		}
		ok, err := in.ban(ctx, cfg, f)
		if err != nil {
			in.Log.Warn("ban an address", "ip", f.IP, "err", err)
		}
		banned = banned || ok
	}
	if banned {
		if _, err := fwcfg.EnqueueApply(ctx, in.Queue, "xcp-logd"); err != nil {
			in.Log.Warn("queue the firewall", "err", err)
		}
	}
}

// ban records a ban of an address that has none in force. Repeat
// offenders are banned for good.
func (in *Ingester) ban(ctx context.Context, cfg fwcfg.Config, f Failure) (bool, error) {
	now := time.Now().UTC()
	if active, err := store.IsBanned(ctx, in.DB.R, f.IP.String(), now); err != nil || active {
		return false, err
	}
	prev, err := store.CountBans(ctx, in.DB.R, f.IP.String())
	if err != nil {
		return false, err
	}
	b := &store.FWBan{ID: ids.New(), IP: f.IP.String(), Source: f.Source, CreatedAt: now}
	b.Reason = fmt.Sprintf("%d failed logins (%s) within %d minutes", cfg.Brute.Threshold, f.Source, cfg.Brute.WindowMinutes)
	if cfg.Brute.PermanentAfter == 0 || prev < cfg.Brute.PermanentAfter {
		t := now.Add(time.Duration(cfg.Brute.BanMinutes) * time.Minute)
		b.ExpiresAt = &t
	} else {
		b.Reason += fmt.Sprintf("; banned %d times before", prev)
	}
	if err := store.InsertBan(ctx, in.DB.W, b); err != nil {
		return false, err
	}
	if in.Audit != nil {
		_ = in.Audit.Record(ctx, audit.Event{
			Action: "firewall.ban", Result: audit.ResultOK, Role: "system", TargetType: "firewall", TargetID: b.ID,
			Details: map[string]any{"ip": b.IP, "source": f.Source, "permanent": b.ExpiresAt == nil},
		})
	}
	in.Log.Info("banned", "ip", b.IP, "source", f.Source, "permanent", b.ExpiresAt == nil)
	return true, nil
}
