package messages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
)

// Notices (ADR-0033): mail to a customer when something happens to its
// account (suspended, reactivated) or when it nears or reaches a limit (disk,
// monthly traffic). The texts can be changed by the admin and by each reseller.

// Kinds of notice.
const (
	NoticeSuspended      = "suspended"
	NoticeUnsuspended    = "unsuspended"
	NoticeDiskWarning    = "disk_warning"
	NoticeDiskFull       = "disk_full"
	NoticeTrafficWarning = "traffic_warning"
	NoticeTrafficFull    = "traffic_full"
)

// NoticeKinds lists them in display order.
var NoticeKinds = []string{NoticeSuspended, NoticeUnsuspended, NoticeDiskWarning, NoticeDiskFull, NoticeTrafficWarning, NoticeTrafficFull}

// Job kinds and schedule of the notices.
const (
	JobNotice      = "messages.notice"
	JobUsage       = "messages.usage"
	UsageSchedule  = "20 * * * *"
	settingEnabled = "settings.notices.enabled" // everything on or off
	settingPercent = "settings.notices.percent" // from this share of a limit
	defaultPercent = 80
)

var defaultNotices = map[string][2]string{
	NoticeSuspended:      {"Your hosting account {{domain}} is suspended", "Hello,\n\nYour account {{username}} for {{domain}} has been suspended.\n\nReason: {{reason}}\n\nYour website, mail and files are not available until it is reactivated. Please contact {{owner}}.\n"},
	NoticeUnsuspended:    {"Your hosting account {{domain}} is active again", "Hello,\n\nYour account {{username}} for {{domain}} has been reactivated. Your website, mail and files are available again.\n\nSign in: {{panel_url}}\n"},
	NoticeDiskWarning:    {"Your disk space is almost used up ({{percent}}%)", "Hello,\n\nThe account {{username}} for {{domain}} uses {{used}} of {{limit}} disk space ({{percent}}%).\n\nFree some space or ask {{owner}} for a bigger package before it is full: when it is, files cannot be saved and mail may bounce.\n"},
	NoticeDiskFull:       {"Your disk space is full", "Hello,\n\nThe account {{username}} for {{domain}} has used all of its disk space ({{used}} of {{limit}}). New files cannot be saved and incoming mail may bounce.\n\nDelete files you do not need, or ask {{owner}} for a bigger package.\n"},
	NoticeTrafficWarning: {"Your traffic this month is almost used up ({{percent}}%)", "Hello,\n\nThe account {{username}} for {{domain}} has used {{used}} of its {{limit}} monthly traffic ({{percent}}%).\n\nIf you need more, ask {{owner}} for a bigger package.\n"},
	NoticeTrafficFull:    {"Your traffic this month is used up", "Hello,\n\nThe account {{username}} for {{domain}} has used all of its monthly traffic ({{used}} of {{limit}}). Contact {{owner}} if your website should stay reachable.\n"},
}

// UsePlans and UseDisk give the service what the usage notices need: the
// package limits and the disk each account uses (bytes by account name).
func (s *Service) UsePlans(p *plans.Service) { s.plans = p }

// UseDisk sets where the disk use of the accounts comes from.
func (s *Service) UseDisk(f func(ctx context.Context) (map[string]int64, error)) { s.disk = f }

// NoticeTemplate is one notice's text for the sender.
type NoticeTemplate struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Custom  bool   `json:"custom"` // false: the built-in text, or the admin's for a reseller
}

func (s *Service) noticeTemplate(ctx context.Context, owner, kind string) NoticeTemplate {
	d := defaultNotices[kind]
	t := NoticeTemplate{Kind: kind, Subject: d[0], Body: d[1]}
	for _, o := range []string{owner, ""} {
		sub, body, found, err := s.db.NoticeTemplate(ctx, o, kind)
		if err == nil && found {
			t.Subject, t.Body, t.Custom = sub, body, o == owner
			return t
		}
	}
	return t
}

// Notices returns the texts of every notice for the sender.
func (s *Service) Notices(ctx context.Context, p *auth.Principal) ([]NoticeTemplate, error) {
	own, err := scopeOf(p)
	if err != nil {
		return nil, err
	}
	out := make([]NoticeTemplate, 0, len(NoticeKinds))
	for _, k := range NoticeKinds {
		out = append(out, s.noticeTemplate(ctx, own, k))
	}
	return out, nil
}

// SetNotice changes one notice's text; an empty subject and body go back to
// the default (the admin's for a reseller).
func (s *Service) SetNotice(ctx context.Context, c auth.Client, p *auth.Principal, kind, subject, body string) (NoticeTemplate, error) {
	own, err := scopeOf(p)
	if err != nil {
		return NoticeTemplate{}, err
	}
	if _, ok := defaultNotices[kind]; !ok {
		return NoticeTemplate{}, store.ErrNotFound
	}
	if strings.TrimSpace(subject) == "" && strings.TrimSpace(body) == "" {
		if err := s.db.DeleteNoticeTemplate(ctx, own, kind); err != nil {
			return NoticeTemplate{}, err
		}
	} else {
		if subject, body, err = checkText(subject, body); err != nil {
			return NoticeTemplate{}, err
		}
		if err := s.db.SetNoticeTemplate(ctx, own, kind, subject, body, s.Now().UTC()); err != nil {
			return NoticeTemplate{}, err
		}
	}
	if err := s.audit.Record(ctx, event(c, p, "messages.notice.set", kind, map[string]any{"reset": subject == ""})); err != nil {
		return NoticeTemplate{}, err
	}
	return s.noticeTemplate(ctx, own, kind), nil
}

func (s *Service) noticesOn(ctx context.Context) bool {
	on := true
	_ = s.db.GetSetting(ctx, settingEnabled, &on)
	return on
}

func (s *Service) percent(ctx context.Context) int {
	p := defaultPercent
	_ = s.db.GetSetting(ctx, settingPercent, &p)
	if p < 50 || p > 99 {
		return defaultPercent
	}
	return p
}

type noticePayload struct {
	AccountID string            `json:"account_id"`
	Kind      string            `json:"kind"`
	Extra     map[string]string `json:"extra"`
}

// AccountEvent queues the notice of something that happened to an account
// (suspended or reactivated). reason is shown in the suspension notice.
func (s *Service) AccountEvent(ctx context.Context, a *store.Account, kind, reason string) {
	if a.Email == "" || !s.noticesOn(ctx) {
		return
	}
	if _, err := s.jobs.Enqueue(ctx, JobNotice, noticePayload{AccountID: a.ID, Kind: kind, Extra: map[string]string{"reason": reason}},
		jobs.EnqueueOptions{AccountID: a.ID, MaxAttempts: 3}); err != nil {
		s.log.Warn("queue a notice", "account", a.Username, "kind", kind, "err", err)
	}
}

func (s *Service) noticeJob(ctx context.Context, j *jobs.Job, _ jobs.Reporter) (any, error) {
	var p noticePayload
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.AccountID == "" {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	if _, ok := defaultNotices[p.Kind]; !ok {
		return nil, jobs.Permanent(fmt.Errorf("unknown notice %q", p.Kind))
	}
	a, err := s.db.AccountByID(ctx, p.AccountID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "account removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	if a.Email == "" {
		return map[string]string{"skipped": "no email address"}, nil
	}
	t := s.noticeTemplate(ctx, a.OwnerID, p.Kind)
	v := s.vars(ctx, a)
	for k, x := range p.Extra {
		v[k] = x
	}
	if v["reason"] == "" {
		v["reason"] = "no reason was given"
	}
	if err := s.mailer.Send(ctx, s.info.From(ctx), a.Email, Render(t.Subject, v), Render(t.Body, v)); err != nil {
		return nil, err
	}
	return map[string]string{"sent_to": a.Email, "kind": p.Kind}, nil
}

// Schedule adds the hourly look at the accounts' usage.
func (s *Service) Schedule(sched *jobs.Scheduler) error {
	return sched.Every(UsageSchedule, JobUsage, struct{}{})
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// usageJob mails the customers whose disk or monthly traffic reached the
// warning share of their package or all of it. Each notice goes out once:
// disk again after the use has fallen below the warning share, traffic once a
// month.
func (s *Service) usageJob(ctx context.Context, _ *jobs.Job, r jobs.Reporter) (any, error) {
	if !s.noticesOn(ctx) || s.plans == nil {
		return map[string]string{"skipped": "notices are off"}, nil
	}
	pct := s.percent(ctx)
	accts, err := s.db.ListAccounts(ctx, store.AccountFilter{OwnerID: "*"})
	if err != nil {
		return nil, err
	}
	var disk map[string]int64
	if s.disk != nil {
		if disk, err = s.disk(ctx); err != nil {
			r.Logf("disk use: %v", err)
		}
	}
	now := s.Now().UTC()
	month := now.Format("2006-01")
	first := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)
	sent := 0
	for i := range accts {
		a := &accts[i]
		if a.Status != store.AccountActive || a.Email == "" {
			continue
		}
		lim, _, err := s.plans.Entitlements(ctx, a.PackageID)
		if err != nil {
			continue
		}
		type check struct {
			warn, full string
			used, max  int64
			period     string
		}
		var checks []check
		if lim.DiskMB != nil && *lim.DiskMB > 0 {
			if used, ok := disk[a.Username]; ok {
				checks = append(checks, check{NoticeDiskWarning, NoticeDiskFull, used, *lim.DiskMB << 20, ""})
			}
		}
		if lim.BandwidthMB != nil && *lim.BandwidthMB > 0 {
			us, err := store.AccountUsage(ctx, s.db.R, a.ID, first, now.Format(time.DateOnly))
			if err == nil {
				var total int64
				for _, u := range us {
					total += u.Web + u.Mail + u.FTP
				}
				checks = append(checks, check{NoticeTrafficWarning, NoticeTrafficFull, total, *lim.BandwidthMB << 20, month})
			}
		}
		for _, c := range checks {
			share := c.used * 100 / c.max
			level := ""
			switch {
			case c.used >= c.max:
				level = c.full
			case share >= int64(pct):
				level = c.warn
			}
			// Under the warning share again: a later rise is news again.
			if level == "" && c.period == "" {
				_ = s.db.ClearNoticeSent(ctx, a.ID, c.warn)
				_ = s.db.ClearNoticeSent(ctx, a.ID, c.full)
				continue
			}
			if level == "" {
				continue
			}
			if level == c.warn && c.period == "" && c.used < c.max {
				_ = s.db.ClearNoticeSent(ctx, a.ID, c.full)
			}
			if done, err := s.db.NoticeSent(ctx, a.ID, level, c.period); err != nil || done {
				continue
			}
			// Once "full" was told, the earlier warning is not told again.
			if level == c.warn {
				if full, _ := s.db.NoticeSent(ctx, a.ID, c.full, c.period); full {
					continue
				}
			}
			if err := s.db.MarkNoticeSent(ctx, a.ID, level, c.period, now); err != nil {
				return nil, err
			}
			if _, err := s.jobs.Enqueue(ctx, JobNotice, noticePayload{AccountID: a.ID, Kind: level, Extra: map[string]string{
				"used": humanBytes(c.used), "limit": humanBytes(c.max), "percent": fmt.Sprint(share),
			}}, jobs.EnqueueOptions{AccountID: a.ID, MaxAttempts: 3}); err != nil {
				return nil, err
			}
			sent++
		}
	}
	return map[string]int{"queued": sent}, nil
}
