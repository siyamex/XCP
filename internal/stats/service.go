// Package stats shows an account's bandwidth per domain and month
// (USR-STAT-01) and its web server logs (USR-STAT-03). xcp-logd counts the
// bytes; the agent reads the logs (ADR-0012).
package stats

import (
	"context"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Features that switch the pages on.
const (
	FeatureStats = "stats"
	FeatureLogs  = "logs"
)

// Bytes are bytes by kind.
type Bytes struct {
	Web   int64 `json:"web"`
	Mail  int64 `json:"mail"`
	FTP   int64 `json:"ftp"`
	Total int64 `json:"total"`
}

func (b *Bytes) add(u store.Usage) {
	b.Web += u.Web
	b.Mail += u.Mail
	b.FTP += u.FTP
	b.Total += u.Web + u.Mail + u.FTP
}

// DomainBytes is one domain's month.
type DomainBytes struct {
	Domain string `json:"domain"`
	Bytes
}

// DayBytes is the account's day.
type DayBytes struct {
	Day string `json:"day"`
	Bytes
}

// Bandwidth is an account's month.
type Bandwidth struct {
	Month   string        `json:"month"` // 2006-01
	LimitMB *int64        `json:"limit_mb"`
	Total   Bytes         `json:"total"`
	Domains []DomainBytes `json:"domains"`
	Days    []DayBytes    `json:"days"` // every day of the month up to today
}

// Service shows usage and logs.
type Service struct {
	db    *store.DB
	plans *plans.Service
	agent agentrpc.Client
	Now   func() time.Time
}

// NewService returns a stats service.
func NewService(db *store.DB, pl *plans.Service, ag agentrpc.Client) *Service {
	return &Service{db: db, plans: pl, agent: ag, Now: time.Now}
}

// access loads an account the caller may see (admins the admin-owned
// accounts, users their own with the feature), with its limits.
func (s *Service) access(ctx context.Context, p *auth.Principal, accountID, feature string) (*store.Account, plans.Limits, error) {
	if p == nil {
		return nil, plans.Limits{}, apperr.ErrForbidden
	}
	a, err := s.db.AccountByID(ctx, accountID)
	if err != nil {
		return nil, plans.Limits{}, err
	}
	lim, features, err := s.plans.Entitlements(ctx, a.PackageID)
	if err != nil {
		return nil, plans.Limits{}, err
	}
	switch p.Login.Role {
	case store.RoleAdmin:
		if a.OwnerID != "" {
			return nil, plans.Limits{}, store.ErrNotFound
		}
	case store.RoleUser:
		if p.Login.AccountID != a.ID {
			return nil, plans.Limits{}, store.ErrNotFound
		}
		if !slices.Contains(features, feature) {
			return nil, plans.Limits{}, apperr.ErrForbidden
		}
	default:
		return nil, plans.Limits{}, apperr.ErrForbidden
	}
	return a, lim, nil
}

// Bandwidth returns an account's bandwidth in a month ("2006-01"; empty:
// this month), in UTC days.
func (s *Service) Bandwidth(ctx context.Context, p *auth.Principal, accountID, month string) (Bandwidth, error) {
	a, lim, err := s.access(ctx, p, accountID, FeatureStats)
	if err != nil {
		return Bandwidth{}, err
	}
	now := s.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	if month != "" {
		if start, err = time.Parse("2006-01", month); err != nil {
			return Bandwidth{}, &validate.Error{Field: "month", Code: validate.CodeFormat, Message: "a month like 2026-11"}
		}
	}
	last := start.AddDate(0, 1, -1)
	b := Bandwidth{Month: start.Format("2006-01"), LimitMB: lim.BandwidthMB, Domains: []DomainBytes{}, Days: []DayBytes{}}
	us, err := store.AccountUsage(ctx, s.db.R, a.ID, start.Format(time.DateOnly), last.Format(time.DateOnly))
	if err != nil {
		return b, err
	}
	byDomain := map[string]*DomainBytes{}
	byDay := map[string]*Bytes{}
	for _, u := range us {
		b.Total.add(u)
		d := byDomain[u.Domain]
		if d == nil {
			d = &DomainBytes{Domain: u.Domain}
			byDomain[u.Domain] = d
		}
		d.add(u)
		if byDay[u.Day] == nil {
			byDay[u.Day] = &Bytes{}
		}
		byDay[u.Day].add(u)
	}
	for _, d := range byDomain {
		b.Domains = append(b.Domains, *d)
	}
	slices.SortFunc(b.Domains, func(x, y DomainBytes) int {
		if x.Total != y.Total {
			return int(min(max(y.Total-x.Total, -1), 1))
		}
		return strings.Compare(x.Domain, y.Domain)
	})
	for d := start; !d.After(last) && !d.After(now); d = d.AddDate(0, 0, 1) {
		day := DayBytes{Day: d.Format(time.DateOnly)}
		if v := byDay[day.Day]; v != nil {
			day.Bytes = *v
		}
		b.Days = append(b.Days, day)
	}
	return b, nil
}

func checkKind(kind string) error {
	if kind != agent.LogAccess && kind != agent.LogError {
		return &validate.Error{Field: "kind", Code: validate.CodeFormat, Message: "access or error"}
	}
	return nil
}

// Tail returns the last lines of an account's access or error log.
func (s *Service) Tail(ctx context.Context, p *auth.Principal, accountID, kind string, lines int, contains string) ([]string, error) {
	a, _, err := s.access(ctx, p, accountID, FeatureLogs)
	if err != nil {
		return nil, err
	}
	if err := checkKind(kind); err != nil {
		return nil, err
	}
	if lines < 1 || lines > agent.LogMaxLines {
		return nil, &validate.Error{Field: "lines", Code: validate.CodeOutOfRange, Message: "1 to 1000"}
	}
	if len(contains) > agent.LogMaxContains || strings.ContainsAny(contains, "\r\n") {
		return nil, &validate.Error{Field: "q", Code: validate.CodeFormat, Message: "one line of at most 200 characters"}
	}
	res, err := s.agent.SiteLogTail(ctx, &agentv1.SiteLogTailRequest{Username: a.Username, Kind: kind, Lines: int32(lines), Contains: contains}) //nolint:gosec // G115: 1..1000
	if err != nil {
		return nil, err
	}
	out := res.GetLines()
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// Download writes an account's whole current log to w, as big as it was
// when the download started. start is called before the first byte, so the
// caller can send headers only when the log is there.
func (s *Service) Download(ctx context.Context, p *auth.Principal, accountID, kind string, start func(), w io.Writer) error {
	a, _, err := s.access(ctx, p, accountID, FeatureLogs)
	if err != nil {
		return err
	}
	if err := checkKind(kind); err != nil {
		return err
	}
	size := int64(-1)
	for off := int64(0); size < 0 || off < size; {
		res, err := s.agent.SiteLogRead(ctx, &agentv1.SiteLogReadRequest{Username: a.Username, Kind: kind, Offset: off, Length: agent.LogMaxChunk})
		if err != nil {
			if off == 0 {
				return err
			}
			return nil // headers are out: end the body early
		}
		if size < 0 {
			size = res.GetSize()
			start()
		}
		if len(res.GetData()) == 0 {
			break
		}
		if _, err := w.Write(res.GetData()); err != nil {
			return nil //nolint:nilerr // the client went away: nothing to report to it
		}
		off += int64(len(res.GetData()))
	}
	return nil
}
