// Package resellers manages reseller logins and their limits (ADM-RSL-01,
// 02; RSL-USE-01; ADR-0023).
package resellers

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Service manages resellers.
type Service struct {
	db    *store.DB
	audit *audit.Recorder
	auth  *auth.Service
	plans *plans.Service
	Now   func() time.Time
}

// NewService returns a resellers service.
func NewService(db *store.DB, rec *audit.Recorder, a *auth.Service, pl *plans.Service) *Service {
	return &Service{db: db, audit: rec, auth: a, plans: pl, Now: time.Now}
}

// Limits are a reseller's caps; null is unlimited.
type Limits struct {
	MaxAccounts       *int64 `json:"max_accounts"`
	DiskMB            *int64 `json:"disk_mb"`
	BandwidthMB       *int64 `json:"bandwidth_mb"`
	OversellDisk      bool   `json:"oversell_disk"`
	OversellBandwidth bool   `json:"oversell_bandwidth"`
}

// Usage is what a reseller has given out.
type Usage struct {
	Accounts           int   `json:"accounts"`
	Active             int   `json:"active"`
	Suspended          int   `json:"suspended"`
	DiskMB             int64 `json:"disk_mb"`        // disk the packages of its accounts give out
	DiskUnlimited      bool  `json:"disk_unlimited"` // some package has no disk limit
	BandwidthMB        int64 `json:"bandwidth_mb"`
	BandwidthUnlimited bool  `json:"bandwidth_unlimited"`
}

// Reseller is the API view.
type Reseller struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	Limits    Limits    `json:"limits"`
	Usage     Usage     `json:"usage"`
}

func adminOnly(p *auth.Principal) error {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return apperr.ErrForbidden
	}
	return nil
}

func bad(field, msg string) error {
	return &validate.Error{Field: field, Code: validate.CodeOutOfRange, Message: msg}
}

func (l Limits) check() error {
	for field, v := range map[string]*int64{"max_accounts": l.MaxAccounts, "disk_mb": l.DiskMB, "bandwidth_mb": l.BandwidthMB} {
		if v != nil && (*v < 0 || *v > 1_000_000_000) {
			return bad(field, "0 to 1000000000, or empty for unlimited")
		}
	}
	return nil
}

func limitsOf(l store.ResellerLimits) Limits {
	return Limits{MaxAccounts: l.MaxAccounts, DiskMB: l.DiskMB, BandwidthMB: l.BandwidthMB, OversellDisk: l.OversellDisk, OversellBandwidth: l.OversellBandwidth}
}

func (s *Service) usage(ctx context.Context, ownerID string) (Usage, error) {
	owned, err := s.db.OwnedAccounts(ctx, ownerID)
	if err != nil {
		return Usage{}, err
	}
	u := Usage{Accounts: len(owned)}
	for _, a := range owned {
		switch a.Status {
		case store.AccountActive:
			u.Active++
		case store.AccountSuspended:
			u.Suspended++
		}
		l, _, err := s.plans.Entitlements(ctx, a.PackageID)
		if err != nil {
			return u, err
		}
		if l.DiskMB == nil {
			u.DiskUnlimited = true
		} else {
			u.DiskMB += *l.DiskMB
		}
		if l.BandwidthMB == nil {
			u.BandwidthUnlimited = true
		} else {
			u.BandwidthMB += *l.BandwidthMB
		}
	}
	return u, nil
}

func (s *Service) view(ctx context.Context, row store.ResellerRow) (Reseller, error) {
	lim, err := s.db.ResellerLimitsOf(ctx, row.ID)
	if err != nil {
		return Reseller{}, err
	}
	u, err := s.usage(ctx, row.ID)
	if err != nil {
		return Reseller{}, err
	}
	return Reseller{ID: row.ID, Username: row.Username, Email: row.Email, Status: row.Status, CreatedAt: row.CreatedAt, Limits: limitsOf(lim), Usage: u}, nil
}

// List returns the resellers (admins).
func (s *Service) List(ctx context.Context, p *auth.Principal) ([]Reseller, error) {
	if err := adminOnly(p); err != nil {
		return nil, err
	}
	rows, err := s.db.ListResellers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Reseller, 0, len(rows))
	for _, r := range rows {
		v, err := s.view(ctx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Service) find(ctx context.Context, id string) (store.ResellerRow, error) {
	rows, err := s.db.ListResellers(ctx)
	if err != nil {
		return store.ResellerRow{}, err
	}
	for _, r := range rows {
		if r.ID == id {
			return r, nil
		}
	}
	return store.ResellerRow{}, store.ErrNotFound
}

// CreateInput makes a reseller.
type CreateInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Limits   Limits `json:"limits"`
}

// Create makes a reseller login with limits (admins).
func (s *Service) Create(ctx context.Context, c auth.Client, p *auth.Principal, in CreateInput) (Reseller, error) {
	if err := adminOnly(p); err != nil {
		return Reseller{}, err
	}
	if err := in.Limits.check(); err != nil {
		return Reseller{}, err
	}
	email := ""
	if e := strings.TrimSpace(in.Email); e != "" {
		var err error
		if email, err = validate.Email(e); err != nil {
			return Reseller{}, validate.WithField(err, "email")
		}
	}
	l, err := s.auth.CreateLogin(ctx, c, p, auth.NewLogin{Username: in.Username, Password: in.Password, Email: email, Role: store.RoleReseller, OwnerID: p.Login.ID})
	if err != nil {
		return Reseller{}, err
	}
	if err := store.SetResellerLimits(ctx, s.db.W, store.ResellerLimits{
		LoginID: l.ID, MaxAccounts: in.Limits.MaxAccounts, DiskMB: in.Limits.DiskMB, BandwidthMB: in.Limits.BandwidthMB,
		OversellDisk: in.Limits.OversellDisk, OversellBandwidth: in.Limits.OversellBandwidth,
	}, s.Now().UTC()); err != nil {
		return Reseller{}, err
	}
	if err := s.audit.Record(ctx, s.event(c, p, "reseller.create", l.ID, map[string]any{"username": l.Username})); err != nil {
		return Reseller{}, err
	}
	row, err := s.find(ctx, l.ID)
	if err != nil {
		return Reseller{}, err
	}
	return s.view(ctx, row)
}

// SetLimits changes a reseller's limits (admins). Lowering them below what
// the reseller has already given out is allowed: it only stops new accounts.
func (s *Service) SetLimits(ctx context.Context, c auth.Client, p *auth.Principal, id string, in Limits) (Reseller, error) {
	if err := adminOnly(p); err != nil {
		return Reseller{}, err
	}
	if err := in.check(); err != nil {
		return Reseller{}, err
	}
	row, err := s.find(ctx, id)
	if err != nil {
		return Reseller{}, err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetResellerLimits(ctx, tx, store.ResellerLimits{
			LoginID: id, MaxAccounts: in.MaxAccounts, DiskMB: in.DiskMB, BandwidthMB: in.BandwidthMB,
			OversellDisk: in.OversellDisk, OversellBandwidth: in.OversellBandwidth,
		}, s.Now().UTC()); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, s.event(c, p, "reseller.limits", id, map[string]any{"username": row.Username}))
	})
	if err != nil {
		return Reseller{}, err
	}
	return s.view(ctx, row)
}

// SetStatus suspends or reactivates a reseller's own login (admins). Its
// customers' accounts are not touched: suspend them separately.
func (s *Service) SetStatus(ctx context.Context, c auth.Client, p *auth.Principal, id string, suspend bool) (Reseller, error) {
	if err := adminOnly(p); err != nil {
		return Reseller{}, err
	}
	row, err := s.find(ctx, id)
	if err != nil {
		return Reseller{}, err
	}
	status, action := store.LoginActive, "reseller.unsuspend"
	if suspend {
		status, action = store.LoginSuspended, "reseller.suspend"
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetLoginStatus(ctx, tx, id, status); err != nil {
			return err
		}
		if suspend {
			if err := store.DeleteLoginSessions(ctx, tx, id, nil); err != nil {
				return err
			}
		}
		return s.audit.RecordTx(ctx, tx, s.event(c, p, action, id, map[string]any{"username": row.Username}))
	})
	if err != nil {
		return Reseller{}, err
	}
	row.Status = status
	return s.view(ctx, row)
}

// Overview is a reseller's own dashboard (RSL-USE-01): the limits and what
// has been given out, with overselling shown.
func (s *Service) Overview(ctx context.Context, p *auth.Principal) (Reseller, error) {
	if p == nil || p.Login.Role != store.RoleReseller {
		return Reseller{}, apperr.ErrForbidden
	}
	row, err := s.find(ctx, p.Login.ID)
	if err != nil {
		return Reseller{}, err
	}
	return s.view(ctx, row)
}

func (s *Service) event(c auth.Client, p *auth.Principal, action, id string, details map[string]any) audit.Event {
	return audit.Event{
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: "reseller", TargetID: id, Details: details,
	}
}
