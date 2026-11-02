// Package ftp manages the FTP logins of accounts (USR-FTP-01): create,
// delete, change password, folder and quota. The panel database is the
// source of truth; jobs give the agent each account's logins (ADR-0010).
package ftp

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/pwhash"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// FeatureFTP switches FTP management on in a feature list.
const FeatureFTP = "ftp"

// Domain is a domain FTP logins can be named after.
type Domain struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// Login is the API view of an FTP login.
type Login struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	Login     string    `json:"login"`  // name@domain
	Folder    string    `json:"folder"` // relative to the home; "." is the home
	QuotaMB   int64     `json:"quota_mb"`
	CreatedAt time.Time `json:"created_at"`
	JobID     string    `json:"job_id,omitempty"`
}

// Overview is everything the FTP page shows.
type Overview struct {
	Domains   []Domain `json:"domains"`
	Logins    []Login  `json:"logins"`
	MaxLogins *int64   `json:"max_logins"`
	Server    string   `json:"server"` // the host name FTP clients connect to
	Port      int      `json:"port"`
}

// Input creates a login.
type Input struct {
	DomainID string `json:"domain_id"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Folder   string `json:"folder"` // empty: the home
	QuotaMB  int64  `json:"quota_mb"`
}

// Update changes a login's folder and quota.
type Update struct {
	Folder  string `json:"folder"`
	QuotaMB int64  `json:"quota_mb"`
}

// HostnameSource tells the server's host name (package ssl).
type HostnameSource interface {
	Hostname(ctx context.Context) string
}

// Service manages FTP logins.
type Service struct {
	db    *store.DB
	audit *audit.Recorder
	plans *plans.Service
	jobs  *jobs.Queue
	agent agentrpc.Client
	host  HostnameSource
}

// NewService returns an FTP service.
func NewService(db *store.DB, rec *audit.Recorder, pl *plans.Service, q *jobs.Queue, ag agentrpc.Client, host HostnameSource) *Service {
	return &Service{db: db, audit: rec, plans: pl, jobs: q, agent: ag, host: host}
}

func badField(field, code, msg string) error {
	return &validate.Error{Field: field, Code: code, Message: msg}
}

func event(c auth.Client, p *auth.Principal, action, accountID, targetID string, details map[string]any) audit.Event {
	return audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: "ftp_account", TargetID: targetID, AccountID: accountID, Details: details,
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
	}
}

// access loads an account the caller may manage (admins the admin-owned
// accounts, users their own with the ftp feature), with its limits.
func (s *Service) access(ctx context.Context, p *auth.Principal, accountID string) (*store.Account, plans.Limits, error) {
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
		if !slices.Contains(features, FeatureFTP) {
			return nil, plans.Limits{}, apperr.ErrForbidden
		}
	default:
		return nil, plans.Limits{}, apperr.ErrForbidden
	}
	return a, lim, nil
}

func (s *Service) forChange(ctx context.Context, p *auth.Principal, accountID string) (*store.Account, plans.Limits, error) {
	a, lim, err := s.access(ctx, p, accountID)
	if err != nil {
		return nil, lim, err
	}
	if a.Status != store.AccountActive && a.Status != store.AccountSuspended {
		return nil, lim, apperr.NewConflict("bad_status", "not possible while the account is "+a.Status)
	}
	return a, lim, nil
}

func usable(d store.Domain) bool { return !strings.HasPrefix(d.Name, "*.") }

func (s *Service) server(ctx context.Context) string {
	if s.host != nil {
		return s.host.Hostname(ctx)
	}
	return ""
}

// Overview returns an account's FTP logins.
func (s *Service) Overview(ctx context.Context, p *auth.Principal, accountID string) (Overview, error) {
	a, lim, err := s.access(ctx, p, accountID)
	if err != nil {
		return Overview{}, err
	}
	o := Overview{MaxLogins: lim.FTPAccounts, Server: s.server(ctx), Port: 21, Domains: []Domain{}, Logins: []Login{}}
	ds, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return o, err
	}
	names := map[string]string{}
	for _, d := range ds {
		names[d.ID] = d.Name
		if usable(d) {
			o.Domains = append(o.Domains, Domain{ID: d.ID, Name: d.Name, DisplayName: validate.DomainUnicode(d.Name)})
		}
	}
	fs, err := store.AccountFTPAccounts(ctx, s.db.R, a.ID)
	if err != nil {
		return o, err
	}
	for _, f := range fs {
		o.Logins = append(o.Logins, view(f, names[f.DomainID]))
	}
	return o, nil
}

func view(f store.FTPAccount, domain string) Login {
	return Login{ID: f.ID, DomainID: f.DomainID, Login: f.Name + "@" + domain, Folder: f.HomeRel, QuotaMB: f.QuotaMB, CreatedAt: f.CreatedAt}
}

// folder checks a login's folder, relative to the home.
func folder(in string) (string, error) {
	in = strings.Trim(strings.TrimSpace(in), "/")
	if in == "" {
		return ".", nil
	}
	rel, err := validate.RelPath(in)
	if err != nil {
		return "", validate.WithField(err, "folder")
	}
	if strings.HasPrefix(rel, ".xcp") {
		return "", badField("folder", validate.CodeFormat, "the panel's own folder cannot be an FTP folder")
	}
	return rel, nil
}

func quota(mb int64) (int64, error) {
	if mb < 0 || mb > plans.MaxLimit {
		return 0, badField("quota_mb", validate.CodeOutOfRange, "the quota is 0 (none) or a size in MB")
	}
	return mb, nil
}

func checkLimit(n int, err error, limit *int64) error {
	if err != nil || limit == nil {
		return err
	}
	if int64(n) >= *limit {
		return apperr.NewConflict("limit_reached", "the package allows no more FTP logins")
	}
	return nil
}

// Create adds a login.
func (s *Service) Create(ctx context.Context, c auth.Client, p *auth.Principal, accountID string, in Input) (Login, error) {
	a, lim, err := s.forChange(ctx, p, accountID)
	if err != nil {
		return Login{}, err
	}
	d, err := s.db.DomainByID(ctx, in.DomainID)
	if errors.Is(err, store.ErrNotFound) || err == nil && (d.AccountID != a.ID || !usable(*d)) {
		return Login{}, badField("domain_id", validate.CodeFormat, "choose one of the account's domains")
	}
	if err != nil {
		return Login{}, err
	}
	f := &store.FTPAccount{ID: ids.New(), DomainID: d.ID, Name: strings.ToLower(strings.TrimSpace(in.Name))}
	if agent.CheckFTPLogin(f.Name+"@"+d.Name) != nil {
		return Login{}, badField("name", validate.CodeFormat, "1 to 32 lower-case letters, digits, dots, dashes or underscores, starting and ending with a letter or digit")
	}
	if err := validate.Password(in.Password); err != nil {
		return Login{}, validate.WithField(err, "password")
	}
	if f.HomeRel, err = folder(in.Folder); err != nil {
		return Login{}, err
	}
	if f.QuotaMB, err = quota(in.QuotaMB); err != nil {
		return Login{}, err
	}
	f.PasswordHash = pwhash.Hash(in.Password)
	login := f.Name + "@" + d.Name
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		n, err := store.CountFTPAccounts(ctx, tx, a.ID)
		if err := checkLimit(n, err, lim.FTPAccounts); err != nil {
			return err
		}
		if err := store.InsertFTPAccount(ctx, tx, f); errors.Is(err, store.ErrConflict) {
			return apperr.NewConflict("login_taken", login+" exists already")
		} else if err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "ftp.create", a.ID, f.ID, map[string]any{"login": login, "folder": f.HomeRel, "quota_mb": f.QuotaMB}))
	})
	if err != nil {
		return Login{}, err
	}
	v := view(*f, d.Name)
	v.JobID = jobID
	return v, nil
}

func (s *Service) own(ctx context.Context, p *auth.Principal, id string) (*store.FTPAccount, *store.Account, string, error) {
	f, err := s.db.FTPAccountByID(ctx, id)
	if err != nil {
		return nil, nil, "", err
	}
	d, err := s.db.DomainByID(ctx, f.DomainID)
	if err != nil {
		return nil, nil, "", err
	}
	a, _, err := s.forChange(ctx, p, d.AccountID)
	return f, a, d.Name, err
}

// change stores f and queues the account's apply, with an audit event.
func (s *Service) change(ctx context.Context, c auth.Client, p *auth.Principal, a *store.Account, f *store.FTPAccount, action string, details map[string]any,
	write func(context.Context, *sql.Tx) error,
) (string, error) {
	var jobID string
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := write(ctx, tx); err != nil {
			return err
		}
		var err error
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, action, a.ID, f.ID, details))
	})
	return jobID, err
}

// Update changes a login's folder and quota.
func (s *Service) Update(ctx context.Context, c auth.Client, p *auth.Principal, id string, in Update) (Login, error) {
	f, a, domain, err := s.own(ctx, p, id)
	if err != nil {
		return Login{}, err
	}
	if f.HomeRel, err = folder(in.Folder); err != nil {
		return Login{}, err
	}
	if f.QuotaMB, err = quota(in.QuotaMB); err != nil {
		return Login{}, err
	}
	jobID, err := s.change(ctx, c, p, a, f, "ftp.update", map[string]any{"login": f.Name + "@" + domain, "folder": f.HomeRel, "quota_mb": f.QuotaMB},
		func(ctx context.Context, tx *sql.Tx) error { return store.UpdateFTPAccount(ctx, tx, f) })
	if err != nil {
		return Login{}, err
	}
	v := view(*f, domain)
	v.JobID = jobID
	return v, nil
}

// SetPassword changes a login's password.
func (s *Service) SetPassword(ctx context.Context, c auth.Client, p *auth.Principal, id, password string) (string, error) {
	f, a, domain, err := s.own(ctx, p, id)
	if err != nil {
		return "", err
	}
	if err := validate.Password(password); err != nil {
		return "", validate.WithField(err, "password")
	}
	f.PasswordHash = pwhash.Hash(password)
	return s.change(ctx, c, p, a, f, "ftp.password", map[string]any{"login": f.Name + "@" + domain},
		func(ctx context.Context, tx *sql.Tx) error { return store.UpdateFTPAccount(ctx, tx, f) })
}

// Delete removes a login. Its files stay.
func (s *Service) Delete(ctx context.Context, c auth.Client, p *auth.Principal, id string) (string, error) {
	f, a, domain, err := s.own(ctx, p, id)
	if err != nil {
		return "", err
	}
	return s.change(ctx, c, p, a, f, "ftp.delete", map[string]any{"login": f.Name + "@" + domain},
		func(ctx context.Context, tx *sql.Tx) error { return store.DeleteFTPAccount(ctx, tx, f.ID) })
}
