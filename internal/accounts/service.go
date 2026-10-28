// Package accounts manages hosting accounts (ADM-ACC-01..06, 09, 11). An
// account is a Linux user with a home folder and resource limits from its
// package, plus a panel login with the "user" role. Changes to the system
// run as jobs through the agent (jobs.go).
package accounts

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Account is the API view of an account.
type Account struct {
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	UID           int       `json:"uid"`
	PrimaryDomain string    `json:"primary_domain"`
	Email         string    `json:"email"`
	PackageID     string    `json:"package_id"`
	PackageName   string    `json:"package_name"`
	Status        string    `json:"status"`
	StatusDetail  string    `json:"status_detail"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	JobID         string    `json:"job_id,omitempty"` // the job started by the last change, if any
}

// CreateInput creates an account.
type CreateInput struct {
	Username  string `json:"username"`
	Domain    string `json:"domain"`
	PackageID string `json:"package_id"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

// UpdateInput changes an account's package and contact email.
type UpdateInput struct {
	PackageID string `json:"package_id"`
	Email     string `json:"email"`
}

// Job kinds.
const (
	JobApply     = "account.apply"     // create or update the Linux side to match the DB
	JobTerminate = "account.terminate" // remove the Linux side and the account
)

// Service manages accounts.
type Service struct {
	db    *store.DB
	audit *audit.Recorder
	auth  *auth.Service
	plans *plans.Service
	jobs  *jobs.Queue
	agent agentrpc.Client
}

// NewService returns an accounts service.
func NewService(db *store.DB, rec *audit.Recorder, a *auth.Service, pl *plans.Service, q *jobs.Queue, ag agentrpc.Client) *Service {
	return &Service{db: db, audit: rec, auth: a, plans: pl, jobs: q, agent: ag}
}

// scope returns the owner filter for p: admins manage admin-owned accounts
// (resellers get their own in P2).
func scope(p *auth.Principal) (string, error) {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return "", apperr.ErrForbidden
	}
	return "", nil
}

func event(c auth.Client, p *auth.Principal, action, accountID string, details map[string]any) audit.Event {
	e := audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: "account", TargetID: accountID, AccountID: accountID, Details: details, Role: "system",
	}
	if p != nil {
		e.ActorID, e.ImpersonatorID, e.Role = p.Login.ID, p.Session.ImpersonatorID, p.Login.Role
	}
	return e
}

func (s *Service) view(ctx context.Context, a *store.Account) Account {
	v := Account{
		ID: a.ID, Username: a.Username, UID: a.UID, PrimaryDomain: a.PrimaryDomain, Email: a.Email,
		PackageID: a.PackageID, Status: a.Status, StatusDetail: a.StatusDetail, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}
	if pk, err := s.db.PackageByID(ctx, a.PackageID); err == nil {
		v.PackageName = pk.Name
	}
	return v
}

// account loads an account the caller may manage; others look like "not found".
func (s *Service) account(ctx context.Context, p *auth.Principal, id string) (*store.Account, error) {
	own, err := scope(p)
	if err != nil {
		return nil, err
	}
	a, err := s.db.AccountByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if a.OwnerID != own {
		return nil, store.ErrNotFound
	}
	return a, nil
}

// List returns the caller's accounts, newest first.
func (s *Service) List(ctx context.Context, p *auth.Principal, search, status string) ([]Account, error) {
	own, err := scope(p)
	if err != nil {
		return nil, err
	}
	list, err := s.db.ListAccounts(ctx, store.AccountFilter{OwnerID: own, Search: search, Status: status})
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(list))
	for i := range list {
		out = append(out, s.view(ctx, &list[i]))
	}
	return out, nil
}

// Get returns one account.
func (s *Service) Get(ctx context.Context, p *auth.Principal, id string) (Account, error) {
	a, err := s.account(ctx, p, id)
	if err != nil {
		return Account{}, err
	}
	return s.view(ctx, a), nil
}

func fieldErr(err error, name string) error { return validate.WithField(err, name) }

// Create adds an account and its login, and queues the job that creates
// the Linux user. The account starts in status "creating".
func (s *Service) Create(ctx context.Context, c auth.Client, p *auth.Principal, in CreateInput) (Account, error) {
	own, err := scope(p)
	if err != nil {
		return Account{}, err
	}
	username := strings.ToLower(strings.TrimSpace(in.Username))
	if err := fieldErr(validate.Username(username), "username"); err != nil {
		return Account{}, err
	}
	domain, err := validate.Domain(in.Domain)
	if err != nil {
		return Account{}, fieldErr(err, "domain")
	}
	email := ""
	if strings.TrimSpace(in.Email) != "" {
		if email, err = validate.Email(in.Email); err != nil {
			return Account{}, fieldErr(err, "email")
		}
	}
	if _, err := s.plans.GetPackage(ctx, p, in.PackageID); errors.Is(err, store.ErrNotFound) {
		return Account{}, &validate.Error{Field: "package_id", Code: validate.CodeFormat, Message: "no such package"}
	} else if err != nil {
		return Account{}, err
	}
	hash, err := s.auth.HashPassword(ctx, in.Password) // slow: done before taking the write lock
	if err != nil {
		return Account{}, err
	}

	a := &store.Account{
		ID: ids.New(), Username: username, OwnerID: own, PackageID: in.PackageID,
		PrimaryDomain: domain, Email: email, Status: store.AccountCreating,
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		taken, err := store.UsernameTaken(ctx, tx, username)
		if err != nil {
			return err
		}
		if taken {
			return apperr.NewConflict("username_taken", "this username is already used by an account or a login")
		}
		if a.UID, err = store.NextAccountUID(ctx, tx); err != nil {
			return err
		}
		if err := store.InsertAccount(ctx, tx, a); errors.Is(err, store.ErrConflict) {
			return apperr.NewConflict("domain_taken", "another account already uses this domain")
		} else if err != nil {
			return err
		}
		login := &store.Login{
			ID: ids.New(), Username: username, Role: store.RoleUser, PasswordHash: hash,
			Email: email, AccountID: a.ID, OwnerID: p.Login.ID,
		}
		if err := store.CreateLogin(ctx, tx, login); err != nil {
			return err
		}
		if jobID, err = s.enqueue(ctx, tx, p, JobApply, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "account.create", a.ID, map[string]any{
			"username": username, "domain": domain, "package_id": in.PackageID, "uid": a.UID,
		}))
	})
	if err != nil {
		return Account{}, err
	}
	v := s.view(ctx, a)
	v.JobID = jobID
	return v, nil
}

func (s *Service) enqueue(ctx context.Context, tx *sql.Tx, p *auth.Principal, kind, accountID string) (string, error) {
	opt := jobs.EnqueueOptions{AccountID: accountID, LockKey: "account:" + accountID, MaxAttempts: 3}
	if p != nil {
		opt.CreatedBy = p.Login.ID
	}
	return s.jobs.EnqueueTx(ctx, tx, kind, jobPayload{AccountID: accountID}, opt)
}

// change loads an account, checks it is in one of the allowed states, runs
// fn in a transaction and queues an apply (or terminate) job.
func (s *Service) change(ctx context.Context, p *auth.Principal, id string, allowed []string, kind string,
	fn func(tx *sql.Tx, a *store.Account) error,
) (Account, error) {
	a, err := s.account(ctx, p, id)
	if err != nil {
		return Account{}, err
	}
	ok := false
	for _, st := range allowed {
		ok = ok || a.Status == st
	}
	if !ok {
		return Account{}, apperr.NewConflict("bad_status", "not possible while the account is "+a.Status)
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := fn(tx, a); err != nil {
			return err
		}
		if err := store.UpdateAccount(ctx, tx, a); err != nil {
			return err
		}
		if kind == "" {
			return nil
		}
		jobID, err = s.enqueue(ctx, tx, p, kind, a.ID)
		return err
	})
	if err != nil {
		return Account{}, err
	}
	v := s.view(ctx, a)
	v.JobID = jobID
	return v, nil
}

var editable = []string{store.AccountActive, store.AccountSuspended, store.AccountError}

// Update changes the package and contact email, then re-applies limits.
func (s *Service) Update(ctx context.Context, c auth.Client, p *auth.Principal, id string, in UpdateInput) (Account, error) {
	email := ""
	if strings.TrimSpace(in.Email) != "" {
		var err error
		if email, err = validate.Email(in.Email); err != nil {
			return Account{}, fieldErr(err, "email")
		}
	}
	if _, err := s.plans.GetPackage(ctx, p, in.PackageID); errors.Is(err, store.ErrNotFound) {
		return Account{}, &validate.Error{Field: "package_id", Code: validate.CodeFormat, Message: "no such package"}
	} else if err != nil {
		return Account{}, err
	}
	return s.change(ctx, p, id, editable, JobApply, func(tx *sql.Tx, a *store.Account) error {
		before := a.PackageID
		a.PackageID, a.Email = in.PackageID, email
		if a.Status == store.AccountError {
			a.Status, a.StatusDetail = store.AccountCreating, "" // retry the failed setup
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "account.update", a.ID, map[string]any{
			"package_from": before, "package_to": in.PackageID, "email": email,
		}))
	})
}

// Suspend blocks the account: its login is disabled, its sessions end and
// its Linux user is locked with all processes stopped.
func (s *Service) Suspend(ctx context.Context, c auth.Client, p *auth.Principal, id, reason string) (Account, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 500 {
		return Account{}, &validate.Error{Field: "reason", Code: validate.CodeTooLong, Message: "reason must be at most 500 characters"}
	}
	return s.change(ctx, p, id, []string{store.AccountActive}, JobApply, func(tx *sql.Tx, a *store.Account) error {
		a.Status, a.StatusDetail = store.AccountSuspended, reason
		if err := s.setLogin(ctx, tx, a.ID, store.LoginSuspended); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "account.suspend", a.ID, map[string]any{"reason": reason}))
	})
}

// Unsuspend restores a suspended account.
func (s *Service) Unsuspend(ctx context.Context, c auth.Client, p *auth.Principal, id string) (Account, error) {
	return s.change(ctx, p, id, []string{store.AccountSuspended}, JobApply, func(tx *sql.Tx, a *store.Account) error {
		a.Status, a.StatusDetail = store.AccountActive, ""
		if err := s.setLogin(ctx, tx, a.ID, store.LoginActive); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "account.unsuspend", a.ID, nil))
	})
}

// setLogin changes the account login's status and ends its sessions when blocking.
func (s *Service) setLogin(ctx context.Context, tx *sql.Tx, accountID, status string) error {
	l, err := s.db.AccountLogin(ctx, accountID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := store.SetLoginStatus(ctx, tx, l.ID, status); err != nil {
		return err
	}
	if status != store.LoginActive {
		return store.DeleteLoginSessions(ctx, tx, l.ID, nil)
	}
	return nil
}

// SetPassword sets the account login's password and ends its sessions.
func (s *Service) SetPassword(ctx context.Context, c auth.Client, p *auth.Principal, id, password string, mustChange bool) error {
	a, err := s.account(ctx, p, id)
	if err != nil {
		return err
	}
	hash, err := s.auth.HashPassword(ctx, password)
	if err != nil {
		return err
	}
	l, err := s.db.AccountLogin(ctx, a.ID)
	if err != nil {
		return err
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetLoginPassword(ctx, tx, l.ID, hash, mustChange); err != nil {
			return err
		}
		if err := store.DeleteLoginSessions(ctx, tx, l.ID, nil); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "account.password", a.ID, map[string]any{"must_change": mustChange}))
	})
}

// Terminate starts removing an account. confirm must equal the username.
func (s *Service) Terminate(ctx context.Context, c auth.Client, p *auth.Principal, id, confirm string) (Account, error) {
	all := []string{store.AccountCreating, store.AccountActive, store.AccountSuspended, store.AccountError}
	return s.change(ctx, p, id, all, JobTerminate, func(tx *sql.Tx, a *store.Account) error {
		if confirm != a.Username {
			return &validate.Error{Field: "confirm", Code: validate.CodeFormat, Message: "type the account's username to confirm"}
		}
		a.Status, a.StatusDetail = store.AccountTerminating, ""
		if err := s.setLogin(ctx, tx, a.ID, store.LoginLocked); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "account.terminate", a.ID, map[string]any{"username": a.Username}))
	})
}
