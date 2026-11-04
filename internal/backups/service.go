// Package backups makes, lists, downloads and deletes account backups
// (USR-BAK-01) and runs the admin's backup schedule (ADM-BAK-01). The agent
// makes the archives (ADR-0013); the panel records them.
package backups

import (
	"context"
	"database/sql"
	"io"
	"slices"
	"time"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
)

// FeatureBackups switches backups on in a feature list.
const FeatureBackups = "backups"

// MaxManual is how many backups an account may keep that it made itself.
const MaxManual = 3

// Backup is the API view of a backup.
type Backup struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`   // manual or scheduled
	Status     string     `json:"status"` // running, ok or failed
	File       string     `json:"file"`
	Size       int64      `json:"size"`
	Detail     string     `json:"detail"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at"`
	JobID      string     `json:"job_id,omitempty"`
}

// Overview is everything the backups page shows.
type Overview struct {
	Backups   []Backup `json:"backups"`
	MaxManual int      `json:"max_manual"`
	Schedule  Schedule `json:"schedule"`
}

// Service manages backups.
type Service struct {
	db    *store.DB
	audit *audit.Recorder
	plans *plans.Service
	jobs  *jobs.Queue
	agent agentrpc.Client
	Now   func() time.Time

	applier Applier
	zones   ZoneQueuer
}

// NewService returns a backups service.
func NewService(db *store.DB, rec *audit.Recorder, pl *plans.Service, q *jobs.Queue, ag agentrpc.Client) *Service {
	return &Service{db: db, audit: rec, plans: pl, jobs: q, agent: ag, Now: time.Now}
}

func event(c auth.Client, p *auth.Principal, action, accountID, targetID string, details map[string]any) audit.Event {
	e := audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: "backup", TargetID: targetID, AccountID: accountID, Details: details,
	}
	if p != nil {
		e.ActorID, e.ImpersonatorID, e.Role = p.Login.ID, p.Session.ImpersonatorID, p.Login.Role
	}
	return e
}

// access loads an account the caller may manage (admins the admin-owned
// accounts, users their own with the backups feature).
func (s *Service) access(ctx context.Context, p *auth.Principal, accountID string) (*store.Account, error) {
	if p == nil {
		return nil, apperr.ErrForbidden
	}
	a, err := s.db.AccountByID(ctx, accountID)
	if err != nil {
		return nil, err
	}
	_, features, err := s.plans.Entitlements(ctx, a.PackageID)
	if err != nil {
		return nil, err
	}
	switch p.Login.Role {
	case store.RoleAdmin:
		if a.OwnerID != "" {
			return nil, store.ErrNotFound
		}
	case store.RoleUser:
		if p.Login.AccountID != a.ID {
			return nil, store.ErrNotFound
		}
		if !slices.Contains(features, FeatureBackups) {
			return nil, apperr.ErrForbidden
		}
	default:
		return nil, apperr.ErrForbidden
	}
	return a, nil
}

func view(b store.Backup) Backup {
	return Backup{
		ID: b.ID, Kind: b.Kind, Status: b.Status, File: b.File, Size: b.Size, Detail: b.Detail,
		CreatedAt: b.CreatedAt, FinishedAt: b.FinishedAt, JobID: b.JobID,
	}
}

// Overview returns an account's backups.
func (s *Service) Overview(ctx context.Context, p *auth.Principal, accountID string) (Overview, error) {
	a, err := s.access(ctx, p, accountID)
	if err != nil {
		return Overview{}, err
	}
	sched, err := s.schedule(ctx)
	if err != nil {
		return Overview{}, err
	}
	o := Overview{Backups: []Backup{}, MaxManual: MaxManual, Schedule: sched}
	bs, err := store.AccountBackups(ctx, s.db.R, a.ID)
	if err != nil {
		return o, err
	}
	for _, b := range bs {
		o.Backups = append(o.Backups, view(b))
	}
	return o, nil
}

// start records a backup and queues its job, inside tx.
func (s *Service) start(ctx context.Context, tx *sql.Tx, createdBy string, a *store.Account, kind string) (*store.Backup, error) {
	b := &store.Backup{ID: ids.New(), AccountID: a.ID, Username: a.Username, Kind: kind, Status: store.BackupRunning}
	jobID, err := s.jobs.EnqueueTx(ctx, tx, JobCreate, createPayload{BackupID: b.ID}, jobs.EnqueueOptions{
		AccountID: a.ID, LockKey: "account:" + a.ID, MaxAttempts: 1, CreatedBy: createdBy,
	})
	if err != nil {
		return nil, err
	}
	b.JobID = jobID
	return b, store.InsertBackup(ctx, tx, b)
}

// Create starts a backup the account makes itself.
func (s *Service) Create(ctx context.Context, c auth.Client, p *auth.Principal, accountID string) (Backup, error) {
	a, err := s.access(ctx, p, accountID)
	if err != nil {
		return Backup{}, err
	}
	if a.Status != store.AccountActive && a.Status != store.AccountSuspended {
		return Backup{}, apperr.NewConflict("bad_status", "not possible while the account is "+a.Status)
	}
	var b *store.Backup
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		bs, err := store.AccountBackups(ctx, tx, a.ID)
		if err != nil {
			return err
		}
		manual := 0
		for _, x := range bs {
			if x.Status == store.BackupRunning {
				return apperr.NewConflict("busy", "a backup of this account is being made")
			}
			if x.Kind == store.BackupManual && x.Status == store.BackupOK {
				manual++
			}
		}
		if manual >= MaxManual {
			return apperr.NewConflict("limit_reached", "delete a backup first: you can keep 3 of your own")
		}
		if b, err = s.start(ctx, tx, p.Login.ID, a, store.BackupManual); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "backup.create", a.ID, b.ID, nil))
	})
	if err != nil {
		return Backup{}, err
	}
	return view(*b), nil
}

// own loads a backup the caller may manage: an account's own, or, for a
// removed account's, any admin.
func (s *Service) own(ctx context.Context, p *auth.Principal, id string) (*store.Backup, error) {
	b, err := s.db.BackupByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if b.AccountID == "" {
		if err := adminOnly(p); err != nil {
			return nil, store.ErrNotFound
		}
		return b, nil
	}
	_, err = s.access(ctx, p, b.AccountID)
	return b, err
}

// remove deletes a backup's file and record.
func (s *Service) remove(ctx context.Context, b *store.Backup) error {
	if b.File != "" {
		if _, err := s.agent.BackupDelete(ctx, &agentv1.BackupDeleteRequest{Username: b.Username, File: b.File}); err != nil {
			return err
		}
	}
	return store.DeleteBackup(ctx, s.db.W, b.ID)
}

// Delete removes a backup.
func (s *Service) Delete(ctx context.Context, c auth.Client, p *auth.Principal, id string) error {
	b, err := s.own(ctx, p, id)
	if err != nil {
		return err
	}
	if b.Status == store.BackupRunning {
		return apperr.NewConflict("busy", "the backup is still being made")
	}
	if err := s.remove(ctx, b); err != nil {
		return err
	}
	return s.audit.Record(ctx, event(c, p, "backup.delete", b.AccountID, b.ID, map[string]any{"file": b.File}))
}

// Download writes a finished backup to w. start is called before the first
// byte, with the file's name and size, so the caller can send headers.
func (s *Service) Download(ctx context.Context, c auth.Client, p *auth.Principal, id string, start func(name string, size int64), w io.Writer) error {
	b, err := s.own(ctx, p, id)
	if err != nil {
		return err
	}
	if b.Status != store.BackupOK {
		return apperr.NewConflict("not_ready", "the backup is not finished")
	}
	if err := s.audit.Record(ctx, event(c, p, "backup.download", b.AccountID, b.ID, map[string]any{"file": b.File})); err != nil {
		return err
	}
	for off := int64(0); off < b.Size; {
		res, err := s.agent.BackupRead(ctx, &agentv1.BackupReadRequest{Username: b.Username, File: b.File, Offset: off, Length: agent.BackupMaxRead})
		if err != nil {
			if off == 0 {
				return err
			}
			return nil // headers are out: end the body early
		}
		if off == 0 {
			start(b.File, res.GetSize())
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

// Apply implements accounts.Extra: backups keep no state on the server
// that an account apply would change.
func (s *Service) Apply(context.Context, *store.Account) (string, error) {
	return "nothing to apply", nil
}

// RemoveAccount implements accounts.Extra: an account's backups stay (they
// are the only way to get it back); their records lose the account and
// show up for admins.
func (s *Service) RemoveAccount(context.Context, string) (string, error) {
	return "backups kept for restore", nil
}
