// Package cronjobs manages the cron jobs of accounts (USR-ADV-01): add,
// edit and delete them, with their next runs and last run. The panel
// database is the source of truth; xcp-agent runs them (ADR-0011).
package cronjobs

import (
	"context"
	"database/sql"
	"slices"
	"strings"
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
	"github.com/siyamex/XCP/internal/validate"
)

// FeatureCron switches cron jobs on in a feature list.
const FeatureCron = "cron"

// Run is a job's last run.
type Run struct {
	Start      time.Time `json:"start"`
	DurationMS int64     `json:"duration_ms"`
	ExitCode   int       `json:"exit_code"`
	Output     string    `json:"output"`
	Skipped    string    `json:"skipped,omitempty"`
}

// Job is the API view of a cron job.
type Job struct {
	ID        string      `json:"id"`
	Schedule  string      `json:"schedule"`
	Command   string      `json:"command"`
	Email     string      `json:"email"`
	Enabled   bool        `json:"enabled"`
	NextRuns  []time.Time `json:"next_runs"`
	LastRun   *Run        `json:"last_run"`
	CreatedAt time.Time   `json:"created_at"`
	JobID     string      `json:"job_id,omitempty"`
}

// Overview is everything the cron page shows.
type Overview struct {
	Jobs         []Job  `json:"jobs"`
	MaxJobs      *int64 `json:"max_jobs"`
	TimeZone     string `json:"time_zone"` // schedules are in the server's time
	DefaultEmail string `json:"default_email"`
	StatusError  string `json:"status_error,omitempty"` // the last runs could not be read
}

// Input creates or changes a job.
type Input struct {
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Email    string `json:"email"`
	Enabled  *bool  `json:"enabled"` // nil: on
}

// Service manages cron jobs.
type Service struct {
	db    *store.DB
	audit *audit.Recorder
	plans *plans.Service
	jobs  *jobs.Queue
	agent agentrpc.Client
	Now   func() time.Time
}

// NewService returns a cron job service.
func NewService(db *store.DB, rec *audit.Recorder, pl *plans.Service, q *jobs.Queue, ag agentrpc.Client) *Service {
	return &Service{db: db, audit: rec, plans: pl, jobs: q, agent: ag, Now: time.Now}
}

func event(c auth.Client, p *auth.Principal, action, accountID, targetID string, details map[string]any) audit.Event {
	return audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: "cron_job", TargetID: targetID, AccountID: accountID, Details: details,
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
	}
}

// access loads an account the caller may manage (admins the admin-owned
// accounts, users their own with the cron feature), with its limits.
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
		if !slices.Contains(features, FeatureCron) {
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

// unitID is a job's id as the agent knows it (part of a unit name).
func unitID(id string) string { return strings.ToLower(id) }

func (s *Service) view(j store.CronJob, last map[string]*Run) Job {
	v := Job{
		ID: j.ID, Schedule: j.Schedule, Command: j.Command, Email: j.Email, Enabled: j.Enabled,
		NextRuns: []time.Time{}, LastRun: last[unitID(j.ID)], CreatedAt: j.CreatedAt,
	}
	if j.Enabled {
		v.NextRuns = agent.Next(j.Schedule, s.Now(), 3)
	}
	return v
}

// Overview returns an account's cron jobs with their next and last runs.
func (s *Service) Overview(ctx context.Context, p *auth.Principal, accountID string) (Overview, error) {
	a, lim, err := s.access(ctx, p, accountID)
	if err != nil {
		return Overview{}, err
	}
	zone, _ := s.Now().Zone()
	if strings.HasPrefix(zone, "+") || strings.HasPrefix(zone, "-") {
		zone = "UTC" + zone // a zone without an abbreviation, like Asia/Karachi's "+05"
	}
	o := Overview{Jobs: []Job{}, MaxJobs: lim.CronJobs, TimeZone: zone, DefaultEmail: a.Email}
	js, err := store.AccountCronJobs(ctx, s.db.R, a.ID)
	if err != nil {
		return o, err
	}
	last := map[string]*Run{}
	st, err := s.agent.CronStatus(ctx, &agentv1.CronStatusRequest{Username: a.Username})
	if err != nil {
		o.StatusError = "the last runs are not available right now"
	}
	for _, r := range st.GetRuns() {
		last[r.GetJobId()] = &Run{
			Start: time.Unix(r.GetStartUnix(), 0).UTC(), DurationMS: r.GetDurationMs(), ExitCode: int(r.GetExitCode()),
			Output: r.GetOutput(), Skipped: r.GetSkipped(),
		}
	}
	for _, j := range js {
		o.Jobs = append(o.Jobs, s.view(j, last))
	}
	return o, nil
}

// check validates and normalises an input into j.
func check(in Input, j *store.CronJob) error {
	var err error
	if j.Schedule, err = validate.CronSchedule(in.Schedule); err != nil {
		return validate.WithField(err, "schedule")
	}
	if j.Command, err = validate.CronCommand(in.Command); err != nil {
		return validate.WithField(err, "command")
	}
	j.Email = ""
	if e := strings.TrimSpace(in.Email); e != "" {
		if j.Email, err = validate.Email(e); err != nil {
			return validate.WithField(err, "email")
		}
	}
	j.Enabled = in.Enabled == nil || *in.Enabled
	return nil
}

// Create adds a job.
func (s *Service) Create(ctx context.Context, c auth.Client, p *auth.Principal, accountID string, in Input) (Job, error) {
	a, lim, err := s.forChange(ctx, p, accountID)
	if err != nil {
		return Job{}, err
	}
	j := &store.CronJob{ID: ids.New(), AccountID: a.ID}
	if err := check(in, j); err != nil {
		return Job{}, err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		n, err := store.CountCronJobs(ctx, tx, a.ID)
		if err != nil {
			return err
		}
		if lim.CronJobs != nil && int64(n) >= *lim.CronJobs {
			return apperr.NewConflict("limit_reached", "the package allows no more cron jobs")
		}
		if err := store.InsertCronJob(ctx, tx, j); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "cron.create", a.ID, j.ID, map[string]any{
			"schedule": j.Schedule, "command": j.Command, "email": j.Email, "enabled": j.Enabled,
		}))
	})
	if err != nil {
		return Job{}, err
	}
	v := s.view(*j, nil)
	v.JobID = jobID
	return v, nil
}

func (s *Service) own(ctx context.Context, p *auth.Principal, id string) (*store.CronJob, *store.Account, error) {
	j, err := s.db.CronJobByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	a, _, err := s.forChange(ctx, p, j.AccountID)
	return j, a, err
}

// Update changes a job.
func (s *Service) Update(ctx context.Context, c auth.Client, p *auth.Principal, id string, in Input) (Job, error) {
	j, a, err := s.own(ctx, p, id)
	if err != nil {
		return Job{}, err
	}
	if err := check(in, j); err != nil {
		return Job{}, err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.UpdateCronJob(ctx, tx, j); err != nil {
			return err
		}
		var err error
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "cron.update", a.ID, j.ID, map[string]any{
			"schedule": j.Schedule, "command": j.Command, "email": j.Email, "enabled": j.Enabled,
		}))
	})
	if err != nil {
		return Job{}, err
	}
	v := s.view(*j, nil)
	v.JobID = jobID
	return v, nil
}

// Delete removes a job. A run that is going keeps going.
func (s *Service) Delete(ctx context.Context, c auth.Client, p *auth.Principal, id string) (string, error) {
	j, a, err := s.own(ctx, p, id)
	if err != nil {
		return "", err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteCronJob(ctx, tx, j.ID); err != nil {
			return err
		}
		var err error
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "cron.delete", a.ID, j.ID, map[string]any{"command": j.Command}))
	})
	return jobID, err
}
