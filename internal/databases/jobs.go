package databases

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
)

// Job kinds. Apply and drop share the account's lock key, so they run in
// order with each other and with the account's own jobs.
const (
	JobApply  = "mysql.apply"  // make MariaDB hold the account's users, grants and databases
	JobDrop   = "mysql.drop"   // drop one database with its data
	JobExpire = "mysql.expire" // drop expired phpMyAdmin sign-on users
)

// ExpireSchedule is how often JobExpire runs.
const ExpireSchedule = "*/10 * * * *"

type applyPayload struct {
	AccountID string `json:"account_id"`
}

type dropPayload struct {
	AccountID string `json:"account_id"`
	Database  string `json:"database"`
}

// RegisterJobs adds the database job handlers to a worker.
func (s *Service) RegisterJobs(w *jobs.Worker) {
	w.Register(JobApply, 4, s.applyJob)
	w.Register(JobDrop, 2, s.dropJob)
	w.Register(JobExpire, 1, s.expireJob)
}

// Schedule adds the expiry of sign-on users to a scheduler.
func (s *Service) Schedule(sched *jobs.Scheduler) error {
	return sched.Every(ExpireSchedule, JobExpire, struct{}{})
}

func (s *Service) enqueueApply(ctx context.Context, tx *sql.Tx, createdBy, accountID string) (string, error) {
	return s.jobs.EnqueueTx(ctx, tx, JobApply, applyPayload{AccountID: accountID}, jobs.EnqueueOptions{
		AccountID: accountID, LockKey: "account:" + accountID, MaxAttempts: 3, CreatedBy: createdBy,
	})
}

func (s *Service) enqueueDrop(ctx context.Context, tx *sql.Tx, createdBy, accountID, name string) (string, error) {
	return s.jobs.EnqueueTx(ctx, tx, JobDrop, dropPayload{AccountID: accountID, Database: name}, jobs.EnqueueOptions{
		AccountID: accountID, LockKey: "account:" + accountID, MaxAttempts: 3, CreatedBy: createdBy,
	})
}

// AccountRequest builds the agent request that makes MariaDB hold the
// account's databases and users as stored, locked if it is suspended.
func (s *Service) AccountRequest(ctx context.Context, a *store.Account) (*agentv1.MySQLAccountApplyRequest, error) {
	dbs, err := s.db.ListDatabases(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	users, err := store.ListDBUsers(ctx, s.db.R, a.ID)
	if err != nil {
		return nil, err
	}
	grants, err := store.AccountGrants(ctx, s.db.R, a.ID)
	if err != nil {
		return nil, err
	}
	req := &agentv1.MySQLAccountApplyRequest{Username: a.Username, Locked: a.Status == store.AccountSuspended}
	name := map[string]string{}
	for _, d := range dbs {
		req.Databases = append(req.Databases, d.Name)
		name[d.ID] = d.Name
	}
	byUser := map[string][]*agentv1.MySQLGrant{}
	for _, g := range grants {
		byUser[g.UserID] = append(byUser[g.UserID], &agentv1.MySQLGrant{Database: name[g.DatabaseID], Privileges: g.Privileges})
	}
	for _, u := range users {
		hash, err := s.box.Open(u.PasswordEnc, []byte("db-user:"+u.ID))
		if err != nil {
			return nil, fmt.Errorf("database user %s: %w", u.Name, err)
		}
		req.Users = append(req.Users, &agentv1.MySQLUser{Name: u.Name, PasswordHash: string(hash), Grants: byUser[u.ID]})
	}
	return req, nil
}

// permanentIfRefused stops retrying when the agent refused the request
// itself: retrying cannot help.
func permanentIfRefused(err error) error {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied:
		return jobs.Permanent(err)
	}
	return err
}

// Apply makes MariaDB hold the account's databases and users. It reports
// "skipped" when MariaDB is not installed.
func (s *Service) Apply(ctx context.Context, a *store.Account) (string, error) {
	req, err := s.AccountRequest(ctx, a)
	if err != nil {
		return "", err
	}
	_, err = s.agent.MySQLAccountApply(ctx, req)
	switch {
	case status.Code(err) == codes.NotFound:
		return "skipped: MariaDB is not installed", nil
	case err != nil:
		return "", permanentIfRefused(err)
	}
	return fmt.Sprintf("applied: %d database(s), %d user(s)", len(req.GetDatabases()), len(req.GetUsers())), nil
}

func (s *Service) applyJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p applyPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.AccountID == "" {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	a, err := s.db.AccountByID(ctx, p.AccountID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "account removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	if a.Status == store.AccountTerminating {
		return map[string]string{"skipped": "account is being terminated"}, nil
	}
	res, err := s.Apply(ctx, a)
	if err != nil {
		return nil, err
	}
	r.Logf("databases %s", res)
	return map[string]string{"databases": res}, nil
}

func (s *Service) dropJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p dropPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.AccountID == "" || p.Database == "" {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	a, err := s.db.AccountByID(ctx, p.AccountID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "account removed"}, nil // terminating dropped everything
	}
	if err != nil {
		return nil, err
	}
	if _, err := s.db.DatabaseByName(ctx, p.Database); err == nil {
		// Made again after the delete: keep the new one.
		return map[string]string{"skipped": p.Database + " exists again"}, nil
	}
	r.Logf("dropping database %s", p.Database)
	res, err := s.agent.MySQLDatabaseDrop(ctx, &agentv1.MySQLDatabaseDropRequest{Username: a.Username, Database: p.Database})
	switch {
	case status.Code(err) == codes.NotFound:
		return map[string]string{"skipped": "MariaDB is not installed"}, nil
	case err != nil:
		return nil, permanentIfRefused(err)
	}
	return map[string]any{"database": p.Database, "dropped": res.GetDropped()}, nil
}

func (s *Service) expireJob(ctx context.Context, _ *jobs.Job, _ jobs.Reporter) (any, error) {
	res, err := s.agent.MySQLSignonExpire(ctx, &agentv1.MySQLSignonExpireRequest{})
	if status.Code(err) == codes.NotFound {
		return map[string]string{"skipped": "MariaDB is not installed"}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]uint32{"dropped": res.GetDropped()}, nil
}

// RemoveAccount drops all databases and users of an account from MariaDB
// (when the account is terminated).
func (s *Service) RemoveAccount(ctx context.Context, username string) (string, error) {
	res, err := s.agent.MySQLAccountRemove(ctx, &agentv1.MySQLAccountRemoveRequest{Username: username})
	switch {
	case status.Code(err) == codes.NotFound:
		return "skipped: MariaDB is not installed", nil
	case err != nil:
		return "", permanentIfRefused(err)
	}
	return fmt.Sprintf("removed %d database(s) and %d user(s)", res.GetDatabases(), res.GetUsers()), nil
}
