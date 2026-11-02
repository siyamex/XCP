package cronjobs

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

// JobApply gives the agent all cron jobs of an account. It shares the
// account's lock key, so it runs in order with the account's other jobs.
const JobApply = "cron.apply"

type applyPayload struct {
	AccountID string `json:"account_id"`
}

// RegisterJobs adds the cron job handlers to a worker.
func (s *Service) RegisterJobs(w *jobs.Worker) {
	w.Register(JobApply, 4, s.applyJob)
}

// EnqueueApply queues, inside tx, the job that applies an account's cron jobs.
func (s *Service) EnqueueApply(ctx context.Context, tx *sql.Tx, createdBy, accountID string) (string, error) {
	return s.jobs.EnqueueTx(ctx, tx, JobApply, applyPayload{AccountID: accountID}, jobs.EnqueueOptions{
		AccountID: accountID, LockKey: "account:" + accountID, MaxAttempts: 3, CreatedBy: createdBy,
	})
}

// AccountRequest builds the agent request with an account's enabled jobs;
// a suspended account has none.
func (s *Service) AccountRequest(ctx context.Context, a *store.Account) (*agentv1.CronAccountApplyRequest, error) {
	req := &agentv1.CronAccountApplyRequest{Username: a.Username}
	if a.Status == store.AccountSuspended {
		return req, nil
	}
	js, err := store.AccountCronJobs(ctx, s.db.R, a.ID)
	if err != nil {
		return nil, err
	}
	for _, j := range js {
		if j.Enabled {
			req.Jobs = append(req.Jobs, &agentv1.CronJob{Id: unitID(j.ID), Schedule: j.Schedule, Command: j.Command, MailTo: j.Email})
		}
	}
	return req, nil
}

func permanentIfRefused(err error) error {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied:
		return jobs.Permanent(err)
	}
	return err
}

// Apply gives the agent all cron jobs of an account.
func (s *Service) Apply(ctx context.Context, a *store.Account) (string, error) {
	req, err := s.AccountRequest(ctx, a)
	if err != nil {
		return "", err
	}
	if _, err := s.agent.CronAccountApply(ctx, req); err != nil {
		return "", permanentIfRefused(err)
	}
	return fmt.Sprintf("applied: %d cron job(s)", len(req.GetJobs())), nil
}

// RemoveAccount drops an account's cron jobs (when the account is terminated).
func (s *Service) RemoveAccount(ctx context.Context, username string) (string, error) {
	if _, err := s.agent.CronAccountRemove(ctx, &agentv1.CronAccountRemoveRequest{Username: username}); err != nil {
		return "", permanentIfRefused(err)
	}
	return "removed", nil
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
	if a.Status == store.AccountTerminating || a.Status == store.AccountCreating {
		return map[string]string{"skipped": "account is " + a.Status}, nil
	}
	res, err := s.Apply(ctx, a)
	if err != nil {
		return nil, err
	}
	r.Logf("cron %s", res)
	return map[string]string{"cron": res}, nil
}
