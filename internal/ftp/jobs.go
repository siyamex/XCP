package ftp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
)

// JobApply gives the agent all FTP logins of an account. It shares the
// account's lock key, so it runs in order with the account's other jobs.
const JobApply = "ftp.apply"

type applyPayload struct {
	AccountID string `json:"account_id"`
}

// RegisterJobs adds the FTP job handlers to a worker.
func (s *Service) RegisterJobs(w *jobs.Worker) {
	w.Register(JobApply, 4, s.applyJob)
}

// EnqueueApply queues, inside tx, the job that applies an account's FTP
// logins. It is also the hook domains call when a domain is removed.
func (s *Service) EnqueueApply(ctx context.Context, tx *sql.Tx, createdBy, accountID string) (string, error) {
	return s.jobs.EnqueueTx(ctx, tx, JobApply, applyPayload{AccountID: accountID}, jobs.EnqueueOptions{
		AccountID: accountID, LockKey: "account:" + accountID, MaxAttempts: 3, CreatedBy: createdBy,
	})
}

// AccountRequest builds the agent request with an account's logins; a
// suspended account has none.
func (s *Service) AccountRequest(ctx context.Context, a *store.Account) (*agentv1.FTPAccountApplyRequest, error) {
	req := &agentv1.FTPAccountApplyRequest{Username: a.Username}
	if a.Status == store.AccountSuspended {
		return req, nil
	}
	ds, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, d := range ds {
		names[d.ID] = d.Name
	}
	fs, err := store.AccountFTPAccounts(ctx, s.db.R, a.ID)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		req.Logins = append(req.Logins, &agentv1.FTPLogin{
			Login: f.Name + "@" + names[f.DomainID], PasswordHash: f.PasswordHash, Dir: f.HomeRel, QuotaMb: f.QuotaMB,
		})
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

// Apply gives the agent all FTP logins of an account. It reports
// "skipped" when the FTP server is not installed.
func (s *Service) Apply(ctx context.Context, a *store.Account) (string, error) {
	req, err := s.AccountRequest(ctx, a)
	if err != nil {
		return "", err
	}
	res, err := s.agent.FTPAccountApply(ctx, req)
	switch {
	case status.Code(err) == codes.NotFound:
		return "skipped: the FTP server is not installed", nil
	case err != nil:
		return "", permanentIfRefused(err)
	}
	out := fmt.Sprintf("applied: %d FTP login(s)", len(req.GetLogins()))
	if p := res.GetProblems(); len(p) > 0 {
		out += "; " + strings.Join(p, "; ")
	}
	return out, nil
}

// RemoveAccount drops an account's FTP logins (when the account is terminated).
func (s *Service) RemoveAccount(ctx context.Context, username string) (string, error) {
	_, err := s.agent.FTPAccountRemove(ctx, &agentv1.FTPAccountRemoveRequest{Username: username})
	switch {
	case status.Code(err) == codes.NotFound:
		return "skipped: the FTP server is not installed", nil
	case err != nil:
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
	r.Logf("ftp %s", res)
	return map[string]string{"ftp": res}, nil
}
