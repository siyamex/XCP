package accounts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
)

type jobPayload struct {
	AccountID string `json:"account_id"`
}

// RegisterJobs adds the account job handlers to a worker.
func (s *Service) RegisterJobs(w *jobs.Worker) {
	w.Register(JobApply, 4, s.applyJob)
	w.Register(JobTerminate, 2, s.terminateJob)
}

func payload(j *jobs.Job) (string, error) {
	var p jobPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.AccountID == "" {
		return "", jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	return p.AccountID, nil
}

// permanentIfRefused stops retrying when the agent refused the request
// itself (bad input, a foreign Linux user): retrying cannot help.
func permanentIfRefused(err error) error {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied:
		return jobs.Permanent(err)
	}
	return err
}

func shellOf(l plans.Limits) agentv1.Shell {
	switch l.Shell {
	case plans.ShellJailed:
		return agentv1.Shell_SHELL_JAILED
	case plans.ShellFull:
		return agentv1.Shell_SHELL_FULL
	}
	return agentv1.Shell_SHELL_NONE
}

func u32(v *int64) *uint32 {
	if v == nil {
		return nil
	}
	x := uint32(min(max(*v, 0), 1<<31)) //nolint:gosec // G115: clamped above
	return &x
}

func u64(v *int64) *uint64 {
	if v == nil {
		return nil
	}
	x := uint64(max(*v, 0)) //nolint:gosec // G115: clamped above
	return &x
}

// phpChildren derives the PHP worker count from the process limit: a quarter
// of it, between 2 and 50 (10 when unlimited).
func phpChildren(l plans.Limits) uint32 {
	if l.Processes == nil {
		return 10
	}
	return uint32(min(max(*l.Processes/4, 2), 50)) //nolint:gosec // G115: clamped to 2..50
}

func agentLimits(l plans.Limits) *agentv1.ResourceLimits {
	return &agentv1.ResourceLimits{
		CpuPercent: u32(l.CPUPercent), MemoryMb: u64(l.MemoryMB), Tasks: u32(l.Processes),
		DiskMb: u64(l.DiskMB), Inodes: u64(l.Inodes),
	}
}

// applyJob makes the Linux side match the database: user, home, limits and
// suspension state. A new account becomes active when it succeeds.
func (s *Service) applyJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	id, err := payload(j)
	if err != nil {
		return nil, err
	}
	a, err := s.db.AccountByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, jobs.Permanent(err)
	}
	if err != nil {
		return nil, err
	}
	if a.Status == store.AccountTerminating {
		return map[string]string{"skipped": "account is being terminated"}, nil
	}
	pk, err := s.plans.GetPackage(ctx, systemPrincipal, a.PackageID)
	if err != nil {
		return nil, s.fail(ctx, j, a, fmt.Errorf("package: %w", err))
	}
	r.Logf("creating or updating Linux user %s (uid %d)", a.Username, a.UID)
	res, err := s.agent.AccountEnsure(ctx, &agentv1.AccountEnsureRequest{
		Username: a.Username, Uid: uint32(a.UID), Shell: shellOf(pk.Limits), //nolint:gosec // G115: UID is 10000..59999 by schema
		Limits: agentLimits(pk.Limits), PrimaryDomain: a.PrimaryDomain,
	})
	if err != nil {
		return nil, s.fail(ctx, j, a, err)
	}
	r.Progress(50)
	_, err = s.agent.AccountSetSuspended(ctx, &agentv1.AccountSetSuspendedRequest{
		Username: a.Username, Suspended: a.Status == store.AccountSuspended, Shell: shellOf(pk.Limits),
	})
	if err != nil {
		return nil, s.fail(ctx, j, a, err)
	}
	r.Progress(70)
	r.Logf("configuring the website (Apache + PHP-FPM)")
	site, err := s.agent.SiteApply(ctx, &agentv1.SiteApplyRequest{
		Username: a.Username, Uid: uint32(a.UID), Domains: []string{a.PrimaryDomain}, //nolint:gosec // G115: UID is 10000..59999
		PhpVersion: a.PHPVersion, Suspended: a.Status == store.AccountSuspended, MaxChildren: phpChildren(pk.Limits),
	})
	website := "configured"
	switch {
	case status.Code(err) == codes.NotFound:
		website = "skipped: no web server installed"
		r.Logf("website %s", website)
	case err != nil:
		return nil, s.fail(ctx, j, a, err)
	}
	if a.Status == store.AccountCreating || a.Status == store.AccountError {
		if err := s.db.SetAccountStatus(ctx, a.ID, store.AccountActive, ""); err != nil {
			return nil, err
		}
	}
	if !res.GetQuotaApplied() {
		r.Logf("disk quota not applied: the home filesystem has no user quotas enabled")
	}
	return map[string]any{
		"created": res.GetCreated(), "quota_applied": res.GetQuotaApplied(), "home": res.GetHome(),
		"website": website, "php_version": site.GetPhpVersion(),
	}, nil
}

// fail records the error on the account. On the last attempt (or a
// permanent error) an account still being created moves to "error".
func (s *Service) fail(ctx context.Context, j *jobs.Job, a *store.Account, err error) error {
	err = permanentIfRefused(err)
	if a.Status == store.AccountCreating && (jobs.IsPermanent(err) || j.Attempts >= j.MaxAttempts) {
		_ = s.db.SetAccountStatus(ctx, a.ID, store.AccountError, err.Error())
	}
	return err
}

// terminateJob removes the Linux user and then the account and its logins.
func (s *Service) terminateJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	id, err := payload(j)
	if err != nil {
		return nil, err
	}
	a, err := s.db.AccountByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "already removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	r.Logf("removing the website of %s", a.Username)
	if _, err := s.agent.SiteRemove(ctx, &agentv1.SiteRemoveRequest{Username: a.Username}); err != nil && status.Code(err) != codes.NotFound {
		return nil, permanentIfRefused(err)
	}
	r.Logf("removing Linux user %s and its home folder", a.Username)
	res, err := s.agent.AccountDelete(ctx, &agentv1.AccountDeleteRequest{Username: a.Username})
	if err != nil {
		return nil, permanentIfRefused(err)
	}
	r.Progress(80)
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteAccount(ctx, tx, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(auth.Client{}, nil, "account.terminated", a.ID,
			map[string]any{"username": a.Username, "linux_user_removed": res.GetDeleted()}))
	})
	return map[string]any{"username": a.Username, "linux_user_removed": res.GetDeleted()}, err
}

// systemPrincipal lets jobs read admin-owned packages. Jobs run on behalf of
// whoever queued them, after that request was authorised.
var systemPrincipal = &auth.Principal{Login: &store.Login{ID: "system", Role: store.RoleAdmin}, Session: &store.Session{}}
