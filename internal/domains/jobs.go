package domains

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

// JobSiteApply re-applies all websites of an account after a domain or
// redirect change. It shares the account's lock key, so it runs in order
// with the account's own jobs.
const JobSiteApply = "site.apply"

type jobPayload struct {
	AccountID string `json:"account_id"`
}

// RegisterJobs adds the domain job handlers to a worker.
func (s *Service) RegisterJobs(w *jobs.Worker) {
	w.Register(JobSiteApply, 4, s.siteJob)
}

func (s *Service) enqueue(ctx context.Context, tx *sql.Tx, p *auth.Principal, accountID string) (string, error) {
	return s.EnqueueSite(ctx, tx, p.Login.ID, accountID)
}

// EnqueueSite queues, inside tx, the job that applies an account's websites
// again (after a certificate changed, for example).
func (s *Service) EnqueueSite(ctx context.Context, tx *sql.Tx, createdBy, accountID string) (string, error) {
	return s.jobs.EnqueueTx(ctx, tx, JobSiteApply, jobPayload{AccountID: accountID}, jobs.EnqueueOptions{
		AccountID: accountID, LockKey: "account:" + accountID, MaxAttempts: 3, CreatedBy: createdBy,
	})
}

// CertSource gives the websites their certificates (package ssl).
type CertSource interface {
	// SiteTLS returns the certificate a domain's site serves (nil: none) and
	// whether HTTP redirects to HTTPS.
	SiteTLS(ctx context.Context, d store.Domain) (*agentv1.TLS, bool, error)
	// Hostname is the server's own name, which no account may add.
	Hostname(ctx context.Context) string
}

// SetCertSource connects the certificate source; without one, sites are HTTP only.
func (s *Service) SetCertSource(c CertSource) { s.certs = c }

var canonicals = map[string]agentv1.Canonical{
	store.CanonicalBoth: agentv1.Canonical_CANONICAL_UNSPECIFIED,
	store.CanonicalWWW:  agentv1.Canonical_CANONICAL_WWW,
	store.CanonicalBare: agentv1.Canonical_CANONICAL_BARE,
}

// SiteRequest builds the agent request that configures all of an account's
// websites: one virtual host per domain, aliases showing their domain's
// document root. The account job (package accounts) uses it too.
func (s *Service) SiteRequest(ctx context.Context, a *store.Account, lim plans.Limits) (*agentv1.SiteApplyRequest, error) {
	ds, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	if len(ds) == 0 {
		return nil, fmt.Errorf("account %s has no domains", a.Username)
	}
	rs, err := s.db.ListRedirects(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	byID := index(ds)
	req := &agentv1.SiteApplyRequest{
		Username: a.Username, Uid: uint32(a.UID), PhpVersion: a.PHPVersion, //nolint:gosec // G115: UID is 10000..59999 by schema
		Suspended: a.Status == store.AccountSuspended, MaxChildren: lim.PHPWorkers(),
	}
	for _, d := range ds {
		root := d.DocRoot
		if d.Kind == store.DomainAlias {
			root = byID[d.ParentID].DocRoot
		}
		v := &agentv1.VirtualHost{Name: d.Name, DocRoot: root, Canonical: canonicals[d.Canonical]}
		if s.certs != nil {
			if v.Tls, v.ForceHttps, err = s.certs.SiteTLS(ctx, d); err != nil {
				return nil, err
			}
		}
		for _, r := range rs {
			if r.DomainID == d.ID {
				v.Redirects = append(v.Redirects, &agentv1.Redirect{
					Path: r.Path, Target: r.Target, Code: uint32(r.Code), KeepPath: r.KeepPath, //nolint:gosec // G115: 301..308 by schema
				})
			}
		}
		req.Vhosts = append(req.Vhosts, v)
	}
	return req, nil
}

// siteJob configures the account's websites through the agent.
func (s *Service) siteJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p jobPayload
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
	if a.Status != store.AccountActive && a.Status != store.AccountSuspended {
		// The account's own job configures the websites once it is set up.
		return map[string]string{"skipped": "account is " + a.Status}, nil
	}
	lim, _, err := s.plans.Entitlements(ctx, a.PackageID)
	if err != nil {
		return nil, err
	}
	req, err := s.SiteRequest(ctx, a, lim)
	if err != nil {
		return nil, err
	}
	r.Logf("configuring %d domain(s) of %s", len(req.GetVhosts()), a.Username)
	res, err := s.agent.SiteApply(ctx, req)
	switch {
	case status.Code(err) == codes.NotFound:
		r.Logf("no web server installed")
		return map[string]string{"website": "skipped: no web server installed"}, nil
	case err != nil:
		return nil, permanentIfRefused(err)
	}
	return map[string]any{"website": "configured", "domains": len(req.GetVhosts()), "changed": res.GetChanged()}, nil
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
