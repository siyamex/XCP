package ssl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/hostinfo"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/tlsx"
)

// JobAutoSSL issues and renews certificates; it runs daily and on demand.
const JobAutoSSL = "ssl.autossl"

// AutoSSLSchedule is when the daily run starts (UTC).
const AutoSSLSchedule = "17 3 * * *"

type runPayload struct {
	AccountID string `json:"account_id,omitempty"` // "" = every account and the server's host name
}

// RegisterJobs adds the SSL job handler to a worker.
func (s *Service) RegisterJobs(w *jobs.Worker) { w.Register(JobAutoSSL, 1, s.autoSSLJob) }

// Schedule adds the daily AutoSSL run to a scheduler.
func (s *Service) Schedule(sched *jobs.Scheduler) error {
	return sched.Every(AutoSSLSchedule, JobAutoSSL, runPayload{})
}

// Run queues an AutoSSL run now: for one account, or (admins, accountID
// "") for every account and the server's host name.
func (s *Service) Run(ctx context.Context, c auth.Client, p *auth.Principal, accountID string) (string, error) {
	if accountID == "" {
		if err := admin(p); err != nil {
			return "", err
		}
	} else if _, err := s.access(ctx, p, accountID); err != nil {
		return "", err
	}
	id, err := s.jobs.Enqueue(ctx, JobAutoSSL, runPayload{AccountID: accountID}, jobs.EnqueueOptions{
		AccountID: accountID, LockKey: "ssl:autossl", CreatedBy: p.Login.ID,
	})
	if err != nil {
		return "", err
	}
	return id, s.audit.Record(ctx, event(c, p, "ssl.run", accountID, "ssl", "autossl", map[string]any{"job": id}))
}

// result counts what a run did.
type result struct {
	Issued   int    `json:"issued"`
	OK       int    `json:"ok"`
	Failed   int    `json:"failed"`
	Skipped  int    `json:"skipped"`
	Hostname string `json:"hostname,omitempty"` // what happened to the server's certificate
}

func (s *Service) autoSSLJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p runPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	set, err := s.Settings(ctx)
	if err != nil {
		return nil, err
	}
	if !set.Enabled {
		return map[string]string{"skipped": "AutoSSL is turned off"}, nil
	}
	// The ACME account is set up only once something needs a certificate.
	var (
		iss    issuer
		issErr error
	)
	getIssuer := func() (issuer, error) {
		if iss == nil && issErr == nil {
			iss, issErr = s.newIssuer(ctx, set)
		}
		return iss, issErr
	}
	ours := s.serverAddresses(ctx)

	var res result
	accts, err := s.db.ListAccounts(ctx, store.AccountFilter{OwnerID: "*"})
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if a.Status != store.AccountActive || (p.AccountID != "" && a.ID != p.AccountID) {
			continue
		}
		changed, err := s.account(ctx, r, &a, ours, getIssuer, &res)
		if err != nil {
			return res, err
		}
		if changed {
			err := s.db.Tx(ctx, func(tx *sql.Tx) error {
				_, err := s.domains.EnqueueSite(ctx, tx, "autossl", a.ID)
				return err
			})
			if err != nil {
				return res, err
			}
		}
	}
	if p.AccountID == "" {
		res.Hostname = s.hostname(ctx, r, set, ours, getIssuer)
	}
	return res, nil
}

// account runs AutoSSL for one account's domains; it reports whether a
// certificate changed, so the sites must be applied again.
func (s *Service) account(ctx context.Context, r jobs.Reporter, a *store.Account, ours []string,
	getIssuer func() (issuer, error), res *result,
) (bool, error) {
	ds, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return false, err
	}
	certs, err := s.db.AccountCertificates(ctx, a.ID)
	if err != nil {
		return false, err
	}
	changed := false
	for _, d := range ds {
		var cur *store.Certificate
		if c, ok := certs[d.ID]; ok {
			cur = &c
		}
		status, detail, issued := s.autoDomain(ctx, d, cur, ours, getIssuer)
		switch {
		case issued:
			res.Issued++
			changed = true
		case status == store.SSLOK:
			res.OK++
		case status == store.SSLFailed:
			res.Failed++
		default:
			res.Skipped++
		}
		r.Logf("%s: %s %s", d.Name, status, detail)
		if err := s.db.SetDomainSSLStatus(ctx, d.ID, status, detail); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

// autoDomain decides what AutoSSL does for one domain, and does it.
func (s *Service) autoDomain(ctx context.Context, d store.Domain, cur *store.Certificate, ours []string,
	getIssuer func() (issuer, error),
) (status, detail string, issued bool) {
	soon := time.Now().Add(RenewBefore)
	switch {
	case !d.AutoSSL:
		return store.SSLSkipped, "left out of AutoSSL", false
	case strings.HasPrefix(d.Name, "*."):
		return store.SSLSkipped, "a wildcard needs DNS validation, which AutoSSL does not do yet; upload a certificate", false
	case cur != nil && cur.Source == store.CertUpload && cur.NotAfter.After(soon):
		return store.SSLOK, "uploaded certificate, valid until " + cur.NotAfter.Format(time.DateOnly), false
	}
	names, why := s.reachable(ctx, d.Name, ours)
	if len(names) == 0 {
		return store.SSLSkipped, why, false
	}
	if cur != nil && cur.Source == store.CertACME && cur.NotAfter.After(soon) && covers(cur.Names, names) {
		return store.SSLOK, "valid until " + cur.NotAfter.Format(time.DateOnly), false
	}
	iss, err := getIssuer()
	if err != nil {
		return store.SSLFailed, err.Error(), false
	}
	pair, err := issue(ctx, iss, names)
	if err != nil {
		return store.SSLFailed, err.Error(), false
	}
	if err := store.PutCertificate(ctx, s.db.W, s.record(d.ID, store.CertACME, pair)); err != nil {
		return store.SSLFailed, err.Error(), false
	}
	return store.SSLOK, "issued for " + strings.Join(names, ", ") + ", valid until " + pair.Leaf.NotAfter.Format(time.DateOnly), true
}

// issue gets a certificate for names with a new key.
func issue(ctx context.Context, iss issuer, names []string) (tlsx.Pair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsx.Pair{}, err
	}
	certPEM, err := iss.Issue(ctx, names, key)
	if err != nil {
		return tlsx.Pair{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tlsx.Pair{}, err
	}
	return tlsx.Parse(certPEM, "", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
}

// covers reports whether a certificate's names include all of want.
func covers(have, want []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

// serverAddresses are the addresses names must point to: those of the DNS
// settings, else the server's interfaces.
func (s *Service) serverAddresses(ctx context.Context) []string {
	var out []string
	if set, err := s.zones.Settings(ctx); err == nil {
		for _, ip := range []string{set.IPv4, set.IPv6} {
			if ip != "" {
				out = append(out, ip)
			}
		}
	}
	if len(out) == 0 {
		out = hostinfo.ServerIPs()
	}
	return out
}

// reachable returns name, and www.name if it points here too, when DNS
// sends name to this server; else an explanation for the user.
func (s *Service) reachable(ctx context.Context, name string, ours []string) ([]string, string) {
	here := func(n string) (bool, []string) {
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		addrs, err := s.resolver.LookupHost(lctx, n)
		if err != nil {
			return false, nil
		}
		return slices.ContainsFunc(addrs, func(a string) bool { return slices.Contains(ours, a) }), addrs
	}
	ok, addrs := here(name)
	if !ok {
		if len(addrs) == 0 {
			return nil, name + " does not resolve yet; point its DNS to this server"
		}
		return nil, fmt.Sprintf("%s points to %s, not to this server (%s)", name, strings.Join(addrs, ", "), strings.Join(ours, ", "))
	}
	names := []string{name}
	if www, _ := here("www." + name); www {
		names = append(names, "www."+name)
	}
	return names, ""
}

// hostname keeps the server's own certificate (ADM-SSL-02) and installs it
// for the panel; it returns what happened.
func (s *Service) hostname(ctx context.Context, r jobs.Reporter, set Settings, ours []string, getIssuer func() (issuer, error)) string {
	if set.Hostname == "" {
		return "skipped: no host name set"
	}
	cur, err := s.db.ServerCertificate(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "failed: " + err.Error()
	}
	if cur == nil || !cur.NotAfter.After(time.Now().Add(RenewBefore)) || !slices.Contains(cur.Names, set.Hostname) {
		names, why := s.reachable(ctx, set.Hostname, ours)
		if len(names) == 0 {
			return "skipped: " + why
		}
		iss, err := getIssuer()
		if err != nil {
			return "failed: " + err.Error()
		}
		pair, err := issue(ctx, iss, names[:1])
		if err != nil {
			return "failed: " + err.Error()
		}
		cur = s.record("", store.CertACME, pair)
		if err := store.PutCertificate(ctx, s.db.W, cur); err != nil {
			return "failed: " + err.Error()
		}
	}
	key, err := s.box.Open(cur.KeyEnc, keyAD(cur.ID))
	if err != nil {
		return "failed: " + err.Error()
	}
	res, err := s.agent.HostCertificateInstall(ctx, &agentv1.HostCertificateInstallRequest{
		Hostname: set.Hostname, Tls: &agentv1.TLS{CertPem: cur.CertPEM, KeyPem: string(key)},
	})
	if err != nil {
		return "failed: " + err.Error()
	}
	r.Logf("%s: certificate valid until %s (installed: %v)", set.Hostname, cur.NotAfter.Format(time.DateOnly), res.GetChanged())
	return "ok: valid until " + cur.NotAfter.Format(time.DateOnly)
}
