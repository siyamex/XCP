// Package ssl gives hosted domains and the server their certificates
// (ADM-SSL-01, 02, 05; USR-SSL-01, 03, 06; ADR-0005): AutoSSL through ACME,
// uploaded certificates, force HTTPS, and the expiry dashboard.
package ssl

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/domains"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/tlsx"
	"github.com/siyamex/XCP/internal/validate"
	"github.com/siyamex/XCP/internal/zones"
)

// FeatureSSL is the feature-list entry that gives users SSL management.
const FeatureSSL = "ssl"

// RenewBefore is how long before expiry AutoSSL replaces a certificate.
const RenewBefore = 30 * 24 * time.Hour

// HostResolver looks up addresses (*net.Resolver in production).
type HostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// ChallengeDir is where xcp-install lets xcp-api write HTTP-01 answers;
// Apache serves it as /.well-known/acme-challenge/ for every host name.
const ChallengeDir = "/var/www/xcp-acme"

// Options are the paths the service works with.
type Options struct {
	PanelCert    string // the panel's certificate file, to find the host name
	ChallengeDir string // where HTTP-01 answers go (/var/www/xcp-acme)
}

// Service manages certificates.
type Service struct {
	db           *store.DB
	audit        *audit.Recorder
	plans        *plans.Service
	jobs         *jobs.Queue
	agent        agentrpc.Client
	domains      *domains.Service
	zones        *zones.Service
	box          *secretbox.Box
	resolver     HostResolver
	panelCert    string
	challengeDir string
	// newIssuer makes the ACME client; tests replace it.
	newIssuer func(ctx context.Context, set Settings) (issuer, error)
}

// NewService returns an SSL service and makes it the certificate source of
// the domains' websites.
func NewService(db *store.DB, rec *audit.Recorder, pl *plans.Service, q *jobs.Queue, ag agentrpc.Client,
	dom *domains.Service, zs *zones.Service, box *secretbox.Box, r HostResolver, opt Options,
) *Service {
	s := &Service{
		db: db, audit: rec, plans: pl, jobs: q, agent: ag, domains: dom, zones: zs, box: box, resolver: r,
		panelCert: opt.PanelCert, challengeDir: opt.ChallengeDir,
	}
	s.newIssuer = s.newACMEIssuer
	dom.SetCertSource(s)
	return s
}

// CertView is a certificate as the API shows it (never its key).
type CertView struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"` // "" for the server's own certificate
	AccountID string    `json:"account_id,omitempty"`
	Account   string    `json:"account,omitempty"`
	Source    string    `json:"source"` // acme or upload
	Names     []string  `json:"names"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DaysLeft  int       `json:"days_left"`
}

func certView(c store.Certificate) CertView {
	return CertView{
		ID: c.ID, Source: c.Source, Names: c.Names, Issuer: c.Issuer, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		DaysLeft: int(time.Until(c.NotAfter).Hours() / 24),
	}
}

// DomainSSL is a domain's SSL state.
type DomainSSL struct {
	DomainID    string     `json:"domain_id"`
	Domain      string     `json:"domain"`
	DisplayName string     `json:"display_name"`
	Kind        string     `json:"kind"`
	AutoSSL     bool       `json:"autossl"`
	ForceHTTPS  bool       `json:"force_https"`
	Status      string     `json:"status"` // AutoSSL's last result: "", ok, failed, skipped
	Detail      string     `json:"detail"`
	CheckedAt   *time.Time `json:"checked_at,omitempty"`
	Certificate *CertView  `json:"certificate,omitempty"`
	JobID       string     `json:"job_id,omitempty"`
}

func domainView(d store.Domain, c *store.Certificate) DomainSSL {
	v := DomainSSL{
		DomainID: d.ID, Domain: d.Name, DisplayName: validate.DomainUnicode(strings.TrimPrefix(d.Name, "*.")), Kind: d.Kind,
		AutoSSL: d.AutoSSL, ForceHTTPS: d.ForceHTTPS, Status: d.SSLStatus, Detail: d.SSLDetail, CheckedAt: d.SSLChecked,
	}
	if strings.HasPrefix(d.Name, "*.") {
		v.DisplayName = "*." + v.DisplayName
	}
	if c != nil {
		cv := certView(*c)
		v.Certificate = &cv
	}
	return v
}

func event(c auth.Client, p *auth.Principal, action, accountID, targetType, targetID string, details map[string]any) audit.Event {
	e := audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: targetType, TargetID: targetID, AccountID: accountID, Details: details, Role: "system",
	}
	if p != nil {
		e.ActorID, e.ImpersonatorID, e.Role = p.Login.ID, p.Session.ImpersonatorID, p.Login.Role
	}
	return e
}

// access loads an account the caller may manage SSL for: admins the
// admin-owned accounts, users their own if the feature list has "ssl".
func (s *Service) access(ctx context.Context, p *auth.Principal, accountID string) (*store.Account, error) {
	if p == nil {
		return nil, apperr.ErrForbidden
	}
	a, err := s.db.AccountByID(ctx, accountID)
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
		_, features, err := s.plans.Entitlements(ctx, a.PackageID)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(features, FeatureSSL) {
			return nil, apperr.ErrForbidden
		}
	default:
		return nil, apperr.ErrForbidden
	}
	return a, nil
}

func (s *Service) domain(ctx context.Context, p *auth.Principal, id string) (*store.Domain, *store.Account, error) {
	d, err := s.db.DomainByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	a, err := s.access(ctx, p, d.AccountID)
	if err != nil {
		return nil, nil, err
	}
	if a.Status != store.AccountActive && a.Status != store.AccountSuspended {
		return nil, nil, apperr.NewConflict("bad_status", "not possible while the account is "+a.Status)
	}
	return d, a, nil
}

// AccountSSL returns the SSL state of an account's domains.
func (s *Service) AccountSSL(ctx context.Context, p *auth.Principal, accountID string) ([]DomainSSL, error) {
	a, err := s.access(ctx, p, accountID)
	if err != nil {
		return nil, err
	}
	ds, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	certs, err := s.db.AccountCertificates(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	out := make([]DomainSSL, 0, len(ds))
	for _, d := range ds {
		var c *store.Certificate
		if cert, ok := certs[d.ID]; ok {
			c = &cert
		}
		out = append(out, domainView(d, c))
	}
	return out, nil
}

// OptionsInput sets a domain's SSL options.
type OptionsInput struct {
	AutoSSL    bool `json:"autossl"`     // false leaves the domain out of AutoSSL (USR-SSL-06)
	ForceHTTPS bool `json:"force_https"` // needs a valid certificate
}

// SetOptions changes whether AutoSSL covers a domain and whether HTTP
// redirects to HTTPS.
func (s *Service) SetOptions(ctx context.Context, c auth.Client, p *auth.Principal, domainID string, in OptionsInput) (DomainSSL, error) {
	d, a, err := s.domain(ctx, p, domainID)
	if err != nil {
		return DomainSSL{}, err
	}
	cert, err := s.db.DomainCertificate(ctx, d.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return DomainSSL{}, err
	}
	if in.ForceHTTPS && (cert == nil || !time.Now().Before(cert.NotAfter)) {
		return DomainSSL{}, apperr.NewConflict("needs_certificate", d.Name+" needs a valid certificate before HTTPS can be forced")
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetDomainSSL(ctx, tx, d.ID, in.AutoSSL, in.ForceHTTPS); err != nil {
			return err
		}
		if jobID, err = s.domains.EnqueueSite(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "ssl.options", a.ID, "domain", d.ID, map[string]any{
			"domain": d.Name, "autossl": in.AutoSSL, "force_https": in.ForceHTTPS,
		}))
	})
	if err != nil {
		return DomainSSL{}, err
	}
	d.AutoSSL, d.ForceHTTPS = in.AutoSSL, in.ForceHTTPS
	v := domainView(*d, cert)
	v.JobID = jobID
	return v, nil
}

// UploadInput is a certificate a user brings (USR-SSL-03).
type UploadInput struct {
	Certificate string `json:"certificate"`
	Chain       string `json:"chain"` // optional: the intermediate certificates
	Key         string `json:"key"`
}

// Upload installs a user's own certificate on a domain, after checking that
// the key matches, the certificate covers the domain and is valid now.
func (s *Service) Upload(ctx context.Context, c auth.Client, p *auth.Principal, domainID string, in UploadInput) (DomainSSL, error) {
	d, a, err := s.domain(ctx, p, domainID)
	if err != nil {
		return DomainSSL{}, err
	}
	pair, err := tlsx.Parse(in.Certificate, in.Chain, in.Key)
	if err != nil {
		return DomainSSL{}, badField("certificate", err.Error())
	}
	switch {
	case !tlsx.Covers(pair.Leaf, d.Name):
		return DomainSSL{}, badField("certificate", "the certificate does not cover "+d.Name)
	case !tlsx.Valid(pair.Leaf, time.Now()):
		return DomainSSL{}, badField("certificate", "the certificate is not valid now (it expired or is not valid yet)")
	}
	cert := s.record(d.ID, store.CertUpload, pair)
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.PutCertificate(ctx, tx, cert); err != nil {
			return err
		}
		if jobID, err = s.domains.EnqueueSite(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "ssl.upload", a.ID, "domain", d.ID, map[string]any{
			"domain": d.Name, "names": cert.Names, "issuer": cert.Issuer, "not_after": cert.NotAfter,
		}))
	})
	if err != nil {
		return DomainSSL{}, err
	}
	v := domainView(*d, cert)
	v.JobID = jobID
	return v, nil
}

// record makes a certificate row from a checked pair, its key encrypted.
func (s *Service) record(domainID, source string, pair tlsx.Pair) *store.Certificate {
	c := &store.Certificate{
		ID: ids.New(), DomainID: domainID, Source: source, Names: pair.Leaf.DNSNames, Issuer: pair.Leaf.Issuer.CommonName,
		NotBefore: pair.Leaf.NotBefore, NotAfter: pair.Leaf.NotAfter, CertPEM: pair.CertPEM,
	}
	if c.Issuer == "" {
		c.Issuer = pair.Leaf.Issuer.String()
	}
	c.KeyEnc = s.box.Seal([]byte(pair.KeyPEM), keyAD(c.ID))
	return c
}

// DeleteCertificate removes a domain's certificate; HTTPS is no longer
// forced. AutoSSL issues a new one on its next run, unless left out.
func (s *Service) DeleteCertificate(ctx context.Context, c auth.Client, p *auth.Principal, domainID string) (string, error) {
	d, a, err := s.domain(ctx, p, domainID)
	if err != nil {
		return "", err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteDomainCertificate(ctx, tx, d.ID); err != nil {
			return err
		}
		if err := store.SetDomainSSL(ctx, tx, d.ID, d.AutoSSL, false); err != nil {
			return err
		}
		if jobID, err = s.domains.EnqueueSite(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "ssl.delete", a.ID, "domain", d.ID, map[string]any{"domain": d.Name}))
	})
	return jobID, err
}

// Certificates returns certificates, soonest to expire first (ADM-SSL-05):
// for admins all of them, the server's own included; for users their own.
func (s *Service) Certificates(ctx context.Context, p *auth.Principal) ([]CertView, error) {
	if p == nil {
		return nil, apperr.ErrForbidden
	}
	scope := "*"
	if p.Login.Role != store.RoleAdmin {
		if _, err := s.access(ctx, p, p.Login.AccountID); err != nil {
			return nil, err
		}
		scope = p.Login.AccountID
	}
	list, err := s.db.ListCertificates(ctx, scope)
	if err != nil {
		return nil, err
	}
	out := make([]CertView, 0, len(list))
	for _, c := range list {
		v := certView(c.Certificate)
		v.Domain, v.AccountID, v.Account = c.Domain, c.AccountID, c.Account
		out = append(out, v)
	}
	return out, nil
}

// SiteTLS gives package domains the certificate a domain's site serves,
// and whether HTTP redirects to HTTPS (only while the certificate is valid).
func (s *Service) SiteTLS(ctx context.Context, d store.Domain) (*agentv1.TLS, bool, error) {
	c, err := s.db.DomainCertificate(ctx, d.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	key, err := s.box.Open(c.KeyEnc, keyAD(c.ID))
	if err != nil {
		return nil, false, err
	}
	return &agentv1.TLS{CertPem: c.CertPEM, KeyPem: string(key)}, d.ForceHTTPS && time.Now().Before(c.NotAfter), nil
}
