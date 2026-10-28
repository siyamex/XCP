// Package domains manages an account's domains and redirects (USR-DOM-01..07):
// addon domains, subdomains (wildcards included), aliases, document roots,
// the www/bare choice and redirects. Every change re-applies the account's
// websites through the agent in a job (jobs.go).
package domains

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/agent"
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

// Features of the feature list that switch domain management on.
const (
	FeatureDomains   = "domains"
	FeatureRedirects = "redirects"
)

// Domain is the API view of a domain.
type Domain struct {
	ID          string    `json:"id"`
	AccountID   string    `json:"account_id"`
	Name        string    `json:"name"`         // ASCII (punycode)
	DisplayName string    `json:"display_name"` // Unicode form of an internationalised name
	Kind        string    `json:"kind"`         // primary, addon, sub, alias
	ParentID    string    `json:"parent_id,omitempty"`
	ParentName  string    `json:"parent_name,omitempty"`
	DocRoot     string    `json:"docroot"` // for an alias: the document root of the site it shows
	Canonical   string    `json:"canonical"`
	CreatedAt   time.Time `json:"created_at"`
	JobID       string    `json:"job_id,omitempty"` // the job applying this change
}

// AddInput adds a domain.
type AddInput struct {
	Kind string `json:"kind"` // addon, sub or alias
	// Name is the domain for addon and alias; for sub, the part before the
	// parent domain ("blog", or "*" for every name below it).
	Name string `json:"name"`
	// ParentID is, for sub, the domain it goes under and, for alias, the
	// domain whose site it shows. Both must be the account's primary or addon domains.
	ParentID string `json:"parent_id"`
	DocRoot  string `json:"docroot"` // addon and sub; "" = domains/<name>
}

// UpdateInput changes a domain's settings.
type UpdateInput struct {
	DocRoot   string `json:"docroot"` // not for an alias
	Canonical string `json:"canonical"`
}

// Redirect is the API view of a redirect.
type Redirect struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	Domain    string    `json:"domain"`
	Path      string    `json:"path"`
	Target    string    `json:"target"`
	Code      int       `json:"code"`
	KeepPath  bool      `json:"keep_path"`
	CreatedAt time.Time `json:"created_at"`
	JobID     string    `json:"job_id,omitempty"`
}

// RedirectInput adds a redirect.
type RedirectInput struct {
	Path     string `json:"path"`
	Target   string `json:"target"`
	Code     int    `json:"code"`
	KeepPath bool   `json:"keep_path"`
}

// Verification tells how to prove control of a domain (USR-DOM-07).
type Verification struct {
	Name     string `json:"name"`
	Required bool   `json:"required"` // another account uses a name under the same registered domain
	Record   string `json:"record"`   // TXT record to publish
	Value    string `json:"value"`
	Verified bool   `json:"verified"` // the record is visible in DNS now
}

// TXTResolver looks up DNS TXT records (*net.Resolver in production).
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// StaticTXT is a TXTResolver with fixed answers, for tests and the fake agent setup.
type StaticTXT map[string][]string

// LookupTXT implements TXTResolver.
func (m StaticTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	if txt, ok := m[name]; ok {
		return txt, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// Service manages domains and redirects.
type Service struct {
	db       *store.DB
	audit    *audit.Recorder
	plans    *plans.Service
	jobs     *jobs.Queue
	agent    agentrpc.Client
	resolver TXTResolver
	key      []byte // signs verification tokens
}

// NewService returns a domains service. key signs the TXT verification
// tokens; it must stay the same across restarts.
func NewService(db *store.DB, rec *audit.Recorder, pl *plans.Service, q *jobs.Queue, ag agentrpc.Client,
	resolver TXTResolver, key []byte,
) *Service {
	return &Service{db: db, audit: rec, plans: pl, jobs: q, agent: ag, resolver: resolver, key: key}
}

func fieldErr(err error, name string) error { return validate.WithField(err, name) }

func badField(field, code, msg string) error {
	return &validate.Error{Field: field, Code: code, Message: msg}
}

func event(c auth.Client, p *auth.Principal, action, accountID, targetType, targetID string, details map[string]any) audit.Event {
	return audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: targetType, TargetID: targetID, AccountID: accountID, Details: details,
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
	}
}

// access loads an account the caller may manage: admins the admin-owned
// accounts (as in package accounts), users their own account, and only if
// its package's feature list has feature. Anything else looks like "not found".
func (s *Service) access(ctx context.Context, p *auth.Principal, accountID, feature string) (*store.Account, error) {
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
		if !slices.Contains(features, feature) {
			return nil, apperr.ErrForbidden
		}
	default:
		return nil, apperr.ErrForbidden
	}
	return a, nil
}

// changeable refuses changes while the account is being set up or removed.
func changeable(a *store.Account) error {
	if a.Status != store.AccountActive && a.Status != store.AccountSuspended {
		return apperr.NewConflict("bad_status", "not possible while the account is "+a.Status)
	}
	return nil
}

// ownDomain loads one of the account's domains.
func (s *Service) ownDomain(ctx context.Context, a *store.Account, id string) (*store.Domain, error) {
	d, err := s.db.DomainByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if d.AccountID != a.ID {
		return nil, store.ErrNotFound
	}
	return d, nil
}

func view(d store.Domain, byID map[string]store.Domain) Domain {
	v := Domain{
		ID: d.ID, AccountID: d.AccountID, Name: d.Name, DisplayName: validate.DomainUnicode(d.Name), Kind: d.Kind,
		ParentID: d.ParentID, DocRoot: d.DocRoot, Canonical: d.Canonical, CreatedAt: d.CreatedAt,
	}
	if strings.HasPrefix(d.Name, "*.") {
		v.DisplayName = "*." + validate.DomainUnicode(d.Name[2:])
	}
	if parent, ok := byID[d.ParentID]; ok {
		v.ParentName = parent.Name
		if d.Kind == store.DomainAlias {
			v.DocRoot = parent.DocRoot
		}
	}
	return v
}

func index(ds []store.Domain) map[string]store.Domain {
	m := make(map[string]store.Domain, len(ds))
	for _, d := range ds {
		m[d.ID] = d
	}
	return m
}

// List returns an account's domains, the primary first.
func (s *Service) List(ctx context.Context, p *auth.Principal, accountID string) ([]Domain, error) {
	a, err := s.access(ctx, p, accountID, FeatureDomains)
	if err != nil {
		return nil, err
	}
	ds, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	byID := index(ds)
	out := make([]Domain, 0, len(ds))
	for _, d := range ds {
		out = append(out, view(d, byID))
	}
	return out, nil
}

// defaultDocRoot is where a new addon or subdomain lives unless the user picks another folder.
func defaultDocRoot(name string) string {
	if base, ok := strings.CutPrefix(name, "*."); ok {
		return "domains/_wildcard." + base
	}
	return "domains/" + name
}

// Add adds an addon domain, subdomain or alias and queues the job that
// configures it.
func (s *Service) Add(ctx context.Context, c auth.Client, p *auth.Principal, accountID string, in AddInput) (Domain, error) {
	a, err := s.access(ctx, p, accountID, FeatureDomains)
	if err != nil {
		return Domain{}, err
	}
	if err := changeable(a); err != nil {
		return Domain{}, err
	}
	d := &store.Domain{ID: ids.New(), AccountID: a.ID, Kind: in.Kind}
	var parent *store.Domain
	if in.Kind == store.DomainSub || in.Kind == store.DomainAlias {
		if parent, err = s.ownDomain(ctx, a, in.ParentID); errors.Is(err, store.ErrNotFound) {
			return Domain{}, badField("parent_id", validate.CodeFormat, "choose one of the account's domains")
		} else if err != nil {
			return Domain{}, err
		}
		if parent.Kind != store.DomainPrimary && parent.Kind != store.DomainAddon {
			return Domain{}, badField("parent_id", validate.CodeFormat, "choose the primary domain or an addon domain")
		}
		d.ParentID = parent.ID
	}
	switch in.Kind {
	case store.DomainAddon, store.DomainAlias:
		if d.Name, err = validate.Domain(in.Name); err != nil {
			return Domain{}, fieldErr(err, "name")
		}
		// www. is served with every domain: "www.example.com" means example.com.
		if base, ok := strings.CutPrefix(d.Name, "www."); ok {
			if n, err := validate.Domain(base); err == nil {
				d.Name = n
			}
		}
	case store.DomainSub:
		label, err := validate.SubdomainLabel(in.Name)
		if err != nil {
			return Domain{}, fieldErr(err, "name")
		}
		if label == "www" {
			return Domain{}, badField("name", validate.CodeReserved, "www is served with every domain already")
		}
		if d.Name, err = validate.WildcardDomain(label + "." + parent.Name); err != nil {
			return Domain{}, fieldErr(err, "name")
		}
	default:
		return Domain{}, badField("kind", validate.CodeFormat, "kind must be addon, sub or alias")
	}
	if in.Kind != store.DomainAlias {
		root := in.DocRoot
		if strings.TrimSpace(root) == "" {
			root = defaultDocRoot(d.Name)
		}
		if d.DocRoot, err = validate.DocRoot(root); err != nil {
			return Domain{}, fieldErr(err, "docroot")
		}
	}
	lim, _, err := s.plans.Entitlements(ctx, a.PackageID)
	if err != nil {
		return Domain{}, err
	}
	if p.Login.Role != store.RoleAdmin {
		v, err := s.verification(ctx, a, d.Name)
		if err != nil {
			return Domain{}, err
		}
		if v.Required && !v.Verified {
			return Domain{}, apperr.NewConflict("verification_required", "another account uses a domain under "+
				validate.Registrable(d.Name)+": publish the TXT record "+v.Record+" with the value "+v.Value+" and try again")
		}
	}

	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := checkLimit(ctx, tx, a.ID, d.Kind, lim); err != nil {
			return err
		}
		if err := store.InsertDomain(ctx, tx, d); errors.Is(err, store.ErrConflict) {
			return apperr.NewConflict("domain_taken", d.Name+" is already used on this server")
		} else if err != nil {
			return err
		}
		if jobID, err = s.enqueue(ctx, tx, p, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "domain.add", a.ID, "domain", d.ID, map[string]any{
			"name": d.Name, "kind": d.Kind, "parent_id": d.ParentID, "docroot": d.DocRoot,
		}))
	})
	if err != nil {
		return Domain{}, err
	}
	byID := map[string]store.Domain{}
	if parent != nil {
		byID[parent.ID] = *parent
	}
	v := view(*d, byID)
	v.JobID = jobID
	return v, nil
}

// checkLimit enforces the package's number of addon domains, subdomains and aliases.
func checkLimit(ctx context.Context, tx *sql.Tx, accountID, kind string, lim plans.Limits) error {
	limit, what := lim.AddonDomains, "addon domains"
	switch kind {
	case store.DomainSub:
		limit, what = lim.Subdomains, "subdomains"
	case store.DomainAlias:
		limit, what = lim.Aliases, "aliases"
	}
	if limit == nil {
		return nil
	}
	n, err := store.CountDomains(ctx, tx, accountID, kind)
	if err != nil {
		return err
	}
	if int64(n) >= *limit {
		return apperr.NewConflict("limit_reached", "the package allows no more "+what)
	}
	return nil
}

// Update changes a domain's document root and canonical host.
func (s *Service) Update(ctx context.Context, c auth.Client, p *auth.Principal, id string, in UpdateInput) (Domain, error) {
	d, a, err := s.domainForChange(ctx, p, id, FeatureDomains)
	if err != nil {
		return Domain{}, err
	}
	before := *d
	if d.Kind == store.DomainAlias {
		if strings.TrimSpace(in.DocRoot) != "" {
			return Domain{}, badField("docroot", validate.CodeFormat, "an alias shows the site of its domain; it has no folder of its own")
		}
	} else if d.DocRoot, err = validate.DocRoot(in.DocRoot); err != nil {
		return Domain{}, fieldErr(err, "docroot")
	}
	switch in.Canonical {
	case store.CanonicalBoth:
	case store.CanonicalWWW, store.CanonicalBare:
		if strings.HasPrefix(d.Name, "*.") {
			return Domain{}, badField("canonical", validate.CodeFormat, "a wildcard subdomain has no www form")
		}
	default:
		return Domain{}, badField("canonical", validate.CodeFormat, `canonical must be "", "www" or "bare"`)
	}
	d.Canonical = in.Canonical
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.UpdateDomain(ctx, tx, d); err != nil {
			return err
		}
		if jobID, err = s.enqueue(ctx, tx, p, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "domain.update", a.ID, "domain", d.ID, map[string]any{
			"name": d.Name, "docroot_from": before.DocRoot, "docroot_to": d.DocRoot,
			"canonical_from": before.Canonical, "canonical_to": d.Canonical,
		}))
	})
	if err != nil {
		return Domain{}, err
	}
	ds, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return Domain{}, err
	}
	v := view(*d, index(ds))
	v.JobID = jobID
	return v, nil
}

// domainForChange loads a domain the caller may change, with its account.
func (s *Service) domainForChange(ctx context.Context, p *auth.Principal, id, feature string) (*store.Domain, *store.Account, error) {
	d, err := s.db.DomainByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	a, err := s.access(ctx, p, d.AccountID, feature)
	if err != nil {
		return nil, nil, err
	}
	return d, a, changeable(a)
}

// Delete removes a domain and its redirects. Files stay in the home folder.
func (s *Service) Delete(ctx context.Context, c auth.Client, p *auth.Principal, id string) (string, error) {
	d, a, err := s.domainForChange(ctx, p, id, FeatureDomains)
	if err != nil {
		return "", err
	}
	if d.Kind == store.DomainPrimary {
		return "", apperr.NewConflict("primary_domain", "the primary domain belongs to the account and cannot be removed")
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		n, err := store.DomainDependents(ctx, tx, d.ID)
		if err != nil {
			return err
		}
		if n > 0 {
			return apperr.NewConflict("has_dependents", "remove the subdomains and aliases of "+d.Name+" first")
		}
		if err := store.DeleteDomain(ctx, tx, d.ID); err != nil {
			return err
		}
		if jobID, err = s.enqueue(ctx, tx, p, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "domain.delete", a.ID, "domain", d.ID, map[string]any{"name": d.Name, "kind": d.Kind}))
	})
	return jobID, err
}

// token is the TXT value that proves an account controls a domain. It is
// derived from the account and the name, so it needs no storage.
func (s *Service) token(accountID, name string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("domain-verification\x00" + accountID + "\x00" + name))
	return "xcp-verify=" + hex.EncodeToString(m.Sum(nil))[:32]
}

// verification decides whether adding name needs proof of control: another
// account uses a name under the same registered domain, and name is not
// below one of this account's own domains. Then it checks DNS for the record.
func (s *Service) verification(ctx context.Context, a *store.Account, name string) (Verification, error) {
	base := strings.TrimPrefix(name, "*.")
	v := Verification{Name: name, Record: "_xcp-verify." + base, Value: s.token(a.ID, name)}
	under, err := store.DomainsUnder(ctx, s.db.R, validate.Registrable(base))
	if err != nil {
		return v, err
	}
	for _, d := range under {
		if d.AccountID != a.ID {
			v.Required = true
		} else if base == d.Name || strings.HasSuffix(base, "."+d.Name) {
			return Verification{Name: name}, nil // below a domain the account has already
		}
	}
	if !v.Required {
		return Verification{Name: name}, nil
	}
	lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	txts, err := s.resolver.LookupTXT(lookup, v.Record)
	if err == nil {
		for _, t := range txts {
			v.Verified = v.Verified || strings.TrimSpace(t) == v.Value
		}
	}
	return v, nil
}

// Verification tells whether adding name to the account needs a TXT
// record, which one, and whether DNS shows it already.
func (s *Service) Verification(ctx context.Context, p *auth.Principal, accountID, name string) (Verification, error) {
	a, err := s.access(ctx, p, accountID, FeatureDomains)
	if err != nil {
		return Verification{}, err
	}
	n, err := validate.WildcardDomain(name)
	if err != nil {
		return Verification{}, fieldErr(err, "name")
	}
	if p.Login.Role == store.RoleAdmin {
		return Verification{Name: n}, nil // admins are trusted with any domain
	}
	return s.verification(ctx, a, n)
}

func toRedirect(r store.Redirect, domain string) Redirect {
	return Redirect{
		ID: r.ID, DomainID: r.DomainID, Domain: domain, Path: r.Path, Target: r.Target,
		Code: r.Code, KeepPath: r.KeepPath, CreatedAt: r.CreatedAt,
	}
}

// ListRedirects returns the redirects of an account's domains.
func (s *Service) ListRedirects(ctx context.Context, p *auth.Principal, accountID string) ([]Redirect, error) {
	a, err := s.access(ctx, p, accountID, FeatureRedirects)
	if err != nil {
		return nil, err
	}
	ds, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	byID := index(ds)
	rs, err := s.db.ListRedirects(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	out := make([]Redirect, 0, len(rs))
	for _, r := range rs {
		out = append(out, toRedirect(r, byID[r.DomainID].Name))
	}
	return out, nil
}

// AddRedirect adds a redirect to a domain.
func (s *Service) AddRedirect(ctx context.Context, c auth.Client, p *auth.Principal, domainID string, in RedirectInput) (Redirect, error) {
	d, a, err := s.domainForChange(ctx, p, domainID, FeatureRedirects)
	if err != nil {
		return Redirect{}, err
	}
	r := &store.Redirect{ID: ids.New(), DomainID: d.ID, Code: in.Code, KeepPath: in.KeepPath}
	if r.Path, err = validate.RedirectPath(in.Path); err != nil {
		return Redirect{}, fieldErr(err, "path")
	}
	if r.Target, err = validate.RedirectTarget(in.Target); err != nil {
		return Redirect{}, fieldErr(err, "target")
	}
	if err := validate.RedirectCode(in.Code); err != nil {
		return Redirect{}, fieldErr(err, "code")
	}
	if r.KeepPath && strings.ContainsAny(r.Target, "?#") {
		return Redirect{}, badField("target", validate.CodeFormat, "when the rest of the path is kept, the destination cannot have ? or #")
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		n, err := store.CountRedirects(ctx, tx, d.ID)
		if err != nil {
			return err
		}
		if n >= agent.MaxVhostRedirects {
			return apperr.NewConflict("limit_reached", "a domain can have at most 100 redirects")
		}
		if err := store.InsertRedirect(ctx, tx, r); errors.Is(err, store.ErrConflict) {
			return apperr.NewConflict("redirect_exists", d.Name+" has a redirect for "+r.Path+" already")
		} else if err != nil {
			return err
		}
		if jobID, err = s.enqueue(ctx, tx, p, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "redirect.add", a.ID, "redirect", r.ID, map[string]any{
			"domain": d.Name, "path": r.Path, "target": r.Target, "code": r.Code, "keep_path": r.KeepPath,
		}))
	})
	if err != nil {
		return Redirect{}, err
	}
	v := toRedirect(*r, d.Name)
	v.JobID = jobID
	return v, nil
}

// DeleteRedirect removes a redirect.
func (s *Service) DeleteRedirect(ctx context.Context, c auth.Client, p *auth.Principal, id string) (string, error) {
	r, err := s.db.RedirectByID(ctx, id)
	if err != nil {
		return "", err
	}
	d, a, err := s.domainForChange(ctx, p, r.DomainID, FeatureRedirects)
	if err != nil {
		return "", err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteRedirect(ctx, tx, r.ID); err != nil {
			return err
		}
		if jobID, err = s.enqueue(ctx, tx, p, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "redirect.delete", a.ID, "redirect", r.ID, map[string]any{
			"domain": d.Name, "path": r.Path, "target": r.Target,
		}))
	})
	return jobID, err
}
