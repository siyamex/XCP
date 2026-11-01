// Package mail manages the mail of accounts' domains: mailboxes,
// forwarders, default addresses, DKIM and the deliverability check
// (USR-MAIL-01, 03, 06, 09), and the server's mail settings (ADM-MAIL-01).
// The panel database is the source of truth; jobs give the agent each
// account's mail (ADR-0007).
package mail

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
	"github.com/siyamex/XCP/internal/zones"
)

// FeatureEmail switches mail management on in a feature list.
const FeatureEmail = "email"

// Domain is a domain as the mail page shows it.
type Domain struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Kind        string   `json:"kind"`
	Routing     string   `json:"routing"`            // local, remote or backup (the zone's email routing)
	AliasOf     string   `json:"alias_of,omitempty"` // an alias domain's mail goes to the same address there
	CatchAll    []string `json:"catch_all"`          // where unknown addresses go; empty rejects them
	DKIM        bool     `json:"dkim"`               // has a signing key
}

// Mailbox is the API view of a mailbox.
type Mailbox struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	Address   string    `json:"address"`
	QuotaMB   int64     `json:"quota_mb"`
	Login     bool      `json:"login"`
	Receive   bool      `json:"receive"`
	Send      bool      `json:"send"`
	CreatedAt time.Time `json:"created_at"`
	JobID     string    `json:"job_id,omitempty"`
}

// Forwarder is the API view of a forwarder.
type Forwarder struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	Address   string    `json:"address"`
	To        []string  `json:"to"`
	Fail      string    `json:"fail,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	JobID     string    `json:"job_id,omitempty"`
}

// Overview is everything the mail page shows.
type Overview struct {
	Domains       []Domain    `json:"domains"`
	Mailboxes     []Mailbox   `json:"mailboxes"`
	Forwarders    []Forwarder `json:"forwarders"`
	MaxMailboxes  *int64      `json:"max_mailboxes"`
	MaxForwarders *int64      `json:"max_forwarders"`
	MaxQuotaMB    *int64      `json:"max_quota_mb"`
	Server        string      `json:"server"` // the host name mail clients connect to
}

// MailboxInput creates a mailbox.
type MailboxInput struct {
	DomainID string `json:"domain_id"`
	Local    string `json:"local"`
	Password string `json:"password"`
	QuotaMB  int64  `json:"quota_mb"` // 0: the package's largest
}

// MailboxUpdate changes a mailbox's quota and switches.
type MailboxUpdate struct {
	QuotaMB int64 `json:"quota_mb"`
	Login   bool  `json:"login"`
	Receive bool  `json:"receive"`
	Send    bool  `json:"send"`
}

// ForwarderInput creates a forwarder: to addresses, or a rejection.
type ForwarderInput struct {
	DomainID string   `json:"domain_id"`
	Local    string   `json:"local"`
	To       []string `json:"to"`
	Fail     string   `json:"fail"`
}

// HostnameSource tells the server's host name (package ssl).
type HostnameSource interface {
	Hostname(ctx context.Context) string
}

// Service manages mail.
type Service struct {
	db       *store.DB
	audit    *audit.Recorder
	plans    *plans.Service
	jobs     *jobs.Queue
	agent    agentrpc.Client
	zones    *zones.Service
	box      *secretbox.Box
	resolver Resolver
	host     HostnameSource
}

// NewService returns a mail service. box encrypts the DKIM keys.
func NewService(db *store.DB, rec *audit.Recorder, pl *plans.Service, q *jobs.Queue, ag agentrpc.Client, zs *zones.Service,
	box *secretbox.Box, r Resolver, host HostnameSource,
) *Service {
	return &Service{db: db, audit: rec, plans: pl, jobs: q, agent: ag, zones: zs, box: box, resolver: r, host: host}
}

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

// access loads an account the caller may manage (admins the admin-owned
// accounts, users their own with the email feature), with its limits.
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
		if !slices.Contains(features, FeatureEmail) {
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

// mailDomain loads one of the account's domains that can have addresses:
// not a wildcard, not an alias (its mail goes to its domain).
func (s *Service) mailDomain(ctx context.Context, a *store.Account, id string) (*store.Domain, error) {
	d, err := s.db.DomainByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) || err == nil && d.AccountID != a.ID {
		return nil, badField("domain_id", validate.CodeFormat, "choose one of the account's domains")
	}
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasPrefix(d.Name, "*."):
		return nil, badField("domain_id", validate.CodeFormat, "a wildcard subdomain has no mail of its own")
	case d.Kind == store.DomainAlias:
		return nil, badField("domain_id", validate.CodeFormat, "mail for an alias goes to the same address at its domain; add it there")
	}
	return d, nil
}

func (s *Service) server(ctx context.Context) string {
	if s.host != nil {
		if h := s.host.Hostname(ctx); h != "" {
			return h
		}
	}
	set, err := s.Settings(ctx, nil)
	if err == nil {
		return set.Hostname
	}
	return ""
}

// Overview returns an account's mail.
func (s *Service) Overview(ctx context.Context, p *auth.Principal, accountID string) (Overview, error) {
	a, lim, err := s.access(ctx, p, accountID)
	if err != nil {
		return Overview{}, err
	}
	o := Overview{MaxMailboxes: lim.Mailboxes, MaxForwarders: lim.Forwarders, MaxQuotaMB: lim.MailboxMB, Server: s.server(ctx)}
	ds, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return o, err
	}
	mds, err := store.AccountMailDomains(ctx, s.db.R, a.ID)
	if err != nil {
		return o, err
	}
	byID := map[string]store.Domain{}
	for _, d := range ds {
		byID[d.ID] = d
	}
	o.Domains = []Domain{}
	for _, d := range ds {
		if strings.HasPrefix(d.Name, "*.") {
			continue
		}
		routing, err := s.zones.MailRouting(ctx, d)
		if err != nil {
			return o, err
		}
		md := mds[d.ID]
		v := Domain{
			ID: d.ID, Name: d.Name, DisplayName: validate.DomainUnicode(d.Name), Kind: d.Kind, Routing: routing,
			CatchAll: md.CatchAll, DKIM: len(md.DKIMKeyEnc) > 0,
		}
		if v.CatchAll == nil {
			v.CatchAll = []string{}
		}
		if d.Kind == store.DomainAlias {
			v.AliasOf = byID[d.ParentID].Name
		}
		o.Domains = append(o.Domains, v)
	}
	boxes, err := store.AccountMailboxes(ctx, s.db.R, a.ID)
	if err != nil {
		return o, err
	}
	o.Mailboxes = make([]Mailbox, 0, len(boxes))
	for _, m := range boxes {
		o.Mailboxes = append(o.Mailboxes, mailboxView(m, byID[m.DomainID].Name))
	}
	fws, err := store.AccountForwarders(ctx, s.db.R, a.ID)
	if err != nil {
		return o, err
	}
	o.Forwarders = make([]Forwarder, 0, len(fws))
	for _, f := range fws {
		o.Forwarders = append(o.Forwarders, forwarderView(f, byID[f.DomainID].Name))
	}
	return o, nil
}

func mailboxView(m store.Mailbox, domain string) Mailbox {
	return Mailbox{
		ID: m.ID, DomainID: m.DomainID, Address: m.LocalPart + "@" + domain, QuotaMB: m.QuotaMB,
		Login: m.CanLogin, Receive: m.CanReceive, Send: m.CanSend, CreatedAt: m.CreatedAt,
	}
}

func forwarderView(f store.Forwarder, domain string) Forwarder {
	to := f.Destinations
	if to == nil {
		to = []string{}
	}
	return Forwarder{ID: f.ID, DomainID: f.DomainID, Address: f.LocalPart + "@" + domain, To: to, Fail: f.FailMessage, CreatedAt: f.CreatedAt}
}

// HashPassword returns the {ARGON2ID} hash Dovecot checks: libsodium's
// format at its "interactive" cost.
func HashPassword(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt) // never fails (crypto/rand)
	const t, m, p = 2, 64 * 1024, 1
	key := argon2.IDKey([]byte(password), salt, t, m, p, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("{ARGON2ID}$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p, enc.EncodeToString(salt), enc.EncodeToString(key))
}

// quota checks a mailbox quota against the package; 0 means the largest allowed.
func quota(mb int64, lim plans.Limits) (int64, error) {
	if mb < 0 {
		return 0, badField("quota_mb", validate.CodeOutOfRange, "the quota cannot be negative")
	}
	if lim.MailboxMB != nil {
		if mb == 0 {
			return *lim.MailboxMB, nil
		}
		if mb > *lim.MailboxMB {
			return 0, badField("quota_mb", validate.CodeOutOfRange, fmt.Sprintf("the package allows at most %d MB per mailbox", *lim.MailboxMB))
		}
	}
	return mb, nil
}

func checkLimit(n int, err error, limit *int64, what string) error {
	if err != nil || limit == nil {
		return err
	}
	if int64(n) >= *limit {
		return apperr.NewConflict("limit_reached", "the package allows no more "+what)
	}
	return nil
}

// ensureMailDomain gives a domain its mail row and DKIM key on first use,
// and publishes the key in its zone when this server serves it.
func (s *Service) ensureMailDomain(ctx context.Context, tx *sql.Tx, createdBy string, d *store.Domain) error {
	mds, err := store.AccountMailDomains(ctx, tx, d.AccountID)
	if err != nil {
		return err
	}
	md, ok := mds[d.ID]
	if ok && len(md.DKIMKeyEnc) > 0 {
		return nil
	}
	if !ok {
		md = store.MailDomain{DomainID: d.ID}
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	md.DKIMKeyEnc = s.box.Seal(keyPEM, []byte("dkim:"+d.ID))
	if err := store.SetMailDomain(ctx, tx, md); err != nil {
		return err
	}
	pub, err := dkimRecord(&k.PublicKey)
	if err != nil {
		return err
	}
	_, err = s.zones.EnsureRecords(ctx, tx, createdBy, *d, []zones.RecordWant{dkimWant(d.Name, pub)})
	if errors.Is(err, zones.ErrNoZone) {
		return nil // the user publishes it where their DNS is
	}
	return err
}

// CreateMailbox adds a mailbox.
func (s *Service) CreateMailbox(ctx context.Context, c auth.Client, p *auth.Principal, accountID string, in MailboxInput) (Mailbox, error) {
	a, lim, err := s.forChange(ctx, p, accountID)
	if err != nil {
		return Mailbox{}, err
	}
	d, err := s.mailDomain(ctx, a, in.DomainID)
	if err != nil {
		return Mailbox{}, err
	}
	m := &store.Mailbox{ID: ids.New(), DomainID: d.ID, CanLogin: true, CanReceive: true, CanSend: true}
	if m.LocalPart, err = validate.MailboxName(in.Local); err != nil {
		return Mailbox{}, validate.WithField(err, "local")
	}
	if err := validate.Password(in.Password); err != nil {
		return Mailbox{}, validate.WithField(err, "password")
	}
	if m.QuotaMB, err = quota(in.QuotaMB, lim); err != nil {
		return Mailbox{}, err
	}
	m.PasswordHash = HashPassword(in.Password)
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		n, err := store.CountMailboxes(ctx, tx, a.ID)
		if err := checkLimit(n, err, lim.Mailboxes, "mailboxes"); err != nil {
			return err
		}
		if err := s.addressFree(ctx, tx, a.ID, d.ID, m.LocalPart); err != nil {
			return err
		}
		if err := store.InsertMailbox(ctx, tx, m); errors.Is(err, store.ErrConflict) {
			return apperr.NewConflict("address_taken", m.LocalPart+"@"+d.Name+" exists already")
		} else if err != nil {
			return err
		}
		if err := s.ensureMailDomain(ctx, tx, p.Login.ID, d); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.mailbox.create", a.ID, "mailbox", m.ID, map[string]any{
			"address": m.LocalPart + "@" + d.Name, "quota_mb": m.QuotaMB,
		}))
	})
	if err != nil {
		return Mailbox{}, err
	}
	v := mailboxView(*m, d.Name)
	v.JobID = jobID
	return v, nil
}

// addressFree refuses a mailbox where a forwarder rejects the address's
// mail: the two cannot share one.
func (s *Service) addressFree(ctx context.Context, tx *sql.Tx, accountID, domainID, local string) error {
	fws, err := store.AccountForwarders(ctx, tx, accountID)
	if err != nil {
		return err
	}
	for _, f := range fws {
		if f.DomainID == domainID && f.LocalPart == local && f.FailMessage != "" {
			return apperr.NewConflict("address_taken", "this address rejects its mail; remove that forwarder first")
		}
	}
	return nil
}

func (s *Service) ownMailbox(ctx context.Context, p *auth.Principal, id string) (*store.Mailbox, *store.Account, plans.Limits, string, error) {
	m, err := s.db.MailboxByID(ctx, id)
	if err != nil {
		return nil, nil, plans.Limits{}, "", err
	}
	d, err := s.db.DomainByID(ctx, m.DomainID)
	if err != nil {
		return nil, nil, plans.Limits{}, "", err
	}
	a, lim, err := s.forChange(ctx, p, d.AccountID)
	return m, a, lim, d.Name, err
}

// UpdateMailbox changes a mailbox's quota and switches.
func (s *Service) UpdateMailbox(ctx context.Context, c auth.Client, p *auth.Principal, id string, in MailboxUpdate) (Mailbox, error) {
	m, a, lim, domain, err := s.ownMailbox(ctx, p, id)
	if err != nil {
		return Mailbox{}, err
	}
	if m.QuotaMB, err = quota(in.QuotaMB, lim); err != nil {
		return Mailbox{}, err
	}
	m.CanLogin, m.CanReceive, m.CanSend = in.Login, in.Receive, in.Send
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.UpdateMailbox(ctx, tx, m); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.mailbox.update", a.ID, "mailbox", m.ID, map[string]any{
			"address": m.LocalPart + "@" + domain, "quota_mb": m.QuotaMB, "login": in.Login, "receive": in.Receive, "send": in.Send,
		}))
	})
	if err != nil {
		return Mailbox{}, err
	}
	v := mailboxView(*m, domain)
	v.JobID = jobID
	return v, nil
}

// SetMailboxPassword changes a mailbox's password.
func (s *Service) SetMailboxPassword(ctx context.Context, c auth.Client, p *auth.Principal, id, password string) (string, error) {
	m, a, _, domain, err := s.ownMailbox(ctx, p, id)
	if err != nil {
		return "", err
	}
	if err := validate.Password(password); err != nil {
		return "", validate.WithField(err, "password")
	}
	m.PasswordHash = HashPassword(password)
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.UpdateMailbox(ctx, tx, m); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.mailbox.password", a.ID, "mailbox", m.ID, map[string]any{"address": m.LocalPart + "@" + domain}))
	})
	return jobID, err
}

// DeleteMailbox removes a mailbox. Its mail stays in the account's home.
func (s *Service) DeleteMailbox(ctx context.Context, c auth.Client, p *auth.Principal, id string) (string, error) {
	m, a, _, domain, err := s.ownMailbox(ctx, p, id)
	if err != nil {
		return "", err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteMailbox(ctx, tx, m.ID); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.mailbox.delete", a.ID, "mailbox", m.ID, map[string]any{"address": m.LocalPart + "@" + domain}))
	})
	return jobID, err
}

// targets checks forwarding addresses and normalises them.
func targets(field string, to []string) ([]string, error) {
	if len(to) == 0 || len(to) > agent.MailMaxForwardTo {
		return nil, badField(field, validate.CodeFormat, fmt.Sprintf("give 1 to %d addresses", agent.MailMaxForwardTo))
	}
	out := make([]string, 0, len(to))
	for _, t := range to {
		e, err := validate.Email(t)
		if err != nil {
			return nil, validate.WithField(err, field)
		}
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out, nil
}

// CreateForwarder adds a forwarder.
func (s *Service) CreateForwarder(ctx context.Context, c auth.Client, p *auth.Principal, accountID string, in ForwarderInput) (Forwarder, error) {
	a, lim, err := s.forChange(ctx, p, accountID)
	if err != nil {
		return Forwarder{}, err
	}
	d, err := s.mailDomain(ctx, a, in.DomainID)
	if err != nil {
		return Forwarder{}, err
	}
	f := &store.Forwarder{ID: ids.New(), DomainID: d.ID}
	if f.LocalPart, err = validate.MailboxName(in.Local); err != nil {
		return Forwarder{}, validate.WithField(err, "local")
	}
	if fail := strings.TrimSpace(in.Fail); fail != "" {
		if len(fail) > 200 || strings.ContainsFunc(fail, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			return Forwarder{}, badField("fail", validate.CodeFormat, "the message is one line of plain text, at most 200 characters")
		}
		if len(in.To) > 0 {
			return Forwarder{}, badField("to", validate.CodeFormat, "a forwarder either forwards or rejects")
		}
		f.FailMessage = fail
	} else if f.Destinations, err = targets("to", in.To); err != nil {
		return Forwarder{}, err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		n, err := store.CountForwarders(ctx, tx, a.ID)
		if err := checkLimit(n, err, lim.Forwarders, "forwarders"); err != nil {
			return err
		}
		if f.FailMessage != "" {
			boxes, err := store.AccountMailboxes(ctx, tx, a.ID)
			if err != nil {
				return err
			}
			if slices.ContainsFunc(boxes, func(m store.Mailbox) bool { return m.DomainID == d.ID && m.LocalPart == f.LocalPart }) {
				return apperr.NewConflict("address_taken", "a mailbox has this address; it cannot also reject its mail")
			}
		}
		if err := store.InsertForwarder(ctx, tx, f); errors.Is(err, store.ErrConflict) {
			return apperr.NewConflict("address_taken", f.LocalPart+"@"+d.Name+" has a forwarder already")
		} else if err != nil {
			return err
		}
		if err := s.ensureMailDomain(ctx, tx, p.Login.ID, d); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.forwarder.create", a.ID, "forwarder", f.ID, map[string]any{
			"address": f.LocalPart + "@" + d.Name, "to": f.Destinations, "fail": f.FailMessage,
		}))
	})
	if err != nil {
		return Forwarder{}, err
	}
	v := forwarderView(*f, d.Name)
	v.JobID = jobID
	return v, nil
}

// DeleteForwarder removes a forwarder.
func (s *Service) DeleteForwarder(ctx context.Context, c auth.Client, p *auth.Principal, id string) (string, error) {
	f, err := s.db.ForwarderByID(ctx, id)
	if err != nil {
		return "", err
	}
	d, err := s.db.DomainByID(ctx, f.DomainID)
	if err != nil {
		return "", err
	}
	a, _, err := s.forChange(ctx, p, d.AccountID)
	if err != nil {
		return "", err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteForwarder(ctx, tx, f.ID); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.forwarder.delete", a.ID, "forwarder", f.ID, map[string]any{"address": f.LocalPart + "@" + d.Name}))
	})
	return jobID, err
}

// SetCatchAll sets where a domain's mail to unknown addresses goes: to
// these addresses (a local mailbox or anywhere), or nowhere (rejected).
func (s *Service) SetCatchAll(ctx context.Context, c auth.Client, p *auth.Principal, domainID string, to []string) (string, error) {
	d, err := s.db.DomainByID(ctx, domainID)
	if err != nil {
		return "", err
	}
	a, _, err := s.forChange(ctx, p, d.AccountID)
	if err != nil {
		return "", err
	}
	if d, err = s.mailDomain(ctx, a, domainID); err != nil {
		return "", err
	}
	list := []string{}
	if len(to) > 0 {
		if list, err = targets("to", to); err != nil {
			return "", err
		}
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.ensureMailDomain(ctx, tx, p.Login.ID, d); err != nil {
			return err
		}
		mds, err := store.AccountMailDomains(ctx, tx, a.ID)
		if err != nil {
			return err
		}
		md := mds[d.ID]
		md.CatchAll = list
		if err := store.SetMailDomain(ctx, tx, md); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.catch_all", a.ID, "domain", d.ID, map[string]any{"domain": d.Name, "to": list}))
	})
	return jobID, err
}
