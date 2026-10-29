// Package zones manages the DNS zones this server serves (ADM-DNS-01..03,
// USR-DNS-01..03): a zone per domain from a template, records added for
// subdomains, a record editor, email routing and the server's DNS settings.
// Zones are applied to PowerDNS by the agent in jobs (jobs.go).
package zones

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/dnsrr"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// FeatureDNS is the feature-list entry that gives users the zone editor.
const FeatureDNS = "dns_editor"

// HostResolver looks up addresses (*net.Resolver in production).
type HostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// StaticHosts is a HostResolver with fixed answers, for tests.
type StaticHosts map[string][]string

// LookupHost implements HostResolver.
func (m StaticHosts) LookupHost(_ context.Context, host string) ([]string, error) {
	if addrs, ok := m[host]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// Service manages zones.
type Service struct {
	db       *store.DB
	audit    *audit.Recorder
	plans    *plans.Service
	jobs     *jobs.Queue
	agent    agentrpc.Client
	resolver HostResolver
}

// NewService returns a zones service.
func NewService(db *store.DB, rec *audit.Recorder, pl *plans.Service, q *jobs.Queue, ag agentrpc.Client, r HostResolver) *Service {
	return &Service{db: db, audit: rec, plans: pl, jobs: q, agent: ag, resolver: r}
}

// Zone is the API view of a zone.
type Zone struct {
	ID          string `json:"id"`
	AccountID   string `json:"account_id"`
	Account     string `json:"account"` // the account's username
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	MailRouting string `json:"mail_routing"`
	// MailRoutingEffective is what "auto" resolves to from the MX records.
	MailRoutingEffective string    `json:"mail_routing_effective,omitempty"`
	Serving              bool      `json:"serving"` // the DNS server has the zone
	Nameservers          []string  `json:"nameservers,omitempty"`
	Records              []Record  `json:"records,omitempty"`
	UpdatedAt            time.Time `json:"updated_at"`
	JobID                string    `json:"job_id,omitempty"`
}

// Record is the API view of a record.
type Record struct {
	ID      string `json:"id"`
	ZoneID  string `json:"zone_id"`
	Name    string `json:"name"` // relative: "@", "www"
	Type    string `json:"type"`
	TTL     uint32 `json:"ttl"`
	Content string `json:"content"` // TXT as plain text
	Managed bool   `json:"managed"` // made for a domain; removed with it
	JobID   string `json:"job_id,omitempty"`
}

// RecordInput adds or replaces a record.
type RecordInput struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     uint32 `json:"ttl"` // 0 = the server's default
	Content string `json:"content"`
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

// access loads an account the caller may manage DNS for: admins the
// admin-owned accounts, users their own if the feature list has the editor.
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
		if !slices.Contains(features, FeatureDNS) {
			return nil, apperr.ErrForbidden
		}
	default:
		return nil, apperr.ErrForbidden
	}
	return a, nil
}

func (s *Service) zone(ctx context.Context, p *auth.Principal, id string) (*store.Zone, *store.Account, error) {
	z, err := store.ZoneByID(ctx, s.db.R, id)
	if err != nil {
		return nil, nil, err
	}
	a, err := s.access(ctx, p, z.AccountID)
	return z, a, err
}

func view(z store.Zone, account string) Zone {
	return Zone{
		ID: z.ID, AccountID: z.AccountID, Account: account, Name: z.Name, DisplayName: validate.DomainUnicode(z.Name),
		MailRouting: z.MailRouting, Serving: z.Serving, UpdatedAt: z.UpdatedAt,
	}
}

func recordView(r store.ZoneRecord, zone string) Record {
	return Record{
		ID: r.ID, ZoneID: r.ZoneID, Name: dnsrr.Relative(r.Name, zone), Type: r.Type, TTL: r.TTL,
		Content: dnsrr.Plain(r.Type, r.Content), Managed: r.DomainID != "",
	}
}

// List returns zones: an admin's are all zones of admin-owned accounts (or
// of one account), a user's those of their own account.
func (s *Service) List(ctx context.Context, p *auth.Principal, accountID, search string) ([]Zone, error) {
	if p == nil {
		return nil, apperr.ErrForbidden
	}
	if p.Login.Role == store.RoleUser {
		accountID = p.Login.AccountID
	}
	var (
		zs  []store.Zone
		err error
	)
	if accountID != "" {
		if _, err := s.access(ctx, p, accountID); err != nil {
			return nil, err
		}
		zs, err = store.AccountZones(ctx, s.db.R, accountID)
	} else {
		if err := admin(p); err != nil {
			return nil, err
		}
		zs, err = s.db.ListZones(ctx, store.ZoneFilter{Search: search})
	}
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	out := make([]Zone, 0, len(zs))
	for _, z := range zs {
		if _, ok := names[z.AccountID]; !ok {
			if a, err := s.db.AccountByID(ctx, z.AccountID); err == nil {
				names[z.AccountID] = a.Username
			}
		}
		out = append(out, view(z, names[z.AccountID]))
	}
	return out, nil
}

// Get returns a zone with its records.
func (s *Service) Get(ctx context.Context, p *auth.Principal, id string) (Zone, error) {
	z, a, err := s.zone(ctx, p, id)
	if err != nil {
		return Zone{}, err
	}
	return s.full(ctx, *z, a.Username)
}

func (s *Service) full(ctx context.Context, z store.Zone, account string) (Zone, error) {
	recs, err := store.ZoneRecords(ctx, s.db.R, z.ID)
	if err != nil {
		return Zone{}, err
	}
	set, err := s.Settings(ctx)
	if err != nil {
		return Zone{}, err
	}
	v := view(z, account)
	v.Nameservers = set.nameservers(z.Name)
	v.MailRoutingEffective = mailRouting(z, recs, set)
	v.Records = make([]Record, 0, len(recs))
	for _, r := range recs {
		v.Records = append(v.Records, recordView(r, z.Name))
	}
	return v, nil
}

// mailRouting resolves "auto" from the MX records at the zone's top: mail
// is local when the most preferred MX is this server, backup when a less
// preferred one is, and remote otherwise. No MX means mail goes to the
// domain itself, which is served here.
func mailRouting(z store.Zone, recs []store.ZoneRecord, set Settings) string {
	if z.MailRouting != store.MailAuto {
		return z.MailRouting
	}
	ours := func(host string) bool {
		for _, r := range recs {
			if r.Name == host && (r.Type == "A" || r.Type == "AAAA") && (r.Content == set.IPv4 || r.Content == set.IPv6) {
				return true
			}
		}
		return false
	}
	best, bestOurs, anyOurs, seen := 0, false, false, false
	for _, r := range recs {
		if r.Name != z.Name || r.Type != "MX" {
			continue
		}
		f := strings.Fields(r.Content)
		if len(f) != 2 {
			continue
		}
		pref, _ := strconv.Atoi(f[0])
		mine := ours(strings.TrimSuffix(f[1], "."))
		anyOurs = anyOurs || mine
		if !seen || pref < best || (pref == best && mine) {
			best, bestOurs, seen = pref, mine, true
		}
	}
	switch {
	case !seen || bestOurs:
		return store.MailLocal
	case anyOurs:
		return store.MailBackup
	}
	return store.MailRemote
}

// SetMailRouting changes who handles a zone's mail. The mail service uses it.
func (s *Service) SetMailRouting(ctx context.Context, c auth.Client, p *auth.Principal, id, routing string) (Zone, error) {
	z, a, err := s.zone(ctx, p, id)
	if err != nil {
		return Zone{}, err
	}
	if !slices.Contains([]string{store.MailAuto, store.MailLocal, store.MailRemote, store.MailBackup}, routing) {
		return Zone{}, badField("mail_routing", validate.CodeFormat, "mail routing must be auto, local, remote or backup")
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetZoneMailRouting(ctx, tx, z.ID, routing); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dns.mail_routing", a.ID, "zone", z.ID, map[string]any{
			"zone": z.Name, "from": z.MailRouting, "to": routing,
		}))
	})
	if err != nil {
		return Zone{}, err
	}
	z.MailRouting = routing
	return s.full(ctx, *z, a.Username)
}

func toDNSRR(recs []store.ZoneRecord) []dnsrr.Record {
	out := make([]dnsrr.Record, len(recs))
	for i, r := range recs {
		out[i] = dnsrr.Record{Name: r.Name, Type: r.Type, TTL: r.TTL, Content: r.Content}
	}
	return out
}

// record checks one record's input in a zone and returns it in stored form.
func (s *Service) record(ctx context.Context, zone string, in RecordInput) (store.ZoneRecord, error) {
	typ := strings.ToUpper(strings.TrimSpace(in.Type))
	name, err := dnsrr.Name(in.Name, zone)
	if err != nil {
		return store.ZoneRecord{}, field("name", err)
	}
	content, err := dnsrr.Content(typ, in.Content, zone)
	if err != nil {
		return store.ZoneRecord{}, field("content", err)
	}
	ttl := in.TTL
	if ttl == 0 {
		set, err := s.Settings(ctx)
		if err != nil {
			return store.ZoneRecord{}, err
		}
		ttl = set.TTL
	}
	if ttl < dnsrr.MinTTL || ttl > dnsrr.MaxTTL {
		return store.ZoneRecord{}, badField("ttl", validate.CodeOutOfRange, "TTL must be 60 to 604800 seconds")
	}
	return store.ZoneRecord{Name: name, Type: typ, TTL: ttl, Content: content}, nil
}

// change validates the zone with one record added, replaced or removed,
// saves it, queues the zone's job and records the audit event.
func (s *Service) change(ctx context.Context, c auth.Client, p *auth.Principal, z *store.Zone, a *store.Account,
	action string, rec *store.ZoneRecord, removeID string,
) (string, error) {
	var jobID string
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		recs, err := store.ZoneRecords(ctx, tx, z.ID)
		if err != nil {
			return err
		}
		recs = slices.DeleteFunc(recs, func(r store.ZoneRecord) bool { return r.ID == removeID || (rec != nil && r.ID == rec.ID) })
		if rec != nil {
			if slices.ContainsFunc(recs, func(r store.ZoneRecord) bool {
				return r.Name == rec.Name && r.Type == rec.Type && r.Content == rec.Content
			}) {
				return apperr.NewConflict("record_exists", "the zone has this record already")
			}
			recs = append(recs, *rec)
			if err := dnsrr.CheckZone(z.Name, toDNSRR(recs)); err != nil {
				return apperr.NewConflict("record_conflict", err.Error())
			}
		}
		switch action {
		case "dns.record.add":
			err = store.InsertRecord(ctx, tx, rec)
		case "dns.record.update":
			err = store.UpdateRecord(ctx, tx, rec)
		default:
			err = store.DeleteRecord(ctx, tx, removeID)
		}
		if errors.Is(err, store.ErrConflict) {
			return apperr.NewConflict("record_exists", "the zone has this record already")
		} else if err != nil {
			return err
		}
		if err := store.TouchZone(ctx, tx, z.ID); err != nil {
			return err
		}
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, *z); err != nil {
			return err
		}
		details := map[string]any{"zone": z.Name}
		if rec != nil {
			details["name"], details["type"], details["content"], details["ttl"] = rec.Name, rec.Type, rec.Content, rec.TTL
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, action, a.ID, "zone", z.ID, details))
	})
	return jobID, err
}

// AddRecord adds a record to a zone.
func (s *Service) AddRecord(ctx context.Context, c auth.Client, p *auth.Principal, zoneID string, in RecordInput) (Record, error) {
	z, a, err := s.zone(ctx, p, zoneID)
	if err != nil {
		return Record{}, err
	}
	r, err := s.record(ctx, z.Name, in)
	if err != nil {
		return Record{}, err
	}
	r.ID, r.ZoneID = ids.New(), z.ID
	jobID, err := s.change(ctx, c, p, z, a, "dns.record.add", &r, "")
	if err != nil {
		return Record{}, err
	}
	v := recordView(r, z.Name)
	v.JobID = jobID
	return v, nil
}

// UpdateRecord replaces a record.
func (s *Service) UpdateRecord(ctx context.Context, c auth.Client, p *auth.Principal, id string, in RecordInput) (Record, error) {
	old, err := store.RecordByID(ctx, s.db.R, id)
	if err != nil {
		return Record{}, err
	}
	z, a, err := s.zone(ctx, p, old.ZoneID)
	if err != nil {
		return Record{}, err
	}
	r, err := s.record(ctx, z.Name, in)
	if err != nil {
		return Record{}, err
	}
	r.ID, r.ZoneID, r.DomainID = old.ID, z.ID, old.DomainID
	jobID, err := s.change(ctx, c, p, z, a, "dns.record.update", &r, "")
	if err != nil {
		return Record{}, err
	}
	v := recordView(r, z.Name)
	v.JobID = jobID
	return v, nil
}

// DeleteRecord removes a record.
func (s *Service) DeleteRecord(ctx context.Context, c auth.Client, p *auth.Principal, id string) (string, error) {
	r, err := store.RecordByID(ctx, s.db.R, id)
	if err != nil {
		return "", err
	}
	z, a, err := s.zone(ctx, p, r.ZoneID)
	if err != nil {
		return "", err
	}
	return s.change(ctx, c, p, z, a, "dns.record.delete", nil, r.ID)
}

// hostRecords are the records that make a domain inside an existing zone
// reach this server: A and AAAA, and for an addon domain or alias also www.
func (set Settings) hostRecords(d *store.Domain) []store.ZoneRecord {
	var out []store.ZoneRecord
	for typ, ip := range map[string]string{"A": set.IPv4, "AAAA": set.IPv6} {
		if ip != "" {
			out = append(out, store.ZoneRecord{Name: d.Name, Type: typ, TTL: set.TTL, Content: ip})
		}
	}
	if d.Kind != store.DomainSub {
		out = append(out, store.ZoneRecord{Name: "www." + d.Name, Type: "CNAME", TTL: set.TTL, Content: d.Name + "."})
	}
	slices.SortFunc(out, func(a, b store.ZoneRecord) int { return strings.Compare(a.Name+a.Type, b.Name+b.Type) })
	return out
}

// DomainAdded sets up DNS for a new domain inside tx: records in the
// account's zone that already covers its name, or else its own zone from
// the template. It returns the zones to apply.
func (s *Service) DomainAdded(ctx context.Context, tx *sql.Tx, d *store.Domain) ([]store.Zone, error) {
	set, err := s.Settings(ctx)
	if err != nil {
		return nil, err
	}
	zs, err := store.AccountZones(ctx, tx, d.AccountID)
	if err != nil {
		return nil, err
	}
	base := strings.TrimPrefix(d.Name, "*.")
	var home *store.Zone
	for i, z := range zs {
		if (base == z.Name || strings.HasSuffix(base, "."+z.Name)) && (home == nil || len(z.Name) > len(home.Name)) {
			home = &zs[i]
		}
	}
	if home != nil && home.Name == d.Name {
		return []store.Zone{*home}, nil // the zone is there already
	}
	if home == nil {
		if d.Kind == store.DomainSub {
			return nil, nil // its domain has no zone here
		}
		z := store.Zone{ID: ids.New(), AccountID: d.AccountID, DomainID: d.ID, Name: d.Name}
		if err := store.InsertZone(ctx, tx, &z); errors.Is(err, store.ErrConflict) {
			return nil, apperr.NewConflict("zone_exists", "this server has a DNS zone "+d.Name+" already")
		} else if err != nil {
			return nil, err
		}
		recs, err := set.render(set.Template, z.Name)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			r.ID, r.ZoneID = ids.New(), z.ID
			if err := store.InsertRecord(ctx, tx, &r); err != nil && !errors.Is(err, store.ErrConflict) {
				return nil, err
			}
		}
		return []store.Zone{z}, nil
	}
	existing, err := store.ZoneRecords(ctx, tx, home.ID)
	if err != nil {
		return nil, err
	}
	for _, r := range set.hostRecords(d) {
		if slices.ContainsFunc(existing, func(e store.ZoneRecord) bool { return e.Name == r.Name }) {
			continue // the name has records already: those win
		}
		r.ID, r.ZoneID, r.DomainID = ids.New(), home.ID, d.ID
		if err := store.InsertRecord(ctx, tx, &r); err != nil && !errors.Is(err, store.ErrConflict) {
			return nil, err
		}
	}
	return []store.Zone{*home}, store.TouchZone(ctx, tx, home.ID)
}

// DomainRemoving is called inside tx before a domain is deleted (which
// deletes its zone and records). It returns the zones to delete from the
// DNS server and the other zones to apply again.
func (s *Service) DomainRemoving(ctx context.Context, tx *sql.Tx, d *store.Domain) (remove, apply []store.Zone, err error) {
	remove, err = store.DomainZones(ctx, tx, d.ID)
	if err != nil {
		return nil, nil, err
	}
	for _, z := range remove {
		n, err := store.ForeignDomainRecords(ctx, tx, z.ID, d.ID)
		if err != nil {
			return nil, nil, err
		}
		if n > 0 {
			return nil, nil, apperr.NewConflict("zone_in_use", "the DNS zone "+z.Name+" also holds the records of other domains; remove those domains first")
		}
	}
	zoneIDs, err := store.DomainRecordZones(ctx, tx, d.ID)
	if err != nil {
		return nil, nil, err
	}
	for _, id := range zoneIDs {
		if slices.ContainsFunc(remove, func(z store.Zone) bool { return z.ID == id }) {
			continue
		}
		z, err := store.ZoneByID(ctx, tx, id)
		if err != nil {
			return nil, nil, err
		}
		apply = append(apply, *z)
	}
	return remove, apply, nil
}
