package mail

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/dnsrr"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/tlsx"
	"github.com/siyamex/XCP/internal/zones"
)

// Resolver looks names up in public DNS (*net.Resolver in production).
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Check results.
const (
	CheckOK      = "ok"
	CheckWarning = "warning"
	CheckError   = "error"
)

// Check is one item of the deliverability check (USR-MAIL-09).
type Check struct {
	Name     string   `json:"name"` // mx, spf, dkim, dmarc, ptr
	Status   string   `json:"status"`
	Found    []string `json:"found"`
	Expected string   `json:"expected,omitempty"`
	Detail   string   `json:"detail"`
}

// Deliverability is a domain's check.
type Deliverability struct {
	DomainID   string  `json:"domain_id"`
	Domain     string  `json:"domain"`
	Routing    string  `json:"routing"`
	Checks     []Check `json:"checks"`
	Repairable bool    `json:"repairable"` // this server serves the domain's DNS
}

// The records repair writes.
const (
	spfDefault   = "v=spf1 a mx ~all"
	dmarcDefault = "v=DMARC1; p=none"
)

// dkimRecord is the TXT value that publishes a DKIM public key.
func dkimRecord(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der), nil
}

func dkimName(domain string) string { return "xcp._domainkey." + domain }

func dkimWant(domain, value string) zones.RecordWant {
	return zones.RecordWant{Name: dkimName(domain), Type: "TXT", Content: value, Replace: func(string) bool { return true }}
}

func isSPF(v string) bool   { return strings.HasPrefix(strings.ToLower(v), "v=spf1") }
func isDMARC(v string) bool { return strings.HasPrefix(strings.ToUpper(v), "V=DMARC1") }

// dkimValue returns the DKIM record a domain should publish ("" without a key).
func (s *Service) dkimValue(md store.MailDomain) (string, error) {
	if len(md.DKIMKeyEnc) == 0 {
		return "", nil
	}
	pemKey, err := s.box.Open(md.DKIMKeyEnc, []byte("dkim:"+md.DomainID))
	if err != nil {
		return "", err
	}
	k, err := tlsx.ParseRSAKey(string(pemKey))
	if err != nil {
		return "", err
	}
	return dkimRecord(&k.PublicKey)
}

// serverIPs are the addresses this server's mail comes from.
func (s *Service) serverIPs(ctx context.Context) []string {
	set, err := s.zones.Settings(ctx)
	if err != nil {
		return nil
	}
	var ips []string
	for _, ip := range []string{set.IPv4, set.IPv6} {
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

func (s *Service) resolvesHere(ctx context.Context, host string, ips []string) bool {
	addrs, err := s.resolver.LookupHost(ctx, host)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if slices.Contains(ips, a) {
			return true
		}
	}
	return false
}

func (s *Service) checkMX(ctx context.Context, domain, routing string, ips []string) Check {
	c := Check{Name: "mx", Found: []string{}}
	mxs, err := s.resolver.LookupMX(ctx, domain)
	for _, m := range mxs {
		c.Found = append(c.Found, strings.TrimSuffix(m.Host, "."))
	}
	switch {
	case routing != store.MailLocal:
		c.Status, c.Detail = CheckOK, "mail for this domain is handled by another server ("+routing+")"
	case err != nil || len(mxs) == 0:
		c.Status, c.Detail = CheckError, "the domain has no MX record, so other servers do not know where to deliver its mail"
	case s.resolvesHere(ctx, strings.TrimSuffix(mxs[0].Host, "."), ips):
		c.Status, c.Detail = CheckOK, "mail is delivered to this server"
	default:
		c.Status, c.Detail = CheckError, "the most preferred MX does not point to this server"
	}
	return c
}

// checkSPF looks for one SPF record that lets this server send.
func (s *Service) checkSPF(ctx context.Context, domain string, ips []string) Check {
	c := Check{Name: "spf", Found: []string{}, Expected: spfDefault}
	txts, _ := s.resolver.LookupTXT(ctx, domain)
	for _, t := range txts {
		if isSPF(t) {
			c.Found = append(c.Found, t)
		}
	}
	switch len(c.Found) {
	case 0:
		c.Status, c.Detail = CheckError, "no SPF record: receivers cannot tell this server may send for the domain"
		return c
	case 1:
	default:
		c.Status, c.Detail = CheckError, "more than one SPF record: receivers treat that as no SPF at all"
		return c
	}
	allowed, unknown := false, false
	for _, f := range strings.Fields(strings.ToLower(c.Found[0]))[1:] {
		mech := strings.TrimLeft(f, "+")
		switch {
		case mech == "a":
			allowed = allowed || s.resolvesHere(ctx, domain, ips)
		case mech == "mx":
			mxs, _ := s.resolver.LookupMX(ctx, domain)
			for _, m := range mxs {
				allowed = allowed || s.resolvesHere(ctx, strings.TrimSuffix(m.Host, "."), ips)
			}
		case strings.HasPrefix(mech, "ip4:") || strings.HasPrefix(mech, "ip6:"):
			allowed = allowed || slices.Contains(ips, mech[4:])
		case strings.HasPrefix(mech, "a:"):
			allowed = allowed || s.resolvesHere(ctx, mech[2:], ips)
		case strings.HasPrefix(mech, "include:") || strings.HasPrefix(mech, "redirect="):
			unknown = true
		}
	}
	switch {
	case allowed:
		c.Status, c.Detail = CheckOK, "the SPF record lets this server send"
	case unknown:
		c.Status, c.Detail = CheckWarning, "the SPF record includes other records; make sure one of them lists this server"
	default:
		c.Status, c.Detail = CheckError, "the SPF record does not list this server, so its mail may be refused"
	}
	return c
}

func (s *Service) checkDKIM(ctx context.Context, domain, want string) Check {
	c := Check{Name: "dkim", Found: []string{}, Expected: want}
	txts, _ := s.resolver.LookupTXT(ctx, dkimName(domain))
	c.Found = append(c.Found, txts...)
	norm := func(v string) string { return strings.Join(strings.Fields(strings.ReplaceAll(v, ";", "; ")), " ") }
	switch {
	case want == "":
		c.Status, c.Detail = CheckWarning, "no signing key yet: it is made with the domain's first address"
	case len(txts) == 0:
		c.Status, c.Detail = CheckError, "the DKIM key is not published at "+dkimName(domain)
	case slices.ContainsFunc(txts, func(t string) bool { return norm(t) == norm(want) }):
		c.Status, c.Detail = CheckOK, "the published key matches the one mail is signed with"
	default:
		c.Status, c.Detail = CheckError, "the published DKIM key is not the one mail is signed with"
	}
	return c
}

func (s *Service) checkDMARC(ctx context.Context, domain string) Check {
	c := Check{Name: "dmarc", Found: []string{}, Expected: dmarcDefault}
	txts, _ := s.resolver.LookupTXT(ctx, "_dmarc."+domain)
	for _, t := range txts {
		if isDMARC(t) {
			c.Found = append(c.Found, t)
		}
	}
	switch len(c.Found) {
	case 0:
		c.Status, c.Detail = CheckWarning, "no DMARC record: some receivers trust the domain's mail less"
	case 1:
		c.Status, c.Detail = CheckOK, "a DMARC record is published"
	default:
		c.Status, c.Detail = CheckError, "more than one DMARC record: receivers ignore them all"
	}
	return c
}

// checkPTR checks that the server's addresses have reverse names that
// resolve back to them; this is set where the address comes from.
func (s *Service) checkPTR(ctx context.Context, ips []string, hostname string) Check {
	c := Check{Name: "ptr", Found: []string{}, Expected: hostname}
	confirmed := false
	for _, ip := range ips {
		names, _ := s.resolver.LookupAddr(ctx, ip)
		for _, n := range names {
			n = strings.TrimSuffix(n, ".")
			c.Found = append(c.Found, ip+" → "+n)
			if s.resolvesHere(ctx, n, []string{ip}) {
				confirmed = true
			}
		}
	}
	switch {
	case len(ips) == 0:
		c.Status, c.Detail = CheckWarning, "the server's addresses are not set in the DNS settings"
	case len(c.Found) == 0:
		c.Status, c.Detail = CheckWarning, "the server's address has no reverse name (PTR); ask whoever provides the address to set it to "+hostname
	case !confirmed:
		c.Status, c.Detail = CheckWarning, "the reverse name does not resolve back to the address"
	default:
		c.Status, c.Detail = CheckOK, "the server's address has a reverse name that resolves back"
	}
	return c
}

// Deliverability checks a domain's mail records in public DNS (USR-MAIL-09).
func (s *Service) Deliverability(ctx context.Context, p *auth.Principal, domainID string) (Deliverability, error) {
	d, err := s.db.DomainByID(ctx, domainID)
	if err != nil {
		return Deliverability{}, err
	}
	a, _, err := s.access(ctx, p, d.AccountID)
	if err != nil {
		return Deliverability{}, err
	}
	if d, err = s.mailDomain(ctx, a, domainID); err != nil {
		return Deliverability{}, err
	}
	routing, err := s.zones.MailRouting(ctx, *d)
	if err != nil {
		return Deliverability{}, err
	}
	mds, err := store.AccountMailDomains(ctx, s.db.R, a.ID)
	if err != nil {
		return Deliverability{}, err
	}
	want, err := s.dkimValue(mds[d.ID])
	if err != nil {
		return Deliverability{}, err
	}
	zs, err := store.AccountZones(ctx, s.db.R, a.ID)
	if err != nil {
		return Deliverability{}, err
	}
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ips := s.serverIPs(lctx)
	res := Deliverability{DomainID: d.ID, Domain: d.Name, Routing: routing, Checks: []Check{
		s.checkMX(lctx, d.Name, routing, ips),
		s.checkSPF(lctx, d.Name, ips),
		s.checkDKIM(lctx, d.Name, want),
		s.checkDMARC(lctx, d.Name),
		s.checkPTR(lctx, ips, s.server(ctx)),
	}}
	res.Repairable = slices.ContainsFunc(zs, func(z store.Zone) bool { return d.Name == z.Name || strings.HasSuffix(d.Name, "."+z.Name) })
	return res, nil
}

// Repair writes the domain's SPF, DKIM and DMARC records into its zone on
// this server: SPF and DMARC only when the zone has none (they may be set
// on purpose), the DKIM key always. It returns the DNS job's ID ("" if
// nothing changed).
func (s *Service) Repair(ctx context.Context, c auth.Client, p *auth.Principal, domainID string) (bool, error) {
	d, err := s.db.DomainByID(ctx, domainID)
	if err != nil {
		return false, err
	}
	a, _, err := s.forChange(ctx, p, d.AccountID)
	if err != nil {
		return false, err
	}
	if d, err = s.mailDomain(ctx, a, domainID); err != nil {
		return false, err
	}
	var changed bool
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.ensureMailDomain(ctx, tx, p.Login.ID, d); err != nil {
			return err
		}
		mds, err := store.AccountMailDomains(ctx, tx, a.ID)
		if err != nil {
			return err
		}
		dkim, err := s.dkimValue(mds[d.ID])
		if err != nil {
			return err
		}
		wants := []zones.RecordWant{dkimWant(d.Name, dkim)}
		has, err := s.zoneHas(ctx, tx, d)
		if err != nil {
			return err
		}
		if !has(d.Name, isSPF) {
			wants = append(wants, zones.RecordWant{Name: d.Name, Type: "TXT", Content: spfDefault})
		}
		if !has("_dmarc."+d.Name, isDMARC) {
			wants = append(wants, zones.RecordWant{Name: "_dmarc." + d.Name, Type: "TXT", Content: dmarcDefault})
		}
		if changed, err = s.zones.EnsureRecords(ctx, tx, p.Login.ID, *d, wants); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.dns_repair", a.ID, "domain", d.ID, map[string]any{"domain": d.Name, "changed": changed}))
	})
	if errors.Is(err, zones.ErrNoZone) {
		return false, apperr.NewConflict("no_zone", "the DNS of "+d.Name+" is not on this server: publish the expected records where it is")
	}
	return changed, err
}

// zoneHas returns a test for whether the zone holding d has a TXT record
// at a name that passes a test.
func (s *Service) zoneHas(ctx context.Context, tx *sql.Tx, d *store.Domain) (func(name string, test func(string) bool) bool, error) {
	zs, err := store.AccountZones(ctx, tx, d.AccountID)
	if err != nil {
		return nil, err
	}
	var recs []store.ZoneRecord
	for _, z := range zs {
		if d.Name == z.Name || strings.HasSuffix(d.Name, "."+z.Name) {
			rs, err := store.ZoneRecords(ctx, tx, z.ID)
			if err != nil {
				return nil, err
			}
			recs = append(recs, rs...)
		}
	}
	return func(name string, test func(string) bool) bool {
		return slices.ContainsFunc(recs, func(r store.ZoneRecord) bool {
			return r.Name == name && r.Type == "TXT" && test(dnsrr.Plain(r.Type, r.Content))
		})
	}, nil
}
