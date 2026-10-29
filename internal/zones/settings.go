package zones

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/dnsrr"
	"github.com/siyamex/XCP/internal/hostinfo"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

const settingsKey = "dns"

// Settings are the server's DNS settings (ADM-DNS-02, ADM-DNS-03).
type Settings struct {
	// Nameservers are the NS records of every zone; the first is the
	// primary in the SOA. Empty: ns1 and ns2 of each zone itself.
	Nameservers []string `json:"nameservers"`
	// IPv4 and IPv6 are this server's public addresses, used by the template.
	IPv4     string           `json:"ipv4"`
	IPv6     string           `json:"ipv6"`
	TTL      uint32           `json:"ttl"`      // for new records
	Template []TemplateRecord `json:"template"` // the records of a new zone
}

// TemplateRecord is a record of the zone template. Name and Content may use
// {domain}, {ip4} and {ip6}; a record that needs an address the server does
// not have is left out.
type TemplateRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

// MaxTemplateRecords bounds the zone template.
const MaxTemplateRecords = 100

// DefaultTemplate is the zone template of a new server.
func DefaultTemplate() []TemplateRecord {
	return []TemplateRecord{
		{"@", "A", "{ip4}"},
		{"@", "AAAA", "{ip6}"},
		{"www", "CNAME", "{domain}"},
		{"mail", "A", "{ip4}"},
		{"mail", "AAAA", "{ip6}"},
		{"@", "MX", "10 mail.{domain}"},
		{"@", "TXT", "v=spf1 a mx ~all"},
		{"_dmarc", "TXT", "v=DMARC1; p=none"},
	}
}

// defaultSettings guesses from the host: its addresses (private ones behind
// NAT, which the admin must then correct) and ns1/ns2 of its domain.
func defaultSettings() Settings {
	s := Settings{TTL: 3600, Template: DefaultTemplate(), Nameservers: []string{}}
	for _, ip := range hostinfo.ServerIPs() {
		a, _ := netip.ParseAddr(ip)
		switch {
		case a.Is4() && s.IPv4 == "":
			s.IPv4 = ip
		case a.Is6() && !a.Is4In6() && s.IPv6 == "":
			s.IPv6 = ip
		}
	}
	if host, err := os.Hostname(); err == nil && strings.Contains(host, ".") {
		if d, err := validate.Domain(host); err == nil {
			base := validate.Registrable(d)
			s.Nameservers = []string{"ns1." + base, "ns2." + base}
		}
	}
	return s
}

// EnsureDefaults stores the default settings on first start.
func (s *Service) EnsureDefaults(ctx context.Context) error {
	var cur Settings
	if err := s.db.GetSetting(ctx, settingsKey, &cur); !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return s.db.SetSetting(ctx, settingsKey, defaultSettings())
}

// Settings returns the DNS settings.
func (s *Service) Settings(ctx context.Context) (Settings, error) {
	var set Settings
	err := s.db.GetSetting(ctx, settingsKey, &set)
	if errors.Is(err, store.ErrNotFound) {
		return defaultSettings(), nil
	}
	return set, err
}

// nameservers are the zone's NS records: the settings, or ns1/ns2 of the zone.
func (set Settings) nameservers(zone string) []string {
	if len(set.Nameservers) > 0 {
		return set.Nameservers
	}
	return []string{"ns1." + zone, "ns2." + zone}
}

// render turns template records into a zone's records, skipping those that
// need an address the server does not have.
func (set Settings) render(t []TemplateRecord, zone string) ([]store.ZoneRecord, error) {
	var out []store.ZoneRecord
	for _, tr := range t {
		raw := tr.Name + " " + tr.Content
		if (strings.Contains(raw, "{ip4}") && set.IPv4 == "") || (strings.Contains(raw, "{ip6}") && set.IPv6 == "") {
			continue
		}
		fill := strings.NewReplacer("{domain}", zone, "{ip4}", set.IPv4, "{ip6}", set.IPv6)
		name, err := dnsrr.Name(fill.Replace(tr.Name), zone)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", tr.Name, tr.Type, err)
		}
		content, err := dnsrr.Content(tr.Type, fill.Replace(tr.Content), zone)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", tr.Name, tr.Type, err)
		}
		out = append(out, store.ZoneRecord{Name: name, Type: tr.Type, TTL: set.TTL, Content: content})
	}
	return out, nil
}

func field(name string, err error) error { return validate.WithField(err, name) }

func badField(name, code, msg string) error {
	return &validate.Error{Field: name, Code: code, Message: msg}
}

// check validates settings an admin saves and returns them normalised.
func (set Settings) check() (Settings, error) {
	out := Settings{TTL: set.TTL, Nameservers: []string{}}
	if len(set.Nameservers) > 13 {
		return out, badField("nameservers", validate.CodeOutOfRange, "at most 13 name servers")
	}
	for _, ns := range set.Nameservers {
		if strings.TrimSpace(ns) == "" {
			continue
		}
		n, err := validate.Domain(ns)
		if err != nil {
			return out, field("nameservers", err)
		}
		if !slices.Contains(out.Nameservers, n) {
			out.Nameservers = append(out.Nameservers, n)
		}
	}
	for _, ip := range []struct {
		value *string
		in    string
		v4    bool
		name  string
	}{{&out.IPv4, set.IPv4, true, "ipv4"}, {&out.IPv6, set.IPv6, false, "ipv6"}} {
		in := strings.TrimSpace(ip.in)
		if in == "" {
			continue
		}
		a, err := netip.ParseAddr(in)
		if err != nil || a.Is4() != ip.v4 || a.Is4In6() || !a.IsGlobalUnicast() { // private ones are allowed (NAT)
			return out, badField(ip.name, validate.CodeFormat, "not a usable "+map[bool]string{true: "IPv4", false: "IPv6"}[ip.v4]+" address")
		}
		*ip.value = a.String()
	}
	if out.TTL < dnsrr.MinTTL || out.TTL > dnsrr.MaxTTL {
		return out, badField("ttl", validate.CodeOutOfRange, fmt.Sprintf("TTL must be %d to %d seconds", dnsrr.MinTTL, dnsrr.MaxTTL))
	}
	if len(set.Template) > MaxTemplateRecords {
		return out, badField("template", validate.CodeOutOfRange, fmt.Sprintf("at most %d template records", MaxTemplateRecords))
	}
	for _, tr := range set.Template {
		tr.Type = strings.ToUpper(strings.TrimSpace(tr.Type))
		tr.Name, tr.Content = strings.TrimSpace(tr.Name), strings.TrimSpace(tr.Content)
		out.Template = append(out.Template, tr)
	}
	// The template must give a valid zone, with every placeholder filled.
	sample := Settings{IPv4: "192.0.2.1", IPv6: "2001:db8::1", TTL: out.TTL}
	recs, err := sample.render(out.Template, "example.com")
	if err != nil {
		return out, badField("template", validate.CodeFormat, err.Error())
	}
	if err := dnsrr.CheckZone("example.com", toDNSRR(recs)); err != nil {
		return out, field("template", err)
	}
	return out, nil
}

// NameserverCheck tells whether a name server points to this server (ADM-DNS-03).
type NameserverCheck struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"` // what DNS answers for it
	OK        bool     `json:"ok"`        // one of them is this server's IPv4 or IPv6
	Problem   string   `json:"problem,omitempty"`
}

// SettingsView is the settings with the name server report.
type SettingsView struct {
	Settings
	Report      []NameserverCheck `json:"report"`
	DetectedIPs []string          `json:"detected_ips"` // the addresses of the server's interfaces
}

func admin(p *auth.Principal) error {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return apperr.ErrForbidden
	}
	return nil
}

// GetSettings returns the DNS settings and checks the name servers in DNS.
func (s *Service) GetSettings(ctx context.Context, p *auth.Principal) (SettingsView, error) {
	if err := admin(p); err != nil {
		return SettingsView{}, err
	}
	set, err := s.Settings(ctx)
	if err != nil {
		return SettingsView{}, err
	}
	v := SettingsView{Settings: set, Report: []NameserverCheck{}, DetectedIPs: hostinfo.ServerIPs()}
	for _, ns := range set.Nameservers {
		look, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := s.resolver.LookupHost(look, ns)
		cancel()
		c := NameserverCheck{Name: ns, Addresses: addrs}
		if c.Addresses == nil {
			c.Addresses = []string{}
		}
		for _, a := range addrs {
			c.OK = c.OK || (a != "" && (a == set.IPv4 || a == set.IPv6))
		}
		switch {
		case err != nil:
			c.Problem = "does not resolve: add A records (glue at the registrar if it is under your own domain)"
		case !c.OK:
			c.Problem = "points elsewhere, not to this server's addresses"
		}
		v.Report = append(v.Report, c)
	}
	return v, nil
}

// SaveSettings stores the DNS settings and re-applies every zone, since the
// name servers are in each of them. When the server's address changes, the
// A or AAAA records pointing to the old one move to the new one. It returns
// how many zones were queued.
func (s *Service) SaveSettings(ctx context.Context, c auth.Client, p *auth.Principal, in Settings) (Settings, int, error) {
	if err := admin(p); err != nil {
		return Settings{}, 0, err
	}
	set, err := in.check()
	if err != nil {
		return Settings{}, 0, err
	}
	old, err := s.Settings(ctx)
	if err != nil {
		return Settings{}, 0, err
	}
	zs, err := s.db.AllZones(ctx)
	if err != nil {
		return Settings{}, 0, err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		var moved int64
		for _, m := range []struct{ typ, from, to string }{{"A", old.IPv4, set.IPv4}, {"AAAA", old.IPv6, set.IPv6}} {
			if m.from == "" || m.to == "" || m.from == m.to {
				continue
			}
			n, err := store.MoveAddressRecords(ctx, tx, m.typ, m.from, m.to)
			if err != nil {
				return err
			}
			moved += n
		}
		if err := store.PutSetting(ctx, tx, settingsKey, set); err != nil {
			return err
		}
		for _, z := range zs {
			if _, err := s.enqueueApply(ctx, tx, p.Login.ID, z); err != nil {
				return err
			}
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dns.settings", "", "dns", "settings", map[string]any{
			"nameservers": set.Nameservers, "ipv4": set.IPv4, "ipv6": set.IPv6, "ttl": set.TTL,
			"template_records": len(set.Template), "address_records_moved": moved,
		}))
	})
	return set, len(zs), err
}
