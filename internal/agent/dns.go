package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siyamex/XCP/internal/dnsrr"
	"github.com/siyamex/XCP/internal/validate"
)

// DNS serves hosted zones with PowerDNS, through its HTTP API on localhost
// (06-service-drivers.md §5). The panel database is the source of truth:
// Apply makes PowerDNS hold exactly the zone it is given.
type DNS struct {
	URL     string // http://127.0.0.1:8081
	KeyFile string // the PowerDNS API key; missing means PowerDNS is not installed
	Client  *http.Client
	Now     func() time.Time
	mu      sync.Mutex
}

// Zone is a zone as the agent applies it.
type Zone struct {
	Name        string
	Nameservers []string // its NS records; the first is the primary in the SOA
	Hostmaster  string   // SOA mailbox as a name: "hostmaster.example.com"
	Records     []dnsrr.Record
}

// PDNSURL is the PowerDNS API, which listens on localhost only (set up by xcp-install).
const PDNSURL = "http://127.0.0.1:8081"

// Bounds of a zone's own settings.
const (
	MaxNameservers = 13
	nsTTL          = 3600
	soaTimers      = "10800 3600 604800 3600" // refresh, retry, expire, negative-cache TTL
)

// CheckZone validates a zone request. The fake agent uses it too.
func CheckZone(z Zone) error {
	if err := dnsrr.CheckZone(z.Name, z.Records); err != nil {
		return invalid("%v", err)
	}
	if len(z.Nameservers) == 0 || len(z.Nameservers) > MaxNameservers {
		return invalid("a zone needs 1 to %d name servers", MaxNameservers)
	}
	for _, n := range append(slices.Clone(z.Nameservers), z.Hostmaster) {
		if d, err := validate.Domain(n); err != nil || d != n {
			return invalid("%q is not a normalised host name", n)
		}
	}
	return nil
}

func fqdn(name string) string { return name + "." }

type pdnsRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type pdnsRRset struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	TTL        uint32       `json:"ttl,omitempty"`
	ChangeType string       `json:"changetype,omitempty"`
	Records    []pdnsRecord `json:"records"`
}

type pdnsZone struct {
	Name       string      `json:"name"`
	Kind       string      `json:"kind,omitempty"`
	SOAEditAPI *string     `json:"soa_edit_api,omitempty"`
	RRsets     []pdnsRRset `json:"rrsets"`
}

type rrKey struct{ name, typ string }

// rrset is one name and type: the TTL and the sorted, normalised contents.
type rrset struct {
	ttl      uint32
	contents []string
}

func (r rrset) equal(o rrset) bool { return r.ttl == o.ttl && slices.Equal(r.contents, o.contents) }

// desired groups the zone's records into RRsets, the NS RRset included.
// PowerDNS has one TTL per RRset: the smallest of its records wins.
func desired(z Zone) map[rrKey]rrset {
	m := map[rrKey]rrset{}
	add := func(name, typ string, ttl uint32, content string) {
		k := rrKey{fqdn(name), typ}
		s, ok := m[k]
		if !ok || ttl < s.ttl {
			s.ttl = ttl
		}
		s.contents = append(s.contents, dnsrr.Normalize(name, typ, content))
		m[k] = s
	}
	for _, ns := range z.Nameservers {
		add(z.Name, "NS", nsTTL, fqdn(ns))
	}
	for _, r := range z.Records {
		add(r.Name, r.Type, r.TTL, r.Content)
	}
	for k, s := range m {
		slices.Sort(s.contents)
		m[k] = s
	}
	return m
}

// serial is the next date-based SOA serial (YYYYMMDDnn) after current.
func (d *DNS) serial(current uint32) uint32 {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	day, _ := strconv.ParseUint(now().UTC().Format("20060102")+"00", 10, 32)
	return max(current+1, uint32(day)+1) //nolint:gosec // G115: YYYYMMDD00 fits in uint32 until 2042
}

func (d *DNS) soa(z Zone, serial uint32) pdnsRRset {
	content := fmt.Sprintf("%s %s %d %s", fqdn(z.Nameservers[0]), fqdn(z.Hostmaster), serial, soaTimers)
	return pdnsRRset{Name: fqdn(z.Name), Type: "SOA", TTL: nsTTL, ChangeType: "REPLACE", Records: []pdnsRecord{{Content: content}}}
}

// Apply makes PowerDNS serve exactly z: it creates the zone, or changes
// only the RRsets that differ, in one PATCH that also raises the SOA serial.
func (d *DNS) Apply(ctx context.Context, z Zone) (bool, error) {
	if err := CheckZone(z); err != nil {
		return false, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	want := desired(z)
	var cur pdnsZone
	found, err := d.call(ctx, http.MethodGet, "/zones/"+url.PathEscape(fqdn(z.Name)), nil, &cur)
	if err != nil {
		return false, err
	}
	if !found {
		none := "" // XCP keeps the serial itself
		create := pdnsZone{Name: fqdn(z.Name), Kind: "Native", SOAEditAPI: &none, RRsets: []pdnsRRset{d.soa(z, d.serial(0))}}
		for k, s := range want {
			create.RRsets = append(create.RRsets, rrsetJSON(k, s, ""))
		}
		_, err := d.call(ctx, http.MethodPost, "/zones", create, nil)
		return err == nil, err
	}

	have := map[rrKey]rrset{}
	var serial uint32
	var soaNames string
	for _, rs := range cur.RRsets {
		if rs.Type == "SOA" {
			if len(rs.Records) > 0 {
				f := strings.Fields(rs.Records[0].Content)
				if len(f) == 7 {
					s, _ := strconv.ParseUint(f[2], 10, 32)
					serial, soaNames = uint32(s), f[0]+" "+f[1]+" "+strings.Join(f[3:], " ")
				}
			}
			continue
		}
		s := rrset{ttl: rs.TTL}
		for _, r := range rs.Records {
			s.contents = append(s.contents, dnsrr.Normalize(rs.Name, rs.Type, r.Content))
		}
		slices.Sort(s.contents)
		have[rrKey{rs.Name, rs.Type}] = s
	}
	var changes []pdnsRRset
	for k, s := range want {
		if old, ok := have[k]; !ok || !old.equal(s) {
			changes = append(changes, rrsetJSON(k, s, "REPLACE"))
		}
	}
	for k := range have {
		if _, ok := want[k]; !ok {
			changes = append(changes, pdnsRRset{Name: k.name, Type: k.typ, ChangeType: "DELETE", Records: []pdnsRecord{}})
		}
	}
	soaWant := fqdn(z.Nameservers[0]) + " " + fqdn(z.Hostmaster) + " " + soaTimers
	if len(changes) == 0 && soaNames == soaWant {
		return false, nil
	}
	changes = append(changes, d.soa(z, d.serial(serial)))
	slices.SortFunc(changes, func(a, b pdnsRRset) int { return strings.Compare(a.Name+a.Type, b.Name+b.Type) })
	_, err = d.call(ctx, http.MethodPatch, "/zones/"+url.PathEscape(fqdn(z.Name)), pdnsZone{RRsets: changes}, nil)
	return err == nil, err
}

func rrsetJSON(k rrKey, s rrset, changeType string) pdnsRRset {
	rs := pdnsRRset{Name: k.name, Type: k.typ, TTL: s.ttl, ChangeType: changeType}
	for _, c := range s.contents {
		rs.Records = append(rs.Records, pdnsRecord{Content: c})
	}
	return rs
}

// Delete removes a zone from PowerDNS; it reports whether there was one.
func (d *DNS) Delete(ctx context.Context, zone string) (bool, error) {
	if n, err := validate.Domain(zone); err != nil || n != zone {
		return false, invalid("zone %q is not a normalised domain name", zone)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.call(ctx, http.MethodDelete, "/zones/"+url.PathEscape(fqdn(zone)), nil, nil)
}

// call sends one API request. It reports false for an unknown zone and
// ErrNotInstalled when PowerDNS has not been set up.
func (d *DNS) call(ctx context.Context, method, path string, body, out any) (bool, error) {
	key, err := os.ReadFile(d.KeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("%w: PowerDNS (no API key at %s)", ErrNotInstalled, d.KeyFile)
	}
	if err != nil {
		return false, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return false, err
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, d.URL+"/api/v1/servers/localhost"+path, rd)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-API-Key", strings.TrimSpace(string(key)))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("PowerDNS API: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound,
		resp.StatusCode == http.StatusUnprocessableEntity && bytes.Contains(raw, []byte("Could not find domain")):
		return false, nil
	case resp.StatusCode >= 300:
		return false, fmt.Errorf("PowerDNS API %s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(raw))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return false, fmt.Errorf("PowerDNS API %s %s: %w", method, path, err)
		}
	}
	return true, nil
}
