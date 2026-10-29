package agent

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/dnsrr"
)

// fakePDNS is a small in-memory PowerDNS API.
type fakePDNS struct {
	mu      sync.Mutex
	zones   map[string]map[rrKey]pdnsRRset
	patches [][]pdnsRRset
}

func (f *fakePDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-API-Key") != "secret-key" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	const base = "/api/v1/servers/localhost/zones"
	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, base), "/")
	zone, ok := f.zones[name]
	switch {
	case r.Method == http.MethodPost && name == "":
		var z pdnsZone
		json.NewDecoder(r.Body).Decode(&z)
		if z.SOAEditAPI == nil || *z.SOAEditAPI != "" {
			http.Error(w, `{"error":"want soa_edit_api off"}`, http.StatusBadRequest)
			return
		}
		f.zones[z.Name] = map[rrKey]pdnsRRset{}
		for _, rs := range z.RRsets {
			rs.ChangeType = ""
			f.zones[z.Name][rrKey{rs.Name, rs.Type}] = rs
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("{}"))
	case !ok:
		http.Error(w, `{"error":"Could not find domain '`+name+`'"}`, http.StatusNotFound)
	case r.Method == http.MethodGet:
		z := pdnsZone{Name: name}
		for _, rs := range zone {
			z.RRsets = append(z.RRsets, rs)
		}
		json.NewEncoder(w).Encode(z)
	case r.Method == http.MethodPatch:
		var z pdnsZone
		json.NewDecoder(r.Body).Decode(&z)
		f.patches = append(f.patches, z.RRsets)
		for _, rs := range z.RRsets {
			k := rrKey{rs.Name, rs.Type}
			if rs.ChangeType == "DELETE" {
				delete(zone, k)
			} else {
				rs.ChangeType = ""
				zone[k] = rs
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete:
		delete(f.zones, name)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (f *fakePDNS) contents(zone, name, typ string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.zones[zone][rrKey{name, typ}].Records {
		out = append(out, r.Content)
	}
	return out
}

func newDNS(t *testing.T) (*DNS, *fakePDNS) {
	t.Helper()
	f := &fakePDNS{zones: map[string]map[rrKey]pdnsRRset{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	key := filepath.Join(t.TempDir(), "pdns-api-key")
	if err := os.WriteFile(key, []byte("secret-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	return &DNS{URL: srv.URL, KeyFile: key, Now: func() time.Time { return day }}, f
}

func testZone() Zone {
	rec := func(name, typ, content string) dnsrr.Record {
		return dnsrr.Record{Name: name, Type: typ, TTL: 3600, Content: content}
	}
	return Zone{
		Name: "example.com", Nameservers: []string{"ns1.host.net", "ns2.host.net"}, Hostmaster: "hostmaster.example.com",
		Records: []dnsrr.Record{
			rec("example.com", "A", "192.0.2.10"),
			rec("www.example.com", "CNAME", "example.com."),
			rec("example.com", "MX", "10 mail.example.com."),
			rec("example.com", "TXT", `"v=spf1 a mx ~all"`),
		},
	}
}

func TestDNSApplyCreatesThenChangesOnlyTheDifference(t *testing.T) {
	d, f := newDNS(t)
	z := testZone()
	if changed, err := d.Apply(ctx, z); err != nil || !changed {
		t.Fatalf("create: changed=%v err=%v", changed, err)
	}
	if got := f.contents("example.com.", "example.com.", "SOA"); len(got) != 1 || got[0] != "ns1.host.net. hostmaster.example.com. 2026102801 10800 3600 604800 3600" {
		t.Fatalf("SOA = %q", got)
	}
	if got := f.contents("example.com.", "example.com.", "NS"); !slices.Equal(got, []string{"ns1.host.net.", "ns2.host.net."}) {
		t.Fatalf("NS = %q", got)
	}

	if changed, err := d.Apply(ctx, z); err != nil || changed || len(f.patches) != 0 {
		t.Fatalf("unchanged zone: changed=%v err=%v patches=%v", changed, err, f.patches)
	}

	// One more A record, the CNAME gone: only those RRsets and the SOA change.
	z.Records = append(z.Records[:1], z.Records[2:]...)
	z.Records = append(z.Records, dnsrr.Record{Name: "example.com", Type: "A", TTL: 300, Content: "192.0.2.11"})
	if changed, err := d.Apply(ctx, z); err != nil || !changed {
		t.Fatalf("change: changed=%v err=%v", changed, err)
	}
	var kinds []string
	for _, rs := range f.patches[0] {
		kinds = append(kinds, rs.ChangeType+" "+rs.Name+" "+rs.Type)
	}
	if !slices.Equal(kinds, []string{"REPLACE example.com. A", "REPLACE example.com. SOA", "DELETE www.example.com. CNAME"}) {
		t.Fatalf("patch = %q", kinds)
	}
	if a := f.zones["example.com."][rrKey{"example.com.", "A"}]; a.TTL != 300 || len(a.Records) != 2 {
		t.Fatalf("A RRset = %+v (one TTL per RRset: the smallest)", a)
	}
	if got := f.contents("example.com.", "example.com.", "SOA"); !strings.Contains(got[0], " 2026102802 ") {
		t.Fatalf("serial not raised: %q", got)
	}

	// New name servers change the NS RRset and the SOA.
	z.Nameservers = []string{"ns9.host.net"}
	if changed, err := d.Apply(ctx, z); err != nil || !changed {
		t.Fatal(err)
	}
	if got := f.contents("example.com.", "example.com.", "SOA"); !strings.HasPrefix(got[0], "ns9.host.net. ") || !strings.Contains(got[0], " 2026102803 ") {
		t.Fatalf("SOA after NS change = %q", got)
	}

	if ok, err := d.Delete(ctx, "example.com"); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if ok, err := d.Delete(ctx, "example.com"); err != nil || ok {
		t.Fatalf("delete again: %v %v", ok, err)
	}
}

func TestDNSRefusals(t *testing.T) {
	d, _ := newDNS(t)
	bad := testZone()
	bad.Records = append(bad.Records, dnsrr.Record{Name: "www.example.com", Type: "A", TTL: 3600, Content: "192.0.2.1"})
	if _, err := d.Apply(ctx, bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("CNAME next to A: %v", err)
	}
	noNS := testZone()
	noNS.Nameservers = nil
	if _, err := d.Apply(ctx, noNS); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("no name servers: %v", err)
	}
	if _, err := d.Delete(ctx, "Example.com"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unnormalised delete: %v", err)
	}
	d.KeyFile = filepath.Join(t.TempDir(), "missing")
	if _, err := d.Apply(ctx, testZone()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("no API key: %v", err)
	}
}
