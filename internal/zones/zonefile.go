package zones

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/dnsrr"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/store"
)

// MaxZoneFile is the largest zone file an import takes.
const MaxZoneFile = 1 << 20

// Export returns the zone as a zone file (RFC 1035 master format). The SOA is
// left out: the DNS server keeps it.
func (s *Service) Export(ctx context.Context, p *auth.Principal, id string) (name, text string, err error) {
	z, _, err := s.zone(ctx, p, id)
	if err != nil {
		return "", "", err
	}
	recs, err := store.ZoneRecords(ctx, s.db.R, z.ID)
	if err != nil {
		return "", "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "; Zone file of %s, exported by XCP. The SOA record is kept by the DNS server.\n$ORIGIN %s.\n", z.Name, z.Name)
	for _, r := range recs {
		fmt.Fprintf(&b, "%s.\t%d\tIN\t%s\t%s\n", r.Name, r.TTL, r.Type, r.Content)
	}
	return z.Name + ".zone", b.String(), nil
}

// ImportResult says what an import did.
type ImportResult struct {
	Added       int      `json:"added"`
	Existing    int      `json:"existing"`    // already in the zone
	Unsupported []string `json:"unsupported"` // records of types the panel does not manage (SOA, DNSSEC...)
	JobID       string   `json:"job_id,omitempty"`
}

// Import adds the records of a zone file to the zone. Records the zone has
// already and the SOA are skipped; nothing is replaced or removed. The whole
// file is refused when one record is not valid, or the zone would not be.
func (s *Service) Import(ctx context.Context, c auth.Client, p *auth.Principal, zoneID, text string) (ImportResult, error) {
	z, a, err := s.zone(ctx, p, zoneID)
	if err != nil {
		return ImportResult{}, err
	}
	if len(text) > MaxZoneFile {
		return ImportResult{}, apperr.NewConflict("too_large", "the zone file is larger than 1 MB")
	}
	var (
		res  = ImportResult{Unsupported: []string{}}
		want []store.ZoneRecord
		bad  []string
	)
	zp := dns.NewZoneParser(strings.NewReader(text), z.Name+".", "")
	zp.SetDefaultTTL(3600)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		h := rr.Header()
		typ := dns.TypeToString[h.Rrtype]
		if typ == "SOA" {
			continue
		}
		if !slices.Contains(dnsrr.Types, typ) {
			res.Unsupported = append(res.Unsupported, typ)
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(h.Name, "."))
		if name != z.Name && !strings.HasSuffix(name, "."+z.Name) {
			bad = append(bad, fmt.Sprintf("%s is not in this zone", name))
			continue
		}
		in := RecordInput{Name: dnsrr.Relative(name, z.Name), Type: typ, TTL: h.Ttl, Content: strings.TrimPrefix(rr.String(), h.String())}
		if typ == "TXT" {
			in.Content = dnsrr.Plain(typ, in.Content)
		}
		r, err := s.record(ctx, z.Name, in)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s %s: %v", in.Name, typ, err))
			continue
		}
		want = append(want, r)
	}
	if err := zp.Err(); err != nil {
		bad = append(bad, err.Error())
	}
	if len(bad) > 0 {
		if len(bad) > 5 {
			bad = append(bad[:5], fmt.Sprintf("and %d more", len(bad)-5))
		}
		return ImportResult{}, apperr.NewConflict("bad_zone_file", "nothing was imported: "+strings.Join(bad, "; "))
	}
	res.Unsupported = uniq(res.Unsupported)

	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		recs, err := store.ZoneRecords(ctx, tx, z.ID)
		if err != nil {
			return err
		}
		var added []store.ZoneRecord
		for _, r := range want {
			if slices.ContainsFunc(recs, func(o store.ZoneRecord) bool { return o.Name == r.Name && o.Type == r.Type && o.Content == r.Content }) {
				res.Existing++
				continue
			}
			r.ID, r.ZoneID = ids.New(), z.ID
			recs = append(recs, r)
			added = append(added, r)
		}
		res.Added = len(added)
		if len(added) == 0 {
			return nil
		}
		if len(recs) > dnsrr.MaxRecords {
			return apperr.NewConflict("too_many_records", fmt.Sprintf("a zone can have %d records", dnsrr.MaxRecords))
		}
		if err := dnsrr.CheckZone(z.Name, toDNSRR(recs)); err != nil {
			return apperr.NewConflict("record_conflict", err.Error())
		}
		for i := range added {
			if err := store.InsertRecord(ctx, tx, &added[i]); err != nil && !errors.Is(err, store.ErrConflict) {
				return err
			}
		}
		if err := store.TouchZone(ctx, tx, z.ID); err != nil {
			return err
		}
		if res.JobID, err = s.enqueueApply(ctx, tx, p.Login.ID, *z); err != nil {
			return err
		}
		if s.onMail != nil {
			if err := s.onMail(ctx, tx, p.Login.ID, a.ID); err != nil {
				return err
			}
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dns.zone.import", a.ID, "zone", z.ID, map[string]any{"zone": z.Name, "added": res.Added, "existing": res.Existing}))
	})
	return res, err
}

func uniq(l []string) []string {
	slices.Sort(l)
	return slices.Compact(l)
}
