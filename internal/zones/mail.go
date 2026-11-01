package zones

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/dnsrr"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/store"
)

// ErrNoZone means the domain's DNS is not served here, so its records
// cannot be changed from the panel.
var ErrNoZone = errors.New("the domain's DNS zone is not on this server")

// homeZone returns the account's zone that holds name: the zone of that
// name, or of the closest parent name.
func homeZone(ctx context.Context, q store.Querier, accountID, name string) (*store.Zone, error) {
	zs, err := store.AccountZones(ctx, q, accountID)
	if err != nil {
		return nil, err
	}
	var home *store.Zone
	for i, z := range zs {
		if (name == z.Name || strings.HasSuffix(name, "."+z.Name)) && (home == nil || len(z.Name) > len(home.Name)) {
			home = &zs[i]
		}
	}
	return home, nil
}

// MailRouting tells who handles a domain's mail (store.MailLocal, MailRemote
// or MailBackup): the routing of its own zone, with "auto" resolved from
// the MX records. A domain without a zone of its own (a subdomain in its
// parent's zone, or DNS elsewhere) gets its mail here.
func (s *Service) MailRouting(ctx context.Context, d store.Domain) (string, error) {
	z, err := homeZone(ctx, s.db.R, d.AccountID, d.Name)
	if err != nil || z == nil || z.Name != d.Name {
		return store.MailLocal, err
	}
	recs, err := store.ZoneRecords(ctx, s.db.R, z.ID)
	if err != nil {
		return "", err
	}
	set, err := s.Settings(ctx)
	if err != nil {
		return "", err
	}
	return mailRouting(*z, recs, set), nil
}

// RecordWant is a record another service needs in a domain's zone.
type RecordWant struct {
	Name    string // fully qualified
	Type    string
	Content string // as a user enters it (TXT: plain text)
	// Replace picks the records of the same name and type this one replaces
	// (given as plain text); nil replaces none.
	Replace func(plain string) bool
}

// EnsureRecords makes the zone that holds domain d contain the wanted
// records, replacing the ones they replace, inside tx, and queues the
// zone's job. It reports whether anything changed; ErrNoZone if the
// domain's DNS is not served here.
func (s *Service) EnsureRecords(ctx context.Context, tx *sql.Tx, createdBy string, d store.Domain, wants []RecordWant) (bool, error) {
	z, err := homeZone(ctx, tx, d.AccountID, d.Name)
	if err != nil {
		return false, err
	}
	if z == nil {
		return false, ErrNoZone
	}
	set, err := s.Settings(ctx)
	if err != nil {
		return false, err
	}
	recs, err := store.ZoneRecords(ctx, tx, z.ID)
	if err != nil {
		return false, err
	}
	changed := false
	for _, w := range wants {
		name, err := dnsrr.Name(w.Name, z.Name)
		if err != nil {
			return false, err
		}
		content, err := dnsrr.Content(w.Type, w.Content, z.Name)
		if err != nil {
			return false, err
		}
		have := false
		for _, r := range slices.Clone(recs) {
			if r.Name != name || r.Type != w.Type {
				continue
			}
			if r.Content == content {
				have = true
				continue
			}
			if w.Replace != nil && w.Replace(dnsrr.Plain(r.Type, r.Content)) {
				if err := store.DeleteRecord(ctx, tx, r.ID); err != nil {
					return false, err
				}
				recs = slices.DeleteFunc(recs, func(x store.ZoneRecord) bool { return x.ID == r.ID })
				changed = true
			}
		}
		if have {
			continue
		}
		r := store.ZoneRecord{ID: ids.New(), ZoneID: z.ID, DomainID: d.ID, Name: name, Type: w.Type, TTL: set.TTL, Content: content}
		recs = append(recs, r)
		if err := dnsrr.CheckZone(z.Name, toDNSRR(recs)); err != nil {
			return false, apperr.NewConflict("record_conflict", err.Error())
		}
		if err := store.InsertRecord(ctx, tx, &r); err != nil {
			return false, err
		}
		changed = true
	}
	if !changed {
		return false, nil
	}
	if err := store.TouchZone(ctx, tx, z.ID); err != nil {
		return false, err
	}
	_, err = s.enqueueApply(ctx, tx, createdBy, *z)
	return true, err
}
