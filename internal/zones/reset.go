package zones

import (
	"context"
	"database/sql"
	"slices"
	"strings"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/dnsrr"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// ResetResult says what a reset did.
type ResetResult struct {
	Removed int    `json:"removed"`
	Added   int    `json:"added"`
	Kept    int    `json:"kept"` // DKIM keys
	JobID   string `json:"job_id,omitempty"`
}

// isDKIM tells a DKIM key record: mail signed with the key must stay
// verifiable, so a reset keeps it.
func isDKIM(r store.ZoneRecord) bool {
	return r.Type == "TXT" && strings.Contains(r.Name, "._domainkey.")
}

// Reset makes a zone what a new one would be: the records of the zone
// template, and the address records of the account's other domains inside
// the zone. Everything else goes, except DKIM keys. confirm is the zone's
// name.
func (s *Service) Reset(ctx context.Context, c auth.Client, p *auth.Principal, zoneID, confirm string) (ResetResult, error) {
	z, a, err := s.zone(ctx, p, zoneID)
	if err != nil {
		return ResetResult{}, err
	}
	if strings.ToLower(strings.TrimSpace(confirm)) != z.Name {
		return ResetResult{}, badField("confirm", validate.CodeFormat, "type the zone's name to confirm")
	}
	set, err := s.Settings(ctx)
	if err != nil {
		return ResetResult{}, err
	}
	want, err := set.render(set.Template, z.Name)
	if err != nil {
		return ResetResult{}, err
	}
	doms, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return ResetResult{}, err
	}
	var res ResetResult
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		old, err := store.ZoneRecords(ctx, tx, z.ID)
		if err != nil {
			return err
		}
		var recs []store.ZoneRecord
		for _, r := range old {
			if isDKIM(r) {
				recs = append(recs, r)
				res.Kept++
				continue
			}
			if err := store.DeleteRecord(ctx, tx, r.ID); err != nil {
				return err
			}
			res.Removed++
		}
		var added []store.ZoneRecord
		add := func(r store.ZoneRecord) {
			if slices.ContainsFunc(recs, func(o store.ZoneRecord) bool { return o.Name == r.Name && o.Type == r.Type && o.Content == r.Content }) {
				return
			}
			r.ID, r.ZoneID = ids.New(), z.ID
			recs, added = append(recs, r), append(added, r)
		}
		for _, r := range want {
			add(r)
		}
		// The account's other domains that live in this zone.
		for _, d := range doms {
			if d.ID == z.DomainID {
				continue
			}
			home, err := homeZone(ctx, tx, a.ID, strings.TrimPrefix(d.Name, "*."))
			if err != nil {
				return err
			}
			if home == nil || home.ID != z.ID {
				continue
			}
			before := slices.Clone(recs)
			for _, r := range set.hostRecords(&d) {
				if slices.ContainsFunc(before, func(o store.ZoneRecord) bool { return o.Name == r.Name }) {
					continue // the name has records already: those win
				}
				r.DomainID = d.ID
				add(r)
			}
		}
		if err := dnsrr.CheckZone(z.Name, toDNSRR(recs)); err != nil {
			return apperr.NewConflict("record_conflict", err.Error())
		}
		for i := range added {
			if err := store.InsertRecord(ctx, tx, &added[i]); err != nil {
				return err
			}
		}
		res.Added = len(added)
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
		return s.audit.RecordTx(ctx, tx, event(c, p, "dns.zone.reset", a.ID, "zone", z.ID, map[string]any{
			"zone": z.Name, "removed": res.Removed, "added": res.Added, "kept": res.Kept,
		}))
	})
	return res, err
}
