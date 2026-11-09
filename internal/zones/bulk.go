package zones

import (
	"context"
	"database/sql"

	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/dnsrr"
	"github.com/siyamex/XCP/internal/store"
)

// BulkResult says what a bulk change did.
type BulkResult struct {
	Records int64 `json:"records"` // changed
	Zones   int   `json:"zones"`   // queued to be served again
}

// SetAllTTL gives every record of every zone the TTL (admins). The zone
// template and the default for new records are left alone.
func (s *Service) SetAllTTL(ctx context.Context, c auth.Client, p *auth.Principal, ttl uint32) (BulkResult, error) {
	if err := admin(p); err != nil {
		return BulkResult{}, err
	}
	if ttl < dnsrr.MinTTL || ttl > dnsrr.MaxTTL {
		return BulkResult{}, badField("ttl", "out_of_range", "TTL must be 60 to 604800 seconds")
	}
	var res BulkResult
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		ids, n, err := store.SetAllRecordTTL(ctx, tx, ttl)
		if err != nil {
			return err
		}
		res.Records, res.Zones = n, len(ids)
		for _, id := range ids {
			z, err := store.ZoneByID(ctx, tx, id)
			if err != nil {
				return err
			}
			if err := store.TouchZone(ctx, tx, id); err != nil {
				return err
			}
			if _, err := s.enqueueApply(ctx, tx, p.Login.ID, *z); err != nil {
				return err
			}
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dns.bulk.ttl", "", "dns", "bulk", map[string]any{"ttl": ttl, "records": n, "zones": len(ids)}))
	})
	return res, err
}
