package zones

import (
	"context"
	"database/sql"
	"slices"

	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/dnsrr"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
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

// RoutingResult says what a bulk routing change did.
type RoutingResult struct {
	Zones int `json:"zones"` // whose routing changed
}

// SetAllMailRouting gives every zone the email routing (admins): auto,
// local, remote or backup. Zones that have it already are left alone; the
// mail service hears once for each account whose zones changed.
func (s *Service) SetAllMailRouting(ctx context.Context, c auth.Client, p *auth.Principal, routing string) (RoutingResult, error) {
	if err := admin(p); err != nil {
		return RoutingResult{}, err
	}
	if !slices.Contains([]string{store.MailAuto, store.MailLocal, store.MailRemote, store.MailBackup}, routing) {
		return RoutingResult{}, badField("mail_routing", validate.CodeFormat, "mail routing must be auto, local, remote or backup")
	}
	var res RoutingResult
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		zs, err := store.ListAllZones(ctx, tx)
		if err != nil {
			return err
		}
		var accounts []string
		for _, z := range zs {
			if z.MailRouting == routing {
				continue
			}
			if err := store.SetZoneMailRouting(ctx, tx, z.ID, routing); err != nil {
				return err
			}
			res.Zones++
			if !slices.Contains(accounts, z.AccountID) {
				accounts = append(accounts, z.AccountID)
			}
		}
		if s.onMail != nil {
			for _, a := range accounts {
				if err := s.onMail(ctx, tx, p.Login.ID, a); err != nil {
					return err
				}
			}
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dns.bulk.mail_routing", "", "dns", "bulk", map[string]any{"to": routing, "zones": res.Zones}))
	})
	return res, err
}
