package zones

import (
	"context"
	"database/sql"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
)

// States of a zone in the sync report.
const (
	SyncMissing = "missing" // the DNS server does not have the zone
	SyncDiffers = "differs" // it serves other records than the panel holds
)

// SyncItem is a zone the DNS server does not serve as the panel holds it.
type SyncItem struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Account string `json:"account"`
	State   string `json:"state"`
}

// SyncReport compares the panel's zones with what the DNS server serves.
type SyncReport struct {
	Zones   int        `json:"zones"`   // the panel holds
	Items   []SyncItem `json:"items"`   // the ones out of sync
	Orphans int        `json:"orphans"` // served, but of no account
}

// SyncCheck compares every zone the panel holds with the DNS server, by
// asking the agent what applying it would change (admins). Nothing changes.
func (s *Service) SyncCheck(ctx context.Context, p *auth.Principal) (SyncReport, error) {
	if err := admin(p); err != nil {
		return SyncReport{}, err
	}
	rep, _, err := s.syncCheck(ctx)
	return rep, err
}

func (s *Service) syncCheck(ctx context.Context) (SyncReport, []store.Zone, error) {
	rep := SyncReport{Items: []SyncItem{}}
	served, err := s.agent.DNSZoneList(ctx, &agentv1.DNSZoneListRequest{})
	if err != nil {
		return rep, nil, err
	}
	all, err := s.db.AllZones(ctx)
	if err != nil {
		return rep, nil, err
	}
	set, err := s.Settings(ctx)
	if err != nil {
		return rep, nil, err
	}
	accts, err := s.db.ListAccounts(ctx, store.AccountFilter{OwnerID: "*"})
	if err != nil {
		return rep, nil, err
	}
	users := map[string]string{}
	for _, a := range accts {
		users[a.ID] = a.Username
	}
	has, known := map[string]bool{}, map[string]bool{}
	for _, n := range served.GetZones() {
		has[n] = true
	}
	var off []store.Zone
	for _, z := range all {
		known[z.Name] = true
		state := ""
		if !has[z.Name] {
			state = SyncMissing
		} else {
			req, err := s.ZoneRequest(ctx, &z)
			if err != nil {
				return rep, nil, err
			}
			req.DryRun = true
			res, err := s.agent.DNSZoneApply(ctx, req)
			if err != nil {
				return rep, nil, err
			}
			if res.GetChanged() {
				state = SyncDiffers
			}
		}
		if state != "" {
			rep.Items = append(rep.Items, SyncItem{ID: z.ID, Name: z.Name, Account: users[z.AccountID], State: state})
			off = append(off, z)
		}
	}
	rep.Zones = len(all)
	for _, n := range served.GetZones() {
		if !isPanelZone(n, known, set) {
			rep.Orphans++
		}
	}
	return rep, off, nil
}

// SyncRepair queues every zone that is out of sync to be served again as
// the panel holds it (admins). It reports how many were queued.
func (s *Service) SyncRepair(ctx context.Context, c auth.Client, p *auth.Principal) (int, error) {
	if err := admin(p); err != nil {
		return 0, err
	}
	_, off, err := s.syncCheck(ctx)
	if err != nil || len(off) == 0 {
		return 0, err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.Enqueue(ctx, tx, p.Login.ID, nil, off); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "dns.sync.repair", "", "dns", "sync", map[string]any{"zones": len(off)}))
	})
	return len(off), err
}
