package zones

import (
	"context"
	"slices"
	"strings"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// isPanelZone tells whether a served zone is the panel's: one of an account,
// or one the name servers' names live in.
func isPanelZone(name string, known map[string]bool, set Settings) bool {
	if known[name] {
		return true
	}
	// A name server's own zone and the host name's zone are set up by the admin.
	for _, ns := range set.Nameservers {
		if ns == name || strings.HasSuffix(ns, "."+name) {
			return true
		}
	}
	return false
}

// OrphanZones lists the zones the DNS server has that the panel does not
// know, that is, that belong to no account (admins).
func (s *Service) OrphanZones(ctx context.Context, p *auth.Principal) ([]string, error) {
	if err := admin(p); err != nil {
		return nil, err
	}
	served, err := s.agent.DNSZoneList(ctx, &agentv1.DNSZoneListRequest{})
	if err != nil {
		return nil, err
	}
	all, err := s.db.AllZones(ctx)
	if err != nil {
		return nil, err
	}
	set, err := s.Settings(ctx)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, z := range all {
		known[z.Name] = true
	}
	out := []string{}
	for _, n := range served.GetZones() {
		if !isPanelZone(n, known, set) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

// DeleteOrphanZone removes a zone from the DNS server that the panel does not
// know. It refuses a zone that belongs to an account.
func (s *Service) DeleteOrphanZone(ctx context.Context, c auth.Client, p *auth.Principal, name string) error {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n, err := validate.Domain(name); err != nil || n != name {
		return badField("zone", validate.CodeFormat, "not a zone name")
	}
	orphans, err := s.OrphanZones(ctx, p)
	if err != nil {
		return err
	}
	if !slices.Contains(orphans, name) {
		if _, err := store.ZoneByName(ctx, s.db.R, name); err == nil {
			return apperr.NewConflict("zone_in_use", "the zone belongs to an account")
		}
		return store.ErrNotFound
	}
	if _, err := s.agent.DNSZoneDelete(ctx, &agentv1.DNSZoneDeleteRequest{Zone: name}); err != nil {
		return err
	}
	return s.audit.Record(ctx, event(c, p, "dns.orphan.delete", "", "dns", name, map[string]any{"zone": name}))
}
