package mail

import (
	"context"
	"errors"
	"strings"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// RepairAllResult says what a bulk repair did.
type RepairAllResult struct {
	Domains int      `json:"domains"` // looked at
	Changed int      `json:"changed"` // got records
	NoZone  []string `json:"no_zone"` // whose DNS is not on this server
	Failed  []string `json:"failed"`  // refused for another reason
}

// RepairAll does Repair for every domain with mail of every active account the
// admin owns: SPF and DMARC where the zone has none, the DKIM key always.
// Domains whose DNS is elsewhere are listed, not an error.
func (s *Service) RepairAll(ctx context.Context, c auth.Client, p *auth.Principal) (RepairAllResult, error) {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return RepairAllResult{}, apperr.ErrForbidden
	}
	accts, err := s.db.ListAccounts(ctx, store.AccountFilter{Status: store.AccountActive})
	if err != nil {
		return RepairAllResult{}, err
	}
	res := RepairAllResult{NoZone: []string{}, Failed: []string{}}
	for _, a := range accts {
		doms, err := s.db.ListDomains(ctx, a.ID)
		if err != nil {
			return res, err
		}
		for _, d := range doms {
			if strings.HasPrefix(d.Name, "*.") || d.Kind == store.DomainAlias {
				continue
			}
			res.Domains++
			changed, err := s.Repair(ctx, c, p, d.ID)
			var conflict *apperr.Conflict
			switch {
			case err == nil:
				if changed {
					res.Changed++
				}
			case errors.As(err, &conflict) && conflict.Code == "no_zone":
				res.NoZone = append(res.NoZone, d.Name)
			case errors.Is(err, validate.ErrValidation), errors.As(err, &conflict), errors.Is(err, store.ErrNotFound):
				res.Failed = append(res.Failed, d.Name)
			default:
				return res, err
			}
		}
	}
	return res, nil
}
