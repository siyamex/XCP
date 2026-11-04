package accounts

import (
	"context"
	"slices"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
)

// allowed reports whether p may use a privilege on accounts: admins always,
// resellers when the admin granted it (ADM-RSL-03).
func (s *Service) allowed(ctx context.Context, p *auth.Principal, priv string) error {
	if p == nil {
		return apperr.ErrForbidden
	}
	switch p.Login.Role {
	case store.RoleAdmin:
		return nil
	case store.RoleReseller:
		lim, err := s.db.ResellerLimitsOf(ctx, p.Login.ID)
		if err != nil {
			return err
		}
		if slices.Contains(lim.Privileges, priv) {
			return nil
		}
	}
	return apperr.ErrForbidden
}
