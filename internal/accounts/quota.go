package accounts

import (
	"context"
	"fmt"

	"github.com/siyamex/XCP/internal/apperr"
)

// checkQuota refuses an account for a reseller that would go past its
// limits (ADM-RSL-02): the number of accounts and, unless overselling is
// allowed, the disk and bandwidth that its packages give out. ownerID ""
// (admin-owned) has no limits. except is an account that changes package:
// its old package no longer counts.
func (s *Service) checkQuota(ctx context.Context, ownerID, packageID, except string) error {
	if ownerID == "" {
		return nil
	}
	lim, err := s.db.ResellerLimitsOf(ctx, ownerID)
	if err != nil {
		return err
	}
	if lim.MaxAccounts == nil && lim.DiskMB == nil && lim.BandwidthMB == nil {
		return nil
	}
	owned, err := s.db.OwnedAccounts(ctx, ownerID)
	if err != nil {
		return err
	}
	n, disk, bw := 0, int64(0), int64(0)
	diskUnlimited, bwUnlimited := false, false
	add := func(pkgID string) error {
		l, _, err := s.plans.Entitlements(ctx, pkgID)
		if err != nil {
			return err
		}
		if l.DiskMB == nil {
			diskUnlimited = true
		} else {
			disk += *l.DiskMB
		}
		if l.BandwidthMB == nil {
			bwUnlimited = true
		} else {
			bw += *l.BandwidthMB
		}
		return nil
	}
	for _, a := range owned {
		if a.ID == except {
			continue
		}
		n++
		if err := add(a.PackageID); err != nil {
			return err
		}
	}
	n++
	if err := add(packageID); err != nil {
		return err
	}
	if lim.MaxAccounts != nil && int64(n) > *lim.MaxAccounts {
		return apperr.NewConflict("reseller_limit", fmt.Sprintf("the limit of %d accounts is reached", *lim.MaxAccounts))
	}
	if lim.DiskMB != nil && !lim.OversellDisk && (diskUnlimited || disk > *lim.DiskMB) {
		return apperr.NewConflict("reseller_limit", fmt.Sprintf("the packages would give out more disk than the %d MB allowed (a package without a disk limit counts as all of it)", *lim.DiskMB))
	}
	if lim.BandwidthMB != nil && !lim.OversellBandwidth && (bwUnlimited || bw > *lim.BandwidthMB) {
		return apperr.NewConflict("reseller_limit", fmt.Sprintf("the packages would give out more bandwidth than the %d MB a month allowed (a package without a limit counts as all of it)", *lim.BandwidthMB))
	}
	return nil
}
