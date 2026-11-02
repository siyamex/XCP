package accounts

import (
	"context"
	"database/sql"
	"errors"

	"github.com/siyamex/XCP/internal/store"
)

// RenderVersion is the version of what the agent renders for an account
// (its sites, pools, and the services attached). Raise it when a release
// changes that output, so existing accounts get it too: for example 2,
// account logs in vhost_combined format (ADR-0012).
const RenderVersion = 2

const renderVersionKey = "accounts.render_version"

// ApplyAfterUpgrade queues an apply of every account when RenderVersion
// changed since the last start. It reports how many it queued.
func (s *Service) ApplyAfterUpgrade(ctx context.Context) (int, error) {
	var have int
	if err := s.db.GetSetting(ctx, renderVersionKey, &have); err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	if have == RenderVersion {
		return 0, nil
	}
	as, err := s.db.ListAccounts(ctx, store.AccountFilter{OwnerID: "*"})
	if err != nil {
		return 0, err
	}
	n := 0
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		for _, a := range as {
			if a.Status != store.AccountActive && a.Status != store.AccountSuspended {
				continue
			}
			if _, err := s.enqueue(ctx, tx, nil, JobApply, a.ID); err != nil {
				return err
			}
			n++
		}
		return store.PutSetting(ctx, tx, renderVersionKey, RenderVersion)
	})
	return n, err
}
