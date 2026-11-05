package accounts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
)

// RenderVersion is the version of what the agent renders for an account
// (its sites, pools, and the services attached). Raise it when a release
// changes that output, so existing accounts get it too: for example 2,
// account logs in vhost_combined format (ADR-0012).
const RenderVersion = 3

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

type nopReporter struct{}

func (nopReporter) Progress(int)        {}
func (nopReporter) Logf(string, ...any) {}

// ApplyNow makes the server match an account's rows, and waits for it: what
// the account's apply job does, for callers that are jobs themselves.
func (s *Service) ApplyNow(ctx context.Context, accountID string) error {
	b, err := json.Marshal(jobPayload{AccountID: accountID})
	if err != nil {
		return err
	}
	_, err = s.applyJob(ctx, &jobs.Job{Payload: b}, nopReporter{})
	return err
}

// ApplyAll queues an apply of every active or suspended account (for
// "rebuild"), and reports how many.
func (s *Service) ApplyAll(ctx context.Context, by string) (int, error) {
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
			if _, err := s.enqueue(ctx, tx, &auth.Principal{Login: &store.Login{ID: by}, Session: &store.Session{}}, JobApply, a.ID); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}
