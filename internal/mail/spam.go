package mail

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// FeatureSpam switches the spam filter settings on in a feature list.
const FeatureSpam = "spam_filter"

// Spam is a mailbox's spam filter (USR-MAIL-08).
type Spam struct {
	Enabled   bool     `json:"enabled"`
	Threshold int      `json:"threshold"` // spam from this score up: 1 to 50 (the server marks 6 and above)
	Action    string   `json:"action"`    // junk or delete
	Allow     []string `json:"allow"`     // senders that are never spam: addresses or patterns like *@example.com
	Block     []string `json:"block"`     // senders that are always spam
	JobID     string   `json:"job_id,omitempty"`
}

func spamView(s store.MailboxSpam) Spam {
	return Spam{Enabled: s.Enabled, Threshold: s.Threshold, Action: s.Action, Allow: s.Allow, Block: s.Block}
}

func (s *Service) spamAllowed(ctx context.Context, p *auth.Principal, a *store.Account) error {
	if p.Login.Role != store.RoleUser {
		return nil
	}
	_, features, err := s.plans.Entitlements(ctx, a.PackageID)
	if err != nil {
		return err
	}
	if !slices.Contains(features, FeatureSpam) {
		return apperr.ErrForbidden
	}
	return nil
}

// Spam returns a mailbox's spam filter.
func (s *Service) Spam(ctx context.Context, p *auth.Principal, mailboxID string) (Spam, error) {
	m, a, _, _, err := s.ownMailbox(ctx, p, mailboxID)
	if err != nil {
		return Spam{}, err
	}
	if err := s.spamAllowed(ctx, p, a); err != nil {
		return Spam{}, err
	}
	sp, err := s.db.MailboxSpamOf(ctx, m.ID)
	if err != nil {
		return Spam{}, err
	}
	return spamView(sp), nil
}

func cleanList(field string, in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	if len(in) > agent.MaxSpamList {
		return nil, &validate.Error{Field: field, Code: validate.CodeOutOfRange, Message: "at most 200 entries"}
	}
	for _, e := range in {
		c, err := agent.CleanSpamPattern(e)
		if err != nil {
			return nil, &validate.Error{Field: field, Code: validate.CodeFormat, Message: err.Error()}
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out, nil
}

// SetSpam saves a mailbox's spam filter and applies it.
func (s *Service) SetSpam(ctx context.Context, c auth.Client, p *auth.Principal, mailboxID string, in Spam) (Spam, error) {
	m, a, _, domain, err := s.ownMailbox(ctx, p, mailboxID)
	if err != nil {
		return Spam{}, err
	}
	if err := s.spamAllowed(ctx, p, a); err != nil {
		return Spam{}, err
	}
	if in.Threshold < 1 || in.Threshold > 50 {
		return Spam{}, &validate.Error{Field: "threshold", Code: validate.CodeOutOfRange, Message: "1 to 50"}
	}
	in.Action = strings.TrimSpace(in.Action)
	if in.Action != agent.SpamJunk && in.Action != agent.SpamDelete {
		return Spam{}, &validate.Error{Field: "action", Code: validate.CodeFormat, Message: "junk or delete"}
	}
	allow, err := cleanList("allow", in.Allow)
	if err != nil {
		return Spam{}, err
	}
	block, err := cleanList("block", in.Block)
	if err != nil {
		return Spam{}, err
	}
	for _, b := range block {
		if slices.Contains(allow, b) {
			return Spam{}, &validate.Error{Field: "block", Code: validate.CodeFormat, Message: b + " is on the allow list too"}
		}
	}
	sp := store.MailboxSpam{MailboxID: m.ID, Enabled: in.Enabled, Threshold: in.Threshold, Action: in.Action, Allow: allow, Block: block}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetMailboxSpam(ctx, tx, sp, time.Now().UTC()); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.spam.set", a.ID, "mailbox", m.ID, map[string]any{
			"address": m.LocalPart + "@" + domain, "enabled": in.Enabled, "threshold": in.Threshold, "action": in.Action,
			"allow": len(allow), "block": len(block),
		}))
	})
	if err != nil {
		return Spam{}, err
	}
	v := spamView(sp)
	v.JobID = jobID
	return v, nil
}
