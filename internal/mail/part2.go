package mail

import (
	"context"
	"database/sql"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// FeatureWebmail switches webmail sign-on on in a feature list.
const FeatureWebmail = "webmail"

// Autoresponder is a mailbox's autoresponder (USR-MAIL-05).
type Autoresponder struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Start   string `json:"start"` // YYYY-MM-DD; "" = from now
	End     string `json:"end"`   // YYYY-MM-DD, inclusive; "" = until removed
	Days    int    `json:"days"`  // at most one reply per sender in this many days
}

// JobWebmailExpire drops expired webmail passwords; WebmailSchedule is how often.
const (
	JobWebmailExpire = "mail.webmail_expire"
	WebmailSchedule  = "*/30 * * * *"
)

// Schedule adds the expiry of webmail passwords to a scheduler.
func (s *Service) Schedule(sched *jobs.Scheduler) error {
	return sched.Every(WebmailSchedule, JobWebmailExpire, struct{}{})
}

func (s *Service) webmailExpireJob(ctx context.Context, _ *jobs.Job, _ jobs.Reporter) (any, error) {
	_, err := s.agent.MailWebmailExpire(ctx, &agentv1.MailWebmailExpireRequest{})
	if status.Code(err) == codes.NotFound {
		return map[string]string{"skipped": "the mail server is not installed"}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]bool{"done": true}, nil
}

// SetAutoresponder sets a mailbox's autoresponder.
func (s *Service) SetAutoresponder(ctx context.Context, c auth.Client, p *auth.Principal, mailboxID string, in Autoresponder) (string, error) {
	m, a, _, domain, err := s.ownMailbox(ctx, p, mailboxID)
	if err != nil {
		return "", err
	}
	in.Subject, in.Start, in.End = strings.TrimSpace(in.Subject), strings.TrimSpace(in.Start), strings.TrimSpace(in.End)
	if in.Days == 0 {
		in.Days = 1
	}
	if err := agent.CheckAutoresponder(agent.Autoresponder(in)); err != nil {
		msg := strings.TrimPrefix(err.Error(), agent.ErrInvalidRequest.Error()+": ")
		return "", &validate.Error{Field: "autoresponder", Code: validate.CodeFormat, Message: msg}
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetAutoresponder(ctx, tx, store.Autoresponder{
			MailboxID: m.ID, Subject: in.Subject, Body: in.Body, StartDate: in.Start, EndDate: in.End, Days: in.Days,
		}); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.autoresponder.set", a.ID, "mailbox", m.ID, map[string]any{
			"address": m.LocalPart + "@" + domain, "start": in.Start, "end": in.End, "days": in.Days,
		}))
	})
	return jobID, err
}

// DeleteAutoresponder removes a mailbox's autoresponder.
func (s *Service) DeleteAutoresponder(ctx context.Context, c auth.Client, p *auth.Principal, mailboxID string) (string, error) {
	m, a, _, domain, err := s.ownMailbox(ctx, p, mailboxID)
	if err != nil {
		return "", err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.DeleteAutoresponder(ctx, tx, m.ID); err != nil {
			return err
		}
		if jobID, err = s.EnqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.autoresponder.delete", a.ID, "mailbox", m.ID, map[string]any{"address": m.LocalPart + "@" + domain}))
	})
	return jobID, err
}

// Webmail signs a mailbox in to webmail (USR-MAIL-11): the agent makes a
// temporary password and a one-time ticket, whose ID it returns.
func (s *Service) Webmail(ctx context.Context, c auth.Client, p *auth.Principal, mailboxID string) (string, error) {
	m, a, _, domain, err := s.ownMailbox(ctx, p, mailboxID)
	if err != nil {
		return "", err
	}
	if p.Login.Role == store.RoleUser {
		_, features, err := s.plans.Entitlements(ctx, a.PackageID)
		if err != nil {
			return "", err
		}
		if !slices.Contains(features, FeatureWebmail) {
			return "", apperr.ErrForbidden
		}
	}
	switch {
	case a.Status != store.AccountActive:
		return "", apperr.NewConflict("bad_status", "webmail opens only for an active account")
	case !m.CanLogin:
		return "", apperr.NewConflict("login_off", "logging in is switched off for this mailbox")
	}
	address := m.LocalPart + "@" + domain
	res, err := s.agent.MailWebmailSignon(ctx, &agentv1.MailWebmailSignonRequest{Username: a.Username, Address: address})
	switch {
	case status.Code(err) == codes.NotFound:
		return "", apperr.NewConflict("not_installed", status.Convert(err).Message())
	case status.Code(err) == codes.InvalidArgument:
		return "", apperr.NewConflict("not_ready", "the mailbox is not set up on the mail server yet; try again in a moment")
	case err != nil:
		return "", err
	}
	_ = s.audit.Record(ctx, event(c, p, "mail.webmail", a.ID, "mailbox", m.ID, map[string]any{"address": address}))
	return res.GetTicket(), nil
}
