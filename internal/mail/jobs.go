package mail

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
)

// Job kinds. An account's apply shares the account's lock key, so it runs
// in order with the account's other jobs.
const (
	JobApply    = "mail.apply"    // give the agent all mail of an account
	JobSettings = "mail.settings" // render the mail servers' configuration
)

type applyPayload struct {
	AccountID string `json:"account_id"`
}

// RegisterJobs adds the mail job handlers to a worker.
func (s *Service) RegisterJobs(w *jobs.Worker) {
	w.Register(JobApply, 4, s.applyJob)
	w.Register(JobSettings, 1, s.settingsJob)
	w.Register(JobWebmailExpire, 1, s.webmailExpireJob)
}

// EnqueueApply queues, inside tx, the job that applies an account's mail.
// It is also the hook domains and zones call when a change affects mail.
func (s *Service) EnqueueApply(ctx context.Context, tx *sql.Tx, createdBy, accountID string) (string, error) {
	return s.jobs.EnqueueTx(ctx, tx, JobApply, applyPayload{AccountID: accountID}, jobs.EnqueueOptions{
		AccountID: accountID, LockKey: "account:" + accountID, MaxAttempts: 3, CreatedBy: createdBy,
	})
}

// EnqueueSettings queues the job that applies the mail settings.
func (s *Service) EnqueueSettings(ctx context.Context, createdBy string) (string, error) {
	return s.jobs.Enqueue(ctx, JobSettings, struct{}{}, jobs.EnqueueOptions{LockKey: "mail:settings", MaxAttempts: 3, CreatedBy: createdBy})
}

// AccountRequest builds the agent request with all of an account's mail:
// the domains whose mail is handled here (local or backup MX), with their
// addresses. A suspended account receives mail but cannot log in or send.
func (s *Service) AccountRequest(ctx context.Context, a *store.Account) (*agentv1.MailAccountApplyRequest, error) {
	ds, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	mds, err := store.AccountMailDomains(ctx, s.db.R, a.ID)
	if err != nil {
		return nil, err
	}
	boxes, err := store.AccountMailboxes(ctx, s.db.R, a.ID)
	if err != nil {
		return nil, err
	}
	fws, err := store.AccountForwarders(ctx, s.db.R, a.ID)
	if err != nil {
		return nil, err
	}
	spam, err := store.AccountSpam(ctx, s.db.R, a.ID)
	if err != nil {
		return nil, err
	}
	replies, err := store.AccountAutoresponders(ctx, s.db.R, a.ID)
	if err != nil {
		return nil, err
	}
	byID := map[string]store.Domain{}
	for _, d := range ds {
		byID[d.ID] = d
	}
	suspended := a.Status == store.AccountSuspended
	req := &agentv1.MailAccountApplyRequest{Username: a.Username}
	for _, d := range ds {
		if strings.HasPrefix(d.Name, "*.") {
			continue
		}
		routing, err := s.zones.MailRouting(ctx, d)
		if err != nil {
			return nil, err
		}
		if routing != store.MailLocal && routing != store.MailBackup {
			continue
		}
		md := &agentv1.MailDomain{Name: d.Name, Routing: routing}
		if routing == store.MailLocal {
			if d.Kind == store.DomainAlias {
				md.AliasOf = byID[d.ParentID].Name
			} else {
				m := mds[d.ID]
				md.CatchAll = m.CatchAll
				if len(m.DKIMKeyEnc) > 0 {
					key, err := s.box.Open(m.DKIMKeyEnc, []byte("dkim:"+d.ID))
					if err != nil {
						return nil, fmt.Errorf("DKIM key of %s: %w", d.Name, err)
					}
					md.DkimKey = string(key)
				}
				for _, b := range boxes {
					if b.DomainID == d.ID {
						md.Mailboxes = append(md.Mailboxes, &agentv1.Mailbox{
							Local: b.LocalPart, PasswordHash: b.PasswordHash, QuotaMb: b.QuotaMB,
							Login: b.CanLogin && !suspended, Receive: b.CanReceive, Send: b.CanSend && !suspended,
						})
						sp, ok := spam[b.ID]
						if !ok {
							sp = store.DefaultSpam(b.ID)
						}
						md.Mailboxes[len(md.Mailboxes)-1].Spam = &agentv1.MailSpamFilter{
							Enabled: sp.Enabled, Threshold: int32(sp.Threshold), Action: sp.Action, Allow: sp.Allow, Block: sp.Block, //nolint:gosec // G115: 1..50
						}
						if r, ok := replies[b.ID]; ok {
							md.Mailboxes[len(md.Mailboxes)-1].Autoresponder = &agentv1.MailAutoresponder{
								Subject: r.Subject, Body: r.Body, Start: r.StartDate, End: r.EndDate, Days: int32(r.Days), //nolint:gosec // G115: 1..30
							}
						}
					}
				}
				for _, f := range fws {
					if f.DomainID == d.ID {
						md.Forwarders = append(md.Forwarders, &agentv1.MailForwarder{Local: f.LocalPart, To: f.Destinations, Fail: f.FailMessage, Pipe: f.Pipe})
					}
				}
			}
		}
		req.Domains = append(req.Domains, md)
	}
	return req, nil
}

func permanentIfRefused(err error) error {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied:
		return jobs.Permanent(err)
	}
	return err
}

// Apply gives the agent all mail of an account. It reports "skipped" when
// the mail server is not installed.
func (s *Service) Apply(ctx context.Context, a *store.Account) (string, error) {
	req, err := s.AccountRequest(ctx, a)
	if err != nil {
		return "", err
	}
	_, err = s.agent.MailAccountApply(ctx, req)
	switch {
	case status.Code(err) == codes.NotFound:
		return "skipped: the mail server is not installed", nil
	case err != nil:
		return "", permanentIfRefused(err)
	}
	return fmt.Sprintf("applied: %d mail domain(s)", len(req.GetDomains())), nil
}

// RemoveAccount drops an account's mail from the mail server (when the account is terminated).
func (s *Service) RemoveAccount(ctx context.Context, username string) (string, error) {
	_, err := s.agent.MailAccountRemove(ctx, &agentv1.MailAccountRemoveRequest{Username: username})
	switch {
	case status.Code(err) == codes.NotFound:
		return "skipped: the mail server is not installed", nil
	case err != nil:
		return "", permanentIfRefused(err)
	}
	return "removed", nil
}

func (s *Service) applyJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p applyPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.AccountID == "" {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	a, err := s.db.AccountByID(ctx, p.AccountID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "account removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	if a.Status == store.AccountTerminating || a.Status == store.AccountCreating {
		return map[string]string{"skipped": "account is " + a.Status}, nil
	}
	res, err := s.Apply(ctx, a)
	if err != nil {
		return nil, err
	}
	r.Logf("mail %s", res)
	return map[string]string{"mail": res}, nil
}

func (s *Service) settingsJob(ctx context.Context, _ *jobs.Job, r jobs.Reporter) (any, error) {
	st, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	m, err := s.agentSettings(st)
	if err != nil {
		return nil, err
	}
	res, err := s.agent.MailSettingsApply(ctx, &agentv1.MailSettingsApplyRequest{
		Hostname: m.Hostname, MaxMessageMb: m.MaxMessageMB, RelayHost: m.RelayHost, RelayUser: m.RelayUser,
		RelayPassword: m.RelayPassword, Rbls: m.RBLs, HeloChecks: m.HeloChecks, Greylisting: m.Greylisting,
	})
	switch {
	case status.Code(err) == codes.NotFound:
		return map[string]string{"skipped": "the mail server is not installed"}, nil
	case err != nil:
		return nil, permanentIfRefused(err)
	}
	r.Logf("mail settings applied (changed: %v)", res.GetChanged())
	return map[string]bool{"changed": res.GetChanged()}, nil
}
