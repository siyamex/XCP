package mail

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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

// Folder is one folder of a mailbox (USR-MAIL-02).
type Folder struct {
	Name     string `json:"name"`
	Messages int64  `json:"messages"`
	Bytes    int64  `json:"bytes"`
}

// Usage is how much a mailbox holds, by folder.
type Usage struct {
	Folders []Folder `json:"folders"`
	Bytes   int64    `json:"bytes"`
	QuotaMB int64    `json:"quota_mb"` // 0: no limit
}

type cleanupPayload struct {
	AccountID string `json:"account_id"`
	MailboxID string `json:"mailbox_id"`
	Address   string `json:"address"`
	Folder    string `json:"folder"`
	Days      int    `json:"days"`
}

// Usage returns a mailbox's folders with their messages and size.
func (s *Service) Usage(ctx context.Context, p *auth.Principal, id string) (Usage, error) {
	m, a, _, domain, err := s.ownMailbox(ctx, p, id)
	if err != nil {
		return Usage{}, err
	}
	uctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	res, err := s.agent.MailboxUsage(uctx, &agentv1.MailboxUsageRequest{Username: a.Username, Address: m.LocalPart + "@" + domain})
	switch {
	case status.Code(err) == codes.NotFound:
		return Usage{}, apperr.NewConflict("not_installed", status.Convert(err).Message())
	case status.Code(err) == codes.InvalidArgument:
		// Not applied yet (a new mailbox), or its domain's mail is elsewhere.
		return Usage{Folders: []Folder{}, QuotaMB: m.QuotaMB}, nil
	case err != nil:
		return Usage{}, err
	}
	u := Usage{Folders: []Folder{}, QuotaMB: m.QuotaMB}
	for _, f := range res.GetFolders() {
		u.Folders = append(u.Folders, Folder{Name: f.GetName(), Messages: f.GetMessages(), Bytes: f.GetBytes()})
		u.Bytes += f.GetBytes()
	}
	return u, nil
}

// Cleanup queues deleting the messages of one folder of a mailbox that
// arrived before days days ago. The job's result has "removed" and "bytes".
func (s *Service) Cleanup(ctx context.Context, c auth.Client, p *auth.Principal, id, folder string, days int) (string, error) {
	m, a, _, domain, err := s.ownMailbox(ctx, p, id)
	if err != nil {
		return "", err
	}
	if days < 1 || days > agent.MaxCleanupDays {
		return "", badField("days", validate.CodeOutOfRange, "days must be 1 to 3650")
	}
	if err := agent.CheckFolderName(folder); err != nil {
		return "", badField("folder", validate.CodeFormat, "not a folder name")
	}
	addr := m.LocalPart + "@" + domain
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		jobID, err = s.jobs.EnqueueTx(ctx, tx, JobCleanup, cleanupPayload{AccountID: a.ID, MailboxID: m.ID, Address: addr, Folder: folder, Days: days},
			jobs.EnqueueOptions{AccountID: a.ID, LockKey: "mailbox:" + m.ID, MaxAttempts: 1, CreatedBy: p.Login.ID})
		if err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "mail.mailbox.cleanup", a.ID, "mailbox", m.ID, map[string]any{"address": addr, "folder": folder, "days": days}))
	})
	return jobID, err
}

func (s *Service) cleanupJob(ctx context.Context, j *jobs.Job, r jobs.Reporter) (any, error) {
	var p cleanupPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil || p.AccountID == "" || p.Address == "" {
		return nil, jobs.Permanent(fmt.Errorf("bad job payload: %s", j.Payload))
	}
	a, err := s.db.AccountByID(ctx, p.AccountID)
	if errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "account removed"}, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := s.db.MailboxByID(ctx, p.MailboxID); errors.Is(err, store.ErrNotFound) {
		return map[string]string{"skipped": "mailbox removed"}, nil
	}
	r.Logf("deleting mail of %s in %s from before %d days ago", p.Address, p.Folder, p.Days)
	res, err := s.agent.MailboxCleanup(ctx, &agentv1.MailboxCleanupRequest{
		Username: a.Username, Address: p.Address, Folder: p.Folder, Days: int32(p.Days), //nolint:gosec // G115: 1..3650
	})
	switch {
	case status.Code(err) == codes.NotFound:
		return nil, jobs.Permanent(errors.New("the mail server is not installed"))
	case err != nil:
		return nil, permanentIfRefused(err)
	}
	return map[string]any{"folder": p.Folder, "removed": res.GetRemoved(), "bytes": res.GetBytes()}, nil
}
