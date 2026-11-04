package mail

import (
	"context"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/agent"
	agentv1 "github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// QueuedRecipient is a recipient of a queued message and why it waits.
type QueuedRecipient struct {
	Address string `json:"address"`
	Reason  string `json:"reason"`
}

// QueuedMessage is one message in Postfix's queue (ADR-0022).
type QueuedMessage struct {
	ID         string            `json:"id"`
	Queue      string            `json:"queue"`
	Arrived    time.Time         `json:"arrived"`
	Size       int64             `json:"size"`
	Sender     string            `json:"sender"`
	Recipients []QueuedRecipient `json:"recipients"`
}

func queueAdmin(p *auth.Principal) error {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return apperr.ErrForbidden
	}
	return nil
}

// Queue returns the messages Postfix has not delivered yet (admins).
func (s *Service) Queue(ctx context.Context, p *auth.Principal) ([]QueuedMessage, error) {
	if err := queueAdmin(p); err != nil {
		return nil, err
	}
	res, err := s.agent.MailQueueList(ctx, &agentv1.MailQueueListRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]QueuedMessage, 0, len(res.GetMessages()))
	for _, m := range res.GetMessages() {
		q := QueuedMessage{ID: m.GetId(), Queue: m.GetQueue(), Arrived: time.Unix(m.GetArrivedUnix(), 0).UTC(), Size: m.GetSize(), Sender: m.GetSender(), Recipients: []QueuedRecipient{}}
		for _, r := range m.GetRecipients() {
			q.Recipients = append(q.Recipients, QueuedRecipient{Address: r.GetAddress(), Reason: r.GetReason()})
		}
		out = append(out, q)
	}
	return out, nil
}

// QueueAction flushes or deletes queued mail (admins): flush_all, flush,
// delete (named messages) or delete_all (everything deferred).
func (s *Service) QueueAction(ctx context.Context, c auth.Client, p *auth.Principal, action string, ids []string) error {
	if err := queueAdmin(p); err != nil {
		return err
	}
	switch action {
	case agent.QueueFlush, agent.QueueDelete:
		if err := agent.CheckQueueIDs(ids); err != nil {
			return validate.WithField(&validate.Error{Code: validate.CodeFormat, Message: err.Error()}, "ids")
		}
	case agent.QueueFlushAll, agent.QueueDeleteAll:
		ids = nil
	default:
		return validate.WithField(&validate.Error{Code: validate.CodeFormat, Message: "flush_all, flush, delete or delete_all"}, "action")
	}
	if _, err := s.agent.MailQueueAction(ctx, &agentv1.MailQueueActionRequest{Action: action, Ids: ids}); err != nil {
		return err
	}
	return s.audit.Record(ctx, event(c, p, "mail.queue."+action, "", "mail", "", map[string]any{"ids": strings.Join(ids, ",")}))
}
