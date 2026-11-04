package agentrpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/siyamex/XCP/internal/agent"
	agentv1 "github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

// MailQueueList implements agentv1.AgentServiceServer.
func (s *Server) MailQueueList(ctx context.Context, _ *agentv1.MailQueueListRequest) (*agentv1.MailQueueListResponse, error) {
	list, err := s.MailQueue.List(ctx)
	if err != nil {
		return nil, s.toStatus(err)
	}
	out := &agentv1.MailQueueListResponse{}
	for _, m := range list {
		q := &agentv1.QueuedMail{Id: m.ID, Queue: m.Queue, ArrivedUnix: m.Arrived.Unix(), Size: m.Size, Sender: m.Sender}
		for _, r := range m.Recipients {
			q.Recipients = append(q.Recipients, &agentv1.QueuedRecipient{Address: r.Address, Reason: r.Reason})
		}
		out.Messages = append(out.Messages, q)
	}
	return out, nil
}

// MailQueueAction implements agentv1.AgentServiceServer.
func (s *Server) MailQueueAction(ctx context.Context, req *agentv1.MailQueueActionRequest) (*agentv1.MailQueueActionResponse, error) {
	if err := s.MailQueue.Do(ctx, req.GetAction(), req.GetIds()); err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MailQueueActionResponse{}, nil
}

type fakeQueue struct {
	mu   sync.Mutex
	msgs []*agentv1.QueuedMail
}

// QueueMail puts a message in the fake queue.
func (f *Fake) QueueMail(id, queue, sender, to, reason string) {
	f.mq.mu.Lock()
	defer f.mq.mu.Unlock()
	f.mq.msgs = append(f.mq.msgs, &agentv1.QueuedMail{
		Id: id, Queue: queue, ArrivedUnix: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), Size: 1000, Sender: sender,
		Recipients: []*agentv1.QueuedRecipient{{Address: to, Reason: reason}},
	})
}

// QueuedIDs returns the ids in the fake queue.
func (f *Fake) QueuedIDs() []string {
	f.mq.mu.Lock()
	defer f.mq.mu.Unlock()
	var out []string
	for _, m := range f.mq.msgs {
		out = append(out, m.Id)
	}
	return out
}

// MailQueueList implements Client.
func (f *Fake) MailQueueList(_ context.Context, _ *agentv1.MailQueueListRequest, _ ...grpc.CallOption) (*agentv1.MailQueueListResponse, error) {
	f.mq.mu.Lock()
	defer f.mq.mu.Unlock()
	return &agentv1.MailQueueListResponse{Messages: append([]*agentv1.QueuedMail(nil), f.mq.msgs...)}, nil
}

// MailQueueAction implements Client.
func (f *Fake) MailQueueAction(_ context.Context, req *agentv1.MailQueueActionRequest, _ ...grpc.CallOption) (*agentv1.MailQueueActionResponse, error) {
	f.recordf("MailQueueAction %s %v", req.GetAction(), req.GetIds())
	switch req.GetAction() {
	case agent.QueueFlush, agent.QueueDelete:
		if err := agent.CheckQueueIDs(req.GetIds()); err != nil {
			return nil, err
		}
	case agent.QueueFlushAll, agent.QueueDeleteAll:
	default:
		return nil, fmt.Errorf("unknown queue action %q", req.GetAction())
	}
	f.mq.mu.Lock()
	defer f.mq.mu.Unlock()
	switch req.GetAction() {
	case agent.QueueDelete:
		keep := f.mq.msgs[:0]
		for _, m := range f.mq.msgs {
			del := false
			for _, id := range req.GetIds() {
				del = del || id == m.Id
			}
			if !del {
				keep = append(keep, m)
			}
		}
		f.mq.msgs = keep
	case agent.QueueDeleteAll:
		f.mq.msgs = nil
	}
	return &agentv1.MailQueueActionResponse{}, nil
}
