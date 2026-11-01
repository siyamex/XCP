package agentrpc

import (
	"context"
	"maps"
	"slices"
	"sync"

	"google.golang.org/grpc"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
)

func mailAccountFrom(req *agentv1.MailAccountApplyRequest) agent.MailAccount {
	a := agent.MailAccount{Username: req.GetUsername()}
	for _, d := range req.GetDomains() {
		md := agent.MailDomain{
			Name: d.GetName(), Routing: d.GetRouting(), AliasOf: d.GetAliasOf(), CatchAll: d.GetCatchAll(), DKIMKey: d.GetDkimKey(),
		}
		for _, m := range d.GetMailboxes() {
			md.Mailboxes = append(md.Mailboxes, agent.Mailbox{
				Local: m.GetLocal(), PasswordHash: m.GetPasswordHash(), QuotaMB: m.GetQuotaMb(),
				Login: m.GetLogin(), Receive: m.GetReceive(), Send: m.GetSend(),
			})
		}
		for _, f := range d.GetForwarders() {
			md.Forwarders = append(md.Forwarders, agent.Forwarder{Local: f.GetLocal(), To: f.GetTo(), Fail: f.GetFail()})
		}
		a.Domains = append(a.Domains, md)
	}
	return a
}

func mailSettingsFrom(req *agentv1.MailSettingsApplyRequest) agent.MailSettings {
	return agent.MailSettings{
		Hostname: req.GetHostname(), MaxMessageMB: req.GetMaxMessageMb(), RelayHost: req.GetRelayHost(),
		RelayUser: req.GetRelayUser(), RelayPassword: req.GetRelayPassword(), RBLs: req.GetRbls(),
		HeloChecks: req.GetHeloChecks(), Greylisting: req.GetGreylisting(),
	}
}

// MailAccountApply implements agentv1.AgentServiceServer.
func (s *Server) MailAccountApply(ctx context.Context, req *agentv1.MailAccountApplyRequest) (*agentv1.MailAccountApplyResponse, error) {
	changed, err := s.Mail.ApplyAccount(ctx, mailAccountFrom(req))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MailAccountApplyResponse{Changed: changed}, nil
}

// MailAccountRemove implements agentv1.AgentServiceServer.
func (s *Server) MailAccountRemove(ctx context.Context, req *agentv1.MailAccountRemoveRequest) (*agentv1.MailAccountRemoveResponse, error) {
	removed, err := s.Mail.RemoveAccount(ctx, req.GetUsername())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MailAccountRemoveResponse{Removed: removed}, nil
}

// MailSettingsApply implements agentv1.AgentServiceServer.
func (s *Server) MailSettingsApply(ctx context.Context, req *agentv1.MailSettingsApplyRequest) (*agentv1.MailSettingsApplyResponse, error) {
	changed, err := s.Mail.ApplySettings(ctx, mailSettingsFrom(req))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MailSettingsApplyResponse{Changed: changed}, nil
}

// fakeMail is the fake agent's mail server.
type fakeMail struct {
	mu       sync.Mutex
	accounts map[string]agent.MailAccount
	settings *agent.MailSettings
}

// MailAccount returns the mail the fake agent holds for an account, for tests.
func (f *Fake) MailAccount(username string) (agent.MailAccount, bool) {
	f.mail.mu.Lock()
	defer f.mail.mu.Unlock()
	a, ok := f.mail.accounts[username]
	return a, ok
}

// MailSettings returns the mail settings applied through the fake agent, for tests.
func (f *Fake) MailSettings() *agent.MailSettings {
	f.mail.mu.Lock()
	defer f.mail.mu.Unlock()
	return f.mail.settings
}

// MailAccountApply implements Client, with the real agent's checks.
func (f *Fake) MailAccountApply(_ context.Context, req *agentv1.MailAccountApplyRequest, _ ...grpc.CallOption) (*agentv1.MailAccountApplyResponse, error) {
	f.recordf("MailAccountApply %s (%d domains)", req.GetUsername(), len(req.GetDomains()))
	a := mailAccountFrom(req)
	a.UID, a.GID = 10000, 10000
	if err := agent.CheckMailAccount(a); err != nil {
		return nil, fakeInvalid(err)
	}
	f.mail.mu.Lock()
	defer f.mail.mu.Unlock()
	for _, user := range slices.Sorted(maps.Keys(f.mail.accounts)) {
		if user == a.Username {
			continue
		}
		for _, d := range f.mail.accounts[user].Domains {
			for _, mine := range a.Domains {
				if d.Name == mine.Name {
					return nil, fakeInvalid(agent.ErrInvalidRequest)
				}
			}
		}
	}
	if f.mail.accounts == nil {
		f.mail.accounts = map[string]agent.MailAccount{}
	}
	f.mail.accounts[a.Username] = a
	return &agentv1.MailAccountApplyResponse{Changed: true}, nil
}

// MailAccountRemove implements Client.
func (f *Fake) MailAccountRemove(_ context.Context, req *agentv1.MailAccountRemoveRequest, _ ...grpc.CallOption) (*agentv1.MailAccountRemoveResponse, error) {
	f.recordf("MailAccountRemove %s", req.GetUsername())
	f.mail.mu.Lock()
	defer f.mail.mu.Unlock()
	_, ok := f.mail.accounts[req.GetUsername()]
	delete(f.mail.accounts, req.GetUsername())
	return &agentv1.MailAccountRemoveResponse{Removed: ok}, nil
}

// MailSettingsApply implements Client.
func (f *Fake) MailSettingsApply(_ context.Context, req *agentv1.MailSettingsApplyRequest, _ ...grpc.CallOption) (*agentv1.MailSettingsApplyResponse, error) {
	f.recordf("MailSettingsApply %s", req.GetHostname())
	s := mailSettingsFrom(req)
	if err := agent.CheckMailSettings(s); err != nil {
		return nil, fakeInvalid(err)
	}
	f.mail.mu.Lock()
	defer f.mail.mu.Unlock()
	f.mail.settings = &s
	return &agentv1.MailSettingsApplyResponse{Changed: true}, nil
}
