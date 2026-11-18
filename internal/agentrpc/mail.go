package agentrpc

import (
	"context"
	"maps"
	"slices"
	"strings"
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
			ForwardTo: d.GetForwardTo(),
		}
		for _, m := range d.GetMailboxes() {
			md.Mailboxes = append(md.Mailboxes, agent.Mailbox{
				Local: m.GetLocal(), PasswordHash: m.GetPasswordHash(), QuotaMB: m.GetQuotaMb(),
				Login: m.GetLogin(), Receive: m.GetReceive(), Send: m.GetSend(),
			})
			if sp := m.GetSpam(); sp != nil {
				md.Mailboxes[len(md.Mailboxes)-1].Spam = &agent.SpamFilter{
					Enabled: sp.GetEnabled(), Threshold: int(sp.GetThreshold()), Action: sp.GetAction(), Allow: sp.GetAllow(), Block: sp.GetBlock(),
				}
			}
			if r := m.GetAutoresponder(); r != nil {
				md.Mailboxes[len(md.Mailboxes)-1].Reply = &agent.Autoresponder{
					Subject: r.GetSubject(), Body: r.GetBody(), Start: r.GetStart(), End: r.GetEnd(), Days: int(r.GetDays()),
				}
			}
		}
		for _, f := range d.GetForwarders() {
			md.Forwarders = append(md.Forwarders, agent.Forwarder{Local: f.GetLocal(), To: f.GetTo(), Fail: f.GetFail(), Pipe: f.GetPipe()})
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
		SpamReject: int(req.GetSpamReject()), SpamAllow: req.GetSpamAllow(), SpamBlock: req.GetSpamBlock(),
		PlusAddressing: req.GetPlusAddressing(),
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

// MailboxUsage implements agentv1.AgentServiceServer.
func (s *Server) MailboxUsage(ctx context.Context, req *agentv1.MailboxUsageRequest) (*agentv1.MailboxUsageResponse, error) {
	list, err := s.Mail.MailboxUsage(ctx, req.GetUsername(), req.GetAddress())
	if err != nil {
		return nil, s.toStatus(err)
	}
	res := &agentv1.MailboxUsageResponse{}
	for _, f := range list {
		res.Folders = append(res.Folders, &agentv1.MailFolder{Name: f.Name, Messages: f.Messages, Bytes: f.Bytes})
	}
	return res, nil
}

// MailboxCleanup implements agentv1.AgentServiceServer.
func (s *Server) MailboxCleanup(ctx context.Context, req *agentv1.MailboxCleanupRequest) (*agentv1.MailboxCleanupResponse, error) {
	n, b, err := s.Mail.MailboxCleanup(ctx, req.GetUsername(), req.GetAddress(), req.GetFolder(), int(req.GetDays()))
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MailboxCleanupResponse{Removed: n, Bytes: b}, nil
}

// MailWebmailSignon implements agentv1.AgentServiceServer.
func (s *Server) MailWebmailSignon(ctx context.Context, req *agentv1.MailWebmailSignonRequest) (*agentv1.MailWebmailSignonResponse, error) {
	ticket, err := s.Mail.WebmailSignon(ctx, req.GetUsername(), req.GetAddress())
	if err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MailWebmailSignonResponse{Ticket: ticket}, nil
}

// MailWebmailExpire implements agentv1.AgentServiceServer.
func (s *Server) MailWebmailExpire(ctx context.Context, _ *agentv1.MailWebmailExpireRequest) (*agentv1.MailWebmailExpireResponse, error) {
	if err := s.Mail.ExpireWebmail(ctx); err != nil {
		return nil, s.toStatus(err)
	}
	return &agentv1.MailWebmailExpireResponse{}, nil
}

func (f *Fake) fakeMailbox(username, address string) bool {
	for _, d := range f.mail.accounts[username].Domains {
		for _, b := range d.Mailboxes {
			if b.Local+"@"+d.Name == address {
				return true
			}
		}
	}
	return false
}

// MailboxUsage implements Client: every mailbox has INBOX with 3 messages
// of 1000 bytes and Sent with 1.
func (f *Fake) MailboxUsage(_ context.Context, req *agentv1.MailboxUsageRequest, _ ...grpc.CallOption) (*agentv1.MailboxUsageResponse, error) {
	f.mail.mu.Lock()
	defer f.mail.mu.Unlock()
	if !f.fakeMailbox(req.GetUsername(), req.GetAddress()) {
		return nil, fakeInvalid(agent.ErrInvalidRequest)
	}
	return &agentv1.MailboxUsageResponse{Folders: []*agentv1.MailFolder{{Name: "INBOX", Messages: 3, Bytes: 3000}, {Name: "Sent", Messages: 1, Bytes: 1000}}}, nil
}

// MailboxCleanup implements Client: it removes 2 messages of INBOX.
func (f *Fake) MailboxCleanup(_ context.Context, req *agentv1.MailboxCleanupRequest, _ ...grpc.CallOption) (*agentv1.MailboxCleanupResponse, error) {
	f.recordf("MailboxCleanup %s %s %d", req.GetAddress(), req.GetFolder(), req.GetDays())
	if err := agent.CheckFolderName(req.GetFolder()); err != nil {
		return nil, fakeInvalid(err)
	}
	f.mail.mu.Lock()
	defer f.mail.mu.Unlock()
	if !f.fakeMailbox(req.GetUsername(), req.GetAddress()) || (req.GetFolder() != "INBOX" && req.GetFolder() != "Sent") {
		return nil, fakeInvalid(agent.ErrInvalidRequest)
	}
	return &agentv1.MailboxCleanupResponse{Removed: 2, Bytes: 2000}, nil
}

// MailWebmailSignon implements Client: a ticket if the mailbox may log in.
func (f *Fake) MailWebmailSignon(_ context.Context, req *agentv1.MailWebmailSignonRequest, _ ...grpc.CallOption) (*agentv1.MailWebmailSignonResponse, error) {
	f.recordf("MailWebmailSignon %s", req.GetAddress())
	f.mail.mu.Lock()
	defer f.mail.mu.Unlock()
	for _, d := range f.mail.accounts[req.GetUsername()].Domains {
		for _, b := range d.Mailboxes {
			if b.Local+"@"+d.Name == req.GetAddress() && b.Login {
				return &agentv1.MailWebmailSignonResponse{Ticket: strings.Repeat("ab", 32)}, nil
			}
		}
	}
	return nil, fakeInvalid(agent.ErrInvalidRequest)
}

// MailWebmailExpire implements Client.
func (f *Fake) MailWebmailExpire(context.Context, *agentv1.MailWebmailExpireRequest, ...grpc.CallOption) (*agentv1.MailWebmailExpireResponse, error) {
	f.recordf("MailWebmailExpire")
	return &agentv1.MailWebmailExpireResponse{}, nil
}
