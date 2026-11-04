// Package firewall is the admin's firewall (ADM-SEC-01..03, ADR-0017): the
// configuration, the bans, and the job that gives the agent the rules.
package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/fwcfg"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Service manages the firewall.
type Service struct {
	db        *store.DB
	audit     *audit.Recorder
	jobs      *jobs.Queue
	agent     agentrpc.Client
	PanelPort int // the port the panel listens on
	Now       func() time.Time
}

// NewService returns a firewall service.
func NewService(db *store.DB, rec *audit.Recorder, q *jobs.Queue, ag agentrpc.Client, panelPort int) *Service {
	return &Service{db: db, audit: rec, jobs: q, agent: ag, PanelPort: panelPort, Now: time.Now}
}

func admin(p *auth.Principal) error {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return apperr.ErrForbidden
	}
	return nil
}

func event(c auth.Client, p *auth.Principal, action, targetID string, details map[string]any) audit.Event {
	return audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: "firewall", TargetID: targetID, Details: details,
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
	}
}

// Ban is a banned address.
type Ban struct {
	ID         string     `json:"id"`
	IP         string     `json:"ip"`
	Reason     string     `json:"reason"`
	Source     string     `json:"source"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	ReleasedAt *time.Time `json:"released_at"`
	ReleasedBy string     `json:"released_by"`
	Active     bool       `json:"active"`
}

func (s *Service) banView(b store.FWBan) Ban {
	return Ban{
		ID: b.ID, IP: b.IP, Reason: b.Reason, Source: b.Source, CreatedAt: b.CreatedAt, ExpiresAt: b.ExpiresAt, ReleasedAt: b.ReleasedAt,
		ReleasedBy: b.ReleasedBy, Active: b.Active(s.Now()),
	}
}

// Overview is everything the firewall page shows.
type Overview struct {
	Config    fwcfg.Config `json:"config"`
	Bans      []Ban        `json:"bans"`    // in force
	History   []Ban        `json:"history"` // the latest 100, in force or not
	YourIP    string       `json:"your_ip"`
	PanelPort int          `json:"panel_port"`
}

// Get returns the firewall.
func (s *Service) Get(ctx context.Context, c auth.Client, p *auth.Principal) (Overview, error) {
	if err := admin(p); err != nil {
		return Overview{}, err
	}
	cfg, err := fwcfg.Load(ctx, s.db, s.PanelPort)
	if err != nil {
		return Overview{}, err
	}
	o := Overview{Config: cfg, Bans: []Ban{}, History: []Ban{}, YourIP: c.IP, PanelPort: s.PanelPort}
	active, err := store.ActiveBans(ctx, s.db.R, s.Now())
	if err != nil {
		return o, err
	}
	for _, b := range active {
		o.Bans = append(o.Bans, s.banView(b))
	}
	recent, err := store.RecentBans(ctx, s.db.R, 100)
	if err != nil {
		return o, err
	}
	for _, b := range recent {
		o.History = append(o.History, s.banView(b))
	}
	return o, nil
}

// SaveResult is what saving the firewall did.
type SaveResult struct {
	Config      fwcfg.Config `json:"config"`
	JobID       string       `json:"job_id"`
	AddedYourIP bool         `json:"added_your_ip"` // the admin's address went on the allow list so they cannot lock themselves out
}

// lockedOut reports whether the configuration would keep an address from
// reaching the panel.
func lockedOut(cfg fwcfg.Config, ip netip.Addr, panelPort int) bool {
	if fwcfg.Contains(fwcfg.Cidrs(cfg.Allow), ip) {
		return false
	}
	switch {
	case fwcfg.Contains(fwcfg.Cidrs(cfg.Deny), ip):
		return true
	case cfg.Policy == "closed" && !cfg.PortOpen(panelPort, "tcp"):
		return true
	}
	r := cfg.Restrict["panel"]
	return len(r) > 0 && !fwcfg.Contains(r, ip)
}

// Save stores the configuration and queues the rules. When it would lock
// the admin out, their address goes on the allow list.
func (s *Service) Save(ctx context.Context, c auth.Client, p *auth.Principal, in fwcfg.Config) (SaveResult, error) {
	if err := admin(p); err != nil {
		return SaveResult{}, err
	}
	if err := in.Normalize(s.PanelPort); err != nil {
		return SaveResult{}, err
	}
	res := SaveResult{}
	if ip, err := netip.ParseAddr(c.IP); err == nil && in.Enabled && !ip.IsLoopback() {
		ip = ip.Unmap()
		if lockedOut(in, ip, s.PanelPort) {
			in.Allow = append(in.Allow, fwcfg.Entry{CIDR: netip.PrefixFrom(ip, ip.BitLen()).String(), Comment: "your address when you saved the firewall"})
			res.AddedYourIP = true
		}
	}
	if err := s.db.SetSetting(ctx, fwcfg.Key, in); err != nil {
		return SaveResult{}, err
	}
	var err error
	if res.JobID, err = fwcfg.EnqueueApply(ctx, s.jobs, p.Login.ID); err != nil {
		return SaveResult{}, err
	}
	res.Config = in
	return res, s.audit.Record(ctx, event(c, p, "firewall.config", "", map[string]any{
		"enabled": in.Enabled, "policy": in.Policy, "ports": len(in.Ports), "allow": len(in.Allow), "deny": len(in.Deny),
		"restricted": len(in.Restrict), "rate_limit": in.Rate.Enabled, "brute": in.Brute.Enabled, "added_your_ip": res.AddedYourIP,
	}))
}

// BanInput bans one address by hand.
type BanInput struct {
	IP      string `json:"ip"`
	Minutes int    `json:"minutes"` // 0: for good
	Reason  string `json:"reason"`
}

// BanIP bans an address (admins).
func (s *Service) BanIP(ctx context.Context, c auth.Client, p *auth.Principal, in BanInput) (Ban, error) {
	if err := admin(p); err != nil {
		return Ban{}, err
	}
	pre, err := fwcfg.ParseCIDR(in.IP)
	if err != nil || !pre.IsSingleIP() {
		return Ban{}, &validate.Error{Field: "ip", Code: validate.CodeFormat, Message: "a single IP address (networks go on the deny list)"}
	}
	ip := pre.Addr()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.String() == c.IP {
		return Ban{}, &validate.Error{Field: "ip", Code: validate.CodeFormat, Message: "not this server and not your own address"}
	}
	if in.Minutes < 0 || in.Minutes > 525600 {
		return Ban{}, &validate.Error{Field: "minutes", Code: validate.CodeOutOfRange, Message: "0 (for good) to 525600"}
	}
	if len(in.Reason) > 200 {
		return Ban{}, &validate.Error{Field: "reason", Code: validate.CodeTooLong, Message: "at most 200 characters"}
	}
	now := s.Now().UTC()
	b := &store.FWBan{ID: ids.New(), IP: ip.String(), Reason: in.Reason, Source: store.BanManual, CreatedAt: now}
	if b.Reason == "" {
		b.Reason = "banned by " + p.Login.Username
	}
	if in.Minutes > 0 {
		t := now.Add(time.Duration(in.Minutes) * time.Minute)
		b.ExpiresAt = &t
	}
	if err := store.InsertBan(ctx, s.db.W, b); err != nil {
		return Ban{}, err
	}
	if _, err := fwcfg.EnqueueApply(ctx, s.jobs, p.Login.ID); err != nil {
		return Ban{}, err
	}
	return s.banView(*b), s.audit.Record(ctx, event(c, p, "firewall.ban", b.ID, map[string]any{"ip": b.IP, "minutes": in.Minutes}))
}

// Unban lifts a ban (admins).
func (s *Service) Unban(ctx context.Context, c auth.Client, p *auth.Principal, id string) error {
	if err := admin(p); err != nil {
		return err
	}
	b, err := s.db.BanByID(ctx, id)
	if err != nil {
		return err
	}
	if !b.Active(s.Now()) {
		return apperr.NewConflict("not_active", "this ban is over already")
	}
	if err := store.ReleaseBan(ctx, s.db.W, id, p.Login.Username, s.Now().UTC()); err != nil {
		return err
	}
	if _, err := fwcfg.EnqueueApply(ctx, s.jobs, p.Login.ID); err != nil {
		return err
	}
	return s.audit.Record(ctx, event(c, p, "firewall.unban", id, map[string]any{"ip": b.IP}))
}

// --- Jobs ---

// JobExpire marks the bans whose time has passed as over.
const JobExpire = "firewall.expire"

// RegisterJobs adds the firewall job handlers to a worker.
func (s *Service) RegisterJobs(w *jobs.Worker) {
	w.Register(fwcfg.JobApply, 1, s.applyJob)
	w.Register(JobExpire, 1, s.expireJob)
}

// Schedule adds the expiry of bans to a scheduler.
func (s *Service) Schedule(sched *jobs.Scheduler) error {
	return sched.Every("*/5 * * * *", JobExpire, struct{}{})
}

func ownAddresses() []netip.Addr {
	var out []netip.Addr
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

func ports(list []fwcfg.Port) []*agentv1.FirewallPort {
	out := make([]*agentv1.FirewallPort, len(list))
	for i, p := range list {
		out[i] = &agentv1.FirewallPort{Port: p.Port, Proto: p.Proto}
	}
	return out
}

// Request builds the agent request for the stored configuration and the
// bans in force. A ban of an allowed address, or of one of the server's
// own addresses, is left out: it could only lock someone out.
func (s *Service) Request(ctx context.Context) (*agentv1.FirewallApplyRequest, error) {
	cfg, err := fwcfg.Load(ctx, s.db, s.PanelPort)
	if err != nil {
		return nil, err
	}
	req := &agentv1.FirewallApplyRequest{
		Enabled: cfg.Enabled, Closed: cfg.Policy == "closed", OpenPorts: ports(cfg.Ports),
		Allow: fwcfg.Cidrs(cfg.Allow), Deny: fwcfg.Cidrs(cfg.Deny),
		RateLimit: cfg.Rate.Enabled, RatePerMinute: int32(cfg.Rate.PerMinute), //nolint:gosec // G115: 5..100000
	}
	for _, p := range cfg.Rate.Ports {
		req.RatePorts = append(req.RatePorts, &agentv1.FirewallPort{Port: p, Proto: "tcp"})
	}
	byService := map[string][]*agentv1.FirewallPort{
		"panel": {{Port: strconv.Itoa(s.PanelPort), Proto: "tcp"}},
		"ssh":   {{Port: strconv.Itoa(cfg.SSHPort), Proto: "tcp"}},
		"ftp":   {{Port: "21", Proto: "tcp"}, {Port: "30000-30999", Proto: "tcp"}},
	}
	for _, name := range fwcfg.Services {
		if list := cfg.Restrict[name]; len(list) > 0 {
			req.Restrictions = append(req.Restrictions, &agentv1.FirewallRestriction{Name: name, Ports: byService[name], Allowed: list})
		}
	}
	now := s.Now()
	active, err := store.ActiveBans(ctx, s.db.R, now)
	if err != nil {
		return nil, err
	}
	own := ownAddresses()
	allow := fwcfg.Cidrs(cfg.Allow)
	for _, b := range active {
		ip, err := netip.ParseAddr(b.IP)
		if err != nil || ip.IsLoopback() || fwcfg.Contains(allow, ip) || contains(own, ip.Unmap()) {
			continue
		}
		var secs int64
		if b.ExpiresAt != nil {
			if secs = int64(b.ExpiresAt.Sub(now).Seconds()); secs < 1 {
				continue
			}
		}
		req.Bans = append(req.Bans, &agentv1.FirewallBan{Ip: ip.Unmap().String(), Seconds: secs})
	}
	return req, nil
}

func contains(list []netip.Addr, ip netip.Addr) bool {
	for _, a := range list {
		if a == ip {
			return true
		}
	}
	return false
}

func permanentIfRefused(err error) error {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied:
		return jobs.Permanent(err)
	}
	return err
}

func (s *Service) applyJob(ctx context.Context, _ *jobs.Job, r jobs.Reporter) (any, error) {
	req, err := s.Request(ctx)
	if err != nil {
		return nil, err
	}
	_, err = s.agent.FirewallApply(ctx, req)
	switch {
	case status.Code(err) == codes.NotFound:
		return map[string]string{"skipped": "nftables is not installed"}, nil
	case err != nil:
		return nil, permanentIfRefused(err)
	}
	state := "off"
	if req.GetEnabled() {
		state = fmt.Sprintf("on: %d ban(s), %d allowed, %d denied", len(req.GetBans()), len(req.GetAllow()), len(req.GetDeny()))
	}
	r.Logf("firewall %s", state)
	return map[string]string{"firewall": state}, nil
}

func (s *Service) expireJob(ctx context.Context, _ *jobs.Job, r jobs.Reporter) (any, error) {
	n, err := store.ExpireBans(ctx, s.db.W, s.Now().UTC())
	if err != nil {
		return nil, err
	}
	if n > 0 {
		r.Logf("%d ban(s) over", n)
	}
	b, _ := json.Marshal(map[string]int64{"expired": n})
	return json.RawMessage(b), nil
}
