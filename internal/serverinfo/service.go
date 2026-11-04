// Package serverinfo is the admin's view of the server (ADR-0014): the
// dashboard (ADM-SVC-03, 05), server information (ADM-SVC-08), the service
// manager (ADM-SVC-01), the job monitor (ADM-SVC-07) and everyone's
// sessions and sign-ins (ADM-SEC-12). Everything here is for admins only.
package serverinfo

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Service serves the admin's server pages.
type Service struct {
	db    *store.DB
	audit *audit.Recorder
	jobs  *jobs.Queue
	agent agentrpc.Client
	Now   func() time.Time

	reauth  func(ctx context.Context, c auth.Client, p *auth.Principal, password string) error
	rebuild func(ctx context.Context, by string) (map[string]int, error)
}

// NewService returns a serverinfo service.
func NewService(db *store.DB, rec *audit.Recorder, q *jobs.Queue, ag agentrpc.Client) *Service {
	return &Service{db: db, audit: rec, jobs: q, agent: ag, Now: time.Now}
}

func admin(p *auth.Principal) error {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return apperr.ErrForbidden
	}
	return nil
}

func event(c auth.Client, p *auth.Principal, action, targetType, targetID string, details map[string]any) audit.Event {
	return audit.Event{
		IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Action: action, Result: audit.ResultOK,
		TargetType: targetType, TargetID: targetID, Details: details,
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
	}
}

// --- Status ---

// Disk is a mounted file system.
type Disk struct {
	Mount     string `json:"mount"`
	Device    string `json:"device"`
	FS        string `json:"fs"`
	Total     uint64 `json:"total"`
	Used      uint64 `json:"used"`
	Files     uint64 `json:"files"`
	FilesUsed uint64 `json:"files_used"`
}

// Net is a network interface's counters since boot.
type Net struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// Proc is a running process.
type Proc struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	User       string  `json:"user"`
	CPUPercent float64 `json:"cpu_percent"`
	RSS        uint64  `json:"rss"`
}

// AccountDisk is how much disk an account's home uses.
type AccountDisk struct {
	Username string `json:"username"`
	Bytes    int64  `json:"bytes"`
	Partial  bool   `json:"partial"`
}

// Version is an installed service's version.
type Version struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

// Status is the dashboard and the server information.
type Status struct {
	Hostname          string         `json:"hostname"`
	OS                string         `json:"os"`
	Kernel            string         `json:"kernel"`
	Arch              string         `json:"arch"`
	CPUModel          string         `json:"cpu_model"`
	Cores             int32          `json:"cores"`
	UptimeSeconds     int64          `json:"uptime_seconds"`
	Load              [3]float64     `json:"load"`
	CPUPercent        float64        `json:"cpu_percent"`
	MemTotal          uint64         `json:"mem_total"`
	MemAvailable      uint64         `json:"mem_available"`
	SwapTotal         uint64         `json:"swap_total"`
	SwapFree          uint64         `json:"swap_free"`
	Disks             []Disk         `json:"disks"`
	Net               []Net          `json:"net"`
	Procs             []Proc         `json:"procs"`
	Accounts          []AccountDisk  `json:"accounts"` // biggest first
	AccountsAt        *time.Time     `json:"accounts_at"`
	AccountsComputing bool           `json:"accounts_computing"`
	Versions          []Version      `json:"versions"`
	XCPVersion        string         `json:"xcp_version"`
	Jobs              map[string]int `json:"jobs"` // by status: the last 24 hours, and all queued or running
}

// Status reports the host and the job counts.
func (s *Service) Status(ctx context.Context, p *auth.Principal) (Status, error) {
	if err := admin(p); err != nil {
		return Status{}, err
	}
	r, err := s.agent.ServerStatus(ctx, &agentv1.ServerStatusRequest{})
	if err != nil {
		return Status{}, err
	}
	st := Status{
		Hostname: r.GetHostname(), OS: r.GetOs(), Kernel: r.GetKernel(), Arch: r.GetArch(), CPUModel: r.GetCpuModel(), Cores: r.GetCores(),
		UptimeSeconds: r.GetUptimeSeconds(), Load: [3]float64{r.GetLoad1(), r.GetLoad5(), r.GetLoad15()}, CPUPercent: r.GetCpuPercent(),
		MemTotal: r.GetMemTotal(), MemAvailable: r.GetMemAvailable(), SwapTotal: r.GetSwapTotal(), SwapFree: r.GetSwapFree(),
		Disks: []Disk{}, Net: []Net{}, Procs: []Proc{}, Accounts: []AccountDisk{}, Versions: []Version{},
		AccountsComputing: r.GetAccountsComputing(), XCPVersion: r.GetXcpVersion(), Jobs: map[string]int{},
	}
	if at := r.GetAccountsAtUnix(); at > 0 {
		t := time.Unix(at, 0).UTC()
		st.AccountsAt = &t
	}
	for _, d := range r.GetDisks() {
		st.Disks = append(st.Disks, Disk{Mount: d.GetMount(), Device: d.GetDevice(), FS: d.GetFs(), Total: d.GetTotal(), Used: d.GetUsed(), Files: d.GetFiles(), FilesUsed: d.GetFilesUsed()})
	}
	for _, n := range r.GetNet() {
		st.Net = append(st.Net, Net{Name: n.GetName(), RxBytes: n.GetRxBytes(), TxBytes: n.GetTxBytes()})
	}
	for _, x := range r.GetProcs() {
		st.Procs = append(st.Procs, Proc{PID: x.GetPid(), Name: x.GetName(), User: x.GetUser(), CPUPercent: x.GetCpuPercent(), RSS: x.GetRss()})
	}
	for _, a := range r.GetAccounts() {
		st.Accounts = append(st.Accounts, AccountDisk{Username: a.GetUsername(), Bytes: a.GetBytes(), Partial: a.GetPartial()})
	}
	for k, v := range r.GetVersions() {
		st.Versions = append(st.Versions, Version{Package: k, Version: v})
	}
	slices.SortFunc(st.Versions, func(a, b Version) int { return compare(a.Package, b.Package) })
	counts, err := s.jobs.Counts(ctx, s.Now().Add(-24*time.Hour))
	if err != nil {
		return st, err
	}
	for k, v := range counts {
		st.Jobs[string(k)] = v
	}
	return st, nil
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// --- Services ---

// ServiceIDs are the services the manager shows, in order.
var ServiceIDs = []string{"panel-api", "agent", "logd", "web", "mta", "imap", "spam", "dns", "db", "ftp", "ftpauth", "ssh", "cron"}

// protected services cannot be stopped, restarted or switched off here:
// doing so would cut the admin off.
var protected = map[string]bool{"panel-api": true, "ssh": true}

// ServiceView is a service's state.
type ServiceView struct {
	ID         string `json:"id"`
	Unit       string `json:"unit"`
	Installed  bool   `json:"installed"`
	State      string `json:"state"` // systemd's active state
	SubState   string `json:"sub_state"`
	Enabled    bool   `json:"enabled"`
	MainPID    int32  `json:"main_pid"`
	Protected  bool   `json:"protected"`
	CanRestart bool   `json:"can_restart"`
}

func (s *Service) service(ctx context.Context, id string) (ServiceView, error) {
	v := ServiceView{ID: id, Protected: protected[id], CanRestart: !protected[id]}
	r, err := s.agent.ServiceStatus(ctx, &agentv1.ServiceStatusRequest{Service: id})
	if status.Code(err) == codes.NotFound {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	v.Installed, v.Unit, v.State, v.SubState, v.Enabled, v.MainPID = true, r.GetUnit(), r.GetActiveState(), r.GetSubState(), r.GetEnabled(), r.GetMainPid()
	return v, nil
}

// Services lists the services with their state.
func (s *Service) Services(ctx context.Context, p *auth.Principal) ([]ServiceView, error) {
	if err := admin(p); err != nil {
		return nil, err
	}
	out := make([]ServiceView, 0, len(ServiceIDs))
	for _, id := range ServiceIDs {
		v, err := s.service(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

var serviceActions = map[string]agentv1.ServiceActionKind{
	"start": agentv1.ServiceActionKind_SERVICE_ACTION_KIND_START, "stop": agentv1.ServiceActionKind_SERVICE_ACTION_KIND_STOP,
	"restart": agentv1.ServiceActionKind_SERVICE_ACTION_KIND_RESTART, "reload": agentv1.ServiceActionKind_SERVICE_ACTION_KIND_RELOAD,
	"enable": agentv1.ServiceActionKind_SERVICE_ACTION_KIND_ENABLE, "disable": agentv1.ServiceActionKind_SERVICE_ACTION_KIND_DISABLE,
}

// ServiceAction starts, stops, restarts, reloads, enables or disables a service.
func (s *Service) ServiceAction(ctx context.Context, c auth.Client, p *auth.Principal, id, action string) (ServiceView, error) {
	if err := admin(p); err != nil {
		return ServiceView{}, err
	}
	kind, ok := serviceActions[action]
	if !ok {
		return ServiceView{}, &validate.Error{Field: "action", Code: validate.CodeFormat, Message: "start, stop, restart, reload, enable or disable"}
	}
	if !slices.Contains(ServiceIDs, id) {
		return ServiceView{}, store.ErrNotFound
	}
	if protected[id] && action != "start" && action != "enable" {
		return ServiceView{}, apperr.NewConflict("protected", "this service carries the panel or your own access: use the server's shell to "+action+" it")
	}
	if _, err := s.agent.ServiceAction(ctx, &agentv1.ServiceActionRequest{Service: id, Action: kind}); err != nil {
		if status.Code(err) == codes.NotFound {
			return ServiceView{}, apperr.NewConflict("not_installed", id+" is not installed")
		}
		return ServiceView{}, err
	}
	if err := s.audit.Record(ctx, event(c, p, "server.service."+action, "service", id, nil)); err != nil {
		return ServiceView{}, err
	}
	return s.service(ctx, id)
}

// ServiceLog returns the last lines of a service's journal.
func (s *Service) ServiceLog(ctx context.Context, p *auth.Principal, id string, lines int) (string, error) {
	if err := admin(p); err != nil {
		return "", err
	}
	if !slices.Contains(ServiceIDs, id) {
		return "", store.ErrNotFound
	}
	if lines < 1 || lines > 500 {
		return "", &validate.Error{Field: "lines", Code: validate.CodeOutOfRange, Message: "1 to 500"}
	}
	r, err := s.agent.ServiceLog(ctx, &agentv1.ServiceLogRequest{Service: id, Lines: int32(lines)}) //nolint:gosec // G115: 1..500
	if err != nil {
		return "", err
	}
	return r.GetText(), nil
}

// --- Jobs ---

// JobView is a job in the monitor.
type JobView struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	Progress    int        `json:"progress"`
	Attempts    int        `json:"attempts"`
	MaxAttempts int        `json:"max_attempts"`
	AccountID   string     `json:"account_id"`
	CreatedBy   string     `json:"created_by"`
	Error       string     `json:"error"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
}

func jobView(j jobs.Job) JobView {
	return JobView{
		ID: j.ID, Kind: j.Kind, Status: string(j.Status), Progress: j.Progress, Attempts: j.Attempts, MaxAttempts: j.MaxAttempts,
		AccountID: j.AccountID, CreatedBy: j.CreatedBy, Error: j.Error, CreatedAt: j.CreatedAt, StartedAt: j.StartedAt, FinishedAt: j.FinishedAt,
	}
}

// Jobs lists jobs, newest first.
func (s *Service) Jobs(ctx context.Context, p *auth.Principal, statusFilter, kind string, limit int) ([]JobView, error) {
	if err := admin(p); err != nil {
		return nil, err
	}
	switch jobs.Status(statusFilter) {
	case "", jobs.StatusQueued, jobs.StatusRunning, jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled:
	default:
		return nil, &validate.Error{Field: "status", Code: validate.CodeFormat, Message: "queued, running, succeeded, failed or canceled"}
	}
	list, err := s.jobs.List(ctx, jobs.ListFilter{Status: jobs.Status(statusFilter), Kind: kind, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]JobView, 0, len(list))
	for _, j := range list {
		out = append(out, jobView(j))
	}
	return out, nil
}

func (s *Service) jobChange(ctx context.Context, c auth.Client, p *auth.Principal, id, action string, do func(context.Context, string) error) (JobView, error) {
	if err := admin(p); err != nil {
		return JobView{}, err
	}
	j, err := s.jobs.Get(ctx, id)
	if err != nil {
		return JobView{}, err
	}
	if err := do(ctx, id); errors.Is(err, jobs.ErrBadState) {
		return JobView{}, apperr.NewConflict("bad_state", "a "+string(j.Status)+" job cannot be "+action+"ed")
	} else if err != nil {
		return JobView{}, err
	}
	if err := s.audit.Record(ctx, event(c, p, "server.job."+action, "job", id, map[string]any{"kind": j.Kind})); err != nil {
		return JobView{}, err
	}
	j, err = s.jobs.Get(ctx, id)
	return jobView(*j), err
}

// CancelJob stops a queued or running job.
func (s *Service) CancelJob(ctx context.Context, c auth.Client, p *auth.Principal, id string) (JobView, error) {
	return s.jobChange(ctx, c, p, id, "cancel", s.jobs.Cancel)
}

// RetryJob queues a failed or canceled job again.
func (s *Service) RetryJob(ctx context.Context, c auth.Client, p *auth.Principal, id string) (JobView, error) {
	return s.jobChange(ctx, c, p, id, "retry", s.jobs.Retry)
}

// --- Sessions and sign-ins ---

// SessionView is a session of any login.
type SessionView struct {
	ID           string    `json:"id"` // hex of the token hash; cannot be used to sign in
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	MFAPassed    bool      `json:"mfa_passed"`
	Impersonated bool      `json:"impersonated"`
	Current      bool      `json:"current"`
}

// Sessions lists every session.
func (s *Service) Sessions(ctx context.Context, p *auth.Principal) ([]SessionView, error) {
	if err := admin(p); err != nil {
		return nil, err
	}
	rows, err := s.db.AllSessions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SessionView, 0, len(rows))
	for _, r := range rows {
		out = append(out, SessionView{
			ID: hex.EncodeToString(r.IDHash), Username: r.Username, Role: r.Role, IP: r.IP, UserAgent: r.UserAgent,
			CreatedAt: r.CreatedAt, LastSeenAt: r.LastSeenAt, ExpiresAt: r.ExpiresAt, MFAPassed: r.MFAPassed,
			Impersonated: r.ImpersonatorID != "", Current: string(r.IDHash) == string(p.Session.IDHash),
		})
	}
	return out, nil
}

// RevokeSession ends any session.
func (s *Service) RevokeSession(ctx context.Context, c auth.Client, p *auth.Principal, id string) error {
	if err := admin(p); err != nil {
		return err
	}
	h, err := hex.DecodeString(id)
	if err != nil || len(h) != 32 {
		return store.ErrNotFound
	}
	sess, err := s.db.SessionByHash(ctx, h)
	if err != nil {
		return err
	}
	login, err := s.db.LoginByID(ctx, sess.LoginID)
	if err != nil {
		return err
	}
	if err := s.db.DeleteSession(ctx, h); err != nil {
		return err
	}
	return s.audit.Record(ctx, event(c, p, "server.session.revoke", "login", login.ID, map[string]any{"username": login.Username, "session": id[:12]}))
}

// LoginView is one sign-in attempt.
type LoginView struct {
	At        time.Time `json:"at"`
	Username  string    `json:"username"`
	Result    string    `json:"result"` // ok or denied
	Step      string    `json:"step"`   // password: the first step of a login with 2FA
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Reason    string    `json:"reason"`
}

// Logins lists the latest sign-in attempts of everyone, newest first.
func (s *Service) Logins(ctx context.Context, p *auth.Principal) ([]LoginView, error) {
	if err := admin(p); err != nil {
		return nil, err
	}
	evs, err := s.db.LoginEvents(ctx, 200)
	if err != nil {
		return nil, err
	}
	out := make([]LoginView, 0, len(evs))
	for _, e := range evs {
		v := LoginView{At: e.At, Username: e.Username, Result: e.Result, Step: "login", IP: e.IP, UserAgent: e.UserAgent}
		if e.Action == "auth.login.password" {
			v.Step = "password"
		}
		v.Reason, _ = e.Detail["reason"].(string)
		out = append(out, v)
	}
	return out, nil
}
