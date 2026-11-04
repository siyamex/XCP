// Package serversettings is the admin's server configuration (ADR-0016):
// global settings with search (ADM-SRV-05), update settings (ADM-SRV-06),
// the first-run setup (ADM-SRV-01) and changing the host name (ADM-SRV-02).
package serversettings

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/mail"
	"github.com/siyamex/XCP/internal/ssl"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
	"github.com/siyamex/XCP/internal/zones"
)

// Service serves the admin's server configuration.
type Service struct {
	db    *store.DB
	audit *audit.Recorder
	agent agentrpc.Client
	zones *zones.Service
	ssl   *ssl.Service
	mail  *mail.Service

	Version string
	Now     func() time.Time

	applyAll  func(ctx context.Context, by string) (int, error)
	setLimits func(idle, max time.Duration)

	mu      sync.Mutex
	updInfo UpdateInfo
	updAt   time.Time
}

// NewService returns a server settings service.
func NewService(db *store.DB, rec *audit.Recorder, ag agentrpc.Client, zs *zones.Service, sslSvc *ssl.Service, mailSvc *mail.Service, version string) *Service {
	return &Service{db: db, audit: rec, agent: ag, zones: zs, ssl: sslSvc, mail: mailSvc, Version: version, Now: time.Now}
}

// SetHooks connects what a changed setting must reach: applying every
// account again (PHP settings) and the panel's session limits.
func (s *Service) SetHooks(applyAll func(ctx context.Context, by string) (int, error), setLimits func(idle, max time.Duration)) {
	s.applyAll, s.setLimits = applyAll, setLimits
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
		TargetType: "server", TargetID: targetID, Details: details,
		ActorID: p.Login.ID, ImpersonatorID: p.Session.ImpersonatorID, Role: p.Login.Role,
	}
}

func badField(field, msg string) error {
	return &validate.Error{Field: field, Code: validate.CodeFormat, Message: msg}
}

// --- Settings ---

type def struct {
	Key, Group, Type string // Type: int, bool, string or enum
	Default          any
	Min, Max         int
	Options          []string
}

var phpVersionRe = regexp.MustCompile(`^[5-9]\.[0-9]$`)

var defs = []def{
	{Key: "php.default_version", Group: "php", Type: "string", Default: ""},
	{Key: "php.upload_max_mb", Group: "php", Type: "int", Default: 64, Min: 1, Max: 2048},
	{Key: "auth.session_idle_minutes", Group: "panel", Type: "int", Default: 30, Min: 5, Max: 1440},
	{Key: "auth.session_max_hours", Group: "panel", Type: "int", Default: 12, Min: 1, Max: 720},
	{Key: "updates.channel", Group: "updates", Type: "enum", Default: "stable", Options: []string{"stable", "beta"}},
	{Key: "updates.window_hour", Group: "updates", Type: "int", Default: 3, Min: 0, Max: 23},
	{Key: "updates.os_auto", Group: "updates", Type: "bool", Default: true},
}

const keyPrefix = "settings."

// Item is one setting with its value.
type Item struct {
	Key     string   `json:"key"`
	Group   string   `json:"group"`
	Type    string   `json:"type"`
	Value   any      `json:"value"`
	Default any      `json:"default"`
	Min     int      `json:"min"`
	Max     int      `json:"max"`
	Options []string `json:"options"`
}

func find(key string) (def, bool) {
	for _, d := range defs {
		if d.Key == key {
			return d, true
		}
	}
	return def{}, false
}

func (s *Service) value(ctx context.Context, d def) any {
	k := keyPrefix + d.Key
	switch d.Type {
	case "int":
		var v int
		if s.db.GetSetting(ctx, k, &v) == nil {
			return v
		}
	case "bool":
		var v bool
		if s.db.GetSetting(ctx, k, &v) == nil {
			return v
		}
	default:
		var v string
		if s.db.GetSetting(ctx, k, &v) == nil {
			return v
		}
	}
	return d.Default
}

// Int returns an integer setting (its default until saved).
func (s *Service) Int(ctx context.Context, key string) int {
	d, ok := find(key)
	if !ok {
		return 0
	}
	v, _ := s.value(ctx, d).(int)
	return v
}

// PHPDefaults returns the default PHP version ("" = newest installed) and
// the upload limit in MB that accounts' PHP gets.
func (s *Service) PHPDefaults(ctx context.Context) (version string, uploadMB int) {
	d, _ := find("php.default_version")
	version, _ = s.value(ctx, d).(string)
	return version, s.Int(ctx, "php.upload_max_mb")
}

// Items returns every setting.
func (s *Service) Items(ctx context.Context, p *auth.Principal) ([]Item, error) {
	if err := admin(p); err != nil {
		return nil, err
	}
	out := make([]Item, 0, len(defs))
	for _, d := range defs {
		opts := d.Options
		if opts == nil {
			opts = []string{}
		}
		out = append(out, Item{Key: d.Key, Group: d.Group, Type: d.Type, Value: s.value(ctx, d), Default: d.Default, Min: d.Min, Max: d.Max, Options: opts})
	}
	return out, nil
}

func (s *Service) check(d def, v any) (any, error) {
	field := "values." + d.Key
	switch d.Type {
	case "int":
		f, ok := v.(float64)
		if !ok || f != float64(int(f)) || int(f) < d.Min || int(f) > d.Max {
			return nil, badField(field, fmt.Sprintf("a whole number from %d to %d", d.Min, d.Max))
		}
		return int(f), nil
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return nil, badField(field, "true or false")
		}
		return b, nil
	}
	str, ok := v.(string)
	if !ok {
		return nil, badField(field, "text")
	}
	switch {
	case d.Type == "enum":
		for _, o := range d.Options {
			if o == str {
				return str, nil
			}
		}
		return nil, badField(field, "one of: "+strings.Join(d.Options, ", "))
	case d.Key == "php.default_version" && str != "" && !phpVersionRe.MatchString(str):
		return nil, badField(field, "a PHP version like 8.3, or empty for the newest installed")
	}
	return str, nil
}

// Update saves the given settings (admins); settings not named stay as they are.
func (s *Service) Update(ctx context.Context, c auth.Client, p *auth.Principal, in map[string]any) ([]Item, error) {
	if err := admin(p); err != nil {
		return nil, err
	}
	clean := map[string]any{}
	for k, v := range in {
		d, ok := find(k)
		if !ok {
			return nil, badField("values."+k, "not a setting of this server")
		}
		cv, err := s.check(d, v)
		if err != nil {
			return nil, err
		}
		clean[k] = cv
	}
	changed := map[string]any{}
	for k, v := range clean {
		d, _ := find(k)
		if s.value(ctx, d) != v {
			changed[k] = v
		}
		if err := s.db.SetSetting(ctx, keyPrefix+k, v); err != nil {
			return nil, err
		}
	}
	if len(changed) == 0 {
		return s.Items(ctx, p)
	}
	if err := s.audit.Record(ctx, event(c, p, "server.settings", "", changed)); err != nil {
		return nil, err
	}
	php, authChanged := false, false
	for k := range changed {
		php = php || strings.HasPrefix(k, "php.")
		authChanged = authChanged || strings.HasPrefix(k, "auth.")
	}
	if php && s.applyAll != nil {
		if _, err := s.applyAll(ctx, p.Login.ID); err != nil {
			return nil, err
		}
	}
	if authChanged {
		s.applySessionLimits(ctx)
	}
	if v, ok := changed["updates.os_auto"].(bool); ok {
		if _, err := s.agent.OSUpdatesSet(ctx, &agentv1.OSUpdatesSetRequest{Enabled: v}); err != nil {
			return nil, fmt.Errorf("automatic OS updates: %w", err)
		}
	}
	return s.Items(ctx, p)
}

func (s *Service) applySessionLimits(ctx context.Context) {
	if s.setLimits != nil {
		s.setLimits(time.Duration(s.Int(ctx, "auth.session_idle_minutes"))*time.Minute, time.Duration(s.Int(ctx, "auth.session_max_hours"))*time.Hour)
	}
}

// Start gives the panel its saved session limits.
func (s *Service) Start(ctx context.Context) { s.applySessionLimits(ctx) }

// --- Setup and host name ---

// Setup is the first-run setup, which the admin can change any time.
type Setup struct {
	Completed   bool     `json:"completed"`
	Hostname    string   `json:"hostname"`
	AdminEmail  string   `json:"admin_email"`
	Timezone    string   `json:"timezone"`
	Nameservers []string `json:"nameservers"`
	IPv4        string   `json:"ipv4"`
	IPv6        string   `json:"ipv6"`
}

const (
	setupDoneKey  = "server.setup_done"
	adminEmailKey = "server.admin_email"
)

// GetSetup returns the server's setup.
func (s *Service) GetSetup(ctx context.Context, p *auth.Principal) (Setup, error) {
	if err := admin(p); err != nil {
		return Setup{}, err
	}
	var out Setup
	_ = s.db.GetSetting(ctx, setupDoneKey, &out.Completed)
	_ = s.db.GetSetting(ctx, adminEmailKey, &out.AdminEmail)
	out.Hostname = s.ssl.Hostname(ctx)
	zs, err := s.zones.Settings(ctx)
	if err != nil {
		return out, err
	}
	out.Nameservers, out.IPv4, out.IPv6 = zs.Nameservers, zs.IPv4, zs.IPv6
	if out.Nameservers == nil {
		out.Nameservers = []string{}
	}
	if st, err := s.agent.ServerStatus(ctx, &agentv1.ServerStatusRequest{}); err == nil {
		out.Timezone = st.GetTimezone()
		if out.Hostname == "" {
			out.Hostname = st.GetHostname()
		}
	}
	return out, nil
}

// SetupInput changes the setup; empty fields stay as they are.
type SetupInput struct {
	Hostname    string   `json:"hostname"`
	AdminEmail  string   `json:"admin_email"`
	Timezone    string   `json:"timezone"`
	Nameservers []string `json:"nameservers"`
	IPv4        string   `json:"ipv4"`
	IPv6        string   `json:"ipv6"`
}

// SaveSetup applies the setup: host name, time zone, the admin's contact
// address and the DNS settings, and marks the setup done.
func (s *Service) SaveSetup(ctx context.Context, c auth.Client, p *auth.Principal, in SetupInput) (Setup, error) {
	if err := admin(p); err != nil {
		return Setup{}, err
	}
	var email string
	if e := strings.TrimSpace(in.AdminEmail); e != "" {
		var err error
		if email, err = validate.Email(e); err != nil {
			return Setup{}, validate.WithField(err, "admin_email")
		}
	}
	for _, ip := range []struct{ field, v string }{{"ipv4", in.IPv4}, {"ipv6", in.IPv6}} {
		if ip.v != "" && net.ParseIP(ip.v) == nil {
			return Setup{}, badField(ip.field, "not an IP address")
		}
	}
	if in.Hostname != "" {
		if _, err := s.ChangeHostname(ctx, c, p, in.Hostname); err != nil {
			return Setup{}, err
		}
	}
	if in.Timezone != "" {
		if _, err := s.agent.TimezoneSet(ctx, &agentv1.TimezoneSetRequest{Timezone: in.Timezone}); err != nil {
			return Setup{}, badField("timezone", "not a known time zone name (like Europe/Berlin)")
		}
	}
	if len(in.Nameservers) > 0 || in.IPv4 != "" || in.IPv6 != "" {
		zs, err := s.zones.Settings(ctx)
		if err != nil {
			return Setup{}, err
		}
		if len(in.Nameservers) > 0 {
			zs.Nameservers = in.Nameservers
		}
		if in.IPv4 != "" {
			zs.IPv4 = in.IPv4
		}
		if in.IPv6 != "" {
			zs.IPv6 = in.IPv6
		}
		if _, _, err := s.zones.SaveSettings(ctx, c, p, zs); err != nil {
			return Setup{}, err
		}
	}
	if email != "" {
		if err := s.db.SetSetting(ctx, adminEmailKey, email); err != nil {
			return Setup{}, err
		}
	}
	if err := s.db.SetSetting(ctx, setupDoneKey, true); err != nil {
		return Setup{}, err
	}
	if err := s.audit.Record(ctx, event(c, p, "server.setup", "", map[string]any{"hostname": in.Hostname, "timezone": in.Timezone, "admin_email": email})); err != nil {
		return Setup{}, err
	}
	return s.GetSetup(ctx, p)
}

// HostnameResult is what changing the host name did.
type HostnameResult struct {
	Hostname string `json:"hostname"`
	Changed  bool   `json:"changed"`
	JobID    string `json:"job_id,omitempty"` // applies the mail server's new name
}

// ChangeHostname sets the server's name: the system, /etc/hosts, the name
// AutoSSL gets a certificate for, and the mail server's name.
func (s *Service) ChangeHostname(ctx context.Context, c auth.Client, p *auth.Principal, hostname string) (HostnameResult, error) {
	if err := admin(p); err != nil {
		return HostnameResult{}, err
	}
	name, err := validate.Domain(strings.TrimSpace(hostname))
	if err != nil {
		return HostnameResult{}, validate.WithField(err, "hostname")
	}
	if name == s.ssl.Hostname(ctx) {
		return HostnameResult{Hostname: name}, nil
	}
	domains, err := store.DomainAccounts(ctx, s.db.R)
	if err != nil {
		return HostnameResult{}, err
	}
	if _, taken := domains[name]; taken {
		return HostnameResult{}, apperr.NewConflict("domain_taken", name+" is an account's domain: the server's own name cannot be one")
	}
	if _, err := s.agent.HostnameSet(ctx, &agentv1.HostnameSetRequest{Hostname: name}); err != nil {
		return HostnameResult{}, err
	}
	if err := s.ssl.SetHostname(ctx, name); err != nil {
		return HostnameResult{}, err
	}
	jobID, err := s.mail.SetHostname(ctx, name, p.Login.ID)
	if err != nil {
		return HostnameResult{}, err
	}
	if err := s.audit.Record(ctx, event(c, p, "server.hostname", name, nil)); err != nil {
		return HostnameResult{}, err
	}
	return HostnameResult{Hostname: name, Changed: true, JobID: jobID}, nil
}

// --- Updates ---

// Repo is where releases are published.
const Repo = "siyamex/XCP"

// UpdateInfo says whether a newer XCP release exists.
type UpdateInfo struct {
	Current     string    `json:"current"`
	Latest      string    `json:"latest"`
	Channel     string    `json:"channel"`
	URL         string    `json:"url"`
	Available   bool      `json:"available"`
	Development bool      `json:"development"` // a build from source: nothing to compare
	CheckedAt   time.Time `json:"checked_at"`
	Error       string    `json:"error,omitempty"`
}

// newer reports whether version a is newer than b ("v1.2.3" or "1.2.3").
func newer(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := range max(len(pa), len(pb)) {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func versionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v, _, _ = strings.Cut(v, "-")
	var out []int
	for _, f := range strings.Split(v, ".") {
		n := 0
		for _, r := range f {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}

type release struct {
	Tag string `json:"tag_name"`
	URL string `json:"html_url"`
}

// CheckUpdates asks GitHub for the latest release of the admin's channel
// (cached for an hour). Installing is not done by the panel yet.
func (s *Service) CheckUpdates(ctx context.Context, p *auth.Principal) (UpdateInfo, error) {
	if err := admin(p); err != nil {
		return UpdateInfo{}, err
	}
	d, _ := find("updates.channel")
	channel, _ := s.value(ctx, d).(string)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updInfo.Channel == channel && s.Now().Sub(s.updAt) < time.Hour && s.updInfo.Error == "" {
		return s.updInfo, nil
	}
	info := UpdateInfo{Current: s.Version, Channel: channel, CheckedAt: s.Now().UTC(), Development: s.Version == "dev" || s.Version == ""}
	rel, err := fetchRelease(ctx, channel)
	switch {
	case err != nil:
		info.Error = err.Error()
	case rel == nil:
		info.Error = "no release has been published yet"
	default:
		info.Latest, info.URL = rel.Tag, rel.URL
		info.Available = !info.Development && newer(rel.Tag, s.Version)
	}
	s.updInfo, s.updAt = info, s.Now()
	return info, nil
}

// MarshalJSON keeps UpdateInfo's zero time out of the answer.
func (u UpdateInfo) MarshalJSON() ([]byte, error) {
	type plain UpdateInfo
	return json.Marshal(plain(u))
}
