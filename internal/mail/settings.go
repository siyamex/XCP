package mail

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// settingsKey is where the mail settings are kept.
const settingsKey = "mail"

// Settings are the server's mail settings (ADM-MAIL-01).
type Settings struct {
	Hostname     string   `json:"hostname"`
	MaxMessageMB int64    `json:"max_message_mb"`
	RelayHost    string   `json:"relay_host"`
	RelayUser    string   `json:"relay_user"`
	HasRelayPass bool     `json:"has_relay_password"`
	RBLs         []string `json:"rbls"`
	HeloChecks   bool     `json:"helo_checks"`
	Greylisting  bool     `json:"greylisting"`
}

// SettingsInput changes them; an empty relay password keeps the stored one.
type SettingsInput struct {
	Hostname      string   `json:"hostname"`
	MaxMessageMB  int64    `json:"max_message_mb"`
	RelayHost     string   `json:"relay_host"`
	RelayUser     string   `json:"relay_user"`
	RelayPassword string   `json:"relay_password"`
	RBLs          []string `json:"rbls"`
	HeloChecks    bool     `json:"helo_checks"`
	Greylisting   bool     `json:"greylisting"`
}

// stored is the settings as kept in the database.
type stored struct {
	Hostname     string   `json:"hostname"`
	MaxMessageMB int64    `json:"max_message_mb"`
	RelayHost    string   `json:"relay_host"`
	RelayUser    string   `json:"relay_user"`
	RelayPassEnc []byte   `json:"relay_password_enc,omitempty"`
	RBLs         []string `json:"rbls"`
	HeloChecks   bool     `json:"helo_checks"`
	Greylisting  bool     `json:"greylisting"`
}

const relayAD = "mail-relay-password"

// DefaultMaxMessageMB is the largest message accepted until the admin changes it.
const DefaultMaxMessageMB = 50

func (s *Service) defaults(ctx context.Context) stored {
	host := ""
	if s.host != nil {
		host = s.host.Hostname(ctx)
	}
	if host == "" {
		host, _ = os.Hostname()
	}
	return stored{Hostname: strings.ToLower(host), MaxMessageMB: DefaultMaxMessageMB, RBLs: []string{}, HeloChecks: true}
}

func (s *Service) load(ctx context.Context) (stored, error) {
	var st stored
	err := s.db.GetSetting(ctx, settingsKey, &st)
	if errors.Is(err, store.ErrNotFound) {
		return s.defaults(ctx), nil
	}
	if st.RBLs == nil {
		st.RBLs = []string{}
	}
	return st, err
}

func view(st stored) Settings {
	return Settings{
		Hostname: st.Hostname, MaxMessageMB: st.MaxMessageMB, RelayHost: st.RelayHost, RelayUser: st.RelayUser,
		HasRelayPass: len(st.RelayPassEnc) > 0, RBLs: st.RBLs, HeloChecks: st.HeloChecks, Greylisting: st.Greylisting,
	}
}

// Settings returns the mail settings (admins; nil principal for internal use).
func (s *Service) Settings(ctx context.Context, p *auth.Principal) (Settings, error) {
	if p != nil && p.Login.Role != store.RoleAdmin {
		return Settings{}, apperr.ErrForbidden
	}
	st, err := s.load(ctx)
	return view(st), err
}

// SaveSettings stores the mail settings and queues the job that applies them.
func (s *Service) SaveSettings(ctx context.Context, c auth.Client, p *auth.Principal, in SettingsInput) (Settings, string, error) {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return Settings{}, "", apperr.ErrForbidden
	}
	old, err := s.load(ctx)
	if err != nil {
		return Settings{}, "", err
	}
	st := stored{
		Hostname: strings.ToLower(strings.TrimSpace(in.Hostname)), MaxMessageMB: in.MaxMessageMB,
		RelayHost: strings.ToLower(strings.TrimSpace(in.RelayHost)), RelayUser: strings.TrimSpace(in.RelayUser),
		RBLs: []string{}, HeloChecks: in.HeloChecks, Greylisting: in.Greylisting, RelayPassEnc: old.RelayPassEnc,
	}
	for _, r := range in.RBLs {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" {
			st.RBLs = append(st.RBLs, r)
		}
	}
	if in.RelayPassword != "" {
		st.RelayPassEnc = s.box.Seal([]byte(in.RelayPassword), []byte(relayAD))
	}
	if st.RelayUser == "" {
		st.RelayPassEnc = nil
	}
	req, err := s.agentSettings(st)
	if err != nil {
		return Settings{}, "", err
	}
	// The agent checks the same rules; checking here gives a clear answer now.
	if err := agent.CheckMailSettings(req); err != nil {
		msg := strings.TrimPrefix(err.Error(), agent.ErrInvalidRequest.Error()+": ")
		return Settings{}, "", &validate.Error{Field: "settings", Code: validate.CodeFormat, Message: msg}
	}
	if err := s.db.SetSetting(ctx, settingsKey, st); err != nil {
		return Settings{}, "", err
	}
	jobID, err := s.EnqueueSettings(ctx, p.Login.ID)
	if err != nil {
		return Settings{}, "", err
	}
	_ = s.audit.Record(ctx, event(c, p, "mail.settings", "", "server", "mail", map[string]any{
		"hostname": st.Hostname, "max_message_mb": st.MaxMessageMB, "relay_host": st.RelayHost, "rbls": st.RBLs,
		"helo_checks": st.HeloChecks, "greylisting": st.Greylisting,
	}))
	return view(st), jobID, nil
}

func (s *Service) agentSettings(st stored) (agent.MailSettings, error) {
	m := agent.MailSettings{
		Hostname: st.Hostname, MaxMessageMB: st.MaxMessageMB, RelayHost: st.RelayHost, RelayUser: st.RelayUser,
		RBLs: st.RBLs, HeloChecks: st.HeloChecks, Greylisting: st.Greylisting,
	}
	if len(st.RelayPassEnc) > 0 {
		pw, err := s.box.Open(st.RelayPassEnc, []byte(relayAD))
		if err != nil {
			return m, err
		}
		m.RelayPassword = string(pw)
	}
	return m, nil
}
