package ssl

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"strings"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

const settingsKey = "ssl"

// ACME providers.
const (
	ProviderLetsEncrypt        = "letsencrypt"
	ProviderLetsEncryptStaging = "letsencrypt-staging"
	ProviderCustom             = "custom" // any ACME directory (ZeroSSL, Buypass, an internal CA)
)

var directories = map[string]string{
	ProviderLetsEncrypt:        "https://acme-v02.api.letsencrypt.org/directory",
	ProviderLetsEncryptStaging: "https://acme-staging-v02.api.letsencrypt.org/directory",
}

// Settings are the AutoSSL settings (ADM-SSL-01).
type Settings struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	// DirectoryURL, CABundle and EABKeyID are for the custom provider: the
	// ACME directory, the CA that signed its HTTPS certificate if it is not
	// a public one, and an External Account Binding key ID (ZeroSSL).
	DirectoryURL string `json:"directory_url"`
	CABundle     string `json:"ca_bundle"`
	EABKeyID     string `json:"eab_key_id"`
	Email        string `json:"email"`    // the ACME account's contact; expiry mail from the CA
	Hostname     string `json:"hostname"` // the server's own name: its certificate is used by the panel
	// EABKeyEnc is the EAB HMAC key, encrypted; the API never returns it.
	EABKeyEnc []byte `json:"eab_key_enc,omitempty"`
}

// SettingsInput changes the settings. An empty EABKey keeps the stored key.
type SettingsInput struct {
	Enabled      bool   `json:"enabled"`
	Provider     string `json:"provider"`
	DirectoryURL string `json:"directory_url"`
	CABundle     string `json:"ca_bundle"`
	EABKeyID     string `json:"eab_key_id"`
	EABKey       string `json:"eab_key"` // base64url HMAC key, as the CA shows it
	ClearEABKey  bool   `json:"clear_eab_key"`
	Email        string `json:"email"`
	Hostname     string `json:"hostname"`
}

// SettingsView is the settings as the API shows them.
type SettingsView struct {
	Enabled      bool   `json:"enabled"`
	Provider     string `json:"provider"`
	DirectoryURL string `json:"directory_url"`
	CABundle     string `json:"ca_bundle"`
	EABKeyID     string `json:"eab_key_id"`
	HasEABKey    bool   `json:"has_eab_key"`
	Email        string `json:"email"`
	Hostname     string `json:"hostname"`
}

func (s Settings) view() SettingsView {
	return SettingsView{
		Enabled: s.Enabled, Provider: s.Provider, DirectoryURL: s.DirectoryURL, CABundle: s.CABundle,
		EABKeyID: s.EABKeyID, HasEABKey: len(s.EABKeyEnc) > 0, Email: s.Email, Hostname: s.Hostname,
	}
}

// directory is the ACME directory URL of the settings.
func (s Settings) directory() string {
	if s.Provider == ProviderCustom {
		return s.DirectoryURL
	}
	return directories[s.Provider]
}

// hostnameFromCert reads the server's name from the panel certificate that
// xcp-install made for --hostname (its first name that is not localhost).
func hostnameFromCert(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // the configured panel certificate
	if err != nil {
		return ""
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return ""
	}
	for _, n := range c.DNSNames {
		if d, err := validate.Domain(n); err == nil && n != "localhost" {
			return d
		}
	}
	return ""
}

// Settings returns the AutoSSL settings; until saved, AutoSSL is on with
// Let's Encrypt and the host name from the panel certificate.
func (s *Service) Settings(ctx context.Context) (Settings, error) {
	var set Settings
	err := s.db.GetSetting(ctx, settingsKey, &set)
	if errors.Is(err, store.ErrNotFound) {
		return Settings{Enabled: true, Provider: ProviderLetsEncrypt, Hostname: hostnameFromCert(s.panelCert)}, nil
	}
	return set, err
}

// Hostname is the server's own name, which no account may add as a domain.
func (s *Service) Hostname(ctx context.Context) string {
	set, err := s.Settings(ctx)
	if err != nil {
		return ""
	}
	return set.Hostname
}

func admin(p *auth.Principal) error {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return apperr.ErrForbidden
	}
	return nil
}

// GetSettings returns the settings (admins).
func (s *Service) GetSettings(ctx context.Context, p *auth.Principal) (SettingsView, error) {
	if err := admin(p); err != nil {
		return SettingsView{}, err
	}
	set, err := s.Settings(ctx)
	return set.view(), err
}

// SaveSettings checks and stores the settings (admins).
func (s *Service) SaveSettings(ctx context.Context, c auth.Client, p *auth.Principal, in SettingsInput) (SettingsView, error) {
	if err := admin(p); err != nil {
		return SettingsView{}, err
	}
	old, err := s.Settings(ctx)
	if err != nil {
		return SettingsView{}, err
	}
	set := Settings{Enabled: in.Enabled, Provider: in.Provider, EABKeyEnc: old.EABKeyEnc}
	switch in.Provider {
	case ProviderLetsEncrypt, ProviderLetsEncryptStaging:
	case ProviderCustom:
		u, err := url.Parse(strings.TrimSpace(in.DirectoryURL))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return SettingsView{}, badField("directory_url", "the ACME directory must be an https:// URL")
		}
		set.DirectoryURL = u.String()
		if b := strings.TrimSpace(in.CABundle); b != "" {
			if !x509.NewCertPool().AppendCertsFromPEM([]byte(b)) || len(b) > 256<<10 {
				return SettingsView{}, badField("ca_bundle", "the CA bundle must be PEM certificates")
			}
			set.CABundle = b + "\n"
		}
		set.EABKeyID = strings.TrimSpace(in.EABKeyID)
		switch {
		case in.ClearEABKey:
			set.EABKeyEnc = nil
		case in.EABKey != "":
			key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(in.EABKey), "="))
			if err != nil || len(key) < 16 {
				return SettingsView{}, badField("eab_key", "the EAB key must be the base64url text the CA gave you")
			}
			set.EABKeyEnc = s.box.Seal(key, []byte(eabAD))
		}
		if set.EABKeyID != "" && len(set.EABKeyEnc) == 0 {
			return SettingsView{}, badField("eab_key", "an EAB key ID needs its key")
		}
	default:
		return SettingsView{}, badField("provider", "provider must be letsencrypt, letsencrypt-staging or custom")
	}
	if e := strings.TrimSpace(in.Email); e != "" {
		if set.Email, err = validate.Email(e); err != nil {
			return SettingsView{}, validate.WithField(err, "email")
		}
	}
	if h := strings.TrimSpace(in.Hostname); h != "" {
		if set.Hostname, err = validate.Domain(h); err != nil {
			return SettingsView{}, validate.WithField(err, "hostname")
		}
	}
	if err := s.db.SetSetting(ctx, settingsKey, set); err != nil {
		return SettingsView{}, err
	}
	err = s.audit.Record(ctx, event(c, p, "ssl.settings", "", "ssl", "settings", map[string]any{
		"enabled": set.Enabled, "provider": set.Provider, "directory_url": set.DirectoryURL, "email": set.Email,
		"hostname": set.Hostname, "eab": len(set.EABKeyEnc) > 0,
	}))
	return set.view(), err
}

func badField(name, msg string) error {
	return &validate.Error{Field: name, Code: validate.CodeFormat, Message: msg}
}
