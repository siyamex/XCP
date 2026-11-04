package domains

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/siyamex/XCP/internal/agent"
	agentv1 "github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// WebSettings is the API view of a domain's web settings.
type WebSettings struct {
	agent.WebOptions
	JobID string `json:"job_id,omitempty"`
}

func decodeWeb(raw string) agent.WebOptions {
	var o agent.WebOptions
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &o)
	}
	o, _ = o.Clean()
	return o
}

// WebSettings returns the web settings of a domain.
func (s *Service) WebSettings(ctx context.Context, p *auth.Principal, domainID string) (WebSettings, error) {
	d, err := s.db.DomainByID(ctx, domainID)
	if err != nil {
		return WebSettings{}, err
	}
	if _, err := s.access(ctx, p, d.AccountID, FeatureDomains); err != nil {
		return WebSettings{}, err
	}
	raw, err := s.db.DomainWeb(ctx, d.ID)
	if err != nil {
		return WebSettings{}, err
	}
	return WebSettings{WebOptions: stripHashes(decodeWeb(raw))}, nil
}

// stripHashes removes the password hashes: the API never shows them.
func stripHashes(o agent.WebOptions) agent.WebOptions {
	dirs := make([]agent.ProtectedDir, len(o.ProtectedDirs))
	for i, d := range o.ProtectedDirs {
		d.Users = slices.Clone(d.Users)
		for j := range d.Users {
			d.Users[j].Hash = ""
		}
		dirs[i] = d
	}
	o.ProtectedDirs = dirs
	return o
}

// SetWebSettings saves the web settings of a domain and applies them.
func (s *Service) SetWebSettings(ctx context.Context, c auth.Client, p *auth.Principal, domainID string, in agent.WebOptions) (WebSettings, error) {
	d, a, err := s.domainForChange(ctx, p, domainID, FeatureDomains)
	if err != nil {
		return WebSettings{}, err
	}
	if d.Kind == store.DomainAlias {
		return WebSettings{}, badField("domain", validate.CodeFormat, "an alias shows another domain's site: set it there")
	}
	// This form does not carry the protected folders: they keep what they have.
	raw0, err := s.db.DomainWeb(ctx, d.ID)
	if err != nil {
		return WebSettings{}, err
	}
	in.ProtectedDirs = decodeWeb(raw0).ProtectedDirs
	clean, err := in.Clean()
	if err != nil {
		return WebSettings{}, badField("options", validate.CodeFormat, err.Error())
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return WebSettings{}, err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetDomainWeb(ctx, tx, d.ID, string(raw), time.Now().UTC()); err != nil {
			return err
		}
		if jobID, err = s.enqueue(ctx, tx, p, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "domain.web", a.ID, "domain", d.ID, map[string]any{
			"domain": d.Name, "blocked": len(clean.Blocked), "hotlink": clean.Hotlink.Enabled, "compress": clean.Compress,
			"error_pages": len(clean.ErrorPages), "cache_rules": len(clean.CacheRules),
		}))
	})
	if err != nil {
		return WebSettings{}, err
	}
	return WebSettings{WebOptions: stripHashes(clean), JobID: jobID}, nil
}

// protoWeb converts saved web settings for the agent request.
func protoWeb(o agent.WebOptions) *agentv1.WebOptions {
	w := &agentv1.WebOptions{
		ErrorPages: o.ErrorPages, Hotlink: o.Hotlink.Enabled, HotlinkHosts: o.Hotlink.Hosts, HotlinkExts: o.Hotlink.Extensions,
		HotlinkAllowEmpty: o.Hotlink.AllowEmpty, Blocked: o.Blocked, Compress: o.Compress,
	}
	for _, d := range o.ProtectedDirs {
		pd := &agentv1.ProtectedDir{Path: d.Path, Realm: d.Realm}
		for _, u := range d.Users {
			pd.Users = append(pd.Users, &agentv1.HtUser{Name: u.Name, Hash: u.Hash})
		}
		w.ProtectedDirs = append(w.ProtectedDirs, pd)
	}
	for _, r := range o.CacheRules {
		w.CacheRules = append(w.CacheRules, &agentv1.CacheRule{Exts: r.Extensions, Days: uint32(r.Days)}) //nolint:gosec // G115: 1..365 by Clean
	}
	return w
}

// ProtectedInput is a protected folder as sent by the user: users with a
// password get a new hash, users without keep the one they have.
type ProtectedInput struct {
	Path  string `json:"path"`
	Realm string `json:"realm"`
	Users []struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	} `json:"users"`
}

// SetProtectedDirs replaces the domain's password-protected folders (ADR-0025).
func (s *Service) SetProtectedDirs(ctx context.Context, c auth.Client, p *auth.Principal, domainID string, in []ProtectedInput) (WebSettings, error) {
	d, a, err := s.domainForChange(ctx, p, domainID, FeatureDomains)
	if err != nil {
		return WebSettings{}, err
	}
	if d.Kind == store.DomainAlias {
		return WebSettings{}, badField("domain", validate.CodeFormat, "an alias shows another domain's site: set it there")
	}
	raw, err := s.db.DomainWeb(ctx, d.ID)
	if err != nil {
		return WebSettings{}, err
	}
	cur := decodeWeb(raw)
	known := map[string]string{} // folder + "|" + user -> hash
	for _, pd := range cur.ProtectedDirs {
		for _, u := range pd.Users {
			known[pd.Path+"|"+u.Name] = u.Hash
		}
	}
	var dirs []agent.ProtectedDir
	for _, x := range in {
		pd := agent.ProtectedDir{Path: strings.TrimSuffix(x.Path, "/"), Realm: x.Realm}
		for _, u := range x.Users {
			hash := known[pd.Path+"|"+u.Name]
			if u.Password != "" {
				if err := validate.Password(u.Password); err != nil {
					return WebSettings{}, validate.WithField(err, "password")
				}
				b, err := bcrypt.GenerateFromPassword([]byte(u.Password), 10)
				if err != nil {
					return WebSettings{}, badField("password", validate.CodeTooLong, "bcrypt takes at most 72 bytes")
				}
				hash = string(b)
			}
			if hash == "" {
				return WebSettings{}, badField("password", validate.CodeRequired, "a new user needs a password: "+u.Name)
			}
			pd.Users = append(pd.Users, agent.HtUser{Name: u.Name, Hash: hash})
		}
		dirs = append(dirs, pd)
	}
	cur.ProtectedDirs = dirs
	clean, err := cur.Clean()
	if err != nil {
		return WebSettings{}, badField("protected_dirs", validate.CodeFormat, err.Error())
	}
	enc, err := json.Marshal(clean)
	if err != nil {
		return WebSettings{}, err
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetDomainWeb(ctx, tx, d.ID, string(enc), time.Now().UTC()); err != nil {
			return err
		}
		if jobID, err = s.enqueue(ctx, tx, p, a.ID); err != nil {
			return err
		}
		users := 0
		for _, pd := range clean.ProtectedDirs {
			users += len(pd.Users)
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "domain.protected_dirs", a.ID, "domain", d.ID, map[string]any{
			"domain": d.Name, "folders": len(clean.ProtectedDirs), "users": users,
		}))
	})
	if err != nil {
		return WebSettings{}, err
	}
	return WebSettings{WebOptions: stripHashes(clean), JobID: jobID}, nil
}
