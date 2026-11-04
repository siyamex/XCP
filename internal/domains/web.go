package domains

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

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
	return WebSettings{WebOptions: decodeWeb(raw)}, nil
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
	return WebSettings{WebOptions: clean, JobID: jobID}, nil
}

// protoWeb converts saved web settings for the agent request.
func protoWeb(o agent.WebOptions) *agentv1.WebOptions {
	w := &agentv1.WebOptions{
		ErrorPages: o.ErrorPages, Hotlink: o.Hotlink.Enabled, HotlinkHosts: o.Hotlink.Hosts, HotlinkExts: o.Hotlink.Extensions,
		HotlinkAllowEmpty: o.Hotlink.AllowEmpty, Blocked: o.Blocked, Compress: o.Compress,
	}
	for _, r := range o.CacheRules {
		w.CacheRules = append(w.CacheRules, &agentv1.CacheRule{Exts: r.Extensions, Days: uint32(r.Days)}) //nolint:gosec // G115: 1..365 by Clean
	}
	return w
}
