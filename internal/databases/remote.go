package databases

import (
	"context"
	"database/sql"
	"net/netip"
	"slices"
	"strings"

	"github.com/siyamex/XCP/internal/agent"
	"github.com/siyamex/XCP/internal/agentrpc/agentv1"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// settingRemote holds whether MariaDB listens on every address.
const settingRemote = "mysql.remote"

// RemoteHost turns what a user types into a MariaDB host pattern: "%" or
// "any" for any host, an IP address, or an IPv4 network in CIDR form
// (192.0.2.0/24 becomes 192.0.2.0/255.255.255.0). MariaDB matches IPv6
// networks only by wildcards, so an IPv6 network is refused.
func RemoteHost(in string) (string, error) {
	in = strings.ToLower(strings.TrimSpace(in))
	bad := func(msg string) (string, error) {
		return "", &validate.Error{Field: "hosts", Code: validate.CodeFormat, Message: in + ": " + msg}
	}
	switch {
	case in == "%" || in == "any":
		return "%", nil
	case strings.Contains(in, "/"):
		p, err := netip.ParsePrefix(in)
		if err != nil {
			return bad("not a network; write it like 192.0.2.0/24")
		}
		if p.Masked() != p {
			return bad("the address has bits set beyond the network; use " + p.Masked().String())
		}
		a := p.Addr().Unmap()
		if !a.Is4() {
			if p.Bits() == 128 {
				return a.String(), nil
			}
			return bad("IPv6 networks are not possible in MariaDB; give single addresses")
		}
		if p.Bits() == 32 {
			return a.String(), nil
		}
		mask := netip.PrefixFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), p.Bits()).Masked().Addr()
		return a.String() + "/" + mask.String(), nil
	}
	a, err := netip.ParseAddr(in)
	if err != nil || a.Zone() != "" {
		return bad("not an IP address")
	}
	return a.Unmap().String(), nil
}

// Remote is an account's remote database access.
type Remote struct {
	Hosts   []string `json:"hosts"`   // MariaDB host patterns
	Enabled bool     `json:"enabled"` // the server accepts connections from outside
}

func (s *Service) remoteEnabled(ctx context.Context) bool {
	var on bool
	_ = s.db.GetSetting(ctx, settingRemote, &on)
	return on
}

// Remote returns the hosts an account's database users may connect from
// besides the server (USR-DB-05).
func (s *Service) Remote(ctx context.Context, p *auth.Principal, accountID string) (Remote, error) {
	a, _, err := s.access(ctx, p, accountID, FeatureMySQL)
	if err != nil {
		return Remote{}, err
	}
	hosts, err := store.DBRemoteHosts(ctx, s.db.R, a.ID)
	return Remote{Hosts: hosts, Enabled: s.remoteEnabled(ctx)}, err
}

// SetRemote replaces the hosts every database user of the account may also
// connect from, and queues the job that applies them in MariaDB.
func (s *Service) SetRemote(ctx context.Context, c auth.Client, p *auth.Principal, accountID string, in []string) (Remote, string, error) {
	a, _, err := s.forChange(ctx, p, accountID)
	if err != nil {
		return Remote{}, "", err
	}
	hosts := []string{}
	for _, h := range in {
		if strings.TrimSpace(h) == "" {
			continue
		}
		pat, err := RemoteHost(h)
		if err != nil {
			return Remote{}, "", err
		}
		if err := agent.CheckRemoteHost(pat); err != nil {
			return Remote{}, "", badField("hosts", validate.CodeFormat, h+": not a host pattern")
		}
		if !slices.Contains(hosts, pat) {
			hosts = append(hosts, pat)
		}
	}
	if len(hosts) > agent.MaxRemoteHosts {
		return Remote{}, "", badField("hosts", validate.CodeTooLong, "an account can have 20 remote hosts")
	}
	var jobID string
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := store.SetDBRemoteHosts(ctx, tx, a.ID, hosts); err != nil {
			return err
		}
		if jobID, err = s.enqueueApply(ctx, tx, p.Login.ID, a.ID); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, tx, event(c, p, "database.remote_hosts", a.ID, "account", a.ID, map[string]any{"hosts": hosts}))
	})
	return Remote{Hosts: hosts, Enabled: s.remoteEnabled(ctx)}, jobID, err
}

// SetRemoteEnabled makes MariaDB listen on every address, or on the server
// only (admins). MariaDB restarts when that changes. Which hosts may connect
// stays each account's choice; the firewall must let port 3306 in too.
func (s *Service) SetRemoteEnabled(ctx context.Context, c auth.Client, p *auth.Principal, on bool) error {
	if err := admin(p); err != nil {
		return err
	}
	_, err := s.agent.MySQLListen(ctx, &agentv1.MySQLListenRequest{Remote: on})
	if status.Code(err) == codes.NotFound {
		return apperr.NewConflict("not_installed", status.Convert(err).Message())
	}
	if err != nil {
		return err
	}
	if err := s.db.SetSetting(ctx, settingRemote, on); err != nil {
		return err
	}
	return s.audit.Record(ctx, event(c, p, "mysql.remote", "", "server", "mysql", map[string]any{"enabled": on}))
}
