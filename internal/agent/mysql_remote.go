package agent

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/siyamex/XCP/internal/fsx"
)

// Remote access to MariaDB (USR-DB-05).
const (
	// MySQLRemoteConf makes MariaDB listen on every address. It sorts after
	// xcp-install's 90-xcp.cnf, so its bind-address wins; without it
	// MariaDB listens on 127.0.0.1 only.
	MySQLRemoteConf = "/etc/mysql/mariadb.conf.d/91-xcp-remote.cnf"
	MySQLUnit       = "mariadb.service"
	MaxRemoteHosts  = 20
	anyHost         = "%"
)

const mysqlRemoteConf = `# Managed by XCP (ADR-0038): remote database access is on. Do not edit.
[mysqld]
bind-address = *
`

// CheckRemoteHost validates a MariaDB host pattern of the panel: "%" (any
// host), an IP address, or an IPv4 network as address/netmask. The fake
// agent uses it too.
func CheckRemoteHost(h string) error {
	if h == anyHost {
		return nil
	}
	if a, err := netip.ParseAddr(h); err == nil && a.String() == h && !a.Is4In6() && a.Zone() == "" {
		return nil
	}
	ip, mask, ok := strings.Cut(h, "/")
	if ok {
		a, err1 := netip.ParseAddr(ip)
		m, err2 := netip.ParseAddr(mask)
		if err1 == nil && err2 == nil && a.Is4() && m.Is4() && a.String() == ip && m.String() == mask {
			if bits := maskBits(m); bits >= 0 {
				if p := netip.PrefixFrom(a, bits); p.Masked().Addr() == a {
					return nil
				}
			}
		}
	}
	return invalid("%q is not a host pattern: give %%, an IP address or an IPv4 network as address/netmask", h)
}

// maskBits returns the prefix length of a contiguous IPv4 netmask, or -1.
func maskBits(m netip.Addr) int {
	b := m.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n := 0
	for v&(1<<31) != 0 {
		n++
		v <<= 1
	}
	if v != 0 {
		return -1
	}
	return n
}

// Listen makes MariaDB listen on every address (remote) or on 127.0.0.1
// only, and restarts it if that changed. It reports whether it changed.
func (m *MySQL) Listen(ctx context.Context, remote bool) (bool, error) {
	if _, err := os.Stat(m.Server); errors.Is(err, fs.ErrNotExist) {
		return false, ErrNotInstalled
	}
	conf := m.RemoteConf
	if conf == "" {
		conf = MySQLRemoteConf
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	have, err := os.ReadFile(conf)
	switch {
	case remote && err == nil && string(have) == mysqlRemoteConf,
		!remote && errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	dir, err := fsx.OpenRoot(filepath.Dir(conf))
	if err != nil {
		return false, err
	}
	defer dir.Close()
	if remote {
		err = dir.WriteFileAtomic(filepath.Base(conf), []byte(mysqlRemoteConf), 0o644)
	} else if err = dir.Remove(filepath.Base(conf)); errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return false, err
	}
	if m.db != nil { // the restart ends the connection
		_ = m.db.Close()
		m.db = nil
	}
	return true, m.Services.Do(ctx, MySQLUnit, ActionRestart)
}
