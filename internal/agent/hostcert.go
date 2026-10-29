package agent

import (
	"bytes"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/tlsx"
	"github.com/siyamex/XCP/internal/validate"
)

// HostCert holds the certificate of the server's host name, which the
// panel serves to clients asking for that name (next to its own
// self-signed pair) and mail and FTP will use.
type HostCert struct {
	CertFile string // /etc/xcp/ssl/hostname.crt
	KeyFile  string // /etc/xcp/ssl/hostname.key, readable by Group
	Group    string // the group xcp-api runs as
	Now      func() time.Time
	mu       sync.Mutex
}

// InstallCertificate replaces the host name certificate with one that
// covers hostname and is valid now. It reports whether the files changed.
func (p *HostCert) InstallCertificate(hostname string, t TLS) (bool, error) {
	if n, err := validate.Domain(hostname); err != nil || n != hostname {
		return false, invalid("host name %q is not a normalised domain name", hostname)
	}
	pair, err := tlsx.Parse(t.CertPEM, "", t.KeyPEM)
	if err != nil {
		return false, invalid("host name certificate: %v", err)
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	if !tlsx.Covers(pair.Leaf, hostname) || !tlsx.Valid(pair.Leaf, now()) {
		return false, invalid("the certificate is not valid for %s now", hostname)
	}
	gid := 0
	if g, err := user.LookupGroup(p.Group); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	root, err := fsx.OpenRoot(filepath.Dir(p.CertFile))
	if err != nil {
		return false, err
	}
	defer root.Close()
	certName, keyName := filepath.Base(p.CertFile), filepath.Base(p.KeyFile)
	oldCert, _ := root.ReadFile(certName, tlsx.MaxPEM)
	oldKey, _ := root.ReadFile(keyName, tlsx.MaxPEM)
	if bytes.Equal(oldCert, []byte(pair.CertPEM)) && bytes.Equal(oldKey, []byte(pair.KeyPEM)) {
		return false, nil
	}
	// The key first: until the certificate follows, xcp-api's reload sees a
	// mismatch and keeps serving the old pair.
	if err := root.WriteFileAtomic(keyName, []byte(pair.KeyPEM), 0o640); err != nil {
		return false, err
	}
	if err := root.Chown(keyName, -1, gid); err != nil { // owner stays root (the agent's)
		return false, err
	}
	return true, root.WriteFileAtomic(certName, []byte(pair.CertPEM), 0o644)
}
