package main

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// certReloader serves a certificate from files and picks up a new one (from
// AutoSSL, through xcp-agent) without a restart. It looks at the files at
// most every 30 seconds; a pair that does not load (missing, or half
// replaced) is ignored and the previous one stays.
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	modCert, modKey   time.Time
	checked           time.Time
}

func newCertReloader(certFile, keyFile string) *certReloader {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	_ = r.load()
	r.checked = time.Now()
	return r
}

func modTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

func (r *certReloader) load() error {
	mc, mk := modTime(r.certFile), modTime(r.keyFile)
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.modCert, r.modKey = &c, mc, mk
	return nil
}

// current returns the certificate, nil if it never loaded.
func (r *certReloader) current() *tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) > 30*time.Second {
		r.checked = time.Now()
		if !modTime(r.certFile).Equal(r.modCert) || !modTime(r.keyFile).Equal(r.modKey) {
			_ = r.load()
		}
	}
	return r.cert
}

// panelCerts chooses by the name the client asks for: the server's host
// name certificate (AutoSSL) when it covers that name, else the panel's own
// self-signed one, which local tools reach by IP and pin.
type panelCerts struct {
	panel, host *certReloader
}

// GetCertificate implements tls.Config.GetCertificate.
func (p panelCerts) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := p.host.current(); c != nil && c.Leaf != nil && hello.ServerName != "" && c.Leaf.VerifyHostname(hello.ServerName) == nil {
		return c, nil
	}
	return p.panel.current(), nil
}
