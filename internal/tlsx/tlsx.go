// Package tlsx checks certificates and private keys: parsed, matched, and
// re-encoded, so nothing but certificates and a key reaches a service
// (07-security.md §7). The API and the agent use it alike.
package tlsx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Bounds of what is accepted.
const (
	MaxPEM       = 64 << 10 // bytes of a certificate chain or a key
	MaxChain     = 10       // certificates in a chain
	MinRSABits   = 2048
	wildcardTest = "xcp-wildcard-check"
)

// Pair is a checked certificate chain and its private key.
type Pair struct {
	CertPEM string // the certificate, then the rest of the chain
	KeyPEM  string // PKCS #8
	Leaf    *x509.Certificate
}

// Parse reads a certificate chain (the certificate first; chainPEM may
// carry the rest separately) and a private key, and checks that the key
// belongs to the certificate.
func Parse(certPEM, chainPEM, keyPEM string) (Pair, error) {
	if len(certPEM)+len(chainPEM) > MaxPEM || len(keyPEM) > MaxPEM {
		return Pair{}, errors.New("certificate or key is too large")
	}
	var ders [][]byte
	rest := []byte(certPEM + "\n" + chainPEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return Pair{}, fmt.Errorf("unexpected %q block among the certificates", b.Type)
		}
		ders = append(ders, b.Bytes)
	}
	switch {
	case len(ders) == 0:
		return Pair{}, errors.New("no certificate found (paste the PEM text starting with -----BEGIN CERTIFICATE-----)")
	case len(ders) > MaxChain:
		return Pair{}, fmt.Errorf("more than %d certificates in the chain", MaxChain)
	case strings.TrimSpace(string(rest)) != "":
		return Pair{}, errors.New("text after the last certificate that is not PEM")
	}
	certs := make([]*x509.Certificate, len(ders))
	var out strings.Builder
	for i, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return Pair{}, fmt.Errorf("certificate %d: %w", i+1, err)
		}
		certs[i] = c
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}

	kb, krest := pem.Decode([]byte(keyPEM))
	if kb == nil || strings.TrimSpace(string(krest)) != "" {
		return Pair{}, errors.New("the private key must be exactly one PEM block")
	}
	key, err := parseKey(kb)
	if err != nil {
		return Pair{}, err
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < MinRSABits {
			return Pair{}, fmt.Errorf("RSA keys must have at least %d bits", MinRSABits)
		}
	case *ecdsa.PrivateKey:
	default:
		return Pair{}, errors.New("only RSA and ECDSA keys are supported")
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Pair{}, err
	}
	keyOut := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	if _, err := tls.X509KeyPair([]byte(out.String()), []byte(keyOut)); err != nil {
		return Pair{}, errors.New("the private key does not belong to the certificate")
	}
	return Pair{CertPEM: out.String(), KeyPEM: keyOut, Leaf: certs[0]}, nil
}

func parseKey(b *pem.Block) (crypto.PrivateKey, error) {
	if strings.Contains(b.Type, "ENCRYPTED") || b.Headers["Proc-Type"] != "" {
		return nil, errors.New("the private key is encrypted; upload it without a passphrase")
	}
	switch b.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(b.Bytes)
	}
	return nil, fmt.Errorf("unexpected %q block where the private key should be", b.Type)
}

// Covers reports whether the certificate is valid for name; "*.example.com"
// needs a wildcard certificate.
func Covers(c *x509.Certificate, name string) bool {
	if base, ok := strings.CutPrefix(name, "*."); ok {
		return c.VerifyHostname(wildcardTest+"."+base) == nil
	}
	return c.VerifyHostname(name) == nil
}

// Valid reports whether the certificate is valid at t.
func Valid(c *x509.Certificate, t time.Time) bool {
	return !t.Before(c.NotBefore) && !t.After(c.NotAfter)
}
