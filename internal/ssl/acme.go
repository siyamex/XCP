package ssl

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/siyamex/XCP/internal/fsx"
	"github.com/siyamex/XCP/internal/store"
)

// issuer gets a certificate for names, signed for key.
type issuer interface {
	Issue(ctx context.Context, names []string, key crypto.Signer) (certPEM string, err error)
}

// Associated data binding encrypted values to their purpose.
const (
	eabAD       = "xcp acme eab key"
	accountAD   = "xcp acme account key"
	accountKey  = "acme_account"
	acmeTimeout = 3 * time.Minute
)

func keyAD(certID string) []byte { return []byte("xcp certificate key " + certID) }

// acmeAccount is the ACME account key of one directory, stored encrypted.
type acmeAccount struct {
	Directory string `json:"directory"`
	KeyEnc    []byte `json:"key_enc"`
}

// acmeKey loads the ACME account key of the directory, or makes one.
func (s *Service) acmeKey(ctx context.Context, directory string) (crypto.Signer, error) {
	var a acmeAccount
	err := s.db.GetSetting(ctx, accountKey, &a)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if err == nil && a.Directory == directory {
		der, err := s.box.Open(a.KeyEnc, []byte(accountAD))
		if err != nil {
			return nil, err
		}
		k, err := x509.ParseECPrivateKey(der)
		return k, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	a = acmeAccount{Directory: directory, KeyEnc: s.box.Seal(der, []byte(accountAD))}
	return k, s.db.SetSetting(ctx, accountKey, a)
}

// acmeIssuer issues certificates with HTTP-01 challenges, which Apache
// serves from challengeDir for every host name (ADR-0005).
type acmeIssuer struct {
	client       *acme.Client
	challengeDir string
}

// newACMEIssuer registers (or finds) the ACME account of the settings.
func (s *Service) newACMEIssuer(ctx context.Context, set Settings) (issuer, error) {
	dir := set.directory()
	if dir == "" {
		return nil, errors.New("no ACME directory configured")
	}
	key, err := s.acmeKey(ctx, dir)
	if err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if set.CABundle != "" {
		roots.AppendCertsFromPEM([]byte(set.CABundle))
	}
	hc := &http.Client{Timeout: time.Minute, Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
	}}
	c := &acme.Client{Key: key, DirectoryURL: dir, HTTPClient: hc, UserAgent: "xcp"}
	acct := &acme.Account{}
	if set.Email != "" {
		acct.Contact = []string{"mailto:" + set.Email}
	}
	if len(set.EABKeyEnc) > 0 {
		hmac, err := s.box.Open(set.EABKeyEnc, []byte(eabAD))
		if err != nil {
			return nil, err
		}
		acct.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: set.EABKeyID, Key: hmac}
	}
	rctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()
	if _, err := c.Register(rctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("ACME account at %s: %w", dir, err)
	}
	return &acmeIssuer{client: c, challengeDir: s.challengeDir}, nil
}

// tokenRe is the base64url alphabet of ACME tokens; anything else could
// leave the challenge folder.
var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)

// Issue orders a certificate for names, answers the HTTP-01 challenges and
// returns the certificate and its chain.
func (a *acmeIssuer) Issue(ctx context.Context, names []string, key crypto.Signer) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()
	order, err := a.client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return "", err
	}
	for _, u := range order.AuthzURLs {
		z, err := a.client.GetAuthorization(ctx, u)
		if err != nil {
			return "", err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		if err := a.validate(ctx, z); err != nil {
			return "", fmt.Errorf("%s: %w", z.Identifier.Value, err)
		}
	}
	if order, err = a.client.WaitOrder(ctx, order.URI); err != nil {
		return "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
	}, key)
	if err != nil {
		return "", err
	}
	ders, _, err := a.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, d := range ders {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	return out.String(), nil
}

// validate answers one authorization's HTTP-01 challenge.
func (a *acmeIssuer) validate(ctx context.Context, z *acme.Authorization) error {
	var ch *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == "http-01" {
			ch = c
		}
	}
	if ch == nil {
		return errors.New("the CA offers no HTTP validation for this name")
	}
	if !tokenRe.MatchString(ch.Token) {
		return fmt.Errorf("the CA sent an unusable token %q", ch.Token)
	}
	body, err := a.client.HTTP01ChallengeResponse(ch.Token)
	if err != nil {
		return err
	}
	root, err := fsx.OpenRoot(a.challengeDir)
	if err != nil {
		return fmt.Errorf("challenge folder: %w", err)
	}
	defer root.Close()
	if err := root.WriteFileAtomic(ch.Token, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write the challenge: %w", err)
	}
	defer root.Remove(ch.Token) //nolint:errcheck // best effort; the token is useless afterwards
	// xcp-api's umask (0027) would hide it from Apache.
	if err := root.Chmod(ch.Token, 0o644); err != nil {
		return err
	}
	if _, err := a.client.Accept(ctx, ch); err != nil {
		return err
	}
	_, err = a.client.WaitAuthorization(ctx, z.URI)
	return err
}
