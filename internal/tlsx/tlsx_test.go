package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// selfSigned returns a certificate for names and its key, both PEM.
func selfSigned(t *testing.T, names ...string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func TestParseChecksAndReencodes(t *testing.T) {
	cert, key := selfSigned(t, "example.com", "www.example.com")
	p, err := Parse("Issued by: Example CA\n"+cert, "", key) // a note before the first block is skipped
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.CertPEM, "-----BEGIN CERTIFICATE-----") || !strings.HasPrefix(p.KeyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("not re-encoded: %q / %q", p.CertPEM[:30], p.KeyPEM[:30])
	}
	if !Covers(p.Leaf, "www.example.com") || Covers(p.Leaf, "other.example.com") || !Valid(p.Leaf, time.Now()) {
		t.Fatal("Covers/Valid")
	}

	other, otherKey := selfSigned(t, "other.example")
	wild, wildKey := selfSigned(t, "*.example.net")
	if p, err := Parse(wild, "", wildKey); err != nil || !Covers(p.Leaf, "*.example.net") || Covers(p.Leaf, "*.example.org") {
		t.Fatalf("wildcard: %v", err)
	}
	if p, err := Parse(cert, other, key); err != nil || strings.Count(p.CertPEM, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("separate chain: %v", err)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	smallPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)}))
	bad := map[string][3]string{
		"key of another cert": {cert, "", otherKey},
		"no certificate":      {"", "", key},
		"key in cert field":   {key, "", key},
		"two keys":            {cert, "", key + key},
		"trailing junk":       {cert + "\nnot pem", "", key},
		"weak RSA":            {cert, "", smallPEM},
		"encrypted key":       {cert, "", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"},
		"too big":             {strings.Repeat("x", MaxPEM+1), "", key},
	}
	for name, in := range bad {
		if _, err := Parse(in[0], in[1], in[2]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
