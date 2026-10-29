package ssl

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/domains"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
	"github.com/siyamex/XCP/internal/zones"
)

const pw = "correct horse battery"

var (
	ctx    = context.Background()
	client = auth.Client{IP: "192.0.2.1"}
)

// testCA signs whatever names it is asked for, like a permissive ACME CA.
type testCA struct {
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	mu     sync.Mutex
	issued [][]string
	fail   string // names containing this fail
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{key: key, cert: c}
}

func (ca *testCA) sign(names []string, pub crypto.PublicKey, notAfter time.Time) (string, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})), nil
}

func (ca *testCA) Issue(_ context.Context, names []string, key crypto.Signer) (string, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.fail != "" && strings.Contains(strings.Join(names, " "), ca.fail) {
		return "", errors.New("urn:ietf:params:acme:error:unauthorized: invalid response from the server")
	}
	ca.issued = append(ca.issued, slices.Clone(names))
	return ca.sign(names, key.Public(), time.Now().Add(90*24*time.Hour))
}

// pair is a certificate for names signed by the test CA, and its key, as PEM.
func (ca *testCA) pair(t *testing.T, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, err := ca.sign(names, &key.PublicKey, time.Now().Add(200*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return cert, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

type env struct {
	svc   *Service
	doms  *domains.Service
	accts *accounts.Service
	plans *plans.Service
	db    *store.DB
	q     *jobs.Queue
	fake  *agentrpc.Fake
	ca    *testCA
	admin *auth.Principal
	pkgID string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, _ := secretbox.New(make([]byte, secretbox.KeySize))
	rec := audit.NewRecorder(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au, err := auth.NewService(db, rec, box, auth.Options{
		SessionIdle: time.Hour, SessionMax: time.Hour,
		Argon: auth.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	pl := plans.NewService(db, rec)
	if err := pl.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	l, err := au.CreateLogin(ctx, client, nil, auth.NewLogin{Username: "root", Password: pw, Role: store.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	admin := &auth.Principal{Login: l, Session: &store.Session{}}
	pkgs, _ := pl.ListPackages(ctx, admin)
	fake := agentrpc.NewFake()
	q := jobs.NewQueue(db)
	// Everything below points to this server, except other.net and www.shop.net.
	hosts := zones.StaticHosts{}
	for _, n := range []string{"example.com", "www.example.com", "shop.net", "panel.example.com", "bob.example"} {
		hosts[n] = []string{"192.0.2.10"}
	}
	hosts["other.net"] = []string{"198.51.100.99"}
	zs := zones.NewService(db, rec, pl, q, fake, hosts)
	if err := db.SetSetting(ctx, "dns", zones.Settings{IPv4: "192.0.2.10", TTL: 3600, Template: zones.DefaultTemplate()}); err != nil {
		t.Fatal(err)
	}
	doms := domains.NewService(db, rec, pl, q, fake, zs, domains.StaticTXT{}, []byte("test key"))
	accts := accounts.NewService(db, rec, au, pl, q, fake, doms, zs)
	svc := NewService(db, rec, pl, q, fake, doms, zs, box, hosts, Options{ChallengeDir: t.TempDir()})
	ca := newTestCA(t)
	svc.newIssuer = func(context.Context, Settings) (issuer, error) { return ca, nil }
	if _, err := svc.SaveSettings(ctx, client, admin, SettingsInput{Enabled: true, Provider: ProviderLetsEncryptStaging, Hostname: "panel.example.com"}); err != nil {
		t.Fatal(err)
	}
	w := jobs.NewWorker(q, "test", log)
	w.Poll = 10 * time.Millisecond
	accts.RegisterJobs(w)
	doms.RegisterJobs(w)
	zs.RegisterJobs(w)
	svc.RegisterJobs(w)
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return &env{svc: svc, doms: doms, accts: accts, plans: pl, db: db, q: q, fake: fake, ca: ca, admin: admin, pkgID: pkgs[0].ID}
}

func (e *env) waitJob(t *testing.T, id string) *jobs.Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		j, err := e.q.Get(ctx, id)
		if err == nil && (j.Status == jobs.StatusSucceeded || j.Status == jobs.StatusFailed) {
			if j.Status == jobs.StatusFailed {
				t.Fatalf("job %s (%s) failed: %s", id, j.Kind, j.Error)
			}
			return j
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s did not finish", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *env) account(t *testing.T, user, domain string) (accounts.Account, *auth.Principal) {
	t.Helper()
	a, err := e.accts.Create(ctx, client, e.admin, accounts.CreateInput{Username: user, Domain: domain, PackageID: e.pkgID, Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, a.JobID)
	l, _ := e.db.AccountLogin(ctx, a.ID)
	return a, &auth.Principal{Login: l, Session: &store.Session{}}
}

func (e *env) run(t *testing.T, p *auth.Principal, accountID string) result {
	t.Helper()
	id, err := e.svc.Run(ctx, client, p, accountID)
	if err != nil {
		t.Fatal(err)
	}
	var res result
	if err := json.Unmarshal(e.waitJob(t, id).Result, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func (e *env) ssl(t *testing.T, p *auth.Principal, accountID string) map[string]DomainSSL {
	t.Helper()
	list, err := e.svc.AccountSSL(ctx, p, accountID)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]DomainSSL{}
	for _, d := range list {
		m[d.Domain] = d
	}
	return m
}

// served waits until the fake agent's site of user satisfies cond.
func (e *env) served(t *testing.T, user string, cond func(map[string]bool) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		tls := map[string]bool{}
		if site, ok := e.fake.Site(user); ok {
			for _, v := range site.Vhosts {
				tls[v.Name] = v.TLS != nil
				tls[v.Name+" force"] = v.ForceHTTPS
			}
		}
		if cond(tls) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("site of %s: %v", user, tls)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAutoSSL(t *testing.T) {
	e := newEnv(t)
	a, _ := e.account(t, "alice", "example.com")
	e.doms.Add(ctx, client, e.admin, a.ID, domains.AddInput{Kind: store.DomainAddon, Name: "shop.net"})
	e.doms.Add(ctx, client, e.admin, a.ID, domains.AddInput{Kind: store.DomainAddon, Name: "other.net"})

	res := e.run(t, e.admin, "")
	if res.Issued != 2 || res.Skipped != 1 || !strings.HasPrefix(res.Hostname, "ok") {
		t.Fatalf("first run = %+v", res)
	}
	if !slices.ContainsFunc(e.ca.issued, func(n []string) bool { return slices.Equal(n, []string{"example.com", "www.example.com"}) }) ||
		!slices.ContainsFunc(e.ca.issued, func(n []string) bool { return slices.Equal(n, []string{"shop.net"}) }) {
		t.Fatalf("issued %v (www only where it points here)", e.ca.issued)
	}
	st := e.ssl(t, e.admin, a.ID)
	if st["other.net"].Status != store.SSLSkipped || !strings.Contains(st["other.net"].Detail, "198.51.100.99") || st["example.com"].Certificate == nil {
		t.Fatalf("status = %+v", st)
	}
	e.served(t, "alice", func(m map[string]bool) bool { return m["example.com"] && m["shop.net"] && !m["other.net"] })
	if host, cert := e.fake.HostCertificate(); host != "panel.example.com" || cert == "" {
		t.Fatal("the host name certificate was not installed for the panel")
	}

	// Nothing to do the second time; a failure is recorded with its reason.
	if res := e.run(t, e.admin, a.ID); res.Issued != 0 || res.OK != 2 {
		t.Fatalf("second run = %+v", res)
	}
	if _, err := e.db.W.ExecContext(ctx, `DELETE FROM certificates WHERE domain_id IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	e.ca.fail = "shop.net"
	if res := e.run(t, e.admin, a.ID); res.Failed != 1 {
		t.Fatalf("run with a failing CA = %+v", res)
	}
	if d := e.ssl(t, e.admin, a.ID)["shop.net"]; d.Status != store.SSLFailed || !strings.Contains(d.Detail, "unauthorized") {
		t.Fatalf("failure not recorded: %+v", d)
	}

	// Left out of AutoSSL; force HTTPS needs a certificate.
	sh := e.ssl(t, e.admin, a.ID)["shop.net"]
	if _, err := e.svc.SetOptions(ctx, client, e.admin, sh.DomainID, OptionsInput{AutoSSL: false}); err != nil {
		t.Fatal(err)
	}
	e.ca.fail = ""
	e.run(t, e.admin, a.ID)
	if d := e.ssl(t, e.admin, a.ID)["shop.net"]; d.Status != store.SSLSkipped || d.Certificate != nil {
		t.Fatalf("excluded domain = %+v", d)
	}
	var c *apperr.Conflict
	if _, err := e.svc.SetOptions(ctx, client, e.admin, sh.DomainID, OptionsInput{ForceHTTPS: true}); !errors.As(err, &c) || c.Code != "needs_certificate" {
		t.Fatalf("force HTTPS without a certificate: %v", err)
	}
	ex := e.ssl(t, e.admin, a.ID)["example.com"]
	if _, err := e.svc.SetOptions(ctx, client, e.admin, ex.DomainID, OptionsInput{AutoSSL: true, ForceHTTPS: true}); err != nil {
		t.Fatal(err)
	}
	e.served(t, "alice", func(m map[string]bool) bool { return m["example.com force"] })
}

func TestUploadAndDashboard(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice", "example.com")
	b, bob := e.account(t, "bob", "bob.example")
	d := e.ssl(t, alice, a.ID)["example.com"]
	cert, key := e.ca.pair(t, "example.com", "www.example.com")
	_, otherKey := e.ca.pair(t, "example.com")
	wrong, wrongKey := e.ca.pair(t, "elsewhere.example")

	var ve *validate.Error
	for name, in := range map[string]UploadInput{
		"key of another certificate": {Certificate: cert, Key: otherKey},
		"another name":               {Certificate: wrong, Key: wrongKey},
		"not PEM":                    {Certificate: "hello", Key: key},
	} {
		if _, err := e.svc.Upload(ctx, client, alice, d.DomainID, in); !errors.As(err, &ve) || ve.Field != "certificate" {
			t.Errorf("%s: %v", name, err)
		}
	}
	up, err := e.svc.Upload(ctx, client, alice, d.DomainID, UploadInput{Certificate: cert, Key: key})
	if err != nil || up.Certificate == nil || up.Certificate.Source != store.CertUpload || up.Certificate.DaysLeft < 190 {
		t.Fatalf("upload = %+v, %v", up, err)
	}
	e.waitJob(t, up.JobID)
	e.served(t, "alice", func(m map[string]bool) bool { return m["example.com"] })
	if res := e.run(t, alice, a.ID); res.Issued != 0 {
		t.Fatalf("AutoSSL replaced a valid uploaded certificate: %+v", res)
	}
	if got := e.ssl(t, alice, a.ID)["example.com"]; !strings.HasPrefix(got.Detail, "uploaded certificate") {
		t.Fatalf("status = %+v", got)
	}

	// Bob sees nothing of Alice's; the admin sees all, soonest to expire first.
	if _, err := e.svc.Upload(ctx, client, bob, d.DomainID, UploadInput{Certificate: cert, Key: key}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob uploads to alice's domain: %v", err)
	}
	e.run(t, bob, b.ID)
	mine, err := e.svc.Certificates(ctx, bob)
	if err != nil || len(mine) != 1 || mine[0].Domain != "bob.example" {
		t.Fatalf("bob's certificates = %+v, %v", mine, err)
	}
	all, _ := e.svc.Certificates(ctx, e.admin)
	if len(all) != 2 || all[0].Domain != "bob.example" || all[1].Account != "alice" {
		t.Fatalf("dashboard = %+v", all)
	}
	if raw, _ := json.Marshal(all); strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "key_enc") {
		t.Fatal("a private key reached the API")
	}

	jobID, err := e.svc.DeleteCertificate(ctx, client, alice, d.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, jobID)
	e.served(t, "alice", func(m map[string]bool) bool { return !m["example.com"] })
}

func TestSettingsAndReservedHostname(t *testing.T) {
	e := newEnv(t)
	a, alice := e.account(t, "alice", "example.com")
	if _, err := e.svc.GetSettings(ctx, alice); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("settings as a user: %v", err)
	}
	var ve *validate.Error
	for field, in := range map[string]SettingsInput{
		"provider":      {Provider: "acme-of-doom"},
		"directory_url": {Provider: ProviderCustom, DirectoryURL: "http://insecure.example/dir"},
		"ca_bundle":     {Provider: ProviderCustom, DirectoryURL: "https://ca.example/dir", CABundle: "not pem"},
		"eab_key":       {Provider: ProviderCustom, DirectoryURL: "https://ca.example/dir", EABKeyID: "kid"},
		"email":         {Provider: ProviderLetsEncrypt, Email: "not an email"},
	} {
		if _, err := e.svc.SaveSettings(ctx, client, e.admin, in); !errors.As(err, &ve) || ve.Field != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	v, err := e.svc.SaveSettings(ctx, client, e.admin, SettingsInput{
		Enabled: true, Provider: ProviderCustom, DirectoryURL: "https://ca.example/dir", EABKeyID: "kid",
		EABKey: "c2VjcmV0LWhtYWMta2V5LWZyb20tY2E", Hostname: "Panel.Example.com",
	})
	if err != nil || !v.HasEABKey || v.Hostname != "panel.example.com" {
		t.Fatalf("save = %+v, %v", v, err)
	}
	if raw, _ := json.Marshal(v); strings.Contains(string(raw), "c2VjcmV0") {
		t.Fatal("the EAB key came back")
	}
	// The server's own name and names below it are not for accounts.
	for _, in := range []domains.AddInput{
		{Kind: store.DomainAddon, Name: "panel.example.com"},
		{Kind: store.DomainAddon, Name: "x.panel.example.com"},
	} {
		if _, err := e.doms.Add(ctx, client, e.admin, a.ID, in); !errors.As(err, &ve) || ve.Code != validate.CodeReserved {
			t.Errorf("%s: %v", in.Name, err)
		}
	}
}
