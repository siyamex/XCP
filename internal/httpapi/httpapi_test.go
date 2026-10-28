package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TOTP test helper
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/audit"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/secretbox"
	"github.com/siyamex/XCP/internal/store"
)

const rootPW = "correct horse battery"

type harness struct {
	t    *testing.T
	srv  *httptest.Server
	auth *auth.Service
	api  *Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "xcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, _ := secretbox.New(bytes.Repeat([]byte{3}, secretbox.KeySize))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := audit.NewRecorder(db)
	svc, err := auth.NewService(db, rec, box, auth.Options{
		SessionIdle: 30 * time.Minute, SessionMax: 12 * time.Hour,
		Argon: auth.Argon2Params{Memory: 8 * 1024, Time: 1, Threads: 1}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateLogin(ctx, auth.Client{}, nil, auth.NewLogin{Username: "root", Password: rootPW, Role: store.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	pl := plans.NewService(db, rec)
	if err := pl.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	api := New(Deps{Auth: svc, Plans: pl, Agent: agentrpc.NewFake(), Log: log})
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	return &harness{t: t, srv: srv, auth: svc, api: api}
}

// browser is an HTTP client with its own cookie jar, like one browser profile.
type browser struct {
	h    *harness
	c    *http.Client
	csrf string
}

func (h *harness) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{h: h, c: &http.Client{Jar: jar}}
}

type reqOpt func(*http.Request)

func noCSRF(r *http.Request) { r.Header.Del("X-CSRF-Token") }
func header(k, v string) reqOpt {
	return func(r *http.Request) { r.Header.Set(k, v) }
}

func (b *browser) do(method, path string, body any, opts ...reqOpt) *http.Response {
	b.h.t.Helper()
	var rd io.Reader
	if body != nil {
		if raw, ok := body.(string); ok {
			rd = strings.NewReader(raw)
		} else {
			j, _ := json.Marshal(body)
			rd = bytes.NewReader(j)
		}
	}
	req, _ := http.NewRequest(method, b.h.srv.URL+"/api/v1"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.csrf != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	for _, o := range opts {
		o(req)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.h.t.Fatal(err)
	}
	b.h.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (b *browser) login(user, pass string) loginResponse {
	b.h.t.Helper()
	resp := b.do("POST", "/auth/login", map[string]string{"username": user, "password": pass})
	if resp.StatusCode != 200 {
		b.h.t.Fatalf("login status %d: %s", resp.StatusCode, readAll(resp))
	}
	var lr loginResponse
	json.NewDecoder(resp.Body).Decode(&lr)
	b.csrf = lr.CSRFToken
	return lr
}

func readAll(resp *http.Response) string { b, _ := io.ReadAll(resp.Body); return string(b) }

func wantProblem(t *testing.T, resp *http.Response, status int, code string) Problem {
	t.Helper()
	var p Problem
	body := readAll(resp)
	json.Unmarshal([]byte(body), &p)
	if resp.StatusCode != status || p.Code != code || resp.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("got %d %q (%s), want %d %q", resp.StatusCode, p.Code, body, status, code)
	}
	if p.RequestID == "" || p.RequestID != resp.Header.Get("X-Request-ID") {
		t.Fatalf("problem request_id %q does not match header %q", p.RequestID, resp.Header.Get("X-Request-ID"))
	}
	return p
}

func TestHealthHeadersAndNotFound(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	resp := b.do("GET", "/health", nil)
	if resp.StatusCode != 200 || strings.TrimSpace(readAll(resp)) != `{"status":"ok"}` {
		t.Fatalf("health = %d", resp.StatusCode)
	}
	for k, want := range map[string]string{
		"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
		"Referrer-Policy": "no-referrer",
	} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("CSP missing frame-ancestors")
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be sent over plain HTTP dev mode")
	}
	wantProblem(t, b.do("GET", "/nope", nil), 404, "not_found")
}

func TestLoginCookieCSRFLogout(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	wantProblem(t, b.do("POST", "/auth/login", map[string]string{"username": "root", "password": "wrong password!"}), 401, "invalid_credentials")
	wantProblem(t, b.do("GET", "/me", nil), 401, "unauthenticated")

	resp := b.do("POST", "/auth/login", map[string]string{"username": "root", "password": rootPW})
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d %s", resp.StatusCode, readAll(resp))
	}
	sc := resp.Header.Get("Set-Cookie")
	for _, attr := range []string{"xcp_session=", "HttpOnly", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(sc, attr) {
			t.Errorf("Set-Cookie %q missing %s", sc, attr)
		}
	}
	var lr loginResponse
	json.NewDecoder(resp.Body).Decode(&lr)
	b.csrf = lr.CSRFToken

	var me meResponse
	json.NewDecoder(b.do("GET", "/me", nil).Body).Decode(&me)
	if me.Username != "root" || me.Role != "admin" || me.CSRFToken != lr.CSRFToken {
		t.Fatalf("me = %+v", me)
	}

	wantProblem(t, b.do("POST", "/auth/logout", nil, noCSRF), 403, "csrf_failed")
	wantProblem(t, b.do("POST", "/auth/logout", nil, header("X-CSRF-Token", "forged")), 403, "csrf_failed")
	if resp := b.do("POST", "/auth/logout", nil); resp.StatusCode != 204 {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	wantProblem(t, b.do("GET", "/me", nil), 401, "unauthenticated")
}

func TestRequestHardening(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	creds := `{"username":"root","password":"` + rootPW + `"}`
	wantProblem(t, b.do("POST", "/auth/login", creds, header("Content-Type", "text/plain")), 415, "unsupported_media_type")
	wantProblem(t, b.do("POST", "/auth/login", `{"username":"root","password":"x","admin":true}`), 400, "bad_json")
	wantProblem(t, b.do("POST", "/auth/login", creds+creds), 400, "bad_json")
	wantProblem(t, b.do("POST", "/auth/login", `{"username":"`+strings.Repeat("a", maxJSONBody)+`"}`), 413, "body_too_large")
	wantProblem(t, b.do("POST", "/auth/login", creds, header("Origin", "https://evil.example")), 403, "cross_origin")
	wantProblem(t, b.do("POST", "/auth/login", creds, header("Sec-Fetch-Site", "cross-site")), 403, "cross_origin")
	if resp := b.do("POST", "/auth/login", creds, header("Origin", h.srv.URL), header("Sec-Fetch-Site", "same-origin")); resp.StatusCode != 200 {
		t.Fatalf("same-origin login refused: %d %s", resp.StatusCode, readAll(resp))
	}
}

func totpCode(t *testing.T, secretB32 string, at time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

func TestTwoFactorOverHTTP(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	b.login("root", rootPW)

	var setup struct {
		Secret string `json:"secret"`
		URI    string `json:"otpauth_uri"`
	}
	json.NewDecoder(b.do("POST", "/me/2fa/setup", nil).Body).Decode(&setup)
	if setup.Secret == "" || !strings.HasPrefix(setup.URI, "otpauth://totp/") {
		t.Fatalf("setup = %+v", setup)
	}
	now := time.Now()
	var confirmed struct {
		Codes []string `json:"recovery_codes"`
	}
	resp := b.do("POST", "/me/2fa/confirm", map[string]string{"code": totpCode(t, setup.Secret, now)})
	json.NewDecoder(resp.Body).Decode(&confirmed)
	if resp.StatusCode != 200 || len(confirmed.Codes) != 10 {
		t.Fatalf("confirm = %d %+v", resp.StatusCode, confirmed)
	}
	b.do("POST", "/auth/logout", nil)

	b2 := h.browser()
	if lr := b2.login("root", rootPW); !lr.MFARequired {
		t.Fatal("2FA not required")
	}
	wantProblem(t, b2.do("GET", "/me", nil), 401, "mfa_required")
	wantProblem(t, b2.do("POST", "/me/2fa/setup", nil), 401, "mfa_required")
	wantProblem(t, b2.do("POST", "/auth/2fa/verify", map[string]string{"code": "000000"}), 401, "invalid_code")
	// The confirmation used the current 30s step, so use the next one (allowed clock skew).
	if resp := b2.do("POST", "/auth/2fa/verify", map[string]string{"code": totpCode(t, setup.Secret, now.Add(30*time.Second))}); resp.StatusCode != 204 {
		t.Fatalf("verify = %d %s", resp.StatusCode, readAll(resp))
	}
	var me meResponse
	json.NewDecoder(b2.do("GET", "/me", nil).Body).Decode(&me)
	if !me.TOTPEnabled {
		t.Fatalf("me = %+v", me)
	}

	b3 := h.browser()
	b3.login("root", rootPW)
	if resp := b3.do("POST", "/auth/2fa/verify", map[string]string{"code": confirmed.Codes[0]}); resp.StatusCode != 204 {
		t.Fatalf("recovery code = %d %s", resp.StatusCode, readAll(resp))
	}
}

func TestMustChangePassword(t *testing.T) {
	h := newHarness(t)
	_, err := h.auth.CreateLogin(context.Background(), auth.Client{}, nil, auth.NewLogin{
		Username: "alice", Password: rootPW, Role: store.RoleUser, MustChangePassword: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	b := h.browser()
	if lr := b.login("alice", rootPW); !lr.MustChangePassword {
		t.Fatal("must_change_password not reported")
	}
	if resp := b.do("GET", "/me", nil); resp.StatusCode != 200 {
		t.Fatalf("/me must stay reachable: %d", resp.StatusCode)
	}
	wantProblem(t, b.do("GET", "/me/sessions", nil), 403, "password_change_required")
	resp := b.do("POST", "/me/password", map[string]string{"current_password": rootPW, "new_password": "short"})
	p := wantProblem(t, resp, 400, "validation_failed")
	if len(p.Errors) != 1 || p.Errors[0].Field != "new_password" {
		t.Fatalf("field errors = %+v", p.Errors)
	}
	if resp := b.do("POST", "/me/password", map[string]string{"current_password": rootPW, "new_password": "a much better password"}); resp.StatusCode != 204 {
		t.Fatalf("change = %d %s", resp.StatusCode, readAll(resp))
	}
	if resp := b.do("GET", "/me/sessions", nil); resp.StatusCode != 200 {
		t.Fatalf("still blocked after change: %d", resp.StatusCode)
	}
}

func TestRateLimitedLogin(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	for range 5 {
		b.do("POST", "/auth/login", map[string]string{"username": "root", "password": "wrong password!"})
	}
	resp := b.do("POST", "/auth/login", map[string]string{"username": "root", "password": rootPW})
	wantProblem(t, resp, 429, "rate_limited")
	if resp.Header.Get("Retry-After") == "" {
		t.Error("Retry-After header missing")
	}
}

func TestSessionsListAndRevoke(t *testing.T) {
	h := newHarness(t)
	a, other := h.browser(), h.browser()
	a.login("root", rootPW)
	other.login("root", rootPW)

	var list struct {
		Items []sessionJSON `json:"items"`
	}
	json.NewDecoder(a.do("GET", "/me/sessions", nil).Body).Decode(&list)
	if len(list.Items) != 2 {
		t.Fatalf("sessions = %+v", list.Items)
	}
	var target string
	for _, s := range list.Items {
		if !s.Current {
			target = s.ID
		}
	}
	if resp := a.do("DELETE", "/me/sessions/"+target, nil); resp.StatusCode != 204 {
		t.Fatalf("revoke = %d %s", resp.StatusCode, readAll(resp))
	}
	wantProblem(t, other.do("GET", "/me", nil), 401, "unauthenticated")
	wantProblem(t, a.do("DELETE", "/me/sessions/not-hex", nil), 404, "not_found")
}
