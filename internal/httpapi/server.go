package httpapi

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/accounts"
	"github.com/siyamex/XCP/internal/agentrpc"
	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/domains"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/store"
)

// Deps are the services the HTTP layer needs.
type Deps struct {
	Auth     *auth.Service
	Plans    *plans.Service
	Accounts *accounts.Service
	Domains  *domains.Service
	Jobs     *jobs.Queue
	Agent    agentrpc.Client
	Log      *slog.Logger
	// SecureCookies is false only in local development over plain HTTP
	// (api.insecure_dev_http); it also controls HSTS.
	SecureCookies bool
	// UI holds the built web app (index.html, assets/). Nil serves a "not built" message.
	UI fs.FS
}

// access is what a route requires from the caller.
type access int

const (
	public     access = iota // no session
	pendingMFA               // a session, even if the second factor is not done yet
	authed                   // a fully authenticated session
)

type handlerFunc func(w http.ResponseWriter, r *http.Request) error

type route struct {
	method, path string
	access       access
	// allowMustChange lets a login with a forced password change use the route.
	allowMustChange bool
	// roles limits an authenticated route to these login roles (empty: any role).
	roles []string
	h     handlerFunc
}

// adminOnly limits a route to admins (resellers join for their own packages in P2).
var adminOnly = []string{store.RoleAdmin}

// adminOrUser is for an account's own features: the service lets a user
// reach only their own account.
var adminOrUser = []string{store.RoleAdmin, store.RoleUser}

// Server is the xcp-api HTTP handler.
type Server struct {
	Deps
	mux        *http.ServeMux
	routes     []route
	cookieName string
}

// New builds the handler with all routes.
func New(d Deps) *Server {
	s := &Server{Deps: d, mux: http.NewServeMux(), cookieName: "xcp_session"}
	if d.SecureCookies {
		// __Host- cookies must be Secure, path /, and have no Domain: they
		// cannot be set or overwritten by a sibling subdomain.
		s.cookieName = "__Host-xcp_session"
	}
	s.routes = []route{
		{method: "GET", path: "/api/v1/health", access: public, h: s.health},
		{method: "POST", path: "/api/v1/auth/login", access: public, h: s.login},
		{method: "POST", path: "/api/v1/auth/2fa/verify", access: pendingMFA, h: s.verify2FA},
		{method: "POST", path: "/api/v1/auth/logout", access: pendingMFA, h: s.logout},
		{method: "GET", path: "/api/v1/me", access: authed, allowMustChange: true, h: s.me},
		{method: "POST", path: "/api/v1/me/password", access: authed, allowMustChange: true, h: s.changePassword},
		{method: "POST", path: "/api/v1/me/reauth", access: authed, h: s.reauth},
		{method: "GET", path: "/api/v1/me/sessions", access: authed, h: s.listSessions},
		{method: "DELETE", path: "/api/v1/me/sessions/{id}", access: authed, h: s.revokeSession},
		{method: "POST", path: "/api/v1/me/2fa/setup", access: authed, h: s.setup2FA},
		{method: "POST", path: "/api/v1/me/2fa/confirm", access: authed, h: s.confirm2FA},
		{method: "POST", path: "/api/v1/me/2fa/disable", access: authed, h: s.disable2FA},

		{method: "GET", path: "/api/v1/features", access: authed, roles: adminOnly, h: s.listFeatures},
		{method: "GET", path: "/api/v1/feature-lists", access: authed, roles: adminOnly, h: s.listFeatureLists},
		{method: "POST", path: "/api/v1/feature-lists", access: authed, roles: adminOnly, h: s.createFeatureList},
		{method: "GET", path: "/api/v1/feature-lists/{id}", access: authed, roles: adminOnly, h: s.getFeatureList},
		{method: "PUT", path: "/api/v1/feature-lists/{id}", access: authed, roles: adminOnly, h: s.updateFeatureList},
		{method: "DELETE", path: "/api/v1/feature-lists/{id}", access: authed, roles: adminOnly, h: s.deleteFeatureList},
		{method: "GET", path: "/api/v1/packages", access: authed, roles: adminOnly, h: s.listPackages},
		{method: "POST", path: "/api/v1/packages", access: authed, roles: adminOnly, h: s.createPackage},
		{method: "GET", path: "/api/v1/packages/{id}", access: authed, roles: adminOnly, h: s.getPackage},
		{method: "PUT", path: "/api/v1/packages/{id}", access: authed, roles: adminOnly, h: s.updatePackage},
		{method: "DELETE", path: "/api/v1/packages/{id}", access: authed, roles: adminOnly, h: s.deletePackage},

		{method: "GET", path: "/api/v1/accounts", access: authed, roles: adminOnly, h: s.listAccounts},
		{method: "POST", path: "/api/v1/accounts", access: authed, roles: adminOnly, h: s.createAccount},
		{method: "GET", path: "/api/v1/accounts/{id}", access: authed, roles: adminOnly, h: s.getAccount},
		{method: "PUT", path: "/api/v1/accounts/{id}", access: authed, roles: adminOnly, h: s.updateAccount},
		{method: "POST", path: "/api/v1/accounts/{id}/suspend", access: authed, roles: adminOnly, h: s.suspendAccount},
		{method: "POST", path: "/api/v1/accounts/{id}/unsuspend", access: authed, roles: adminOnly, h: s.unsuspendAccount},
		{method: "POST", path: "/api/v1/accounts/{id}/password", access: authed, roles: adminOnly, h: s.setAccountPassword},
		{method: "POST", path: "/api/v1/accounts/{id}/terminate", access: authed, roles: adminOnly, h: s.terminateAccount},
		{method: "GET", path: "/api/v1/accounts/{id}/domains", access: authed, roles: adminOrUser, h: s.listDomains},
		{method: "POST", path: "/api/v1/accounts/{id}/domains", access: authed, roles: adminOrUser, h: s.addDomain},
		{method: "GET", path: "/api/v1/accounts/{id}/domain-verification", access: authed, roles: adminOrUser, h: s.domainVerification},
		{method: "PUT", path: "/api/v1/domains/{id}", access: authed, roles: adminOrUser, h: s.updateDomain},
		{method: "DELETE", path: "/api/v1/domains/{id}", access: authed, roles: adminOrUser, h: s.deleteDomain},
		{method: "GET", path: "/api/v1/accounts/{id}/redirects", access: authed, roles: adminOrUser, h: s.listRedirects},
		{method: "POST", path: "/api/v1/domains/{id}/redirects", access: authed, roles: adminOrUser, h: s.addRedirect},
		{method: "DELETE", path: "/api/v1/redirects/{id}", access: authed, roles: adminOrUser, h: s.deleteRedirect},
		{method: "GET", path: "/api/v1/jobs/{id}", access: authed, roles: adminOrUser, h: s.getJob},
		{method: "GET", path: "/api/v1/server/php-versions", access: authed, roles: adminOnly, h: s.listPHPVersions},
	}
	for _, rt := range s.routes {
		s.mux.Handle(rt.method+" "+rt.path, s.wrap(rt))
	}
	s.mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, r, errNotFound, s.Log)
	}))
	s.mux.Handle("/", s.spa())
	return s
}

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyPrincipal
	keyToken
)

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(keyRequestID).(string)
	return id
}

func principal(r *http.Request) *auth.Principal {
	p, _ := r.Context().Value(keyPrincipal).(*auth.Principal)
	return p
}

func sessionToken(r *http.Request) string {
	t, _ := r.Context().Value(keyToken).(string)
	return t
}

// client describes the caller for audit and rate limits. The panel is served
// directly, so RemoteAddr is the real peer; trusted proxy support comes with
// the proxy subdomains (01-architecture.md §10).
func client(r *http.Request) auth.Client {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return auth.Client{IP: host, UserAgent: r.UserAgent(), RequestID: requestID(r)}
}

// ServeHTTP applies the global middleware, then routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rid := ids.New()
	r = r.WithContext(context.WithValue(r.Context(), keyRequestID, rid))
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	s.securityHeaders(sw, r)
	sw.Header().Set("X-Request-ID", rid)

	defer func() {
		if v := recover(); v != nil {
			s.Log.Error("panic in handler", "request_id", rid, "panic", v, "stack", string(debug.Stack()))
			if !sw.wrote {
				writeProblem(sw, r, newAPIError(http.StatusInternalServerError, "internal", "internal error"), s.Log)
			}
		}
		s.Log.Info("http request", "request_id", rid, "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "duration", time.Since(start), "ip", client(r).IP)
	}()
	s.mux.ServeHTTP(sw, r)
}

func (s *Server) securityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	if s.SecureCookies {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		h.Set("Cache-Control", "no-store")
	}
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// wrap enforces the route's access rules, then runs the handler.
func (s *Server) wrap(rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, err := s.guard(r, rt)
		if err == nil {
			err = rt.h(w, r)
		}
		if err != nil {
			writeProblem(w, r, err, s.Log)
		}
	})
}

func (s *Server) guard(r *http.Request, rt route) (*http.Request, error) {
	unsafe := !isSafeMethod(r.Method)
	if unsafe && !sameOrigin(r) {
		return r, errCrossOrigin
	}
	if rt.access == public {
		return r, nil
	}
	c, err := r.Cookie(s.cookieName)
	if err != nil || c.Value == "" {
		return r, auth.ErrUnauthenticated
	}
	token := c.Value
	if unsafe && !auth.CheckCSRF(token, r.Header.Get("X-CSRF-Token")) {
		return r, errCSRF
	}
	ctx := context.WithValue(r.Context(), keyToken, token)
	if rt.access == authed {
		p, err := s.Auth.Authenticate(ctx, token)
		if err != nil {
			return r, err
		}
		if len(rt.roles) > 0 && !slices.Contains(rt.roles, p.Login.Role) {
			return r, apperr.ErrForbidden
		}
		if p.Login.MustChangePassword && !rt.allowMustChange {
			return r, errMustChangePwd
		}
		ctx = context.WithValue(ctx, keyPrincipal, p)
	}
	return r.WithContext(ctx), nil
}

// sameOrigin refuses state-changing requests that a browser marks as
// coming from another site. Non-browser clients send neither header.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" || site == "same-site" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	return true
}

// setSessionCookie: Secure is false only in plain-HTTP local development (api.insecure_dev_http).
func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure depends on dev mode, see above
		Name: s.cookieName, Value: token, Path: "/",
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure depends on dev mode
		Name: s.cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}
