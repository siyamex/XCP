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
	"github.com/siyamex/XCP/internal/backups"
	"github.com/siyamex/XCP/internal/cronjobs"
	"github.com/siyamex/XCP/internal/databases"
	"github.com/siyamex/XCP/internal/domains"
	"github.com/siyamex/XCP/internal/files"
	"github.com/siyamex/XCP/internal/firewall"
	"github.com/siyamex/XCP/internal/ftp"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/jobs"
	"github.com/siyamex/XCP/internal/mail"
	"github.com/siyamex/XCP/internal/messages"
	"github.com/siyamex/XCP/internal/plans"
	"github.com/siyamex/XCP/internal/resellers"
	"github.com/siyamex/XCP/internal/serverinfo"
	"github.com/siyamex/XCP/internal/serversettings"
	"github.com/siyamex/XCP/internal/ssl"
	"github.com/siyamex/XCP/internal/stats"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/zones"
)

// Deps are the services the HTTP layer needs.
type Deps struct {
	Auth       *auth.Service
	Plans      *plans.Service
	Accounts   *accounts.Service
	Domains    *domains.Service
	Databases  *databases.Service
	Mail       *mail.Service
	Files      *files.Service
	FTP        *ftp.Service
	Cron       *cronjobs.Service
	Stats      *stats.Service
	Backups    *backups.Service
	ServerInfo *serverinfo.Service
	Settings   *serversettings.Service
	Resellers  *resellers.Service
	Messages   *messages.Service
	Firewall   *firewall.Service
	Zones      *zones.Service
	SSL        *ssl.Service
	Jobs       *jobs.Queue
	Agent      agentrpc.Client
	Log        *slog.Logger
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

// adminOrReseller is for managing customers' accounts and the packages for them.
var adminOrReseller = []string{store.RoleAdmin, store.RoleReseller}

// resellerOnly is for a reseller's own pages.
var resellerOnly = []string{store.RoleReseller}

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
		{method: "GET", path: "/api/v1/me/tokens", access: authed, h: s.listTokens},
		{method: "POST", path: "/api/v1/me/tokens", access: authed, h: s.createToken},
		{method: "DELETE", path: "/api/v1/me/tokens/{id}", access: authed, h: s.revokeToken},
		{method: "GET", path: "/api/v1/me/sessions", access: authed, h: s.listSessions},
		{method: "DELETE", path: "/api/v1/me/sessions/{id}", access: authed, h: s.revokeSession},
		{method: "POST", path: "/api/v1/me/2fa/setup", access: authed, allowMustChange: true, h: s.setup2FA},
		{method: "POST", path: "/api/v1/me/2fa/confirm", access: authed, allowMustChange: true, h: s.confirm2FA},
		{method: "POST", path: "/api/v1/me/2fa/disable", access: authed, h: s.disable2FA},

		{method: "GET", path: "/api/v1/features", access: authed, roles: adminOnly, h: s.listFeatures},
		{method: "GET", path: "/api/v1/feature-lists", access: authed, roles: adminOrReseller, h: s.listFeatureLists},
		{method: "POST", path: "/api/v1/feature-lists", access: authed, roles: adminOnly, h: s.createFeatureList},
		{method: "GET", path: "/api/v1/feature-lists/{id}", access: authed, roles: adminOrReseller, h: s.getFeatureList},
		{method: "PUT", path: "/api/v1/feature-lists/{id}", access: authed, roles: adminOnly, h: s.updateFeatureList},
		{method: "DELETE", path: "/api/v1/feature-lists/{id}", access: authed, roles: adminOnly, h: s.deleteFeatureList},
		{method: "GET", path: "/api/v1/packages", access: authed, roles: adminOrReseller, h: s.listPackages},
		{method: "POST", path: "/api/v1/packages", access: authed, roles: adminOrReseller, h: s.createPackage},
		{method: "GET", path: "/api/v1/packages/{id}", access: authed, roles: adminOrReseller, h: s.getPackage},
		{method: "PUT", path: "/api/v1/packages/{id}", access: authed, roles: adminOrReseller, h: s.updatePackage},
		{method: "DELETE", path: "/api/v1/packages/{id}", access: authed, roles: adminOrReseller, h: s.deletePackage},

		{method: "GET", path: "/api/v1/accounts", access: authed, roles: adminOrReseller, h: s.listAccounts},
		{method: "POST", path: "/api/v1/accounts", access: authed, roles: adminOrReseller, h: s.createAccount},
		{method: "GET", path: "/api/v1/accounts/{id}", access: authed, roles: adminOrReseller, h: s.getAccount},
		{method: "PUT", path: "/api/v1/accounts/{id}", access: authed, roles: adminOrReseller, h: s.updateAccount},
		{method: "POST", path: "/api/v1/accounts/{id}/suspend", access: authed, roles: adminOrReseller, h: s.suspendAccount},
		{method: "POST", path: "/api/v1/accounts/{id}/unsuspend", access: authed, roles: adminOrReseller, h: s.unsuspendAccount},
		{method: "POST", path: "/api/v1/accounts/{id}/password", access: authed, roles: adminOrReseller, h: s.setAccountPassword},
		{method: "POST", path: "/api/v1/accounts/{id}/impersonate", access: authed, roles: adminOrReseller, h: s.impersonateAccount},
		{method: "POST", path: "/api/v1/accounts/{id}/terminate", access: authed, roles: adminOrReseller, h: s.terminateAccount},
		{method: "GET", path: "/api/v1/accounts/{id}/domains", access: authed, roles: adminOrUser, h: s.listDomains},
		{method: "POST", path: "/api/v1/accounts/{id}/domains", access: authed, roles: adminOrUser, h: s.addDomain},
		{method: "GET", path: "/api/v1/accounts/{id}/domain-verification", access: authed, roles: adminOrUser, h: s.domainVerification},
		{method: "PUT", path: "/api/v1/domains/{id}", access: authed, roles: adminOrUser, h: s.updateDomain},
		{method: "DELETE", path: "/api/v1/domains/{id}", access: authed, roles: adminOrUser, h: s.deleteDomain},
		{method: "GET", path: "/api/v1/accounts/{id}/redirects", access: authed, roles: adminOrUser, h: s.listRedirects},
		{method: "POST", path: "/api/v1/domains/{id}/redirects", access: authed, roles: adminOrUser, h: s.addRedirect},
		{method: "GET", path: "/api/v1/domains/{id}/web", access: authed, roles: adminOrUser, h: s.getWebSettings},
		{method: "PUT", path: "/api/v1/domains/{id}/web", access: authed, roles: adminOrUser, h: s.putWebSettings},
		{method: "PUT", path: "/api/v1/domains/{id}/protected-dirs", access: authed, roles: adminOrUser, h: s.putProtectedDirs},
		{method: "DELETE", path: "/api/v1/redirects/{id}", access: authed, roles: adminOrUser, h: s.deleteRedirect},
		{method: "GET", path: "/api/v1/dns/zones", access: authed, roles: adminOrUser, h: s.listZones},
		{method: "GET", path: "/api/v1/dns/zones/{id}", access: authed, roles: adminOrUser, h: s.getZone},
		{method: "PUT", path: "/api/v1/dns/zones/{id}", access: authed, roles: adminOrUser, h: s.updateZone},
		{method: "POST", path: "/api/v1/dns/zones/{id}/records", access: authed, roles: adminOrUser, h: s.addRecord},
		{method: "PUT", path: "/api/v1/dns/records/{id}", access: authed, roles: adminOrUser, h: s.updateRecord},
		{method: "DELETE", path: "/api/v1/dns/records/{id}", access: authed, roles: adminOrUser, h: s.deleteRecord},
		{method: "GET", path: "/api/v1/server/dns", access: authed, roles: adminOnly, h: s.getDNSSettings},
		{method: "PUT", path: "/api/v1/server/dns", access: authed, roles: adminOnly, h: s.saveDNSSettings},
		{method: "GET", path: "/api/v1/server/ssl", access: authed, roles: adminOnly, h: s.getSSLSettings},
		{method: "PUT", path: "/api/v1/server/ssl", access: authed, roles: adminOnly, h: s.saveSSLSettings},
		{method: "POST", path: "/api/v1/server/ssl/run", access: authed, roles: adminOnly, h: s.runAutoSSL},
		{method: "GET", path: "/api/v1/ssl/certificates", access: authed, roles: adminOrUser, h: s.listCertificates},
		{method: "GET", path: "/api/v1/accounts/{id}/ssl", access: authed, roles: adminOrUser, h: s.accountSSL},
		{method: "POST", path: "/api/v1/accounts/{id}/ssl/run", access: authed, roles: adminOrUser, h: s.runAutoSSL},
		{method: "PUT", path: "/api/v1/domains/{id}/ssl", access: authed, roles: adminOrUser, h: s.setDomainSSL},
		{method: "PUT", path: "/api/v1/domains/{id}/certificate", access: authed, roles: adminOrUser, h: s.uploadCertificate},
		{method: "DELETE", path: "/api/v1/domains/{id}/certificate", access: authed, roles: adminOrUser, h: s.deleteCertificate},
		{method: "GET", path: "/api/v1/accounts/{id}/databases", access: authed, roles: adminOrUser, h: s.databasesOverview},
		{method: "POST", path: "/api/v1/accounts/{id}/databases", access: authed, roles: adminOrUser, h: s.createDatabase},
		{method: "POST", path: "/api/v1/accounts/{id}/database-wizard", access: authed, roles: adminOrUser, h: s.databaseWizard},
		{method: "PUT", path: "/api/v1/databases/{id}", access: authed, roles: adminOrUser, h: s.renameDatabase},
		{method: "DELETE", path: "/api/v1/databases/{id}", access: authed, roles: adminOrUser, h: s.deleteDatabase},
		{method: "POST", path: "/api/v1/accounts/{id}/database-users", access: authed, roles: adminOrUser, h: s.createDBUser},
		{method: "PUT", path: "/api/v1/database-users/{id}/password", access: authed, roles: adminOrUser, h: s.setDBUserPassword},
		{method: "DELETE", path: "/api/v1/database-users/{id}", access: authed, roles: adminOrUser, h: s.deleteDBUser},
		{method: "PUT", path: "/api/v1/database-users/{id}/grants/{database_id}", access: authed, roles: adminOrUser, h: s.setDBGrant},
		{method: "DELETE", path: "/api/v1/database-users/{id}/grants/{database_id}", access: authed, roles: adminOrUser, h: s.revokeDBGrant},
		{method: "POST", path: "/api/v1/accounts/{id}/phpmyadmin", access: authed, roles: adminOrUser, h: s.phpMyAdminSignon},
		{method: "GET", path: "/api/v1/server/mysql", access: authed, roles: adminOnly, h: s.mysqlStatus},
		{method: "PUT", path: "/api/v1/server/mysql/root-password", access: authed, roles: adminOnly, h: s.setMySQLRootPassword},
		{method: "GET", path: "/api/v1/mailboxes/{id}/spam", access: authed, roles: adminOrUser, h: s.getSpam},
		{method: "PUT", path: "/api/v1/mailboxes/{id}/spam", access: authed, roles: adminOrUser, h: s.putSpam},
		{method: "GET", path: "/api/v1/accounts/{id}/mail", access: authed, roles: adminOrUser, h: s.mailOverview},
		{method: "POST", path: "/api/v1/accounts/{id}/mailboxes", access: authed, roles: adminOrUser, h: s.createMailbox},
		{method: "PUT", path: "/api/v1/mailboxes/{id}", access: authed, roles: adminOrUser, h: s.updateMailbox},
		{method: "PUT", path: "/api/v1/mailboxes/{id}/password", access: authed, roles: adminOrUser, h: s.setMailboxPassword},
		{method: "DELETE", path: "/api/v1/mailboxes/{id}", access: authed, roles: adminOrUser, h: s.deleteMailbox},
		{method: "PUT", path: "/api/v1/mailboxes/{id}/autoresponder", access: authed, roles: adminOrUser, h: s.setAutoresponder},
		{method: "DELETE", path: "/api/v1/mailboxes/{id}/autoresponder", access: authed, roles: adminOrUser, h: s.deleteAutoresponder},
		{method: "POST", path: "/api/v1/mailboxes/{id}/webmail", access: authed, roles: adminOrUser, h: s.webmailSignon},
		{method: "POST", path: "/api/v1/accounts/{id}/forwarders", access: authed, roles: adminOrUser, h: s.createForwarder},
		{method: "DELETE", path: "/api/v1/forwarders/{id}", access: authed, roles: adminOrUser, h: s.deleteForwarder},
		{method: "PUT", path: "/api/v1/domains/{id}/mail/catch-all", access: authed, roles: adminOrUser, h: s.setCatchAll},
		{method: "GET", path: "/api/v1/domains/{id}/mail/deliverability", access: authed, roles: adminOrUser, h: s.mailDeliverability},
		{method: "POST", path: "/api/v1/domains/{id}/mail/repair", access: authed, roles: adminOrUser, h: s.repairMailDNS},
		{method: "GET", path: "/api/v1/server/mail", access: authed, roles: adminOnly, h: s.getMailSettings},
		{method: "PUT", path: "/api/v1/server/mail", access: authed, roles: adminOnly, h: s.putMailSettings},
		{method: "GET", path: "/api/v1/server/firewall", access: authed, roles: adminOnly, h: s.getFirewall},
		{method: "PUT", path: "/api/v1/server/firewall", access: authed, roles: adminOnly, h: s.putFirewall},
		{method: "POST", path: "/api/v1/server/firewall/bans", access: authed, roles: adminOnly, h: s.banIP},
		{method: "DELETE", path: "/api/v1/server/firewall/bans/{id}", access: authed, roles: adminOnly, h: s.unbanIP},
		{method: "GET", path: "/api/v1/server/mail/queue", access: authed, roles: adminOnly, h: s.mailQueue},
		{method: "POST", path: "/api/v1/server/mail/queue", access: authed, roles: adminOnly, h: s.mailQueueAction},
		{method: "GET", path: "/api/v1/messages/welcome", access: authed, roles: adminOrReseller, h: s.getWelcome},
		{method: "PUT", path: "/api/v1/messages/welcome", access: authed, roles: adminOrReseller, h: s.putWelcome},
		{method: "POST", path: "/api/v1/messages/broadcast", access: authed, roles: adminOrReseller, h: s.broadcast},
		{method: "GET", path: "/api/v1/resellers", access: authed, roles: adminOnly, h: s.listResellers},
		{method: "POST", path: "/api/v1/resellers", access: authed, roles: adminOnly, h: s.createReseller},
		{method: "PUT", path: "/api/v1/resellers/{id}/limits", access: authed, roles: adminOnly, h: s.setResellerLimits},
		{method: "POST", path: "/api/v1/resellers/{id}/suspend", access: authed, roles: adminOnly, h: s.suspendReseller},
		{method: "POST", path: "/api/v1/resellers/{id}/unsuspend", access: authed, roles: adminOnly, h: s.unsuspendReseller},
		{method: "GET", path: "/api/v1/reseller/overview", access: authed, roles: resellerOnly, h: s.resellerOverview},
		{method: "GET", path: "/api/v1/server/settings", access: authed, roles: adminOnly, h: s.getSettings},
		{method: "PUT", path: "/api/v1/server/settings", access: authed, roles: adminOnly, h: s.putSettings},
		{method: "GET", path: "/api/v1/server/setup", access: authed, roles: adminOnly, h: s.getSetup},
		{method: "PUT", path: "/api/v1/server/setup", access: authed, roles: adminOnly, h: s.putSetup},
		{method: "PUT", path: "/api/v1/server/hostname", access: authed, roles: adminOnly, h: s.putHostname},
		{method: "GET", path: "/api/v1/server/updates", access: authed, roles: adminOnly, h: s.getUpdates},
		{method: "POST", path: "/api/v1/server/reboot", access: authed, roles: adminOnly, h: s.postReboot},
		{method: "POST", path: "/api/v1/server/rebuild", access: authed, roles: adminOnly, h: s.postRebuild},
		{method: "GET", path: "/api/v1/server/backups", access: authed, roles: adminOnly, h: s.orphanBackups},
		{method: "POST", path: "/api/v1/server/backups/{id}/restore", access: authed, roles: adminOnly, h: s.restoreBackup},
		{method: "GET", path: "/api/v1/server/status", access: authed, roles: adminOnly, h: s.serverStatus},
		{method: "GET", path: "/api/v1/server/services", access: authed, roles: adminOnly, h: s.listServices},
		{method: "POST", path: "/api/v1/server/services/{id}/{action}", access: authed, roles: adminOnly, h: s.serviceAction},
		{method: "GET", path: "/api/v1/server/services/{id}/log", access: authed, roles: adminOnly, h: s.serviceLog},
		{method: "GET", path: "/api/v1/server/jobs", access: authed, roles: adminOnly, h: s.listJobs},
		{method: "POST", path: "/api/v1/server/jobs/{id}/cancel", access: authed, roles: adminOnly, h: s.cancelJob},
		{method: "POST", path: "/api/v1/server/jobs/{id}/retry", access: authed, roles: adminOnly, h: s.retryJob},
		{method: "GET", path: "/api/v1/server/sessions", access: authed, roles: adminOnly, h: s.allSessions},
		{method: "DELETE", path: "/api/v1/server/sessions/{id}", access: authed, roles: adminOnly, h: s.revokeAnySession},
		{method: "GET", path: "/api/v1/server/logins", access: authed, roles: adminOnly, h: s.loginHistory},
		{method: "GET", path: "/api/v1/accounts/{id}/backups", access: authed, roles: adminOrUser, h: s.backupsOverview},
		{method: "POST", path: "/api/v1/accounts/{id}/backups", access: authed, roles: adminOrUser, h: s.createBackup},
		{method: "DELETE", path: "/api/v1/backups/{id}", access: authed, roles: adminOrUser, h: s.deleteBackup},
		{method: "GET", path: "/api/v1/backups/{id}/download", access: authed, roles: adminOrUser, h: s.downloadBackup},
		{method: "GET", path: "/api/v1/server/backups/schedule", access: authed, roles: adminOnly, h: s.getBackupSchedule},
		{method: "PUT", path: "/api/v1/server/backups/schedule", access: authed, roles: adminOnly, h: s.putBackupSchedule},
		{method: "GET", path: "/api/v1/accounts/{id}/stats/bandwidth", access: authed, roles: adminOrUser, h: s.bandwidth},
		{method: "GET", path: "/api/v1/accounts/{id}/logs/{kind}", access: authed, roles: adminOrUser, h: s.tailLog},
		{method: "GET", path: "/api/v1/accounts/{id}/logs/{kind}/download", access: authed, roles: adminOrUser, h: s.downloadLog},
		{method: "GET", path: "/api/v1/accounts/{id}/cron", access: authed, roles: adminOrUser, h: s.cronOverview},
		{method: "POST", path: "/api/v1/accounts/{id}/cron", access: authed, roles: adminOrUser, h: s.createCronJob},
		{method: "PUT", path: "/api/v1/cron/{id}", access: authed, roles: adminOrUser, h: s.updateCronJob},
		{method: "DELETE", path: "/api/v1/cron/{id}", access: authed, roles: adminOrUser, h: s.deleteCronJob},
		{method: "GET", path: "/api/v1/accounts/{id}/ftp", access: authed, roles: adminOrUser, h: s.ftpOverview},
		{method: "POST", path: "/api/v1/accounts/{id}/ftp", access: authed, roles: adminOrUser, h: s.createFTPAccount},
		{method: "GET", path: "/api/v1/accounts/{id}/ftp/sessions", access: authed, roles: adminOrUser, h: s.ftpSessions},
		{method: "DELETE", path: "/api/v1/accounts/{id}/ftp/sessions/{pid}", access: authed, roles: adminOrUser, h: s.endFTPSession},
		{method: "PUT", path: "/api/v1/ftp/{id}", access: authed, roles: adminOrUser, h: s.updateFTPAccount},
		{method: "PUT", path: "/api/v1/ftp/{id}/password", access: authed, roles: adminOrUser, h: s.setFTPPassword},
		{method: "DELETE", path: "/api/v1/ftp/{id}", access: authed, roles: adminOrUser, h: s.deleteFTPAccount},
		{method: "GET", path: "/api/v1/accounts/{id}/files", access: authed, roles: adminOrUser, h: s.listFiles},
		{method: "GET", path: "/api/v1/accounts/{id}/files/download", access: authed, roles: adminOrUser, h: s.downloadFile},
		{method: "PUT", path: "/api/v1/accounts/{id}/files/upload", access: authed, roles: adminOrUser, h: s.uploadFile},
		{method: "POST", path: "/api/v1/accounts/{id}/files/{op}", access: authed, roles: adminOrUser, h: s.fileOp},
		{method: "GET", path: "/api/v1/accounts/{id}/files/search", access: authed, roles: adminOrUser, h: s.searchFiles},
		{method: "GET", path: "/api/v1/accounts/{id}/files/usage", access: authed, roles: adminOrUser, h: s.fileUsage},
		{method: "GET", path: "/api/v1/accounts/{id}/files/text", access: authed, roles: adminOrUser, h: s.readFileText},
		{method: "PUT", path: "/api/v1/accounts/{id}/files/text", access: authed, roles: adminOrUser, h: s.writeFileText},
		{method: "GET", path: "/api/v1/jobs/{id}", access: authed, roles: adminOrUser, h: s.getJob},
		{method: "GET", path: "/api/v1/server/php-versions", access: authed, roles: adminOrReseller, h: s.listPHPVersions},
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
	h.Set("Content-Security-Policy", cspPolicy(""))
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
	if bearer, ok := bearerToken(r); ok && rt.access == authed {
		return s.guardToken(r, rt, bearer, unsafe)
	}
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
		if !rt.allowMustChange && s.Auth.MFAEnrollmentRequired(p.Login) {
			return r, errMFARequired
		}
		// Someone helping a customer cannot change the customer's sign-in.
		if p.Session.ImpersonatorID != "" && unsafe && strings.HasPrefix(rt.path, "/api/v1/me/") {
			return r, errImpersonating
		}
		ctx = context.WithValue(ctx, keyPrincipal, p)
	}
	return r.WithContext(ctx), nil
}

// bearerToken returns the API token of an Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:]), true
	}
	return "", false
}

// guardToken authenticates a request that carries an API token (ADR-0021).
// Tokens need no CSRF token (they are not sent by browsers on their own),
// but they cannot use the pages meant for a person with a session: the
// account's security pages and everything that confirms a password.
func (s *Server) guardToken(r *http.Request, rt route, token string, unsafe bool) (*http.Request, error) {
	tp, err := s.Auth.AuthenticateToken(r.Context(), token, client(r).IP)
	if err != nil {
		return r, err
	}
	p := tp.Principal
	switch {
	case len(rt.roles) > 0 && !slices.Contains(rt.roles, p.Login.Role):
		return r, apperr.ErrForbidden
	case unsafe && tp.Scope != store.TokenWrite:
		return r, errTokenReadOnly
	case !isTokenSafeRoute(rt):
		return r, errTokenForbidden
	case p.Login.MustChangePassword || s.Auth.MFAEnrollmentRequired(p.Login):
		return r, errMFARequired
	}
	return r.WithContext(context.WithValue(r.Context(), keyPrincipal, p)), nil
}

// isTokenSafeRoute reports whether a route may be used with a token: not
// the sign-in, security and session pages, which are for a person.
func isTokenSafeRoute(rt route) bool {
	return rt.path == "/api/v1/me" || !strings.HasPrefix(rt.path, "/api/v1/me/") && !strings.HasPrefix(rt.path, "/api/v1/auth/")
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
