# Status

Update this file in the same change that finishes a task.
Status: `todo` · `doing` · `done`.

## P0 — Foundations

| # | Task | Status | Notes |
|---|---|---|---|
| 1 | Repo init: go.mod, Makefile, lint config, CI, LICENSE, SECURITY.md, ADR template | done | Go 1.26 (toolchain pinned), AGPL-3.0 |
| 2 | `config`, `logging` (slog + secret redaction), `execx`, `fsx` | done | fsx: openat2 on Linux, os.Root dev fallback elsewhere |
| 3 | `validate` + fuzz tests | done | username, password, domain/IDN, wildcard, mailbox, email, IP/CIDR, port, path, cron |
| 4 | SQLite store, migrations, base tables | done | hand-written SQL + built-in migration runner (ADR-0001); tables: logins, sessions, settings, audit_events (append-only triggers), jobs, job_logs; `ids` (ULID) |
| 5 | Job queue + scheduler | done | lease + heartbeat, retry back-off, permanent errors, per-key FIFO, per-kind concurrency, cancel, unique, logs; cron scheduler |
| 6 | Agent RPC contract + fake agent | done | `proto/xcp/agent/v1`; ops: Ping, ServiceStatus, ServiceAction, FileWriteManaged (atomic, validator + rollback), FileRemoveManaged; SO_PEERCRED handshake + per-call UID check; `cmd/xcp-agent` + systemd unit. Not yet run on a real Linux host. |
| 7 | Auth: login, sessions, CSRF, TOTP, rate limit, audit | done | service layer only (`internal/auth`, `audit`, `secretbox`): argon2id with concurrency cap, hashed session tokens, idle + absolute timeouts, TOTP (RFC 6238) with replay protection, recovery codes, re-auth, per-IP/user/2FA rate limits, hash-chained audit log, XChaCha20 master-key encryption. HTTP endpoints and `/me` moved to task 8. |
| 8 | OpenAPI skeleton + problem+json; HTTP auth (cookies, CSRF header), `/auth/*`, `/me` | done | `internal/httpapi` + `cmd/xcp-api` (`create-admin` later moved to `xcpctl admin create`); 12 routes; spec parity test (ADR-0002); security headers, request IDs, same-origin + CSRF checks, JSON-only bodies with size limit; dev config `packaging/dev/xcp.toml`. Smoke-tested with curl on Windows. |
| 9 | Web SPA shell | done | React 19 + TS + Vite 7 + Tailwind 4 + TanStack Router/Query + i18next; types generated from the spec; pages: login (+2FA step), dashboard, login & security (password, 2FA with QR + recovery codes, sessions); role-based menu with planned items; light/dark/system theme; mobile nav; embedded into xcp-api (`web/embed.go`, SPA fallback, immutable asset caching). Verified in headless Chrome: full login/2FA-setup/logout flow, no CSP violations. |
| 10 | `xcpctl` + `xcp-install` skeletons | done | `xcpctl`: login/me/sessions/logout over the API, `admin create [--if-none]`, `doctor` (local commands drop root to the service user). `xcp-install`: user, dirs, binaries, config, master key, self-signed cert, systemd units (xcp-api sandbox score 1.7), first admin with generated password + forced change; idempotent; `--dry-run`. Verified in Ubuntu 24.04 + systemd (Docker): `test/e2e/install/run.sh`, also in CI. |

**P0 is complete.**

## Verification notes

- Linux-only tests (`fsx_linux_test.go`, `execx_unix_test.go`,
  `peercred_linux_test.go`) pass on Linux (run in CI, and locally with
  Docker: `make test-linux`).
- `make e2e-install` installs into Ubuntu 24.04 with systemd in Docker.
- 2026-10-27: installed and tested on an Ubuntu 24.04 WSL2 VM (systemd as
  PID 1): first install, browser journey (forced password change, 2FA
  setup, re-login with 2FA), services auto-start when the VM starts,
  systemd restarts a SIGKILLed xcp-api in ~4 s, binary upgrade through the
  installer keeps all data, re-run changes nothing.
  Docker cannot test disk quotas, real DNS or public TLS: P1 needs a VM or VPS.

## Follow-ups noted during P0

- xcp-agent's systemd sandbox scores 8.2 ("exposed") because it runs as root
  with broad access. Tighten it (ProtectSystem with explicit ReadWritePaths,
  CapabilityBoundingSet) once P1 shows exactly what it must touch.
- The browser smoke test used in task 9 was a throwaway script; add a real
  Playwright suite to `test/e2e/` with the first P1 UI pages.
- Frontend has no ESLint yet.
- Found on the VM: systemd's `RestrictSUIDSGID=` makes `openat2()` fail with
  ENOSYS, which broke all fsx file access in xcp-agent. Removed it from the
  agent unit; `xcpctl doctor` now makes the agent write a file, so the CI
  installer test catches this class of problem. xcp-api keeps the setting:
  its one file write, the ACME answers in its own folder, uses `os.Root`.
- Disk quotas are applied only where the home filesystem has user quotas
  (not on WSL); `xcp-install` should offer to enable them on a real server.
- Account job polling in the UI passes the job ID in the URL; replace with
  router search params once more pages need it.
- PHP-FPM pools run in each version's shared php-fpm service, not in the
  account's systemd slice, so CPU/memory limits do not cover PHP yet. Fix
  with one FPM master per account (or per-pool cgroups) before production.
- Only the distro's PHP (8.3 on Ubuntu 24.04) is installed; installing more
  versions (Sury/Remi) is ADM-WEB-04's second half.
- Domains: the server's own host name is not reserved yet, so a user could
  add it as a domain. Reserve it (and the ACME path) when the config learns
  the host name with hostname certificates (SSL, task 6).
- Domains: all vhosts of an account log to the same files; per-domain logs
  (or `%v` in the format) are needed for per-domain bandwidth (`xcp-logd`).
- Domains: "force HTTPS" (USR-DOM-05) needs certificates and an HTTPS vhost;
  it arrives with SSL (task 6).
- DNS: ALIAS records need PowerDNS's resolver settings, and PTR records need
  reverse zones and IP ownership (IP management, P2); both are left out.
- DNS: every zone belongs to an account; a zone for the server's own domain
  (ns1/ns2 glue) needs an account for now.
- DNS: the default name servers are ns1/ns2 of the host name's domain, so a
  host without a full domain name (like WSL) starts with none; the settings
  page says so. Zones made while the server's IPv4 was unknown got no A
  records (only a change of address moves records).
- SSL: expiry "alerts" are only the dashboard's highlighting; mail
  notifications need the notification system. The AutoSSL time is fixed.
- SSL: wildcard certificates (DNS-01, USR-SSL-02) are P2; until then a
  wildcard subdomain needs an uploaded certificate.
- Apache serves static files as www-data, which reads every public_html.
  Each vhost now allows symlinks in the home folder (document root
  included) only with `SymLinksIfOwnerMatch`; found on the VM that a
  document root swapped for a symlink was followed before. Apache's owner
  check has a known check-then-open race, so stronger isolation is still
  needed for production (per-account file serving or a kernel-level guard).
- Databases: MariaDB only (no MySQL 8: the agent reads mysql.global_priv);
  remote access (USR-DB-05), import/export and repair (USR-DB-06/07) are P2.
  PHP's MySQL extension is installed for the distribution's PHP only; the
  multi-version PHP installer must add it per version.
- Databases: a database in MariaDB that the panel does not know (made by
  root by hand) is left alone and not shown; the orphan list is ADM-DB-02 (P2).
- phpMyAdmin: a session shows the databases that existed at sign-on; it is
  served on the host name over 443, so a firewall (P2) must keep 443 open.
- Mail: pipe scripts run as the account user with Postfix's limits only,
  not in the account's slice (that waits for the jail work, P3). Mail
  certificates are the host name's
  for every domain (per-domain SNI later); mail clients must use the
  server's host name.
- Mail: deleted mailboxes keep their Maildir in the account's home. No
  quota warning mails yet.
- Webmail: the user's own Sieve filters and ManageSieve are P2 (USR-MAIL-07).
- Done after P1 #9: `xcpctl doctor` checks every hosting service through
  the agent (not installed = warning, stopped = failure with the journal
  command) and that each answers (phpMyAdmin over HTTPS, a DNS query, the
  SMTP banner, the IMAPS greeting, Rspamd's milter port, MariaDB through the
  agent, webmail); an MX, A or AAAA change re-applies the account's mail,
  so "auto" routing follows it at once; a Roundcube upgrade runs Roundcube's
  own database updater as `xcp-rc`.
- Files: the trash has no restore or empty yet (USR-FILE-04, P2); uploads
  are one request per file (no resume); symlinks are shown, not followed;
  the helper unit assumes homes in /home.
- Mail on the VM and in CI is tested locally only: outgoing port 25 is
  blocked there, so delivery to other servers is not exercised.

## P1 — MVP progress

| Order | Task | Feature IDs | Status | Notes |
|---|---|---|---|---|
| 1 | Packages + feature lists | ADM-PKG-01, ADM-PKG-02 | done | `internal/plans`: limits as JSON (null = unlimited), 24-feature catalog, Default list + package on first start, admin-only (403 otherwise), audit in same tx, in-use list cannot be deleted; API `/features`, `/feature-lists`, `/packages`; UI pages Packages + Feature lists. |
| 2 | Accounts (Linux user, home, quota, slice) | ADM-ACC-01..06, 09, 11 | done | `internal/accounts` + agent ops AccountEnsure / AccountSetSuspended / AccountDelete: Linux user (UID 10000+, marked `xcp account`; foreign users refused), home 0711 + public_html 0750 group www-data, systemd slice + login-session limits, quota where supported; create/update/suspend/unsuspend/password/terminate as jobs (in xcp-api, ADR-0003); UI list/create/detail with live job status. Verified end to end on the Ubuntu VM. |
| 3 | Apache + PHP-FPM | ADM-WEB-01, 04; USR-WEB-01 | done | agent op SiteApply/SiteRemove/PHPVersions; configs rendered in the agent from typed fields (ADR-0004), checked with apachectl -t / php-fpm -t with rollback; one PHP-FPM pool per account running as the account user, open_basedir to its home, own tmp; suspended sites serve a notice and run no PHP; PHP version per account (package-allowed, installed); installer installs apache2 + php-fpm (`--no-web` to skip). Verified on the VM and in CI (`test/e2e/install/websites.py`). |
| 4 | Domains (addon, sub, alias, redirects) | USR-DOM-01..04, 06, 07; 05 without force HTTPS | done | `internal/domains` + tables `domains` (primary rows backfilled) and `redirects`: addon domains, subdomains (wildcard `*`), aliases, document root per domain (created by the agent if missing, through fsx, 0750 group www-data), www/bare canonical redirect, redirects 301/302/307/308 with or without the rest of the path; package limits (addon/sub/alias counts) and feature list (`domains`, `redirects`) for user logins; takeover protection: a user adding a name under a registered domain another account uses must publish a TXT record `_xcp-verify.<name>` (token derived from the master key). Every change runs job `site.apply`. Agent renders one vhost per domain, wildcards in a file loaded last. API `/accounts/{id}/domains`, `/domains/{id}`, redirects, `/domain-verification`; users reach their own account (`/me` has `account_id`) and its jobs. UI: Domains section on the account page and a Domains page for users. Verified on the VM (`websites.py`, 30 checks) and in the browser. Force HTTPS comes with SSL (task 6). |
| 5 | DNS (PowerDNS, zones, editor) | ADM-DNS-01..03; USR-DNS-01 (without ALIAS, PTR), 02, 03 | done | Installer sets up PowerDNS (gsqlite3; API on localhost, key only for xcp-agent; `--no-dns` to skip). Agent op DNSZoneApply/DNSZoneDelete: diff-based PATCH, SOA serial kept by the agent, NS from settings; records validated with miekg/dns in `internal/dnsrr` by API and agent alike. `internal/zones`: a zone per domain from the admin's template (`{domain}`, `{ip4}`, `{ip6}`), records in the existing zone for subdomains and nested domains (removed with the domain), record editor with zone-wide checks, email routing auto/local/remote/backup (auto from the MX records; for the mail service), DNS settings (name servers with a DNS check, server addresses, TTL, template); a new server address moves the A/AAAA records. Jobs `dns.apply`/`dns.delete` per zone name; `dns.sync` applies zones the server lacks. API `/dns/zones`, `/dns/records`, `/server/dns`; UI DNS pages for admins and users. Verified on the VM with dig (`test/e2e/install/dns.py`, 18 checks) and in the browser. |
| 6 | SSL (AutoSSL, hostname and service certificates) | ADM-SSL-01, 02, 05; USR-SSL-01, 03, 06; USR-DOM-05 force HTTPS | done | ADR-0005: ACME with golang.org/x/crypto/acme (Let's Encrypt, staging, or any directory with CA bundle and EAB), HTTP-01 answers written by xcp-api to /var/www/xcp-acme and served by Apache for every name; keys encrypted in the database; `internal/tlsx` parses, matches and re-encodes certificates and keys for API and agent. AutoSSL job (daily 03:17 UTC and on demand) per domain: skips names not pointing here (with the reason), keeps valid uploaded certificates, renews 30 days ahead, adds www when it points here; the server's host name certificate goes to /etc/xcp/ssl/hostname.crt and xcp-api serves it by SNI next to its self-signed pair. Sites carry their certificate in SiteApply: `:443` vhosts, force HTTPS redirect that keeps ACME challenges on HTTP, default HTTPS host with an error for unknown names; the host name cannot be added as a domain. Upload/remove, AutoSSL opt-out, expiry dashboard; UI SSL/TLS page. Verified on the VM (`certificates.py`) and in the browser; issuing is verified against Pebble, Let's Encrypt's test CA (`acme.py`: its lookups go to our PowerDNS, its HTTP-01 checks to Apache; the site and the panel's host name then serve the issued certificates). |
| 7 | MariaDB (databases, users, phpMyAdmin) | USR-DB-01..04; ADM-DB-08, 09 | done | ADR-0006: the agent reaches MariaDB as root over the socket (unix_socket auth, no credential file); names `<username>_<name>`, checked by the agent so one account's request cannot touch another's; grants escape `_`/`%`. Panel database is the source of truth: agent op MySQLAccountApply makes users, password hashes (mysql_native_password, stored encrypted; plain passwords never reach the agent), privileges (diffed against mysql.db, never revoked and re-granted) and lock state exact and creates missing databases; drops only by name or on terminate. Jobs `mysql.apply`/`mysql.drop` on the account's lock key; suspension locks the users; rename moves tables with one RENAME TABLE (refused with views, triggers, routines, events); sizes from information_schema. Wizard, custom privileges, password change, package limits. phpMyAdmin 5.2.3 (pinned SHA-256) installed by xcp-install in its own FPM pool (`xcp-pma`), served by Apache only on the server's own name, localhost and addresses at `/phpmyadmin/`, a different origin from the panel, with the panel cookie stripped; sign-on only: the agent makes a temporary user (4 h, expiry in its name, dropped by `mysql.expire` every 10 min) and a one-time ticket only phpMyAdmin can read. Root password (ADM-DB-09) added next to the socket. The host name vhost uses the AutoSSL host certificate once there. UI Databases page (users) and Database server (admins). Verified on the VM (`databases.py`, 33 checks) and in the browser through to phpMyAdmin. |
| 8 | Mail part 1 (domains, mailboxes, forwarders, DKIM/SPF/DMARC) | USR-MAIL-01, 03 (without pipes), 06, 09; ADM-MAIL-01 | done | ADR-0007: Postfix + Dovecot (IMAP, POP3, LMTP) + Rspamd (+ Redis) from Ubuntu, configs owned by XCP (`--no-mail` to skip). Agent op MailAccountApply keeps one fragment per account (refuses a domain another account has) and rebuilds the global maps from all: Postfix `texthash:` maps (no postmap), Dovecot passwd-file, Rspamd DKIM keys; the agent finds the account's uid itself. Mail in `/home/<user>/mail/<domain>/<local>/Maildir` owned by the account user; Argon2id passwords; per-mailbox quota (Dovecot) and login/receive/send switches; submission 587/465 sends only as your own address. Forwarders (keep a copy when on a mailbox; reject with a message), default address (deliver/forward, else reject). Which domains are local follows the zone's email routing (remote ones leave, backup MX relays, aliases map @alias to @domain); domain and routing changes re-apply mail. DKIM 2048-bit key per domain made with its first address and published in its zone; deliverability check (MX, SPF incl. a/mx/ip4 evaluation, DKIM, DMARC, PTR with forward check) and repair into our zones. Server settings: host name, size limit, relay host with login, RBLs, HELO checks, greylisting; TLS from the AutoSSL host certificate once there. Suspension keeps receiving, blocks login and sending. UI Email page (users) and Mail server (admins). Verified on the VM with real SMTP/IMAP (`mail.py`, 26 checks) and in the browser. |
| 9 | Mail part 2 (autoresponders, Roundcube SSO, pipes) | USR-MAIL-05, 11; ADM-MAIL-11; USR-MAIL-03 pipes | done | ADR-0008: autoresponders are Sieve vacation scripts the agent writes per mailbox (readable by the account's group, compiled with sievec) and Dovecot runs before delivery; dates checked in the script, reply interval in days. Roundcube 1.7.5 (pinned SHA-256) in its own FPM pool (`xcp-rc`) with SQLite, only its public_html served at `/webmail/` on the server's own name; its sample autologon plugin is removed. Sign-on: the agent adds an 8-hour temporary password to a second Dovecot passdb and writes a one-time ticket only Roundcube can read; the `xcp_sso` plugin logs in with it (IMAP and submission accept it); login off or suspension drops it; job `mail.webmail_expire` every 30 minutes. Pipe forwarders: a Postfix pipe transport per script, run as the account user (master.cf rendered by the agent from the fragments, also by xcp-install). UI: Webmail button and autoresponder form per mailbox, "run a script" forwarders, webmail address in the client settings. Verified on the VM (`mail.py`, now 37 checks: replies, script run as the user, sign-on into the inbox, one-time tickets) and in the browser through to Roundcube's inbox. |
| 10 | File manager via `xcp-userd` | USR-FILE-01..03, 05 | done | ADR-0009: template units `xcp-userd@.socket`/`.service` (socket-activated, in `/run/xcp-userd`, root:xcp 0750; the helper runs as the account user in its slice, read-only system, only its home visible, no network, exits when idle); the agent only starts the socket (`UserHelperStart`, stale socket files cleared, starts serialised) and stops it on suspend/removal. xcp-api checks access (`file_manager` feature, active account), audits changes and streams uploads/downloads (deadlines lifted, 4 GB per upload) over HTTP on the socket. `internal/userfs`: list, upload through a temporary file (folders made), download (images inline only for PNG/JPEG/GIF/WebP), new folder, rename/move (never replaces), copy, delete to `~/.trash`, chmod (recursive), search, disk usage (largest files), text editor with UTF-8/Latin-1/Windows-1252, zip/tar.gz packing, unpacking zip/tar/tar.gz/tar.zst/7z into a new folder with limits; all through fsx, links listed but not followed. UI Files page with drag-and-drop uploads, CodeMirror editor (CSP nonce for its styles), image preview, usage panel. Found and fixed on the way: fsx's directory entries looked their details up from the working directory (wrong owner/size and skipped entries outside tests; also broke the agent's webmail ticket clean-up), and /run/xcp is re-owned by systemd on every agent start. Verified on the VM (`files.py`, 26 checks: owner is the account, helper as the user in its slice, ../ and the user's own symlink to /etc/shadow refused, evil archive refused, other account 404, suspension stops the helper, agent restart keeps it working) and in the browser. |
| 11 | FTP via Pure-FTPd + `xcp-ftpauth` | USR-FTP-01 | todo | next |

## Features done

ADM-PKG-01, ADM-PKG-02, ADM-ACC-01, ADM-ACC-02, ADM-ACC-03, ADM-ACC-04, ADM-ACC-05, ADM-ACC-06, ADM-ACC-09, ADM-ACC-11, ADM-WEB-01 (Apache), ADM-WEB-04 (installed versions), USR-WEB-01,
USR-DOM-01, USR-DOM-02, USR-DOM-03, USR-DOM-04, USR-DOM-05, USR-DOM-06, USR-DOM-07,
ADM-DNS-01, ADM-DNS-02, ADM-DNS-03, USR-DNS-01 (without ALIAS and PTR), USR-DNS-02, USR-DNS-03,
ADM-SSL-01, ADM-SSL-02, ADM-SSL-05 (dashboard), USR-SSL-01, USR-SSL-03, USR-SSL-06, USR-DOM-05 (force HTTPS),
USR-DB-01, USR-DB-02, USR-DB-03, USR-DB-04, ADM-DB-08, ADM-DB-09,
USR-MAIL-01, USR-MAIL-03, USR-MAIL-05, USR-MAIL-06, USR-MAIL-09, USR-MAIL-11, ADM-MAIL-01, ADM-MAIL-11,
USR-FILE-01, USR-FILE-02, USR-FILE-03, USR-FILE-05.
