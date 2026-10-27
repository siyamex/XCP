# 09 — Roadmap, Milestones, Testing

## Phases overview

| Phase | Goal | Result |
|---|---|---|
| **P0** Foundations | Skeleton that builds, tests, and runs | API + agent + DB + jobs + auth + UI shell |
| **P1** MVP single server | One admin can host real sites with mail on Ubuntu 24.04 | "Usable for my own server" |
| **P2** Shared hosting ready | Resellers, limits, security, remote backups, Nginx | "Usable for a small hosting company" |
| **P3** Parity push | Migrations, apps, WordPress, PostgreSQL, isolation, WAF | "Can replace cPanel/DirectAdmin for most hosts" |
| **P4** Scale and ecosystem | Multi-server, DNS cluster, billing modules, plugins, API 1.0 | "Can run a fleet" |
| **P5** Extras | OLS, containers, image tools, more importers | Nice-to-have |

Be realistic: commercial panels took many years with large teams. Ship P1 and
get real users before chasing full parity.

## P0 — Foundations (ordered tasks; one AI session each)
1. Repo init: `go.mod`, Makefile, golangci config, CI (lint, test, build), `LICENSE`, `SECURITY.md`, ADR template.
2. `internal/config`, `slog` setup, `execx`, `fsx` (with tests for symlink/traversal attacks).
3. `internal/validate` with fuzz tests (username, domain/IDN, email, path, IP/CIDR, cron).
4. SQLite store: connection setup (WAL, one writer), goose migrations, sqlc; tables `logins`, `sessions`, `settings`, `audit_events`, `jobs`.
5. Job queue + scheduler (lease, retry, concurrency per kind, progress, logs).
6. Agent: protobuf contract, gRPC over Unix socket with `SO_PEERCRED`, first ops (`ServiceStatus`, `FileWriteManaged`); **fake agent** for dev.
7. Auth: login, argon2id, sessions, CSRF, TOTP, rate limit, audit events; `/me`.
8. OpenAPI skeleton + oapi-codegen strict server + problem+json errors.
9. Web SPA shell: login, 2FA, layout per role, theme, i18n, generated API client, job progress component.
10. `xcpctl` skeleton; `xcp-install` skeleton (checks OS, installs packages, creates users/dirs, enables quotas, writes systemd units).

**Exit criteria:** `make dev` runs the UI on any OS with the fake agent; on an
Ubuntu VM the installer brings up API + agent and the admin can log in with 2FA.

## P1 — MVP (Ubuntu 24.04, Apache + PHP-FPM, Postfix/Dovecot/Rspamd, PowerDNS, MariaDB, Pure-FTPd)
Order (each line is one or two sessions):
1. Packages + feature lists (`ADM-PKG-01/02`).
2. Account create/modify/suspend/terminate: Linux user, home, quota, slice (`ADM-ACC-01..06, 09, 11`).
3. Web driver Apache + PHP-FPM pools + reconciler + golden tests (`ADM-WEB-01, 04`; `USR-WEB-01`).
4. Domains: addon/sub/alias, docroot, force HTTPS, redirects (`USR-DOM-01..07`).
5. DNS: PowerDNS driver, zone templates, zone editor, email routing (`ADM-DNS-01..03`; `USR-DNS-01..03`).
6. SSL: lego, AutoSSL job, hostname/service certs, upload cert (`ADM-SSL-01, 02, 05`; `USR-SSL-01, 03, 06`).
7. MariaDB: DBs, users, grants, wizard, phpMyAdmin SSO (`USR-DB-01..04`; `ADM-DB-08, 09`).
8. Mail part 1: domains, mailboxes, forwarders, catch-all, DKIM/SPF/DMARC, deliverability (`USR-MAIL-01, 03, 06, 09`; `ADM-MAIL-01`).
9. Mail part 2: autoresponders (Sieve), Roundcube SSO (`USR-MAIL-05, 11`; `ADM-MAIL-11`).
10. File manager via `xcp-userd` (`USR-FILE-01..03, 05`).
11. FTP via Pure-FTPd + `xcp-ftpauth` (`USR-FTP-01`).
12. Cron jobs (`USR-ADV-01`).
13. Logs + bandwidth via `xcp-logd` (`USR-STAT-01, 03`).
14. Local backups + download + admin schedule (`USR-BAK-01`; `ADM-BAK-01`).
15. Admin dashboard, service manager, server info, job monitor, sessions (`ADM-SVC-01, 03, 05, 07, 08`; `ADM-SEC-12`).
16. Settings, update mechanism, `xcpctl rebuild`, `xcpctl doctor` (`ADM-SRV-01, 02, 05, 06, 08`).

**Exit criteria (P1 acceptance test, automated in a VM):**
create an account → add a domain → DNS resolves from the server → AutoSSL
issues (staging ACME / Pebble in CI) → upload a WordPress site via FTP → create
a DB → site loads over HTTPS → create a mailbox → send and receive mail
(DKIM passes) → backup → terminate → restore → site works again.

## P2 — Shared hosting ready
Resellers (`ADM-RSL-*`, `RSL-*`), IP management, resource limits (cgroups),
SSH + jailed shell + web terminal, SSH keys, Git deploy, multi-PHP per domain,
PHP ini editor, Nginx and Nginx→Apache drivers, firewall + brute-force,
2FA policy, passkeys, remote backup destinations + restore, mail queue, send
limits (`xcp-mailpolicy`), spam settings, deliverability for all, branding,
notifications, email templates, API tokens for users, Debian + AlmaLinux drivers,
DNS bulk tools, error pages, hotlink, IP blocker, directory privacy, trash,
FTP sessions, track delivery, visitor stats (GoAccess).

## P3 — Parity push
cPanel and DirectAdmin importers + remote transfer tool, app installer
(recipes), WordPress manager, Node.js and Python apps, PostgreSQL, Redis,
DNSSEC, filesystem jail, ModSecurity + CRS, malware scanning, security advisor,
incremental backups, sub-users, resource usage graphs, account rename,
hooks, mail statistics/troubleshooter, Prometheus metrics.

## P4 — Scale and ecosystem
Controller + nodes, DNS cluster, config cluster, remote DB servers, external
DNS providers, OIDC/SAML for admins, plugin system, billing modules (WHMCS,
Blesta, HostBill, FOSSBilling), Mailman 3, CalDAV/CardDAV, WebDAV, tickets,
API v1 freeze with a compatibility promise.

## P5 — Extras
OpenLiteSpeed, rootless Podman apps, image tools, Plesk/Hestia/CyberPanel
importers, Varnish/microcache, leech protection, anonymous FTP, Ruby apps.

## Testing strategy

| Level | What | Where |
|---|---|---|
| Unit | Business rules, limits, RBAC, validators | `go test ./...` on every push |
| Fuzz | Validators, parsers (zone files, backups manifests, cPanel/DA formats) | CI short run + nightly long run |
| Golden | Every generated config (vhosts, pools, mail maps, zones) | `test/golden`, `make golden-update` |
| Security | Cross-tenant tests per endpoint, path traversal and symlink suites, zip-bomb fixtures | CI |
| Integration | Each driver against the real service in containers (MariaDB, PowerDNS, Postfix/Dovecot, Pure-FTPd) | CI (testcontainers) |
| System / E2E | Full install in a VM per supported OS + Playwright UI scenarios + P1 acceptance flow | Nightly and before release |
| Upgrade | Install version N-1, add data, upgrade to N, run acceptance | Before release |
| Load | 1,000 accounts / 5,000 domains on one node: rebuild time, panel response time | Before minor releases |

## Release and community
- Semantic versioning; `0.x` until P2 is done; LTS releases later.
- Public docs site (user, admin, developer), changelog, upgrade notes.
- Demo server reset nightly. Forum or Discussions for support.
- Contributor guide: how to add a driver, a feature, a translation, an app recipe.

## Pick next task (for the AI agent)
1. Find the lowest phase with unfinished items.
2. Pick the first unfinished item in the order above whose dependencies are done.
3. Run one session using the template in `MASTER_PROMPT.md`.
4. Tick the feature IDs in `docs/plan/STATUS.md` (create it on first use:
   one line per feature ID with status `todo | doing | done` and a link to the PR).
