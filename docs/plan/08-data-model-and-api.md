# 08 — Data Model, API, Events

## 1. Core entities (SQLite tables, simplified)

```
logins            id, username, role, password_hash, totp_secret_enc, webauthn, status,
                  locale, theme, last_login_at, account_id (null for admins)
accounts          id, username, uid, owner_id (reseller/admin login), package_id, node_id,
                  primary_domain_id, ip_id, ipv6_id, shell, status, suspend_reason,
                  is_reseller, php_default, created_at, notes
packages          id, owner_id, name, limits (see §2), feature_list_id
feature_lists     id, owner_id, name, features (JSON set of feature keys)
reseller_limits   account_id, max_accounts, disk_mb, bandwidth_mb, oversell flags, acl (JSON)
ips               id, address, family, kind (shared/dedicated), nat_public, owner_id, node_id
domains           id, account_id, name, kind (primary/addon/sub/alias), parent_id,
                  docroot, php_version, force_https, canonical_www, redirect, status
dns_zones         id, account_id, name, dnssec, serial, template_id
dns_records       id, zone_id, name, type, ttl, content, priority, weight, port, managed_by
mail_domains      id, domain_id, enabled, dkim_selector, dkim_key_enc, catch_all, routing
mailboxes         id, mail_domain_id, local_part, password_hash, quota_mb, flags
mail_forwarders   id, mail_domain_id, source, destinations (JSON), kind (forward/pipe/fail)
autoresponders    id, mailbox_id, subject, body, start_at, end_at, interval_h
mail_filters      id, scope (account/mailbox), scope_id, sieve, ui_rules (JSON)
databases         id, account_id, engine (mysql/pgsql), name, server_id
db_users          id, account_id, engine, name, password_hash, hosts (JSON)
db_grants         db_user_id, database_id, privileges (JSON)
ftp_accounts      id, account_id, login, password_hash, home_rel, quota_mb, status
certificates      id, account_id, names (JSON), issuer, not_before, not_after,
                  cert_pem, key_enc, chain_pem, source (acme/upload/selfsigned), auto_renew
cron_jobs         id, account_id, schedule, command, email_output, enabled, last_run, last_status
ssh_keys          id, account_id, name, public_key, fingerprint
php_settings      id, domain_id, key, value, locked
redirects, error_pages, hotlink_rules, ip_blocks, dir_privacy(+users), htaccess_snippets
apps              id, account_id, kind (wordpress/node/python/recipe), domain_id, path,
                  version, runtime, config (JSON), status
git_repos         id, account_id, path, remote_url, deploy_branch, deploy_tasks, webhook_secret_hash
backup_destinations, backup_schedules, backups (id, account_id, dest_id, kind, size, status, manifest)
jobs              (see 01-architecture §5)
audit_events      (see 07-security §9)
api_tokens        id, login_id, name, prefix, hash, scopes, ip_allow, expires_at, last_used_at
sessions          id_hash, login_id, impersonator_id, ip, ua, created_at, last_seen_at, expires_at
usage_bandwidth   account_id, domain_id, bucket_start, bytes_web, bytes_mail, bytes_ftp
usage_disk        account_id, measured_at, disk_bytes, inodes, mail_bytes, db_bytes
notifications, contacts, announcements, branding, templates_override, hooks, plugins,
nodes, settings (key/value, typed), migrations_runs, transfer_jobs
```

Rules:
- Every account-owned table has `account_id` with an index; reseller scope is
  derived via `accounts.owner_id`.
- Secrets marked `_enc` are encrypted with the panel master key (XChaCha20-Poly1305).
- Soft delete is **not** used for resources that exist on disk; deletion goes
  through a job that removes them from the system, then from the DB.

## 2. Package limits (all nullable = unlimited)

```
disk_mb, inodes, bandwidth_mb_month,
addon_domains, subdomains, aliases, redirects,
mailboxes, mailbox_quota_mb_max, forwarders, autoresponders, mailing_lists,
mail_send_per_hour, mail_max_defer_fail_pct,
databases_mysql, databases_pgsql, db_users,
ftp_accounts, cron_jobs, ssh_keys, git_repos, apps, nodejs_apps, python_apps,
redis_mb, backups_kept, user_backups_allowed,
cpu_pct, memory_mb, io_kbps, iops, processes, entry_processes,
php_versions_allowed (JSON), shell (none/jailed/full), dedicated_ip (bool),
features: feature_list_id
```

## 3. REST API design

- Base: `/api/v1`. JSON. Errors as RFC 9457 `application/problem+json` with a
  stable `code` field (e.g. `limit_reached`, `domain_taken`, `validation_failed`).
- Auth: session cookie + CSRF header, or `Authorization: Bearer xcp_...`.
- Pagination: cursor-based `?limit=50&cursor=...`; filtering with explicit
  query params; sorting with `?sort=-created_at`.
- Long operations return `202 Accepted` with `{ "job_id": "..." }`;
  status at `/api/v1/jobs/{id}`, live stream over WebSocket.
- Idempotency: `Idempotency-Key` header supported on POST (stored 24 h), so
  billing systems can retry safely.
- Concurrency: `ETag` / `If-Match` on updates to avoid lost updates.
- Rate limits per token/session with `RateLimit-*` headers.

### Resource map (main paths)
```
/auth/login  /auth/logout  /auth/2fa/*  /auth/webauthn/*  /me  /me/sessions  /me/tokens
/accounts                         (admin, reseller)
/accounts/{id}                    GET PATCH DELETE
/accounts/{id}/suspend|unsuspend|password|package|owner|impersonate
/packages  /feature-lists  /resellers/{id}/limits  /ips
/accounts/{id}/domains            /domains/{id}  /domains/{id}/redirects ...
/accounts/{id}/dns/zones          /dns/zones/{id}/records  /dns/zones/{id}/dnssec
/accounts/{id}/mail/domains       /mail/domains/{id}/mailboxes|forwarders|autoresponders|catch-all|filters|deliverability
/accounts/{id}/databases  /accounts/{id}/db-users  /databases/{id}/grants|import|export
/accounts/{id}/ftp
/accounts/{id}/ssl/certificates   /ssl/autossl/status  /ssl/csr
/accounts/{id}/files?path=        (list)  /files/content  /files/upload  /files/ops (copy/move/delete/chmod/compress/extract)
/accounts/{id}/cron  /ssh-keys  /git  /apps  /php  /backups  /stats/bandwidth|visitors|logs
/server/services  /server/settings  /server/php/versions  /server/mail/queue  /server/firewall
/server/backup/config  /server/transfers  /server/updates  /server/audit  /server/hooks
/jobs/{id}   /jobs/{id}/stream (WS)   /terminal (WS)
```
Shortcut: user-role tokens can use `/me/...` paths instead of `/accounts/{id}/...`.

### Billing-system API profile
A small, stable subset for WHMCS/Blesta modules: create, suspend, unsuspend,
terminate, change package, change password, usage, SSO login URL. This subset
is versioned separately and kept backward compatible.

## 4. CLI (`xcpctl`)
Mirrors the API with the same names:
```
xcpctl account create --user alice --domain example.com --package basic
xcpctl account suspend alice --reason "unpaid"
xcpctl domain add alice shop.example.com --docroot domains/shop
xcpctl dns record add example.com A www 203.0.113.10 --ttl 3600
xcpctl mail box add info@example.com --quota 2048
xcpctl ssl autossl run --account alice
xcpctl backup run --account alice --dest s3-main
xcpctl rebuild all | web | mail | dns | php --dry-run
xcpctl jobs ls --failed ; xcpctl jobs retry <id>
xcpctl doctor            # checks install health, quotas, services, DNS, ports
```
Output: table by default, `--json` for scripts.

## 5. Events and hooks
- Every state change emits an event: `account.created`, `account.suspended`,
  `domain.added`, `mailbox.created`, `ssl.issued`, `backup.failed`, ... with
  payload `{actor, account_id, object, before, after}` (secrets removed).
- Consumers: audit log, notifications, webhooks (HMAC-signed, retries),
  admin hooks (scripts run as root only from `/etc/xcp/hooks/<event>.d/`,
  with timeout), and plugins.
- **Pre-hooks** (P3) can block an action (e.g. a billing check before
  account creation) by returning a non-zero code or HTTP 4xx with a reason.

## 6. Plugin system (P4)
- A plugin = a directory with `plugin.toml` (name, version, permissions,
  events, UI entries) + a backend executable + optional UI bundle.
- Backend runs as its own system user, talks to the panel only through the
  REST API with a scoped token that is issued at install time.
- UI: the plugin's pages load in a sandboxed iframe inside the panel, with a
  small postMessage SDK (theme, user context, navigation, toast).
- Plugins can add: menu items (per role), dashboard widgets, event
  subscriptions, scheduled tasks, and app installer recipes.
