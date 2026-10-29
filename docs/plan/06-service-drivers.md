# 06 — Service Drivers (how each Linux service is managed)

General rule: a driver turns DB models into files and actions. It does not
store its own state. All generated files carry a header:
`# Managed by XCP. Do not edit. Use overrides: <path>`.

## 1. Linux accounts and isolation
- One Linux user per hosting account: `uid ≥ 10000`, home `/home/<user>`,
  group `<user>`. Web server user is in no user group. Files are `0750` / `0640`
  for home, and `public_html` is reached by the web server via ACL or the PHP-FPM user.
- Home layout:
  ```
  /home/<user>/
    public_html/        # primary domain docroot
    domains/<domain>/   # optional addon docroots (configurable)
    mail/<domain>/<box>/  (Maildir, owned by vmail or user — see Mail)
    logs/               # per-domain access/error logs (read-only copies)
    tmp/  .trash/  .xcp/  (internal state, backups staging)
  ```
- **Quotas:** filesystem user quotas (ext4 `usrquota` / XFS user or project
  quotas) for disk and inodes. The installer checks and enables them.
- **Resource limits (cgroups v2):** each account gets a systemd slice
  `xcp-u-<user>.slice` with `CPUQuota`, `MemoryMax`, `MemoryHigh`, `IOWeight`
  / `IOReadBandwidthMax`, `TasksMax`. PHP-FPM pools, cron, SSH sessions, and
  app processes are started in that slice.
- **Jail (P3):** SSH, cron, and the terminal run through a bubblewrap/systemd
  sandbox: private `/tmp`, read-only system dirs, other homes hidden,
  `/proc` hidepid. PHP-FPM gets `open_basedir`, `disable_functions` defaults,
  and a private tmp.

## 2. Web server drivers (`WebServer` interface)
```go
type WebServer interface {
    Name() string
    GenerateVhosts(acc AccountView) ([]GeneratedFile, error)
    GenerateGlobal(cfg GlobalWebConfig) ([]GeneratedFile, error)
    Validate(ctx) error     // apachectl -t / nginx -t
    Reload(ctx) error       // graceful
    SupportsHtaccess() bool
}
```
- **Apache 2.4 (P1):** event MPM, `mod_proxy_fcgi` → PHP-FPM socket per
  account+version, `mod_http2`, `mod_remoteip`. One file per account:
  `/etc/apache2/xcp/vhosts/<user>.conf`, one `<VirtualHost>` per domain
  (an alias is its own vhost with its domain's document root). Wildcard
  subdomains go to `/etc/apache2/xcp/wildcards/<user>.conf`, included after
  all other vhosts, so `*.example.com` never catches a name another vhost
  serves. The include is a site (`sites-available/xcp.conf`), read after
  `000-default`, so unknown host names never reach a customer's site.
  Suspended accounts point to the suspended page.
- **Nginx (P2):** `fastcgi_pass` to FPM. `.htaccess` is not supported; show a
  warning in the UI. Offer a converter for common rewrite rules (WordPress,
  Laravel presets).
- **Nginx → Apache proxy (P2):** Nginx handles TLS, static files, and HTTP/3;
  Apache on `127.0.0.1:8080` handles PHP + `.htaccess`.
- **OpenLiteSpeed (P5):** lsphp, reads `.htaccess` rewrites.
- ACME HTTP-01 path `/.well-known/acme-challenge/` is served from a shared
  directory for all vhosts, before any user rewrite rules.

## 3. PHP (multi-version)
- Install from Sury (Debian/Ubuntu) or Remi (RHEL). Versions: all supported
  upstream releases (e.g. 8.1–8.4+), and legacy versions only if the admin allows.
- One FPM pool per **account per version** in use:
  `/etc/php/<ver>/fpm/pool.d/xcp-<user>.conf`, `user = <user>`, socket
  `/run/php/xcp-<user>-<ver>.sock` (mode 0660, group = web server group).
- `pm = ondemand` by default (good for many small sites); per-package
  `pm.max_children`, `request_terminate_timeout`, `memory_limit`.
- Per-domain ini values go into the pool as `php_admin_value` (locked) or
  `php_value` (user-overridable), based on the admin policy.
- Pools are attached to the account's cgroup slice (FPM `systemd` integration
  or one FPM master per account in large setups — decide in an ADR).

## 4. Mail (Postfix + Dovecot + Rspamd + ClamAV)
- **Virtual domains and mailboxes:** Postfix reads lookup maps generated
  from the DB (`hash:`/`lmdb:` maps compiled with `postmap`) or a socketmap
  served by `xcp-api` (P3 option, no rebuild needed).
- **Storage:** Maildir under `/home/<user>/mail/<domain>/<box>/`, owned by the
  account user, so quota counts toward the account. Dovecot runs with
  `mail_uid` per user from a passwd-file/SQL lookup.
- **Auth:** Dovecot passdb from generated passwd-files (SHA512-CRYPT or
  ARGON2ID), Postfix SASL via Dovecot. Per-mailbox flags: login, receive,
  send disabled.
- **Forwarders, aliases, catch-all, pipes:** Postfix virtual alias maps; pipes
  run through a wrapper as the account user, in its slice.
- **Autoresponders and filters:** Dovecot Pigeonhole Sieve (vacation, filters,
  ManageSieve on 4190).
- **Spam and AV:** Rspamd milter (DKIM signing with per-domain keys, ARC,
  SPF/DMARC checks, greylisting, Bayes, ratelimit), ClamAV via Rspamd.
- **Outbound limits:** `xcp-mailpolicy` (Postfix policy delegation) counts per
  account and per mailbox per hour; holds mail over the limit; alerts the admin.
- **TLS:** SNI per mail domain (`mail.<domain>`) via Postfix and Dovecot SNI
  maps, using AutoSSL certificates.
- **Autoconfig/autodiscover:** served by `xcp-api` on
  `autoconfig.<domain>` / `autodiscover.<domain>`.
- **Webmail:** Roundcube (PHP, its own FPM pool, its own DB); SSO via a
  one-time token plugin.

## 5. DNS (PowerDNS Authoritative)
- Backend: `gsqlite3` (or `lmdb`), managed **only** through the PowerDNS HTTP
  API, which listens on localhost; only xcp-agent has its key
  (`/etc/xcp/secrets/pdns-api-key`). The panel DB is the source of truth;
  `DNSZoneApply` sends the full zone and the agent changes only the RRsets
  that differ, in one PATCH. The zone's NS records come from the server's DNS
  settings and the agent keeps the SOA.
- PowerDNS listens on 127.0.0.1, ::1 and the server's own addresses, not on
  0.0.0.0, because systemd-resolved holds 127.0.0.53:53.
- A zone the DNS server does not have yet (made before PowerDNS was
  installed, or while it was down) is applied by the `dns.sync` job, every
  5 minutes and at xcp-api start.
- SOA serial auto-increment (date-based), NOTIFY to secondaries.
- DNSSEC through the PowerDNS API (`cryptokeys`), DS shown to the user.
- **BIND driver (P4):** zone files + `rndc reload`, `named-checkzone` validation.
- Record validation with `miekg/dns` (one CNAME per name, no CNAME at apex,
  MX target not an IP, TXT split at 255 chars, CAA format).

## 6. Databases
- **MariaDB/MySQL:** the agent holds the root credentials (file readable by
  root only). Naming: `<user>_<name>` for DBs and DB users (prefix enforced).
  Grants are recomputed from the DB on apply. Quota counting via
  `information_schema` sizes (added to the account's usage).
- **PostgreSQL (P3):** role per account (`NOLOGIN` owner) and login roles;
  `pg_hba.conf` generated (local socket + allowed remote hosts).
- **phpMyAdmin/Adminer:** own FPM pool; SSO via a signon session created by
  `xcp-api` with a temporary DB user or the account's credentials (decide in
  an ADR: temporary per-session user is safer).

## 7. FTP (Pure-FTPd)
- Virtual users via `xcp-ftpauth` (Pure-FTPd extauth protocol). Each FTP
  account maps to the account's uid/gid with a chroot home inside
  `/home/<user>/`.
- FTPS (explicit TLS) with the hostname certificate; passive port range opened
  in the firewall. Transfer logs (xferlog) go to `xcp-logd` for bandwidth.
- SFTP uses OpenSSH (`internal-sftp`, chroot option for SFTP-only users, P3).

## 8. SSL/ACME
- **Amended by ADR-0005:** `golang.org/x/crypto/acme` inside xcp-api's job
  worker; challenge files written by xcp-api; certificates travel with
  `SiteApply`. Account keys per ACME directory.
- HTTP-01: challenge files written to the shared challenge dir by the agent.
  DNS-01: through the local PowerDNS API or external DNS providers.
- AutoSSL job: daily. For each domain, check DNS points to the server (skip
  and explain if not), group names into one certificate per domain (with
  `www`, `mail`, `webmail`, `autodiscover`, `autoconfig` subnames), renew at
  30 days left (or use ARI renewal info), install, reload services.
- Rate-limit awareness (per registered domain, failed validations) with
  back-off and clear user messages.

## 9. Firewall and brute-force protection
- nftables table `inet xcp` with sets: `allow4/6`, `deny4/6`,
  `bf_ban4/6` (with timeouts), `geo_block4/6`. Ports from the services enabled.
- `xcp-logd` reads journald and log files (sshd, Postfix/Dovecot auth, Pure-FTPd,
  panel login, WordPress `wp-login.php` POSTs) and bans IPs over thresholds by
  adding them to `bf_ban` with a timeout. Permanent ban after N temporary bans.
- GeoIP: MaxMind GeoLite2 (admin enters a license key) or DB-IP lite.

## 10. Logs, bandwidth, stats
- Web servers log per vhost to a pipe/socket read by `xcp-logd`, or to files
  tailed by `xcp-logd` (simpler; P1). `xcp-logd` counts bytes per domain → 5-minute
  buckets in the DB → daily/monthly roll-ups.
- Mail bytes from Postfix logs, FTP bytes from xferlog.
- Per-user log copies in `~/logs/` (rotated, compressed).
- Visitor stats: GoAccess run per domain by the scheduler (HTML report
  served behind panel auth).

## 11. Backups
- **Account archive format** (portable, versioned, documented):
  ```
  <user>-<ts>.tar.zst
    manifest.json      # format version, panel version, account, package, checksums
    account.json       # account, domains, DNS, mail settings, cron, SSL, apps
    homedir/           # files (tar, preserving modes; owners re-mapped on restore)
    mysql/<db>.sql.zst # mysqldump --single-transaction (or mariadb-dump)
    pgsql/<db>.dump
    mail/              # optional if outside the home
    ssl/               # keys encrypted with the backup key if encryption is on
  ```
- Optional encryption: age (X25519 recipients) so the server can write backups
  it cannot read back without the admin's key (choose per destination).
- Incremental engine (P3): restic or kopia repository per destination
  (deduplicated, encrypted), with the account archive still used for transfers.
- Restore is a job with steps: validate manifest → create/merge account →
  files → DBs → mail → DNS → SSL → apply. Each step is reported.
- Importers (`ADM-MIG-*`) convert cPanel/DirectAdmin archives into this
  internal model, then use the same restore path.

## 12. Monitoring (`xcp-monitor`)
- Checks every 60 s: systemd unit active + a protocol check (HTTP GET,
  SMTP banner, IMAP banner, DNS query, MySQL ping, FTP banner).
- Restart on failure with back-off; alert after N failures; never loop forever.
- Disk, inode, load, and memory thresholds → notifications.

## 13. App runtimes (P3)
- Node.js and Python versions installed in `/opt/xcp/runtimes/...`
  (official tarballs / `uv`-managed Pythons), checksum-verified.
- Each app = a systemd service `xcp-app-<user>-<id>.service`, `User=<user>`,
  in the account slice, listening on a Unix socket in the account's home;
  the web server reverse-proxies the domain or path to it.
