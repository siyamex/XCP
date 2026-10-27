# 03 — Admin Features (server owner level)

Format: `ID` feature — details `(phase)`. Admin can do everything a Reseller
and a User can do, for any account, plus everything below.

## ADM-SRV — Server setup and configuration
- **ADM-SRV-01** First-run setup wizard: hostname, admin email, nameservers, primary IP, timezone, stack choices (web/mail/DNS/DB/FTP), license accept `(P1)`
- **ADM-SRV-02** Change hostname (updates DNS A record, panel SSL, mail HELO, `/etc/hosts`) `(P1)`
- **ADM-SRV-03** Resolver configuration (`/etc/resolv.conf` / systemd-resolved) `(P2)`
- **ADM-SRV-04** Server time and timezone, NTP status `(P2)`
- **ADM-SRV-05** Global settings ("tweak settings"): default PHP, max upload, default quotas, panel session timeout, allowed shells, default skeleton, etc., with search `(P1)`
- **ADM-SRV-06** Panel update settings: channel, auto-update window, OS updates on/off `(P1)`
- **ADM-SRV-07** Change root password, manage root SSH keys `(P2)`
- **ADM-SRV-08** Graceful and forced server reboot `(P1)`
- **ADM-SRV-09** Server profiles: minimal / web-only / mail-only / DNS-only / full (turns roles on or off) `(P3)`
- **ADM-SRV-10** Web terminal as root (2FA re-check required) `(P2)`
- **ADM-SRV-11** System file editor for allow-listed config overrides, with validation and rollback `(P3)`

## ADM-ACC — Account management
- **ADM-ACC-01** Create account: username, primary domain, package, owner (reseller), IP, contact email, password/SSH key, PHP version, DNS template `(P1)`
- **ADM-ACC-02** List and search accounts: filters by owner, package, IP, node, status, disk/bandwidth use; bulk select `(P1)`
- **ADM-ACC-03** Modify account: limits, features, contact, shell, primary domain, IP `(P1)`
- **ADM-ACC-04** Upgrade or downgrade package (single and bulk) `(P1)`
- **ADM-ACC-05** Suspend and unsuspend with reason; suspended page template; options to block web, mail in, mail out, FTP, SSH, cron, panel login `(P1)`
- **ADM-ACC-06** Terminate account (optional final backup, keep DNS option, confirmation by typing the username) `(P1)`
- **ADM-ACC-07** Rename username (moves home, DB prefixes, mail paths, cron, quotas) `(P3)`
- **ADM-ACC-08** Change account owner (move between resellers), single and bulk `(P2)`
- **ADM-ACC-09** Password change and forced password change at next login `(P1)`
- **ADM-ACC-10** Shell access: none / jailed shell / full shell `(P2)`
- **ADM-ACC-11** Quota change (disk and inodes), bandwidth limit change, reset bandwidth counters `(P1)`
- **ADM-ACC-12** Lists: over-quota accounts, bandwidth exceeders (with auto-suspend option), suspended accounts, all domains / subdomains / aliases `(P1)`
- **ADM-ACC-13** Demo mode (read-only account for showcases) `(P4)`
- **ADM-ACC-14** Login as user / login as reseller (impersonation, banner, audited) `(P1)`
- **ADM-ACC-15** Skeleton directory and default files for new accounts (global and per reseller) `(P2)`
- **ADM-ACC-16** Email all users / all resellers (announcement with template variables) `(P2)`
- **ADM-ACC-17** Convert an addon domain into its own account `(P3)`
- **ADM-ACC-18** Account notes and tags (internal, admin-only) `(P2)`

## ADM-PKG — Packages and feature lists
- **ADM-PKG-01** Create, edit, clone, and delete packages (all limits, see `08-data-model` §Limits) `(P1)`
- **ADM-PKG-02** Feature lists: turn each user feature on or off (e.g. no SSH, no Git, no cron); assign to packages `(P1)`
- **ADM-PKG-03** Package-level resource limits: CPU %, RAM, IO, processes, entry processes, outbound mail per hour `(P2)`
- **ADM-PKG-04** Import and export packages (JSON) `(P3)`

## ADM-RSL — Reseller management
- **ADM-RSL-01** Create a reseller, or promote an existing account to reseller `(P2)`
- **ADM-RSL-02** Reseller limits: number of accounts, total disk, total bandwidth, overselling allowed (yes/no per resource), allowed packages `(P2)`
- **ADM-RSL-03** Reseller privileges (ACL list): create/terminate/suspend accounts, edit DNS, create packages, use dedicated IPs, etc. `(P2)`
- **ADM-RSL-04** Reseller IP delegation (shared and dedicated IP pool) `(P2)`
- **ADM-RSL-05** Reseller usage overview; suspend a reseller and all their accounts `(P2)`
- **ADM-RSL-06** Reseller private nameservers (`ns1.reseller.tld`) `(P3)`
- **ADM-RSL-07** Additional admins with limited admin ACLs (e.g. support staff) `(P3)`

## ADM-IP — IP address management
- **ADM-IP-01** Add and remove IPv4 / IPv6 addresses and ranges; show usage per IP `(P2)`
- **ADM-IP-02** Shared vs dedicated IPs; assign a dedicated IP to an account `(P2)`
- **ADM-IP-03** Change an account's IP (updates vhosts, DNS, SPF) `(P2)`
- **ADM-IP-04** IP migration wizard (server moves to new IPs: update all zones and configs) `(P3)`
- **ADM-IP-05** NAT support (private IP ↔ public IP mapping for cloud servers) `(P1)`
- **ADM-IP-06** Per-IP outbound mail IP binding `(P3)`

## ADM-DNS — DNS administration
- **ADM-DNS-01** Zone manager for every zone on the server (all record types) `(P1)`
- **ADM-DNS-02** Zone templates (default records for new domains: A, AAAA, MX, SPF, DKIM, DMARC, CAA, autodiscover, SRV) `(P1)`
- **ADM-DNS-03** Nameserver settings (ns1/ns2 with glue IPs), nameserver record report `(P1)`
- **ADM-DNS-04** Bulk: set TTL, enable DKIM/SPF/DMARC for all, change MX routing for all `(P2)`
- **ADM-DNS-05** DNSSEC: sign zones, key rollover, show DS records `(P3)`
- **ADM-DNS-06** DNS cluster: add remote PowerDNS/BIND secondaries or other XCP nodes; sync status `(P4)`
- **ADM-DNS-07** DNS cleanup (orphan zones with no account), zone sync check `(P2)`
- **ADM-DNS-08** External DNS providers (Cloudflare, Route 53, etc.) as zone backends `(P4)`

## ADM-WEB — Web server and PHP
- **ADM-WEB-01** Choose and switch the web stack: Apache, Nginx, Nginx → Apache proxy, OpenLiteSpeed `(P1: Apache, P2: Nginx+proxy, P5: OLS)`
- **ADM-WEB-02** Global web server settings (workers, timeouts, keep-alive, HTTP/2 and HTTP/3, compression, security headers) `(P2)`
- **ADM-WEB-03** Template overrides and include editor (global, per account, per domain) `(P2)`
- **ADM-WEB-04** PHP version manager: install and remove PHP versions, extensions, default version `(P1)`
- **ADM-WEB-05** Global PHP ini editor (per version, basic and advanced mode) `(P2)`
- **ADM-WEB-06** PHP-FPM pool defaults (pm mode, max children, per-package overrides) `(P2)`
- **ADM-WEB-07** Server status page (requests, workers), top sites by traffic `(P2)`
- **ADM-WEB-08** Log rotation settings (web, mail, panel) `(P2)`
- **ADM-WEB-09** Caching layer options: Varnish or Nginx microcache (per domain on/off) `(P5)`
- **ADM-WEB-10** Per-user `public_html` access (`~user` URLs) on/off `(P2)`

## ADM-MAIL — Mail server administration
- **ADM-MAIL-01** Mail server settings: TLS, max message size, relay hosts (smarthost), greylisting, RBLs, HELO checks `(P1)`
- **ADM-MAIL-02** Mail queue manager: view, search, delete, retry, view headers/body, flush `(P2)`
- **ADM-MAIL-03** Delivery reports and search: who sent what, to whom, result, by domain/account `(P2)`
- **ADM-MAIL-04** Outbound limits: per-account max per hour, max defer/fail %, auto-hold of suspected spammers `(P2)`
- **ADM-MAIL-05** Spam engine settings (Rspamd): scores, Bayes, greylist, whitelist/blacklist, Rspamd web UI proxy `(P2)`
- **ADM-MAIL-06** Antivirus (ClamAV) on/off, update status `(P2)`
- **ADM-MAIL-07** Email deliverability report for all domains (SPF, DKIM, DMARC, PTR/rDNS, HELO) with one-click fix `(P2)`
- **ADM-MAIL-08** Mail statistics: sent/received/rejected per domain and per account; top senders `(P3)`
- **ADM-MAIL-09** Mail troubleshooter: trace how an address is routed `(P3)`
- **ADM-MAIL-10** Repair mailbox permissions, mailbox format conversion (Maildir ↔ mdbox) `(P3)`
- **ADM-MAIL-11** Webmail clients: install and choose Roundcube / SnappyMail `(P1: Roundcube)`
- **ADM-MAIL-12** SMTP restrictions: only the MTA can send out on port 25 (block direct sockets from user processes) `(P2)`
- **ADM-MAIL-13** Mailing list software (Mailman 3) on/off `(P4)`

## ADM-DB — Database server administration
- **ADM-DB-01** MariaDB/MySQL server settings (`my.cnf` tuning presets and custom values) `(P2)`
- **ADM-DB-02** Database map: list all databases and users by owner; fix orphans `(P2)`
- **ADM-DB-03** Process list and kill query; slow-query log viewer `(P3)`
- **ADM-DB-04** Repair and optimize databases `(P2)`
- **ADM-DB-05** Version upgrade wizard (MariaDB major versions, with backup first) `(P4)`
- **ADM-DB-06** Remote DB server profiles (use an external DB server for new accounts) `(P4)`
- **ADM-DB-07** PostgreSQL server enable and settings `(P3)`
- **ADM-DB-08** phpMyAdmin / Adminer install and SSO settings `(P1)`
- **ADM-DB-09** Change DB root password `(P1)`

## ADM-SSL — SSL/TLS administration
- **ADM-SSL-01** AutoSSL: provider (Let's Encrypt, ZeroSSL, Buypass, custom ACME), schedule, which domains are covered, logs `(P1)`
- **ADM-SSL-02** Service certificates (panel, mail, FTP, webmail), auto-issued for the hostname `(P1)`
- **ADM-SSL-03** Install certificates on any domain; SSL storage for all certificates and keys `(P2)`
- **ADM-SSL-04** TLS settings: protocols, ciphers, HSTS defaults, OCSP stapling `(P2)`
- **ADM-SSL-05** Certificate expiry dashboard and alerts `(P1)`

## ADM-SEC — Security center
- **ADM-SEC-01** Brute-force protection for panel, SSH, FTP, mail, and webmail: thresholds, ban times, allow/deny lists, ban history `(P2)`
- **ADM-SEC-02** Firewall manager (nftables): open ports, allow/deny IPs and CIDRs, country blocking (GeoIP), rate limits, port-knocking off by default `(P2)`
- **ADM-SEC-03** Host access control for panel, SSH, and FTP by IP `(P2)`
- **ADM-SEC-04** WAF: ModSecurity + OWASP Core Rule Set; per-domain on/off; per-rule disable; audit log viewer `(P3)`
- **ADM-SEC-05** Malware scanner: ClamAV + YARA rules, scheduled scans, quarantine, restore, reports `(P3)`
- **ADM-SEC-06** Security advisor: checks for weak settings (e.g. root SSH password login, old PHP, open relay, compilers available) with fix buttons `(P3)`
- **ADM-SEC-07** Password strength rules per service; check against known-leaked passwords (k-anonymity API, opt-in) `(P2)`
- **ADM-SEC-08** 2FA policy: require 2FA for admins/resellers/users `(P2)`
- **ADM-SEC-09** Shell fork-bomb protection, compiler access restriction, `open_basedir` defaults `(P2)`
- **ADM-SEC-10** Account isolation level: cgroups limits plus filesystem jail (private `/tmp`, hidden `/home` of other users) `(P3)`
- **ADM-SEC-11** SSH settings: port, password auth on/off, root login policy `(P2)`
- **ADM-SEC-12** Login history and active sessions for all users; kill sessions `(P1)`
- **ADM-SEC-13** External auth for admins (OIDC / SAML: Google, Microsoft, Keycloak) `(P4)`

## ADM-SVC — Services and monitoring
- **ADM-SVC-01** Service manager: status, start, stop, restart, enable at boot; per-service logs `(P1)`
- **ADM-SVC-02** Service monitor with auto-restart and alerts (like chkservd/service monitor) `(P2)`
- **ADM-SVC-03** Dashboard: CPU, RAM, load, disk, inodes, network, top processes, top accounts `(P1)`
- **ADM-SVC-04** Process manager: list, search by user, kill; background process killer rules `(P3)`
- **ADM-SVC-05** Disk usage overview per partition and per account `(P1)`
- **ADM-SVC-06** Resource usage per account (CPU/RAM/IO over time, limit hits) `(P3)`
- **ADM-SVC-07** Task queue monitor (jobs: running, failed, retry, cancel) `(P1)`
- **ADM-SVC-08** Server information (OS, kernel, versions of all services, hardware) `(P1)`
- **ADM-SVC-09** Prometheus metrics endpoint and Grafana dashboard JSON `(P3)`

## ADM-BAK — Backups (server level)
- **ADM-BAK-01** Backup configuration: schedules (daily/weekly/monthly), retention, accounts included, compression, encryption `(P1: local, P2: remote)`
- **ADM-BAK-02** Destinations: local, SFTP, FTP, S3-compatible (AWS, B2, Wasabi, MinIO), Google Drive, Dropbox, WebDAV, rsync, via rclone `(P2)`
- **ADM-BAK-03** Incremental backups (snapshot engine, deduplicated) `(P3)`
- **ADM-BAK-04** Restore whole accounts, or parts (files, DBs, mail, DNS, SSL, cron) from any backup `(P2)`
- **ADM-BAK-05** System backup: panel DB, configs, templates, certificates `(P2)`
- **ADM-BAK-06** Backup reports and failure alerts `(P2)`

## ADM-MIG — Transfers and migrations
- **ADM-MIG-01** Import a cPanel backup (`cpmove-*.tar.gz`) `(P3)`
- **ADM-MIG-02** Import a DirectAdmin backup (`.tar.gz` / `.tar.zst`) `(P3)`
- **ADM-MIG-03** Import a Plesk backup; import from HestiaCP/CyberPanel `(P5)`
- **ADM-MIG-04** Remote transfer tool: connect by SSH to a remote cPanel/DirectAdmin/XCP server, select accounts, transfer live (with rsync for large homes), DNS switch helpers `(P3)`
- **ADM-MIG-05** Transfer review log: per-account steps, warnings (unsupported features), retry `(P3)`
- **ADM-MIG-06** Upload account backups from the browser or a URL `(P3)`

## ADM-UI — Branding, themes, and localisation
- **ADM-UI-01** White-label: logo, colours, product name, favicon, footer, login page, custom CSS (global and per reseller) `(P2)`
- **ADM-UI-02** Language manager: enable languages, edit translations, export/import `(P3)`
- **ADM-UI-03** News and announcements shown on user dashboards `(P2)`
- **ADM-UI-04** Custom links and menu items `(P3)`
- **ADM-UI-05** Email templates for notifications (welcome, suspension, quota, SSL, etc.) `(P2)`

## ADM-NOT — Notifications and contacts
- **ADM-NOT-01** Contact manager: who gets which alerts, via email / webhook / Slack / Telegram / Discord `(P2)`
- **ADM-NOT-02** Alert types: service down, disk full, quota, bandwidth, SSL expiry, backup failure, brute-force, high load, update available, mail queue size `(P2)`

## ADM-DEV — Developer and integration
- **ADM-DEV-01** API tokens for admin (scopes, IP allow-list, expiry) `(P1)`
- **ADM-DEV-02** Hooks: run a script or call a webhook before or after events (`account.create`, `domain.add`, etc.) `(P3)`
- **ADM-DEV-03** Plugin manager: install, enable, disable, and update plugins `(P4)`
- **ADM-DEV-04** API explorer (Swagger UI) and audit log viewer `(P2)`
- **ADM-DEV-05** Billing modules: WHMCS, Blesta, HostBill, FOSSBilling `(P4)`

## ADM-SUP — Support system (optional)
- **ADM-SUP-01** Internal messages / tickets between users ↔ reseller ↔ admin `(P4)`
- **ADM-SUP-02** Temporary support access (time-limited admin login link for a helper) `(P4)`
