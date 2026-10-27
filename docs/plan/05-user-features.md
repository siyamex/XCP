# 05 — User Features (hosting account level)

Every feature can be turned off per package with the feature list (`ADM-PKG-02`),
and every countable item respects the package limits.

## USR-DASH — Dashboard and account
- **USR-DASH-01** Dashboard: disk, inodes, bandwidth, counts vs limits, PHP version, IPs, nameservers, SSL status, recent notices `(P1)`
- **USR-DASH-02** Global search over all features ("where do I add a forwarder?") `(P2)`
- **USR-DASH-03** Change password, contact email, notification preferences `(P1)`
- **USR-DASH-04** 2FA (TOTP) and passkeys (WebAuthn); recovery codes `(P1: TOTP, P2: passkeys)`
- **USR-DASH-05** Login history and active sessions (kill a session) `(P1)`
- **USR-DASH-06** Language, theme (light/dark), date format `(P2)`
- **USR-DASH-07** Sub-users / team members: limited logins with chosen permissions (e.g. "only email", "only files") `(P3)`
- **USR-DASH-08** API tokens (user-scoped, IP allow-list, expiry) `(P2)`
- **USR-DASH-09** Resource usage graphs (CPU, RAM, IO, processes, limit hits) `(P3)`

## USR-DOM — Domains
- **USR-DOM-01** Domains list: primary, addon domains (own document root), subdomains, aliases (parked/pointers) `(P1)`
- **USR-DOM-02** Add/remove addon domain with document root choice `(P1)`
- **USR-DOM-03** Add/remove subdomain (including wildcard `*.domain`) `(P1)`
- **USR-DOM-04** Add/remove alias domain (same site as another domain) `(P1)`
- **USR-DOM-05** Change document root; force HTTPS; `www` ↔ non-`www` canonical choice `(P1)`
- **USR-DOM-06** Redirects: 301/302/307/308, with or without path, wildcard, per domain `(P1)`
- **USR-DOM-07** Domain ownership verification when the domain is already used on the server (TXT record), to prevent takeover `(P1)`
- **USR-DOM-08** Site preview URL (temporary URL before DNS points to the server) `(P3)`
- **USR-DOM-09** Per-domain PHP version and PHP settings `(P2)`
- **USR-DOM-10** Per-domain custom web server snippets (if allowed by admin) `(P3)`

## USR-DNS — DNS
- **USR-DNS-01** Zone editor: A, AAAA, CNAME, MX, TXT, SRV, CAA, NS (sub-delegation), PTR (if owner of IP), ALIAS/ANAME, TLSA, HTTPS/SVCB `(P1)`
- **USR-DNS-02** Simple mode (common records with helpers) and advanced mode (raw records) `(P1)`
- **USR-DNS-03** Email routing: local / remote (e.g. Google Workspace, Microsoft 365) / backup MX, auto-detected from MX `(P1)`
- **USR-DNS-04** Reset zone to template; import / export a zone file `(P2)`
- **USR-DNS-05** DNSSEC on/off, show DS records for the registrar `(P3)`
- **USR-DNS-06** Dynamic DNS (update a record with a secret URL / token) `(P3)`
- **USR-DNS-07** DNS check tool: show what the public internet sees vs our server (nameservers, propagation) `(P2)`

## USR-SSL — SSL/TLS
- **USR-SSL-01** Free automatic certificates (AutoSSL) for all domains/subdomains/aliases, with status and error reasons `(P1)`
- **USR-SSL-02** Wildcard certificates via DNS-01 (when DNS is hosted here, or via a supported DNS provider API) `(P2)`
- **USR-SSL-03** Upload own certificate, key, and CA bundle; validate that they match `(P1)`
- **USR-SSL-04** Generate private keys and CSRs; self-signed certificates `(P2)`
- **USR-SSL-05** HSTS on/off and settings per domain `(P2)`
- **USR-SSL-06** Exclude domains from AutoSSL `(P1)`

## USR-FILE — Files
- **USR-FILE-01** File manager: browse, upload (chunked, drag-and-drop, large files), download, create, rename, move, copy, delete (to trash), search `(P1)`
- **USR-FILE-02** Edit files in a code editor (syntax highlight, encoding choice), view images `(P1)`
- **USR-FILE-03** Permissions (chmod) and owner display; compress/extract zip, tar.gz, tar.zst, 7z (extract only) `(P1)`
- **USR-FILE-04** Trash with restore and empty `(P2)`
- **USR-FILE-05** Disk usage explorer: biggest folders and files `(P1)`
- **USR-FILE-06** Directory privacy: password-protect a folder (htpasswd users) `(P2)`
- **USR-FILE-07** WebDAV access to home folder ("Web Disk") `(P4)`
- **USR-FILE-08** Restore single files/folders from backups `(P2)`
- **USR-FILE-09** Image tools: resize, convert, thumbnails `(P5)`

## USR-FTP — FTP
- **USR-FTP-01** FTP accounts: create, delete, change password, quota, home folder restriction `(P1)`
- **USR-FTP-02** Show current FTP sessions; kill session `(P2)`
- **USR-FTP-03** FTPS required option; client config download (FileZilla XML) `(P2)`
- **USR-FTP-04** Anonymous FTP (admin can disable globally) `(P5)`

## USR-MAIL — Email
- **USR-MAIL-01** Email accounts: create, delete, password, quota, suspend login / incoming / outgoing per mailbox `(P1)`
- **USR-MAIL-02** Mailbox usage; clean up old mail (older than N days, by folder) `(P2)`
- **USR-MAIL-03** Forwarders: address → addresses, address → pipe to script, address → discard with error `(P1)`
- **USR-MAIL-04** Domain forwarders (all mail for domain A → domain B) `(P2)`
- **USR-MAIL-05** Autoresponders / vacation messages with start/end dates and interval `(P1)`
- **USR-MAIL-06** Default address (catch-all): deliver, forward, or reject `(P1)`
- **USR-MAIL-07** Filters (per mailbox and per account): Sieve rules builder + raw Sieve `(P2)`
- **USR-MAIL-08** Spam filter: on/off, score threshold, move to Junk / delete, allow and block lists `(P2)`
- **USR-MAIL-09** Email deliverability check per domain: SPF, DKIM, DMARC, PTR, with one-click repair `(P1)`
- **USR-MAIL-10** Track delivery: search the logs for messages sent or received by the account `(P2)`
- **USR-MAIL-11** Webmail single sign-on (Roundcube / SnappyMail) `(P1)`
- **USR-MAIL-12** Mail client setup: IMAP/POP/SMTP settings, autoconfig (Thunderbird), autodiscover (Outlook), Apple `.mobileconfig` profile `(P2)`
- **USR-MAIL-13** Calendars and contacts (CalDAV/CardDAV), e.g. via Radicale or SabreDAV `(P4)`
- **USR-MAIL-14** Mailing lists (Mailman 3) `(P4)`
- **USR-MAIL-15** Bulk import of mailboxes and forwarders from CSV `(P3)`
- **USR-MAIL-16** PGP/GPG key management for webmail `(P5)`
- **USR-MAIL-17** Send limits shown (per hour) and status if sending is held `(P2)`
- **USR-MAIL-18** Plus addressing (`user+tag@`) on/off `(P2)`

## USR-DB — Databases
- **USR-DB-01** MySQL/MariaDB databases: create, delete, rename, size `(P1)`
- **USR-DB-02** DB users: create, delete, password, privileges per database (all / custom list) `(P1)`
- **USR-DB-03** Database wizard (DB + user + grant in one step, shows connection info) `(P1)`
- **USR-DB-04** phpMyAdmin single sign-on (only their databases) `(P1)`
- **USR-DB-05** Remote access hosts (allow `%` or specific IPs/CIDRs) `(P2)`
- **USR-DB-06** Repair, check, optimize a database `(P2)`
- **USR-DB-07** Import (`.sql`, `.sql.gz`, `.sql.zst`) and export / download dump `(P2)`
- **USR-DB-08** PostgreSQL databases, users, and web admin SSO `(P3)`
- **USR-DB-09** Redis / Memcached per-account instance (private Unix socket, memory limit) `(P3)`

## USR-WEB — Web and PHP settings
- **USR-WEB-01** PHP version per domain (from versions the admin allows) `(P1)`
- **USR-WEB-02** PHP ini editor per domain: basic (common options) and advanced (`.user.ini`-style) `(P2)`
- **USR-WEB-03** PHP extensions on/off (from the admin-allowed list) `(P3)`
- **USR-WEB-04** Custom error pages (400, 401, 403, 404, 500, 502, 503) `(P2)`
- **USR-WEB-05** Hotlink protection (allowed referrers, file types) `(P2)`
- **USR-WEB-06** Directory indexes on/off per folder `(P2)`
- **USR-WEB-07** MIME types and handlers (Apache only) `(P3)`
- **USR-WEB-08** Gzip/Brotli compression on/off, browser caching rules `(P2)`
- **USR-WEB-09** IP blocker for their sites (deny IPs/CIDRs/countries) `(P2)`
- **USR-WEB-10** ModSecurity on/off per domain; disable specific rules (if admin allows) `(P3)`
- **USR-WEB-11** Leech protection (lock users of a protected folder who share passwords) `(P5)`
- **USR-WEB-12** Maintenance mode page per domain `(P3)`

## USR-APP — Applications
- **USR-APP-01** App installer: catalogue of open-source apps (WordPress, Joomla, Drupal, Nextcloud, Matomo, phpBB, Laravel skeleton, etc.) defined as YAML recipes; install, update, uninstall, list `(P3)`
- **USR-APP-02** WordPress manager: detect installs, update core/plugins/themes, clone to staging and push back, maintenance mode, debug mode, reset admin password, search/replace URL, security hardening, auto-update rules `(P3)`
- **USR-APP-03** Node.js apps: choose version, entry file, env vars, npm install, start/stop/restart, logs; served via reverse proxy `(P3)`
- **USR-APP-04** Python apps (WSGI/ASGI): version, virtualenv, pip install from `requirements.txt`, start/stop, logs `(P3)`
- **USR-APP-05** Ruby apps (Rack) `(P5)`
- **USR-APP-06** Git: create or clone repositories, deploy on push (`.xcp.yml` deploy tasks), webhook URL for GitHub/GitLab, SSH deploy keys `(P2)`
- **USR-APP-07** Composer and WP-CLI available in shell and as one-click actions `(P2)`
- **USR-APP-08** Docker/container apps for packages that allow them (rootless Podman per user) `(P5)`

## USR-ADV — Advanced
- **USR-ADV-01** Cron jobs: add/edit/delete with a schedule helper, output email or log, last run status `(P1)`
- **USR-ADV-02** SSH access: manage authorized keys, generate key pairs, SSH/SFTP connection info `(P2)`
- **USR-ADV-03** Web terminal (shell as the user inside their jail) `(P2)`
- **USR-ADV-04** Virus scan of the home folder (ClamAV), results and quarantine `(P3)`
- **USR-ADV-05** Environment variables for web apps per domain `(P3)`

## USR-STAT — Logs and statistics
- **USR-STAT-01** Bandwidth usage: per domain, per month, web/mail/FTP split `(P1)`
- **USR-STAT-02** Visitor statistics (GoAccess HTML reports, updated daily or real-time) `(P2)`
- **USR-STAT-03** Access log and error log viewers (last N lines, search, download raw logs) `(P1)`
- **USR-STAT-04** PHP error log viewer, PHP slow log `(P2)`
- **USR-STAT-05** Raw log archive settings (keep/delete monthly archives) `(P3)`
- **USR-STAT-06** Uptime/site quality check (HTTP check of own sites with alerts) `(P4)`

## USR-BAK — Backups
- **USR-BAK-01** Create full account backup now; download; delete `(P1)`
- **USR-BAK-02** Partial backups: home only, DBs only, mail only, one database `(P2)`
- **USR-BAK-03** Restore from own backup files (full or partial) and from server backups (if admin allows) `(P2)`
- **USR-BAK-04** Own scheduled backups to own remote destination (S3/SFTP/etc.) if allowed `(P3)`
- **USR-BAK-05** Backup of a single file/folder/DB point-in-time from server snapshots (file restore browser) `(P3)`

## USR-SUP — Help
- **USR-SUP-01** Help links per page (docs), contact support (ticket to reseller/admin) `(P4)`
