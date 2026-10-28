# 01 — Architecture

## 1. Process model

```
                Browser (SPA)          xcpctl (CLI)        Billing (WHMCS etc.)
                     │                      │                     │
                     └──────── HTTPS :2443 (REST + WebSocket) ────┘
                                         │
                 ┌───────────────────────▼────────────────────────┐
                 │ xcp-api  (user: xcp, unprivileged)       │
                 │  auth · RBAC · validation · business logic     │
                 │  REST/OpenAPI · SPA assets (go:embed) · WS     │
                 │  SQLite (WAL) · job scheduler                  │
                 └───────┬───────────────────────────┬────────────┘
                         │ gRPC over Unix socket     │ job queue (DB)
                         │ /run/xcp/agent.sock│
                 ┌───────▼───────────┐       ┌───────▼────────────┐
                 │ xcp-agent (root)   │◄──────│ xcp-worker          │
                 │ typed operations  │       │ (unprivileged)     │
                 │ only; no shell    │       │ runs long jobs     │
                 └───────┬───────────┘       └────────────────────┘
                         │ exec argv / D-Bus / files / sockets
     ┌──────────┬────────┼─────────┬──────────┬──────────┬──────────┐
   Apache/   PHP-FPM  Postfix/   PowerDNS   MariaDB/  Pure-FTPd  nftables
   Nginx/OLS  pools   Dovecot/              PostgreSQL           systemd
                      Rspamd
```

Helper daemons (small, single-purpose binaries):

| Binary | Runs as | Purpose |
|---|---|---|
| `xcp-api` | `xcp` | HTTP API, UI, auth, DB owner |
| `xcp-worker` | `xcp` | Executes queued jobs; calls agent for privileged steps |
| `xcp-agent` | `root` | Privileged typed operations only |
| `xcp-userd` | per-user (spawned by agent, setuid to user) | File manager, terminal PTY, git, app installs: runs **as the account user** |
| `xcp-logd` | `xcp` + `adm` group | Ingests web/mail/FTP logs → bandwidth & stats, brute-force detection |
| `xcp-ftpauth` | `root` (socket only) | Pure-FTPd external auth handler backed by the DB |
| `xcp-mailpolicy` | `xcp` | Postfix policy server: per-account send limits, outbound-spam brake |
| `xcp-monitor` | `root` | Service health checks, auto-restart, disk/resource alerts |
| `xcpctl` | admin shell | CLI over the API (or local socket with root) |

All binaries come from one Go module and are shipped as one package.

## 2. Why this split

- A bug in the web-facing process (the most exposed) does **not** give root.
- The agent's surface is a closed list of operations with typed protobuf
  messages, each re-validated inside the agent (never trust the API).
- The agent checks the peer with `SO_PEERCRED`: it only accepts `xcp`
  (api/worker) and root.
- User-content operations run as the user (`xcp-userd`), so file-permission
  bugs cannot escalate across accounts.

## 3. Agent operation catalogue (examples)

Each operation is idempotent and has a typed request and response:

```
UserEnsure(username, uid, home, shell, groups)      UserDelete(username, keepHome)
QuotaSet(username, blocks, inodes)                  SliceSet(username, cpu, mem, io, tasks)
FileWriteManaged(path, content, mode, owner, validateCmdID)
ServiceReload(service) / ServiceRestart / ServiceStatus
WebVhostApply(accountID)    PHPPoolApply(accountID)   MailDomainApply(domainID)
DNSZoneApply(zoneID)        DBCreate/DBUserGrant      FTPAccountApply
CertInstall(certID)         FirewallApply(rulesetVersion)
CronApply(username)         SpawnUserHelper(username, helperKind) → fd/socket
PackageInstall(pkgSet)      (allow-listed package sets only)
```

`FileWriteManaged` only writes inside allow-listed directories
(`/etc/xcp/generated/...`, service include dirs), and `validateCmdID`
picks a **fixed** validator (not a free command).

## 4. Desired state and the reconciler

- The DB holds the desired state. Generators are pure functions:
  `Generate(model) → []File`. They are easy to golden-test.
- `reconcile.Apply(scope)` does this: generate → diff with disk → write
  changed files atomically → validate → reload the affected services →
  on failure restore the previous files and mark the job failed.
- Scopes: `account:<id>`, `domain:<id>`, `service:web`, `service:mail`, `all`.
- `xcpctl rebuild <scope>` exposes it. It is also used after upgrades.
- **Amended by ADR-0004:** configs that can run code (web, mail, DNS) are
  rendered inside the agent from typed requests, not sent as text by the API.
- Admin customisation goes through **template overrides**
  (`/etc/xcp/templates/custom/*.tmpl`) and **per-domain snippets**
  stored in the DB, never by editing generated files.

## 5. Job queue

- Table `jobs(id, kind, payload, status, progress, attempts, run_after,
  locked_by, locked_until, owner_account_id, created_by, result, log)`.
- Workers claim jobs with `UPDATE ... WHERE status='queued' ... RETURNING`
  and a lease. Expired leases are retried. Each job has a max-attempt limit.
- Job kinds have per-kind concurrency limits (for example, 1 backup per
  account, N backups server-wide).
- Progress and logs stream to the UI over WebSocket (`/api/v1/jobs/{id}/stream`).
- Scheduled work (cron-like): backups, AutoSSL renewals, bandwidth roll-ups,
  quota scans, update checks, log rotation.

## 6. Data storage

- **SQLite** in WAL mode (`/var/lib/xcp/xcp.db`), using `modernc.org/sqlite`
  (no cgo). One writer connection plus a read pool. All access goes through
  repository interfaces, so a PostgreSQL backend can be added later for the
  multi-node controller (P4).
- Migrations: forward-only SQL files embedded in the binary
  (`internal/store/migrations`, ADR-0001). Run automatically on start, and
  the DB is backed up (`VACUUM INTO`) before migrating.
- The panel DB itself is backed up nightly (`xcp-db-YYYYMMDD.sqlite.zst`).

## 7. Multi-server (P4)

- **Controller mode:** one `xcp-api` manages many nodes. Each node runs
  `xcp-agent` plus `xcp-node` (mTLS gRPC over TCP, outbound-only from node to
  controller is preferred so it works behind NAT).
- Roles per node: web, mail, dns, db, backup. An account is placed on a
  web node; its mail/DB can live on other nodes.
- **DNS cluster:** PowerDNS primary/secondary (AXFR/NOTIFY) or API sync.
- **Config cluster:** push packages, feature lists, templates, and branding to
  all nodes.
- Account move between nodes = backup → transfer → restore → DNS switch.

## 8. Upgrades

- Release channels: `stable`, `current`, `edge`. Signed releases (minisign/cosign).
- `xcpctl update` downloads, verifies the signature, stops services, swaps the
  binaries, runs migrations, runs `rebuild all --dry-run` and then the real
  rebuild, and starts services. Rolls back to the previous binaries if health
  checks fail.
- OS package updates go through the OS driver with an allow-list.

## 9. Supported OS (OSDriver)

| Phase | OS |
|---|---|
| P1 | Ubuntu 24.04 LTS |
| P2 | Debian 12/13, AlmaLinux / Rocky 9 |
| P3 | AlmaLinux / Rocky 10, Ubuntu 26.04 LTS |

`OSDriver` abstracts: package install (apt/dnf), service names and paths,
repos (Sury PPA / Remi for PHP), user and group tools, quota tools, SELinux
or AppArmor handling, and firewall backend.

## 10. Ports (defaults, configurable)

| Port | Use |
|---|---|
| 2443 | Panel (all roles, HTTPS) |
| 2080 | HTTP → HTTPS redirect for the panel |
| Proxy subdomains | `panel.<domain>`, `webmail.<domain>`, `mail.<domain>` via the web server |
| 80/443 | Websites |
| 25/465/587/110/995/143/993/4190 | Mail (SMTP, submission, POP3, IMAP, ManageSieve) |
| 53 | DNS |
| 21 + passive range | FTP/FTPS |
| 22 | SSH/SFTP |
