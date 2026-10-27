# 02 — Tech Stack, Repo Layout, Conventions

## 1. Backend (Go)

| Concern | Choice | Notes |
|---|---|---|
| Go version | 1.26+ | pinned in `go.mod` (GOTOOLCHAIN auto-downloads it) |
| HTTP router | std `net/http` ServeMux (Go 1.22+ patterns) | one route table with access levels (ADR-0002) |
| API contract | OpenAPI 3.1, hand-written `api/openapi.yaml` | parity test against the route table (ADR-0002) |
| Agent RPC | gRPC + protobuf over Unix socket, `buf` for codegen | `proto/xcp/agent/v1/*.proto` |
| DB | SQLite via `modernc.org/sqlite` | WAL, hand-written SQL and built-in migration runner (ADR-0001) |
| Logging | `log/slog` (JSON in prod) | request ID, actor, account in every log line |
| Config | TOML (`/etc/xcp/xcp.toml`), `BurntSushi/toml` | env overrides for dev |
| ACME | `go-acme/lego/v4` | HTTP-01 + DNS-01 (via local PowerDNS / Cloudflare etc.) |
| DNS | `miekg/dns` (parse, validate, AXFR, checks) + PowerDNS HTTP API | |
| Firewall | `google/nftables` | own table `inet xcp` |
| systemd | `coreos/go-systemd/v22` (D-Bus) | units, slices, transient scopes |
| Metrics | `shirou/gopsutil/v4`, Prometheus `client_golang` | `/metrics` for admins |
| Terminal | `creack/pty` + `coder/websocket` | xterm.js on the frontend |
| Auth | `golang.org/x/crypto/argon2` (argon2id), `pquerna/otp` (TOTP), `go-webauthn/webauthn` (passkeys) | |
| System passwords | SHA-512-crypt / yescrypt (for `/etc/shadow`, Dovecot) | via a vetted crypt lib |
| MySQL / PG clients | `go-sql-driver/mysql`, `jackc/pgx/v5` | |
| Storage clients | `minio-go/v7` (S3-compatible), `pkg/sftp`, `jlaffaye/ftp`; others via `rclone` binary | |
| Compression | `klauspost/compress/zstd` | backup archives `.tar.zst` |
| Cron parsing | `robfig/cron/v3` (validation + scheduler) | |
| Validation | own `internal/validate` + `golang.org/x/net/idna`, `publicsuffix` | |
| Email (sending notices) | `wneessen/go-mail` | |
| Testing | stdlib `testing`, `google/go-cmp`, `testcontainers-go`, fuzzing | |
| Lint | `golangci-lint` (incl. staticcheck, gosec, errcheck), `govulncheck`, `gofumpt` | CI-enforced |
| Release | `goreleaser` + `nfpm` → `.deb` / `.rpm`, cosign signatures | |

## 2. Frontend

| Concern | Choice |
|---|---|
| Framework | React 19 + TypeScript + Vite |
| Routing / data | TanStack Router + TanStack Query |
| UI kit | Tailwind CSS + shadcn/ui (Radix), light/dark themes, CSS variables for white-label |
| API client | generated from OpenAPI (`openapi-typescript` + `openapi-fetch`) |
| Code editor | CodeMirror 6 (file manager, zone editor, config editors) |
| Terminal | xterm.js |
| Charts | Recharts or ECharts |
| i18n | i18next (all strings are keys; `en` first, community translations) |
| Tests | Vitest (unit), Playwright (e2e) |
| Delivery | built to `web/dist`, embedded in `xcp-api` with `go:embed` |

One SPA serves all three roles. The menu and pages depend on the role and
feature list returned by `/api/v1/me`. Admin and reseller can "log in as" a
user (impersonation banner, audited).

## 3. Repository layout

```
/
├── MASTER_PROMPT.md
├── go.mod
├── api/openapi.yaml                 # public REST contract
├── proto/xcp/agent/v1/*.proto # agent RPC contract
├── cmd/
│   ├── xcp-api/  xcp-worker/  xcp-agent/  xcp-userd/
│   ├── xcp-logd/ xcp-ftpauth/ xcp-mailpolicy/ xcp-monitor/
│   ├── xcpctl/                       # CLI
│   └── xcp-install/                  # installer (bootstraps a fresh server)
├── internal/
│   ├── app/                         # wiring / dependency injection per binary
│   ├── config/
│   ├── httpapi/                     # handlers (generated strict server impl), middleware
│   ├── auth/  rbac/  session/  audit/  ratelimit/
│   ├── store/                       # sqlc queries, migrations/, repositories
│   ├── jobs/                        # queue, scheduler, job kinds
│   ├── core/                        # domain services (business rules, limits)
│   │   ├── account/ pkgplan/ domain/ dns/ mail/ db/ ftp/ ssl/
│   │   ├── cron/ backup/ transfer/ php/ apps/ stats/ security/ ...
│   ├── reconcile/                   # generators + apply/rollback
│   ├── drivers/
│   │   ├── os/      (ubuntu, debian, rhel)
│   │   ├── web/     (apache, nginx, nginxproxy, openlitespeed)
│   │   ├── php/     (fpm)
│   │   ├── mail/    (postfix_dovecot)
│   │   ├── spam/    (rspamd)
│   │   ├── dns/     (powerdns, bind)
│   │   ├── dbsrv/   (mariadb, postgres)
│   │   ├── ftp/     (pureftpd)
│   │   ├── firewall/(nftables)
│   │   └── storage/ (local, s3, sftp, ftp, rclone)
│   ├── agentrpc/                    # client + server + op implementations
│   ├── userhelper/                  # xcp-userd: fs ops, pty, git, app installs
│   ├── fsx/                         # safe file ops (openat2, no symlink follow)
│   ├── execx/                       # safe exec (absolute path, argv, env, timeout)
│   ├── validate/                    # all input validators (+ fuzz tests)
│   ├── templates/                   # embedded *.tmpl for all generated configs
│   ├── notify/                      # email, webhook, Slack, Telegram
│   └── i18n/                        # backend messages (emails, errors)
├── pkg/client/                      # public Go SDK for the REST API
├── web/                             # React SPA
├── packaging/                       # systemd units, nfpm config, default configs
├── scripts/                         # dev helpers, install.sh
├── test/
│   ├── golden/                      # expected generated configs
│   ├── integration/                 # driver tests against real services (containers)
│   └── e2e/                         # Playwright + full VM scenarios
└── docs/
    ├── plan/                        # these spec files
    ├── user/  admin/  dev/          # end-user, admin, developer docs
    └── adr/                         # architecture decision records
```

## 4. Coding conventions

- **Layers:** `httpapi` → `core` (rules, limits, RBAC checks) → `store` + `jobs`
  + `agentrpc`. Handlers have no business logic. `core` has no HTTP types.
- **Errors:** typed domain errors (`ErrNotFound`, `ErrLimitReached`,
  `ErrForbidden`, `ErrConflict`, `ErrValidation{Field, Code}`) that map to
  RFC 9457 problem+json responses.
- **IDs:** ULIDs (sortable) as strings in the API; integer `uid`/`gid` only for
  Linux users.
- **Time:** always UTC in DB and API (RFC 3339). Convert in the UI only.
- **Context:** every exported function that does I/O takes `ctx` first.
- **Exec:** only through `execx.Run(ctx, Cmd{Path: "/usr/sbin/postmap", Args: ...})`.
  The linter bans `os/exec` outside `execx`.
- **Files:** only through `fsx` (user content) or `agent.FileWriteManaged`
  (system config). The linter bans `os.WriteFile` in `core` and `drivers`.
- **Templates:** `text/template` with a strict func map. Every value inserted
  into a config has already passed validation. Per-format escaping helpers
  (`apacheQuote`, `nginxQuote`, `dnsTXT`).
- **Feature flags:** every user-level feature checks the account's feature
  list in `core` (never only in the UI).
- **Docs:** each new API endpoint has an OpenAPI description and an example.
  Each new feature has a docs page in `docs/user` or `docs/admin`.
- **Commits:** Conventional Commits, with feature IDs: `feat(mail): add autoresponders (USR-MAIL-05)`.

## 5. Dev environment

- `make dev`: runs `xcp-api` with a **fake agent** (records operations to
  memory), plus the Vite dev server. Lets you build UI and API on any OS,
  including Windows/macOS.
- `make vm`: boots an Ubuntu 24.04 VM (Incus/Multipass/Vagrant), installs
  services, and runs the real agent. Used for driver work.
- `make test`, `make test-integration`, `make e2e`, `make lint`, `make golden-update`.

## 6. License (decide early)

- Recommended: **AGPL-3.0** for the panel (forks that host it must share
  changes), **Apache-2.0** for `pkg/client`, the plugin SDK, and billing
  modules (so commercial billing systems can use them).
- Contributors sign off commits (DCO). Add a `SECURITY.md` with a private
  vulnerability reporting process.
