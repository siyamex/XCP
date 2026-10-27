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
  Docker cannot test disk quotas, real DNS or public TLS: P1 needs a VM or VPS.

## Follow-ups noted during P0

- xcp-agent's systemd sandbox scores 8.2 ("exposed") because it runs as root
  with broad access. Tighten it (ProtectSystem with explicit ReadWritePaths,
  CapabilityBoundingSet) once P1 shows exactly what it must touch.
- The browser smoke test used in task 9 was a throwaway script; add a real
  Playwright suite to `test/e2e/` with the first P1 UI pages.
- Frontend has no ESLint yet.

## Features done

None yet (features start in P1).
