# ADR-0001: Hand-written SQL instead of sqlc (for now)

- Status: accepted
- Date: 2026-10-27

## Context

`02-tech-stack-and-repo.md` planned `sqlc` to generate query code. The sqlc
binary needs cgo (its PostgreSQL parser), so it does not build with
`go install` on a Windows dev machine without a C compiler, and it adds a
code-generation step to every DB change. In P0 we only have a handful of
tables (logins, sessions, settings, audit_events, jobs).

## Decision

- Use `database/sql` with hand-written SQL inside `internal/store`.
- Keep every query in the repository that owns the table, with a test that
  runs it against a real SQLite database (in-memory or temp file).
- Use `modernc.org/sqlite` (pure Go, no cgo), as planned.
- Use a small built-in migration runner (`internal/store/migrate.go`) instead
  of `goose`: forward-only SQL files embedded in the binary, each applied in a
  transaction, with a `VACUUM INTO` backup before migrating an existing
  database. We never need down-migrations (the backup is the rollback), and
  it is one dependency less to trust.

## Consequences

- No generated code and no extra tool. Dev works on Windows.
- Column/struct mismatches are caught by tests, not by a generator, so every
  repository method needs a test.
- Revisit at the end of P1. If the store has grown past ~40 queries, adopt
  sqlc using its prebuilt release binary in CI.
