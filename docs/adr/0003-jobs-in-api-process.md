# ADR-0003: Run background jobs inside xcp-api (for now)

- Status: accepted
- Date: 2026-10-28

## Context

`01-architecture.md` plans a separate `xcp-worker` process for jobs. P1 adds
the first jobs (account create, apply, terminate). A separate service means
another binary, systemd unit, installer step and health check, before there
is any load that needs it.

## Decision

- `xcp-api` starts a `jobs.Worker` in a goroutine and registers the job
  handlers. On shutdown it stops claiming jobs and waits for running jobs.
- The queue stays persistent in SQLite, with leases, so nothing changes for
  callers: jobs are enqueued in the same transaction as the change that
  needs them (`Queue.EnqueueTx`).

## Consequences

- One less process to install and monitor.
- A crash of `xcp-api` also stops running jobs; their leases expire and
  they are retried after restart (handlers are idempotent).
- When job volume grows (backups, transfers), move the worker into
  `cmd/xcp-worker` with the same `RegisterJobs` calls; no queue changes.
