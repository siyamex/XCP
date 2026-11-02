-- Cron jobs of accounts (USR-ADV-01, ADR-0011). The panel database is the
-- source of truth; xcp-agent runs them. Their last runs live in the agent.

CREATE TABLE cron_jobs (
    id         TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    schedule   TEXT NOT NULL,              -- 5 fields, server time
    command    TEXT NOT NULL,              -- one line, run with /bin/sh as the account's user
    email      TEXT NOT NULL DEFAULT '',   -- where output is mailed; '' = kept only
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX cron_jobs_account ON cron_jobs (account_id);
