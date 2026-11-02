-- Account backups (USR-BAK-01, ADM-BAK-01, ADR-0013). The archives are
-- made and kept by xcp-agent in /var/backups/xcp/<user>/; these rows are
-- the panel's record of them.

CREATE TABLE backups (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('manual', 'scheduled')),
    status      TEXT NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
    file        TEXT NOT NULL DEFAULT '',  -- set when it is ok
    size        INTEGER NOT NULL DEFAULT 0,
    sha256      TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',  -- why it failed, or what it left out
    job_id      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    finished_at TEXT
) STRICT;

CREATE INDEX backups_account ON backups (account_id, created_at);
