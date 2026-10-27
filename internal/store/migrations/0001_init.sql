-- P0 base tables. Times are TEXT in store.FormatTime layout (UTC, fixed width).
-- IDs are ULIDs (internal/ids).

CREATE TABLE logins (
    id                   TEXT PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE,
    role                 TEXT NOT NULL CHECK (role IN ('admin', 'reseller', 'user', 'subuser')),
    password_hash        TEXT NOT NULL,
    totp_secret_enc      BLOB,
    totp_last_step       INTEGER NOT NULL DEFAULT 0, -- TOTP replay protection
    status               TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'locked')),
    email                TEXT NOT NULL DEFAULT '',
    locale               TEXT NOT NULL DEFAULT 'en',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    owner_id             TEXT REFERENCES logins (id),  -- reseller/admin who owns this login
    account_id           TEXT,                         -- hosting account (FK added with accounts table in P1)
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    last_login_at        TEXT
) STRICT;

CREATE INDEX logins_owner ON logins (owner_id);

CREATE TABLE sessions (
    id_hash         BLOB PRIMARY KEY,                -- SHA-256 of the session token
    login_id        TEXT NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    impersonator_id TEXT REFERENCES logins (id) ON DELETE CASCADE,
    mfa_passed      INTEGER NOT NULL DEFAULT 0,
    ip              TEXT NOT NULL,
    user_agent      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    reauth_at       TEXT                             -- last password/2FA re-check
) STRICT;

CREATE INDEX sessions_login ON sessions (login_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,                        -- JSON
    updated_at TEXT NOT NULL
) STRICT;

-- Append-only, hash-chained (07-security.md §9).
CREATE TABLE audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              TEXT NOT NULL,
    actor_id        TEXT,
    impersonator_id TEXT,
    role            TEXT NOT NULL DEFAULT '',
    ip              TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT '',
    action          TEXT NOT NULL,
    target_type     TEXT NOT NULL DEFAULT '',
    target_id       TEXT NOT NULL DEFAULT '',
    account_id      TEXT,
    request_id      TEXT NOT NULL DEFAULT '',
    result          TEXT NOT NULL CHECK (result IN ('ok', 'denied', 'error')),
    details         TEXT NOT NULL DEFAULT '{}',      -- JSON, secrets masked
    prev_hash       BLOB,
    hash            BLOB NOT NULL
) STRICT;

CREATE INDEX audit_account ON audit_events (account_id, id);
CREATE INDEX audit_actor ON audit_events (actor_id, id);

CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

-- Persistent job queue (01-architecture.md §5).
CREATE TABLE jobs (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    payload      TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    progress     INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    run_after    TEXT NOT NULL,
    locked_by    TEXT,
    locked_until TEXT,
    lock_key     TEXT,                               -- e.g. "account:<id>" to serialise jobs per account
    account_id   TEXT,
    created_by   TEXT,
    result       TEXT,
    error        TEXT,
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT
) STRICT;

CREATE INDEX jobs_claim ON jobs (status, run_after);
CREATE INDEX jobs_account ON jobs (account_id, created_at);
CREATE INDEX jobs_lock_key ON jobs (lock_key, status);

CREATE TABLE job_logs (
    job_id  TEXT NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    seq     INTEGER NOT NULL,
    at      TEXT NOT NULL,
    level   TEXT NOT NULL,
    message TEXT NOT NULL,
    PRIMARY KEY (job_id, seq)
) STRICT;
