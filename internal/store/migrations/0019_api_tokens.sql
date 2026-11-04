-- API tokens (ADR-0021): a login's own long-lived credentials for scripts.
-- Only the SHA-256 of the secret is kept; the prefix finds the row.

CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    login_id     TEXT NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL UNIQUE,
    hash         BLOB NOT NULL,
    scope        TEXT NOT NULL CHECK (scope IN ('read', 'write')),
    ip_allow     TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    last_used_at TEXT,
    last_used_ip TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX api_tokens_login ON api_tokens (login_id, created_at);
