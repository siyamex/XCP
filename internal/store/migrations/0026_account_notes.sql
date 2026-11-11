-- Internal notes and tags on accounts, for admins only (ADM-ACC-18).

CREATE TABLE account_notes (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    note       TEXT NOT NULL,
    tags       TEXT NOT NULL,           -- JSON array of strings
    updated_by TEXT NOT NULL,           -- login ID
    updated_at TEXT NOT NULL
) STRICT;
