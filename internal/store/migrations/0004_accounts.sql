-- Hosting accounts (ADM-ACC-01..06, 09, 11). One account = one Linux user.

CREATE TABLE accounts (
    id             TEXT PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,              -- Linux user name
    uid            INTEGER NOT NULL UNIQUE CHECK (uid BETWEEN 10000 AND 59999),
    owner_id       TEXT REFERENCES logins (id),       -- reseller who owns it; NULL = admins
    package_id     TEXT NOT NULL REFERENCES packages (id),
    primary_domain TEXT NOT NULL UNIQUE,
    email          TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL CHECK (status IN ('creating', 'active', 'suspended', 'terminating', 'error')),
    status_detail  TEXT NOT NULL DEFAULT '',          -- suspension reason or last error
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
) STRICT;

CREATE INDEX accounts_owner ON accounts (owner_id);
CREATE INDEX accounts_package ON accounts (package_id);

-- The account's own panel login (role "user") points to it via logins.account_id.
CREATE INDEX logins_account ON logins (account_id);
