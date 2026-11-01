-- MariaDB databases and users of accounts (USR-DB-01..03, ADR-0006). The
-- panel database is the source of truth: xcp-agent makes MariaDB match it.
-- Names are the full names on the server: <username>_<name>.

CREATE TABLE databases (
    id         TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    engine     TEXT NOT NULL DEFAULT 'mysql' CHECK (engine IN ('mysql')),
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX databases_engine_name ON databases (engine, name);
CREATE INDEX databases_account ON databases (account_id);

CREATE TABLE db_users (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    engine       TEXT NOT NULL DEFAULT 'mysql' CHECK (engine IN ('mysql')),
    name         TEXT NOT NULL,
    password_enc BLOB NOT NULL,  -- MariaDB's own hash (mysql_native_password), encrypted
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX db_users_engine_name ON db_users (engine, name);
CREATE INDEX db_users_account ON db_users (account_id);

CREATE TABLE db_grants (
    db_user_id  TEXT NOT NULL REFERENCES db_users (id) ON DELETE CASCADE,
    database_id TEXT NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
    privileges  TEXT NOT NULL,  -- JSON array: ["ALL"] or names like "SELECT"
    PRIMARY KEY (db_user_id, database_id)
) STRICT;

CREATE INDEX db_grants_database ON db_grants (database_id);
