-- Hosts besides the server itself from which an account's database users
-- may connect (USR-DB-05), as MariaDB host patterns.

CREATE TABLE db_remote_hosts (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    host       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (account_id, host)
) STRICT;
