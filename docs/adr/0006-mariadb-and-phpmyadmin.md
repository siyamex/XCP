# ADR-0006: MariaDB through the root socket; phpMyAdmin sign-on with one-time tickets

- Status: accepted
- Date: 2026-10-29
- Amends: 06-service-drivers.md §6 (Databases)

## Context

P1 needs MariaDB databases and users per account (USR-DB-01..03), a new
root password on demand (ADM-DB-09) and phpMyAdmin with single sign-on
(USR-DB-04, ADM-DB-08). The plan left open how the agent gets root access,
where database user passwords live, how phpMyAdmin is installed and served
(07-security asks for a separate origin and pinned tarballs) and how the
sign-on works ("temporary per-session user is safer").

## Decision

- **Server:** MariaDB from Ubuntu (10.11 on 24.04), listening on localhost
  only. Remote access (USR-DB-05) is P2.
- **Root access:** the agent runs as root and connects to
  `/run/mysqld/mysqld.sock` as MariaDB's `root`, which Ubuntu sets up with
  `unix_socket` authentication. There is no credential file. A root
  password (ADM-DB-09) is added as a second way in
  (`IDENTIFIED VIA unix_socket OR mysql_native_password`), for the admin's
  own tools; the agent never needs it.
- **Names:** databases and users are `<username>_<name>` with `[a-z0-9_]`;
  databases up to 64 characters, users up to 32 (MySQL's limit, which some
  tools keep). Account names have no `_`, so the prefix tells the owner.
  Grants name the database with `_` and `%` escaped, because MariaDB reads
  them as wildcards there. Users are `'name'@'localhost'`.
- **Source of truth:** the panel database. `MySQLAccountApply` makes the
  account's users, passwords, grants and lock state match exactly, and
  creates missing databases. A database is dropped only when asked by name
  (`MySQLDatabaseDrop`) or when the account is terminated, never because a
  list missed it. The agent checks that every name has the account's
  prefix, so one account's request cannot touch another's databases.
- **Passwords:** xcp-api stores MariaDB's own hash (`mysql_native_password`,
  what MariaDB stores anyway), encrypted with the master key, and sends
  only the hash to the agent (`IDENTIFIED BY PASSWORD`). Plain passwords
  never leave xcp-api's request handling.
- **Suspension** locks the account's database users (`ACCOUNT LOCK`) and
  drops its sign-on users.
- **Rename** is `CREATE DATABASE`, one `RENAME TABLE` for all tables and
  `DROP DATABASE`. Views, triggers, routines and events cannot move that
  way, so rename refuses databases that have them (export/import is P2).
- **phpMyAdmin:** xcp-install downloads a pinned release (version and
  SHA-256 in the code) to `/usr/share/xcp/phpmyadmin` and runs it in its
  own PHP-FPM pool as the system user `xcp-pma`. Apache serves it only on
  the server's host name over HTTPS, at `https://<host>/phpmyadmin/`, a
  different origin from the panel (`:2443`). Cookies do not separate
  ports, so Apache removes the panel's session cookie from requests to
  phpMyAdmin. phpMyAdmin allows sign-on only (no login form, no root).
  That virtual host uses the host name certificate once AutoSSL has one.
- **Sign-on:** the agent creates a temporary MariaDB user
  `xcp_sso_<username>_<expiry>_<random>` with a random password and all
  privileges on the account's databases, valid for 4 hours. The expiry is
  in the name, so a job every 10 minutes can drop expired users without
  any stored state. The agent writes a one-time ticket (user, password,
  2 minutes) to a folder only `xcp-pma` can read and returns its ID; the
  browser goes to `/phpmyadmin/xcp-signon.php?ticket=<id>`, which deletes
  the ticket and starts phpMyAdmin's sign-on session. xcp-api never sees
  the temporary password.

## Consequences

- No MariaDB secret to protect, rotate or lose; root on the server is root
  in MariaDB, as it is anyway.
- The panel database alone can rebuild users and grants (restore, server
  move); data comes from backups (P2).
- `mysql_native_password` is MariaDB 10.11's usual method and what PHP apps
  expect. When MariaDB's newer methods (PARSEC) are common, the stored
  hash changes with them.
- A phpMyAdmin session shows the databases that existed when it started;
  a new database needs a new sign-on. Expired users stop working within
  10 minutes of their expiry.
- phpMyAdmin updates are a code change (new version and SHA-256); the
  installer replaces the tree and keeps its secrets.
- Database tools that need a root login use the socket as root, or the
  root password if the admin set one.
