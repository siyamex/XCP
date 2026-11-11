# ADR-0037: Database export and import

Status: accepted (2026-11-11)

## Context

USR-DB-07: customers export a database to a dump and import dumps
(`.sql`, `.sql.gz`, `.sql.zst`). The dump tools need MariaDB's root, which
only xcp-agent has; the files belong in the customer's reach.

## Decision

- Dumps live in the **account's home**. The file manager already uploads,
  downloads and deletes there, so the databases page needs no transfer of
  its own, and a dump can be as large as the home allows.
- **Export** (`MySQLDatabaseExport`, job `db.export`): `mariadb-dump` of the
  one database, gzipped, into a new file `db-dumps/<db>-<time>.sql.gz`,
  created with `O_EXCL` through `fsx` (no links followed) and given to the
  account's user before any data is written; mode 0600. Without
  `--databases`, so the dump names no database and imports under another
  name.
- Root's writes ignore the disk quota. To bound what exports can pile up,
  an export is refused while `db-dumps` holds 20 files.
- **Import** (`MySQLDatabaseImport`, job `db.import`): the path is cleaned
  and opened beneath the home without following links; the file must be a
  regular file **owned by the account's user**. Otherwise the account could
  make root read another user's file and see parts of it in the client's
  error message.
- The statements run through the same path as a restore (ADR-0015): a
  temporary MariaDB user with all privileges on that one database and
  nothing else, `DEFINER` clauses removed, the client started in the
  database. A dump that reaches for another database fails at that
  statement.
- Both run as jobs under the account's lock key, one attempt: a half-run
  import must not run again by itself.

## Consequences

- An import is not atomic: statements before a failing one stay done.
- A dump made with `--databases` for another name (`USE other;`) fails;
  the customer exports again without it, or edits the file.
- The agent has one MariaDB connection: a long export or import delays
  other database changes on the server.

## Not done

- Upload and download from the databases page itself.
- Scheduled exports (that is what backups are for).
