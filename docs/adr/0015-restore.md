# ADR-0015: Backups outlive their account; an admin restores a removed account

- Status: accepted
- Date: 2026-11-04
- Amends: ADR-0013 (local backups), 06-service-drivers.md §11

## Context

The P1 acceptance test ends with "backup → terminate → restore → the site
works again". ADR-0013 deleted an account's backups with the account, so
nothing was left to restore from, and no restore existed. Restoring writes
into a live server from a file that may be damaged or hostile.

## Decision

- **Backups stay when their account is removed.** The agent keeps the
  folder; the panel's record loses its account id and keeps the account's
  name. Admins see them under "Backups of removed accounts", can download,
  delete or restore them. No user sees them: a later account with the same
  name does not inherit them.
- **P1 restores a removed account** (USR-BAK-03 and ADM-BAK-04 for whole
  accounts). Restoring over an existing account, and partial restores, wait
  for P2. The restore is a job (`backup.restore`, one per account name):
  1. **Inspect (agent, writes nothing):** read the whole archive and check it
     against its manifest: format, account, SHA-256 of every file, no entry
     the manifest does not list, none outside `homedir/`, `mysql/` and the
     two json files.
  2. **Settings (panel, one transaction):** put the rows of `account.json`
     back with their ids, as a new account with a fresh uid, the package of
     the same name (or the admin's choice) and no reseller owner. Table and
     column names come from the server's own schema, never from the archive;
     a column the schema lacks, or a schema newer than the server's, stops the
     restore. An account, domain or login name already in use stops it too.
  3. **Create the account:** the normal account apply (Linux user, home,
     limits, websites with their certificates, and every attached service:
     databases, mail, FTP, cron).
  4. **Files (agent):** the archive's `homedir/` is unpacked by `tar` running
     as the account's user in its slice. Only clean relative names, regular
     files, folders, symlinks and hard links inside the home pass; setuid and
     setgid bits and owners are dropped.
  5. **Databases (agent):** each dump runs in the `mariadb` client as a
     temporary user that has privileges on that one database only, which is
     dropped afterwards; DEFINER clauses are removed from the lines that
     define routines, triggers, views and events.
  6. **DNS:** the account's zones are applied; the backups are linked back to
     the account.

## Consequences

- A removed account's data stays on disk until an admin deletes its backups:
  removal is no longer a way to free that space.
- A restore trusts the archive only as far as the checks above: a crafted
  backup can change the account's own files, databases and settings, never
  another account's or the system's.
- Restoring on another server works while the master key is the same
  (certificate keys and 2FA secrets are encrypted with it).
