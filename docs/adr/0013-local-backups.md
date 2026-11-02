# ADR-0013: Local account backups made by the agent, the home read as the user

- Status: accepted
- Date: 2026-11-02
- Amends: 06-service-drivers.md §11 (Backups)

## Context

USR-BAK-01 needs a full account backup on demand, to download and delete;
ADM-BAK-01 needs scheduled backups with retention (local in P1). The
archive format is set (06-service-drivers.md §11); the P1 acceptance test
restores from it, so it must hold everything a restore needs. Left open:
who reads the home (root reading user-controlled paths is what 07-security
forbids), where archives live, and how they are downloaded.

## Decision

- **Archive:** `/var/backups/xcp/<user>/<user>-<UTC time>.tar.zst`, a tar
  compressed with zstd, holding `manifest.json` (format 1, panel version,
  account, time, the size and SHA-256 of every other entry), `account.json`
  (written by xcp-api from the panel database: the account, its package
  name, domains, DNS zones and records, mail domains, mailboxes and
  forwarders with their password hashes and DKIM keys, FTP logins, cron
  jobs, databases with their users and grants, SSL certificates with their
  keys), `homedir/…` (the home folder, mail included) and
  `mysql/<database>.sql` (one dump per database). The folder is root only:
  the account's user can neither read nor change its backups, and they do
  not count against its disk quota.
- **The home is read as the user:** the agent runs `tar` as the account's
  user in its slice through `systemd-run --pipe` (so its CPU and I/O limits
  apply and a symlink can never lead root out of the home) and re-packs
  that stream entry by entry under `homedir/`. Files the user cannot read
  are left out and listed in the job result.
- **Databases** are dumped by the agent with `mariadb-dump
  --single-transaction` (routines, triggers and events included) to a
  root-only staging file, then added.
- **Jobs:** `backup.create` runs one at a time on the server, under the
  account's lock key; a failed backup leaves no file. xcp-api records each
  backup (manual or scheduled, size, checksum, status). Users may keep 3
  manual backups at a time; scheduled ones are pruned to the admin's
  "keep" count. Terminating the account removes its backups.
- **Schedule:** the admin sets daily, weekly or monthly at an hour, and how
  many to keep; an hourly job starts the due run for every active or
  suspended account.
- **Download** streams the archive from the agent in 1 MiB parts
  (`BackupRead`), like the log download.

## Consequences

- A backup's account.json holds the account's secrets (password hashes,
  DKIM and TLS keys). Only the account's user and the admin can download
  it; encryption (age) comes with remote destinations (P2).
- Backups need free space next to `/var/backups`; an out-of-space backup
  fails cleanly and is reported.
- Restore (the P1 acceptance test, then USR-BAK-03 and ADM-BAK-04) reads
  this format with the safe-extraction rules of 07-security §5.
