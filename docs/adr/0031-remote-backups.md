# ADR-0031: Remote backup destinations

- Status: accepted
- Date: 2026-11-08
- Amends: 03-admin-features (ADM-BAK: remote destinations), 04-reseller-features (not yet)

## Decision

- **Destinations** are managed by admins: a **folder** on this server (a
  mounted disk or share), an **SFTP** server, or an **S3** bucket (Amazon or
  any compatible service). They are stored in `backup_destinations` with their
  settings in the open and their secrets (password, private key, secret key)
  sealed with the master key, like the mail relay password. The API never
  returns a secret, only whether one is stored.
- **The agent does the transfers** (it can read the root-only backup folder);
  the panel passes the destination with each call and the agent keeps
  nothing. Files go to `<path>/<account>/<file>`: written as `<file>.part`
  and renamed, so a half-sent file never looks like a backup. After an upload
  the agent lists the destination and compares the size; a copy of the wrong
  size is removed and the job fails (and is retried). Destination folders are
  opened with `fsx`, so a link inside cannot lead the agent elsewhere.
- **Adding one tests it first** (connect, write, delete a small file). An
  SFTP server whose **host key** is not given is trusted on first use: the
  key it presents is saved, returned and shown for the admin to check; from
  then on a different key is refused (the message says someone may be between
  the panel and the server). Folders under `/etc`, `/proc`, `/usr`, `/root` and
  the like are refused.
- **Schedule**: it can name a destination and how many copies per account
  to keep there (default: as many as are kept here). Each scheduled backup is
  copied when it is made; afterwards the oldest copies past the limit are
  deleted by their time-stamped names. Manual backups are copied by an admin on
  request (and count toward the limit only when scheduled copies are pruned).
- **Records**: `backup_remote` says, per backup and destination, whether
  the copy is running, ok (with its size) or failed (with the reason). Admins
  see it; users do not see where copies are kept. Uploads queue per destination
  (one at a time) and retry three times.
- **Disaster recovery**: an admin can list what a destination holds and
  bring a backup back to this server (`fetch`: never over an existing file).
  It appears with the backups of removed accounts (or with the account's, if
  it exists) and is restored like any backup (ADR-0015). Restoring checks the
  archive against its manifest, so a damaged copy is found then.
- Forgetting a destination leaves its files; it cannot be forgotten while
  the schedule uses it.

## Consequences

- Copies are **not encrypted** by XCP: protect them with the destination
  (an encrypted disk, a private bucket, a server you control).
- A large backup is sent in one job (hours at most); an interrupted
  upload starts over.

## Not done

Encryption of copies, bandwidth limits, resellers' own destinations (RSL-BAK),
per-account destinations, incremental backups, and restoring over an account
that exists.
