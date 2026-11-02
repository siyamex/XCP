# ADR-0012: Bandwidth from logs read by xcp-logd; log viewers through the agent

- Status: accepted
- Date: 2026-11-02
- Amends: 06-service-drivers.md §10 (Logs, bandwidth, stats)

## Context

USR-STAT-01 needs bandwidth per domain and month, split into web, mail
and FTP; USR-STAT-03 needs the access and error logs (last lines, search,
download). The plan has `xcp-logd` tail log files (P1) into buckets. It
left open which log formats, how mail bytes are counted, how logd keeps
its place, and who reads logs for the viewers. Two findings: Apache wrote
the per-account logs world-readable, so any account's user could read the
others' visitors and URLs; Pure-FTPd's xferlog was root only.

## Decision

- **Formats:** each account's sites log to
  `/var/log/apache2/xcp/<user>.access.log` in Apache's `vhost_combined`
  format (`%v:%p` first, `%O` bytes sent with headers), and errors to
  `<user>.error.log`. The folder is `root:adm` 0750, so only root and
  `adm` can read the logs. FTP transfers go to Pure-FTPd's xferlog
  (`root:adm` 0640), whose user field is the login `name@domain`.
- **Mail bytes from Postfix's journal entries:** the size comes from
  `qmgr`'s `from=…, size=…` line; a delivery to a mailbox here counts for
  the recipient's domain; a delivery elsewhere counts for the domain of
  the authenticated sender (`sasl_username`), else of the forwarded
  address (`orig_to`), else of the sender.
- **xcp-logd** runs as `xcp` with the `adm` and `systemd-journal` groups,
  without network. Once a minute it reads what the files gained since its
  last offset (following a rotation into `<file>.1`; a truncated file
  starts over) and the journal after its last cursor, adds bytes per
  domain and UTC day, and writes the sums and its new offsets and cursor
  in one database transaction, so a restart neither loses nor repeats
  bytes. Names that are not domains of an account are dropped.
- **Rotation:** XCP's logrotate files rotate the account logs daily (14
  kept, `create 0640 root adm`, Apache reloaded) and the xferlog weekly
  (`copytruncate`, no restart that would end FTP sessions).
- **Viewers through the agent:** xcp-api never reads logs. The agent op
  `SiteLog` returns the last lines of an account's access or error log,
  optionally only lines containing a text, and `SiteLogDownload` streams
  the whole current file.
- The package's monthly bandwidth limit is shown next to the usage; it is
  not enforced yet.

## Consequences

- Bandwidth lags up to a minute behind the logs; mail and FTP bytes count
  message and file sizes, not protocol overhead.
- Rotated, compressed logs are not offered in the viewer (USR-STAT-05).
- The same reader is where brute-force detection (P2) will hook in.
