# ADR-0038: Remote database access

Status: accepted (2026-11-18)

## Context

USR-DB-05: customers let their database users connect from other hosts
(`%`, addresses, networks). Until now MariaDB listened on 127.0.0.1 and
every user existed only at `localhost` (ADR-0006).

## Decision

- **Two switches.** The admin decides whether MariaDB accepts outside
  connections at all; each account decides from which hosts. Neither alone
  opens anything.
- **Server.** `PUT /server/mysql/remote {enabled}` calls the agent's
  `MySQLListen`, which writes or removes `91-xcp-remote.cnf` with
  `bind-address = *` and restarts MariaDB if that changed. The file sorts
  after xcp-install's `90-xcp.cnf`, so a re-run of the installer (which
  writes 127.0.0.1 there) does not undo the choice. The setting
  `mysql.remote` remembers it for the panel. The firewall is not opened by
  this: the admin opens TCP 3306 in the firewall manager.
- **Account.** `db_remote_hosts` (migration 0029) holds up to 20 MariaDB
  host patterns per account. The panel accepts `%` (or `any`), an address,
  or a network in CIDR form, which it turns into MariaDB's
  `address/netmask`. MariaDB cannot match IPv6 networks except by
  wildcards, so only single IPv6 addresses are taken. Host names are not
  taken: MariaDB's name resolution is off on most servers and a DNS answer
  is not a good gate.
- **Users.** `MySQLAccountApply` gets the host list. For every database
  user of the account the agent keeps `user@localhost` and `user@<host>` for
  each listed host, with the same password hash, lock state and grants, and
  drops `user@<host>` for hosts no longer listed. The agent validates each
  pattern again (`CheckRemoteHost`) before it is quoted into SQL.
- The hosts are account data: they are in the account export and come back
  with a restore.

## Consequences

- With the server switch off the lists are kept; they work once it is on.
- `%` lets a user be tried from anywhere; the password is the only gate
  then. The UI says so by example, not by blocking it.
- TLS for remote connections is whatever MariaDB has; XCP does not set up
  certificates for it yet.

## Not done

- Opening 3306 in the firewall only for the listed hosts.
- Per-user host lists.
