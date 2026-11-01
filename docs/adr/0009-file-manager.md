# ADR-0009: The file manager runs as the account user in a socket-activated xcp-userd

- Status: accepted
- Date: 2026-11-01
- Amends: 01-architecture.md (xcp-userd, SpawnUserHelper)

## Context

The file manager (USR-FILE-01..03, 05) reads and writes users' files.
07-security says user-controlled paths are never opened by root and that
user-content work runs as the user (`xcp-userd`). The plan had the agent
spawn the helper and hand back a socket; it left open how the helper
lives, how xcp-api reaches it, and how large uploads and downloads travel.

## Decision

- **Units, not spawned children:** xcp-install adds template units
  `xcp-userd@.socket` and `xcp-userd@.service`. The socket listens on
  `/run/xcp-userd/<user>.sock`, owned by the account user and the `xcp`
  group, mode 0660, in a folder only root and `xcp` can enter (made by
  tmpfiles.d; not `/run/xcp`, which systemd re-owns, sockets included,
  whenever xcp-agent starts). The service
  runs `xcp-userd` as the account user, in the account's slice (its CPU,
  memory and task limits apply), with a read-only system, private `/tmp`
  and only the account's home visible and writable. systemd starts it on
  the first connection; it exits after 10 idle minutes.
- **The agent only starts the socket** (`UserHelperStart`, for XCP
  accounts only) and stops both units when the account is suspended or
  removed. It never touches the files.
- **xcp-api talks HTTP to the helper over the socket**, after its own
  access checks and with audit events; uploads and downloads stream
  through without buffering. If the socket is missing (after a reboot or
  a stop), xcp-api asks the agent to start it and tries again.
- **Inside the helper** every path is relative to the home folder and
  resolved with fsx (openat2 beneath the home, no symlinks), so the helper
  cannot be talked into leaving the home even by links the user made.
  Deleting moves files to `~/.trash/`; archives are made and unpacked with
  the same rules as the installer's (no links, no paths leaving the
  folder, size limits).

## Consequences

- A bug in the file code runs with the account's own rights and limits;
  a compromised xcp-api can reach only what it could already change
  through the panel.
- Symlinks are listed but not followed; users who rely on them manage them
  over SSH or FTP.
- The terminal, git and app installs (later) can use the same helper.
