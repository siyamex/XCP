# ADR-0026: FTP sessions

- Status: accepted
- Date: 2026-11-04

## Decision

- The agent lists connections with `pure-ftpwho -s -n` (one line per session:
  pid, login, seconds, state, file, peer, ..., progress, bandwidth) and
  ends one with SIGTERM. Both are typed agent ops; the runner's allow-list
  has `pure-ftpwho`.
- The panel shows an account only the sessions whose login is one of its own
  FTP logins (`name@domain`), whatever else is connected.
- Ending a session takes a pid from the browser. The panel looks the pid up
  among the account's own sessions, and the agent looks it up again in a
  fresh listing for that same login, so a pid can never name another
  process or another account's session. Anything else is "not found".
- Ending is audited (`ftp.session.end`: login and client address). Only
  accounts that may change their FTP settings (not suspended) can end sessions.

## Not done

Admin view of all sessions, limits on simultaneous connections per login,
kicking by address.
