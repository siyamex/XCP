# ADR-0014: The admin's server pages read the host through the agent

- Status: accepted
- Date: 2026-11-04
- Amends: 03-admin-features (ADM-SVC-01, 03, 05, 07, 08; ADM-SEC-12)

## Context

The admin needs to see and run the server from the panel: load, memory,
disks and inodes, the busiest processes and accounts, installed versions,
services (state, start, stop, restart, enable, logs), the task queue, and
who is signed in. xcp-api runs unprivileged and cannot read most of this.

## Decision

- **One agent op, `ServerStatus`, reads the host** from `/proc`
  (`stat`, `meminfo`, `loadavg`, `uptime`, `net/dev`, `mounts`, per-process
  `stat`), `statfs` for each real file system (once per device), the
  dpkg database for versions and `os-release`: no commands are run. CPU use
  and each process's CPU share are measured over a 300 ms window.
- **Accounts' disk use is cached:** walking every home is slow, so the agent
  measures them in the background (through fsx, never following links, at
  most 200,000 entries per account) at most every 15 minutes and the page
  shows when it was measured. The first report after an agent start begins
  a measurement.
- **Services** are the agent's registry of logical names; the manager shows
  the ones XCP installs, with `systemctl show` state, and offers start, stop,
  restart, reload, enable and disable (no `--now`: a boot setting changes
  boot only) and `journalctl` logs (at most 500 lines). The panel's API and
  SSH cannot be stopped, restarted or disabled from the panel, so the
  admin cannot cut off their own access (409 `protected`).
- **Jobs:** the monitor lists the queue with a state and kind filter, and
  cancels or retries jobs; counts on the dashboard are the last 24 hours
  plus everything queued or running.
- **Sessions and sign-ins:** admins see every session with its login and may
  end any of them; the history is the audit log's sign-in events. Each
  change is audited.
- Everything is admin-only (403 for others).

## Consequences

- The dashboard refreshes every 10 s and each refresh costs the agent one
  300 ms sample; a closed page costs nothing.
- Per-account CPU/RAM/IO over time (ADM-SVC-06), the process manager and
  killer rules (ADM-SVC-04) and a service monitor with auto-restart
  (ADM-SVC-02) are later phases.
