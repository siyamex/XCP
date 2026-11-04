# ADR-0019: SSH settings

- Status: accepted
- Date: 2026-11-04
- Amends: 03-admin-features (ADM-SEC-11)

## Decision

- Two global settings (ADR-0016's catalogue): `ssh.password_auth` (default
  on) and `ssh.root_login` (`yes`, `prohibit-password`, `no`; default
  `prohibit-password`).
- The agent op `SSHSettingsSet` writes `/etc/ssh/sshd_config.d/00-xcp.conf`.
  The name sorts first on purpose: sshd keeps the first value it reads, and
  cloud images ship `50-cloud-init.conf` with `PasswordAuthentication yes`.
  The whole configuration is checked with `sshd -t`; if it fails the old file
  is put back and the change is refused. Then `ssh.service` is reloaded
  (running sessions stay).
- The change is applied *before* it is saved, so a refused change leaves the
  setting as it was.
- Switching passwords off is refused while no login (`/root` or any
  `/home/*`) has a non-empty `authorized_keys`: nobody could sign in again.
- **Not done: the SSH port.** It must move together with the firewall's SSH
  port, its restrictions and the brute-force detector, with a way back if the
  new port is unreachable. It needs its own design.
