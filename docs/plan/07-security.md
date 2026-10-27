# 07 — Security (threat model and mandatory rules)

A hosting panel is a high-value target. One bug can expose every site on the
server. Every rule here is **mandatory**. Code review must check them.

## 1. Threat model

| Attacker | Goal | Main defences |
|---|---|---|
| Internet (no login) | Panel takeover, RCE | Small unauthenticated surface, rate limits, brute-force bans, 2FA, no default passwords, fuzzed parsers |
| Hosted user (logged in) | Read/modify other accounts, get root | RBAC in `core`, ownership checks on every object, privilege split, actions run as the user, jail, cgroups |
| Hosted user's PHP/shell code | Same as above, plus attack the panel locally | Agent socket only for `xcp`/root, no world-readable secrets, `open_basedir`, hidepid, SMTP restrictions |
| Reseller | Access accounts of other resellers | Owner scoping in every query (`WHERE owner_id = ?`), tests for cross-tenant access |
| Malicious backup / migration file | Path traversal, symlink attacks, zip bombs, code exec | Safe extract (see §5), size/inode limits, restore as the user |
| Stolen API token | Abuse | Scopes, IP allow-list, expiry, audit, token prefix for secret scanners |

## 2. Authentication
- Passwords hashed with **argon2id** (memory ≥ 64 MiB, tuned on install).
- Login rate limits per IP and per username; progressive delay; ban via
  firewall after threshold (`ADM-SEC-01`).
- 2FA: TOTP (with replay protection), WebAuthn/passkeys, one-time recovery
  codes (hashed). Admin can require 2FA per role.
- Sessions: random 256-bit IDs, stored hashed server-side, `HttpOnly`,
  `Secure`, `SameSite=Lax`, idle timeout and absolute timeout, bound to
  role + optional IP check. Session list with revoke.
- Re-authentication (password or 2FA) before sensitive actions: root
  terminal, change password/2FA/API tokens, terminate account, view backup
  encryption keys.
- Impersonation ("login as"): separate session flagged with
  `impersonator_id`, visible banner, every action audited with both identities.
- API tokens: format `xcp_<prefix>_<secret>`, store only a hash, scopes
  (e.g. `accounts:read`, `dns:write`), optional IP allow-list and expiry.

## 3. Authorization (RBAC)
- Roles: `admin`, `admin-limited` (ACL list), `reseller` (ACL list), `user`,
  `subuser` (permission list inside one account).
- **Every** `core` service method gets an `Actor` and checks:
  1. role or ACL allows the action,
  2. the target object belongs to the actor's scope (own account, owned
     accounts for resellers, all for admin),
  3. the feature is on in the account's feature list,
  4. the package limit is not exceeded.
- Repository queries take a scope filter, so "list" endpoints cannot leak.
- Mandatory tests: for each endpoint, a **cross-tenant test** (user A cannot
  read/change user B; reseller A cannot touch reseller B's accounts).

## 4. Web security (panel)
- CSRF: SameSite cookies **plus** a CSRF token header for cookie sessions
  (API tokens are exempt).
- Strict CSP (no inline scripts), `X-Frame-Options: DENY` (except embedded
  tools on their own subdomain), HSTS, `Referrer-Policy`, `Permissions-Policy`.
- JSON only; strict request size limits; uploads streamed to disk as the
  user with quota checks.
- All output encoded by React; no `dangerouslySetInnerHTML` except
  sanitised Markdown (DOMPurify) for announcements.
- phpMyAdmin, webmail, and file downloads served from **separate
  origins/subdomains** or paths with their own cookies, so a bug there cannot
  steal panel sessions.
- WebSocket connections check `Origin` and the session.

## 5. File system safety
- User-controlled paths are **never** opened by root. `xcp-userd` runs as the
  user and uses `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
  RESOLVE_NO_MAGICLINKS` relative to the home directory fd.
- When root must touch user dirs (create home, fix permissions, restore),
  use `fsx` helpers that walk with `O_NOFOLLOW` and `fstatat`, and check the owner
  before every change. `chown -R` style operations never follow symlinks.
- Archive extraction (backups, uploads, app installs): reject absolute paths,
  `..`, device files, hard links outside the target, and setuid bits; limit
  total size, file count, and compression ratio (zip-bomb guard); extract as
  the user.
- Config files written by the agent only inside allow-listed directories,
  atomically, with fixed owner and mode.

## 6. Command execution
- No shell (`sh -c`) anywhere. A linter rule blocks it.
- `execx` requires an absolute binary path from an allow-list, an argv slice,
  an empty or explicit environment, a timeout, and a max output size.
- User-provided values that become arguments are validated first, and
  separated from options with `--` when the tool supports it.
- Anything that must run user code (cron, git hooks, app builds, composer,
  wp-cli, mail pipes) runs **as the user**, inside their slice and jail.

## 7. Input validation (`internal/validate`)
One function per type, shared by the API, CLI, agent, and importers. Each
one has fuzz tests.
- `Username`: `^[a-z][a-z0-9]{0,15}$`, not reserved (root, mail, www-data,
  xcp, mysql, postgres, ...), not already used as a system user.
- `Domain`: IDNA to punycode, total ≤ 253, labels ≤ 63, valid public suffix,
  not the server hostname or a reserved name unless admin.
- `Email` local part: RFC 5322 subset that is safe for Postfix maps (no
  spaces, quotes, or `|`).
- `Path` (relative to home): no NUL, no `..` after cleaning, length limits.
- DNS record content per type, cron expressions, PHP ini keys (allow-list)
  and values (type-checked), SSH public keys (parsed), certificates and keys
  (parsed and matched), IPs and CIDRs, ports.

## 8. Secrets
- Panel secrets in `/etc/xcp/secrets/` (root `0600`); the API gets only
  what it needs through systemd credentials (`LoadCredential=`).
- DB root password, DKIM private keys, ACME account keys, and backup
  encryption keys are never returned by the API.
- User-visible secrets (DB passwords, FTP passwords) are only shown once at
  creation; reset instead of show.
- Log redaction: a `slog` handler drops fields named `password`, `secret`,
  `token`, `key`, and any value matching the token prefix.

## 9. Audit log
- Append-only table plus a daily file export with a hash chain (each entry
  includes the hash of the previous one) to detect tampering.
- Fields: time, actor, impersonator, role, IP, user agent, action, target
  type and ID, request ID, result, and a diff of changed fields (secrets masked).
- Visible to admin (all), reseller (own accounts), and user (own account).

## 10. Supply chain and releases
- Go modules pinned and verified (`go.sum`), `govulncheck` in CI, Dependabot
  or Renovate, and SBOM (CycloneDX) per release.
- Release binaries reproducible where possible, signed (cosign), with a
  checksum file. The updater refuses unsigned or downgraded releases.
- Third-party tarballs (Roundcube, phpMyAdmin, runtimes, app recipes) are
  pinned by version and SHA-256 in the repo.
- App installer recipes are reviewed YAML only, with no arbitrary remote
  scripts.

## 11. Security process
- `SECURITY.md` with a private reporting address and a response time target.
- Security review checklist in every PR template (exec, files, RBAC, input,
  secrets, audit).
- Before 1.0: an external security audit, and a public bug bounty if possible.
