# ADR-0025: Directory privacy

- Status: accepted
- Date: 2026-11-04

## Decision

- A user can put folders of a site behind a user name and password (HTTP
  basic authentication), per domain, up to 20 folders with 30 users each. It is
  part of the domain's web settings document (ADR-0020) but has its own
  endpoint, `PUT /domains/{id}/protected-dirs`, because it carries secrets.
- The panel stores **bcrypt hashes** (cost 10) only, made when a password is
  set (checked against the server's password rules; bcrypt reads at most
  72 bytes). The API never returns hashes. A user listed without a password
  keeps the hash they have; a new user needs a password. Saving the general
  web form leaves the folders as they are.
- The agent checks everything again (`WebOptions.Clean`): the folder is a
  clean URL path (never `/` or with `..`), the title and names have a narrow
  alphabet, and a hash must look like bcrypt, so a stored value cannot add
  a line to a password file or a directive to the vhost.
- Rendering: a `<Directory "<docroot><folder>">` block with `AuthType Basic`,
  `AuthBasicProvider file`, `AuthUserFile` and `Require valid-user`. The
  password files are in `/etc/xcp/webauth/<account>/<hash of domain and
  folder>.htpasswd`, `root:www-data` 0640 in a 0750 folder: Apache's workers
  read them, and neither the account's own user nor other accounts can. Files
  of removed folders and of removed accounts go.
- A suspended account's vhost has no protected folders and no files (it serves
  only the notice page).

## Consequences

- Basic authentication sends the password with each request: it is only
  safe over HTTPS (the UI says nothing about this yet; turn on "force HTTPS").
- A user's own `.htaccess` with `AllowOverride AuthConfig` can still add
  protection to other folders; it cannot remove the panel's.
