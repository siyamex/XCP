# ADR-0021: API tokens

- Status: accepted
- Date: 2026-11-04
- Amends: 08-data-model-and-api (api_tokens, `/me/tokens`)

## Decision

- A login can make up to 20 tokens `xcp_<8 hex>_<48 hex>` (192 bits of
  secret) under `/me/tokens`, after confirming its password. The secret is
  shown once; only its SHA-256 is stored, and the 8-hex part finds the row.
  Optional end date (up to 365 days) and list of networks it may be used from.
  Scope `read` (GET only) or `write`.
- A request with `Authorization: Bearer <token>` is authenticated by the
  token instead of the cookie. No CSRF token is needed, since browsers do not
  send the header on their own. It acts as the token's login with that
  login's role and limits, so everything else (roles, account ownership,
  feature lists, 2FA enrollment policy) applies unchanged.
- A token cannot use `/auth/*` or `/me/*` (except `GET /me`): no new tokens,
  password, 2FA or session changes, so a stolen token cannot lock the owner
  out or make more tokens. Its stand-in session never has a password
  confirmation, so actions that ask for one (reboot, impersonation) are out
  of reach.
- Using a token is not audited call by call (the API's normal audit of
  changes still names the login); `last_used_at` and address are kept,
  updated at most once a minute. Making and revoking are audited. Suspending
  or removing a login ends its tokens. Tokens are not part of account backups.

## Not done

Per-route scopes, rate limits per token, a token that acts for another
login (reseller on behalf of a user).
