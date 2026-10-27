# ADR-0002: Hand-written HTTP handlers on net/http, checked against the spec

- Status: accepted
- Date: 2026-10-27

## Context

`02-tech-stack-and-repo.md` planned chi plus `oapi-codegen` (strict server)
generated from `api/openapi.yaml`. When building the auth endpoints we found:

- Setting and clearing cookies, and the CSRF/same-origin checks, have to work
  around the strict server's response objects.
- Go's standard `net/http.ServeMux` (Go 1.22+) already routes by method and
  path parameters, so chi adds nothing we need.
- Request validation happens in our own `validate` package anyway, because
  the CLI, agent and importers must apply the same rules.

## Decision

- Handlers are written by hand in `internal/httpapi`, registered from one
  route table that also declares each route's access level
  (public / pending-2FA / authenticated) and whether a forced password
  change blocks it.
- `api/openapi.yaml` stays the published contract and is written by hand.
- `TestRoutesMatchOpenAPISpec` fails the build when:
  - a route is missing from the spec, or the spec lists a route that does not exist;
  - a route's public/authenticated status differs between code and spec;
  - a state-changing authenticated route does not list the `csrfHeader`
    security scheme (`X-CSRF-Token`). It is modelled as a security scheme,
    not a parameter, so generated clients add it in one middleware instead
    of on every call.
- The web UI generates its TypeScript types from the spec (task 9).

## Consequences

- No generated server code and no router dependency.
- Request/response *body schemas* are not checked against the spec by the
  test, only routes and security. Handler tests must cover body shapes; we
  can add schema checks later if drift appears.
