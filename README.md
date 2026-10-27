# XCP — XControl Panel

An open-source web hosting control panel written in Go, with Admin,
Reseller, and User levels.

> **Status:** early development (phase P0, foundations). Not usable yet.

- Plan and specs: [docs/plan/](docs/plan/)
- AI/dev working rules: [MASTER_PROMPT.md](MASTER_PROMPT.md)
- Progress: [docs/plan/STATUS.md](docs/plan/STATUS.md)
- Security reports: [SECURITY.md](SECURITY.md)

## Install on a server (Ubuntu 24.04)

XCP is not ready for production. To try it on a test server:

```sh
make web build            # on your machine: builds bin/xcp-agent, xcp-api, xcpctl, xcp-install
scp bin/* root@server:/opt/xcp/
ssh root@server /opt/xcp/xcp-install --hostname panel.example.com
```

The installer prints the panel URL and a one-time admin password. Re-running
it upgrades the binaries and keeps your config, keys and data. Use
`--dry-run` to see what it would change, and `xcpctl doctor` to check the server.

## Development

Requirements: Go 1.26+ (an older `go` command downloads 1.26 automatically),
Node 22+ (for the web UI, later).

```sh
go build ./...
go test ./...
```

On Linux, `make all` runs lint, tests, and builds the binaries into `bin/`.

### Run the API locally (any OS)

The dev config uses plain HTTP on 127.0.0.1 and an in-memory fake agent, so
nothing on your machine is changed. Data goes to `.dev/` (git-ignored).

```sh
go run ./cmd/xcpctl admin create --config packaging/dev/xcp.toml --username root
go run ./cmd/xcp-api --config packaging/dev/xcp.toml
curl http://127.0.0.1:2443/api/v1/health
```

Then open http://127.0.0.1:2443 for the web UI (build it first, below).
The API is described in [api/openapi.yaml](api/openapi.yaml).

### Web UI

```sh
cd web
npm ci
npm run build      # into web/dist; rebuild xcp-api to embed it
npm run dev        # or: hot-reload dev server on http://localhost:5173 (proxies /api to xcp-api)
npm run gen:api    # after changing api/openapi.yaml
```

## License

AGPL-3.0. See [LICENSE](LICENSE).
