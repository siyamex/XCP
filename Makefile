# XCP developer tasks. CI runs these on Linux.
# On Windows, use scripts/dev.ps1 or run the go commands directly.

GO       ?= go
BIN_DIR  ?= bin
BINARIES := $(notdir $(wildcard cmd/*))
LDFLAGS  := -s -w -X github.com/siyamex/XCP/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build test test-race fuzz lint vuln fmt tidy clean dev proto proto-check web web-dev test-linux e2e-install

all: lint test web build

# Builds the React UI into web/dist, which xcp-api embeds. Run before `build`.
web:
	cd web && npm ci && npm run gen:api && npm test && npm run build

# Vite dev server on :5173 with hot reload, proxying /api to xcp-api (`make dev`).
web-dev:
	cd web && npm run dev

build:
	@mkdir -p $(BIN_DIR)
	@for b in $(BINARIES); do \
		CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$b ./cmd/$$b || exit 1; \
	done

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# Linux-only tests (fsx, execx, peer credentials) from any OS, via Docker.
test-linux:
	docker run --rm -v "$(CURDIR):/src" -v xcp-gomod:/go/pkg/mod -w /src golang:1.26 go test ./...

# Installs into Ubuntu 24.04 + systemd in Docker and checks the result.
e2e-install:
	sh test/e2e/install/run.sh

# Short fuzz run for every Fuzz* target in internal/validate.
fuzz:
	@for f in $$($(GO) test -list 'Fuzz.*' ./internal/validate | grep ^Fuzz); do \
		$(GO) test ./internal/validate -run '^$$' -fuzz "^$$f$$" -fuzztime 15s || exit 1; \
	done

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

fmt:
	gofumpt -l -w .

tidy:
	$(GO) mod tidy

# Regenerate gRPC code (committed). Needs buf, protoc-gen-go, protoc-gen-go-grpc:
#   go install github.com/bufbuild/buf/cmd/buf@latest
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
proto:
	buf lint
	buf generate

# Fails if the committed generated code is out of date.
proto-check: proto
	git diff --exit-code -- internal/agentrpc/agentv1

clean:
	rm -rf $(BIN_DIR)

# Runs the API with the in-memory fake agent (works on any OS).
dev:
	$(GO) run ./cmd/xcp-api --config ./packaging/dev/xcp.toml
