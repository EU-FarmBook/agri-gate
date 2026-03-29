# Go Notes For This Repository

This document captures the Go-specific conventions and workflows used in `agri-gate`.

## Module And Layout

The repository is a single Go module defined in [go.mod](../go.mod).

Key directories:

- [cmd/api](../cmd/api): application entrypoint
- [internal/config](../internal/config): environment-based configuration
- [internal/http](../internal/http): HTTP handlers and server wiring
- [internal/jobs](../internal/jobs): job submission and retrieval flow
- [internal/storage](../internal/storage): in-memory and PostgreSQL storage implementations
- [internal/urlscan](../internal/urlscan): URL validation and scanning logic
- [internal/domain](../internal/domain): core domain models

The `internal` tree contains application code that is private to this module.

## Tooling

Common development commands:

```bash
make run
make test
make fmt
make lint
make build
```

Equivalent direct Go commands:

```bash
go run ./cmd/api
go test ./...
go fmt ./...
go vet ./...
go build -o bin/agri-gate ./cmd/api
```

## Configuration

The application is configured with environment variables. See [.env.example](../.env.example) for the current set.

This repository does not currently auto-load `.env` files in Go code. If you keep local settings in `.env`, export them in your shell before starting the app, or use a tool that injects them into the process environment.

If `DATABASE_URL` is set, the application uses PostgreSQL.
If `DATABASE_URL` is empty, it falls back to the in-memory store.

The URL scanner behavior is also driven by runtime configuration, including request timeout and maximum redirect depth.
The file scanner also uses archive-inspection limits for nested ZIP-based containers.

## Testing

Tests live beside the code they exercise using `_test.go` files.

Current examples:

- [internal/urlscan/scanner_test.go](../internal/urlscan/scanner_test.go)
- [internal/jobs/service_test.go](../internal/jobs/service_test.go)
- [internal/storage/postgres_test.go](../internal/storage/postgres_test.go)

## Formatting And Static Analysis

Formatting uses the standard Go formatter:

```bash
go fmt ./...
```

The current lint baseline uses:

```bash
go vet ./...
```

## Dependency Management

Dependencies are managed through `go.mod` and `go.sum`.

When adding or removing dependencies, keep those files in sync with the source tree.

## Related Docs

- Main project guide: [README.md](../README.md)
- Target architecture: [security-gate-design.md](security-gate-design.md)
- PostgreSQL persistence: [postgres-persistence.md](postgres-persistence.md)
