# Go Onboarding For This Repository

This document explains the Go basics you need in order to work on `agri-gate`.

It is written for someone who is comfortable with Python but new to Go.

## The shortest mental model

If you are used to Python:

- `go.mod` is the project-level module definition
- packages are like importable folders
- `cmd/api` is the executable entrypoint for this service
- `internal/...` holds application code that is private to this module
- `go test ./...` runs tests across all packages
- `go build ./cmd/api` builds the API executable

There is usually no `.venv` in a Go project.

## What `go.mod` does

The file [go.mod](../go.mod) declares:

- the module name: `agri-gate`
- the minimum Go language version expected by the module

The module name is used in imports inside the repo, for example:

```go
import "agri-gate/internal/config"
```

If this project starts using external libraries later, `go mod tidy` will manage dependency entries in `go.mod` and `go.sum`.

## What `GOPATH` is

Your `GOPATH` depends on your local machine and Go installation.

This is not a project directory. It is a general Go workspace/cache area used by the toolchain.

Important points:

- you do not need to place this repo inside `GOPATH`
- you do not commit anything from `GOPATH`
- Go stores downloaded modules and some build cache outside your repo

## Why there is no `.venv`

Python isolates dependencies per project using virtual environments.

Go works differently:

- project requirements are described by `go.mod`
- dependencies are downloaded into a shared cache
- builds are reproducible from `go.mod` and `go.sum`

So the repo itself stays cleaner and you usually do not create any local environment directory.

## Important folders in this repo

### `cmd/api`

This is the executable program entrypoint.

File:

- [main.go](../cmd/api/main.go)

This is where the application is wired together:

- config is loaded
- logger is created
- store is created
- scanner is created
- HTTP server is started

### `internal/config`

File:

- [config.go](../internal/config/config.go)

This package loads environment variables such as port and timeout settings.

### `internal/http`

File:

- [server.go](../internal/http/server.go)

This package registers routes and handles HTTP requests and responses.

### `internal/jobs`

File:

- [service.go](../internal/jobs/service.go)

This package handles request validation, job creation, and retrieving existing jobs.

### `internal/urlscan`

Files:

- [scanner.go](../internal/urlscan/scanner.go)
- [scanner_test.go](../internal/urlscan/scanner_test.go)

This package contains the deterministic URL scanning logic.

### `internal/storage`

File:

- [memory.go](../internal/storage/memory.go)

This package currently stores jobs in memory. Later it can be swapped for PostgreSQL.

### `internal/domain`

File:

- [scan.go](../internal/domain/scan.go)

This package defines the core domain models such as:

- `Job`
- `ScanEvent`
- `ScanResult`

## Commands you will actually use

### Run tests

```bash
go test ./...
```

Or with the repo `Makefile`:

```bash
make test
```

### Run the API in development

```bash
export $(grep -v '^#' .env | xargs)
go run ./cmd/api
```

Or:

```bash
make run
```

### Build the binary

```bash
go build -o bin/agri-gate ./cmd/api
```

Or:

```bash
make build
```

### Clean build output

```bash
make clean
```

### Format the code

```bash
make fmt
```

Or:

```bash
go fmt ./...
```

### Run the built-in lint baseline

```bash
make lint
```

Or:

```bash
go vet ./...
```

## What `./...` means

In Go commands, `./...` means:

- start at the current directory
- include all packages recursively below it

So:

```bash
go test ./...
```

means “run tests for every package in this module.”

## How imports work in this project

Because the module name is `agri-gate`, packages are imported like:

```go
import "agri-gate/internal/urlscan"
```

This is normal for a local module.

## How testing works

Go tests usually live beside the code they test using `_test.go` files.

Examples in this repo:

- [scanner_test.go](../internal/urlscan/scanner_test.go)
- [service_test.go](../internal/jobs/service_test.go)

The `testing` package is built into Go. You do not need `pytest`.

## How formatting works

In Go, formatting is usually automated.

The standard tool is:

```bash
go fmt ./...
```

`go fmt` applies `gofmt` to the packages in the module.

In practice, GoLand usually formats automatically or offers it on save.

For now, the code in this repo is already formatted consistently enough to build and test.

## What linting usually means in this repo

For this project, the initial lint baseline is:

```bash
go vet ./...
```

`go vet` is built into the Go toolchain. It is not as broad as external linters, but it catches a useful class of suspicious code patterns and keeps the bootstrap lightweight.

## What GoLand should be configured to use

Verify your local environment with:

```bash
go env GOROOT GOPATH
```

In GoLand:

1. Open `File > Settings > Go`.
2. Set `GOROOT` to your installed Go SDK.
3. Confirm `GOPATH` is your Go workspace, or keep the default.
4. Open the repo root, not a subfolder.

Recommended Run Configuration:

- type: Go Build or Go Application
- package path: `./cmd/api`
- working directory: repo root

Recommended test usage:

- use the gutter icons in GoLand for package tests
- or run `go test ./...` in the terminal

## Common beginner mistakes

### Building without `-o`

If you run:

```bash
go build ./cmd/api
```

Go may leave a binary in the repo root named after the package, such as `api`.

That is why this repo uses:

```bash
go build -o bin/agri-gate ./cmd/api
```

### Expecting `.env` to auto-load

This repo does not auto-load `.env`. You must export it in your shell first, unless your IDE Run Configuration does that for you.

### Looking for a virtual environment

There is none. The Go SDK and module system replace that workflow.

## Recommended next things to learn

For this repo specifically, the most useful Go topics are:

1. packages and imports
2. structs and methods
3. interfaces
4. the `context` package
5. the `net/http` package
6. table-driven tests

## Related docs

- Main repo guide: [README.md](../README.md)
- System design: [security-gate-design.md](security-gate-design.md)
