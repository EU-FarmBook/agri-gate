# Agri Gate

Agri Gate is an internal gateway service for checking URLs and files before other systems ingest them.

The intended long-term role of this service is:

- validate and scan URLs
- validate and scan uploaded files
- block obviously unsafe or policy-violating inputs
- classify whether content is agriculture-related
- produce structured scan decisions for downstream services
- keep an audit trail of what was checked and why a decision was made

This repository currently contains a runnable v0 scaffold in Go. It is a starting point, not the finished system.

## Current implementation status

Implemented now:

- Go HTTP API
- synchronous `POST /v1/scan/url`
- deterministic URL checks
- basic agriculture relevance scoring from URL text
- in-memory job storage
- health, readiness, version, and job lookup endpoints
- Docker scaffolding
- basic unit tests

Planned but not implemented yet:

- PostgreSQL persistence
- ClamAV integration
- Google Web Risk integration
- file upload scanning
- batch submission and worker flow
- full AGROVOC-backed relevance engine

## Repository structure

```text
.
├── cmd/api                  # application entrypoint
├── deploy/docker            # Dockerfile
├── docs                     # design and onboarding docs
├── internal/config          # env-based configuration loading
├── internal/domain          # core domain models
├── internal/http            # HTTP handlers and server wiring
├── internal/jobs            # job submission and retrieval service
├── internal/storage         # storage implementations
├── internal/urlscan         # deterministic URL scanning logic
├── pkg/types                # reserved for public reusable types later
├── .env.example             # example environment variables
├── docker-compose.yml       # local container stack
├── go.mod                   # Go module definition
└── Makefile                 # common developer commands
```

## API endpoints

The current API surface is:

- `GET /v1/health`
- `GET /v1/ready`
- `GET /v1/version`
- `POST /v1/scan/url`
- `GET /v1/jobs/{id}`

Example scan request:

```json
{
  "url": "https://www.fao.org"
}
```

Example call:

```bash
curl -sS -X POST http://localhost:8080/v1/scan/url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.fao.org"}'
```

## Prerequisites

For local development you need:

- Go 1.22 or newer
- Docker and Docker Compose if you want to use containers
- Git

Verify your local Go setup with:

```bash
which go
go version
go env GOROOT GOPATH
```

## First-time Go note

If you come from Python, the main difference is this:

- Python typically uses a per-project virtual environment like `.venv`
- Go usually does not create a per-project environment folder
- Go uses `go.mod` to define the module and dependency requirements
- downloaded dependencies are stored in a shared module cache outside the repo

So for this project, there is nothing like `.venv` that you need to create in the repository.

More detail is in [docs/go-onboarding.md](docs/go-onboarding.md).

## Local development

### 1. Prepare environment variables

Create a local env file from the example:

```bash
cp .env.example .env
```

The current application reads these variables:

- `APP_ENV`
- `APP_PORT`
- `APP_VERSION`
- `MAX_REDIRECTS`
- `HTTP_TIMEOUT_SECONDS`
- `ENABLE_HTML_EXTRACTION`

The app does not load `.env` automatically. In a shell session, export it manually:

```bash
export $(grep -v '^#' .env | xargs)
```

### 2. Run the app

With Go directly:

```bash
make run
```

Equivalent direct command:

```bash
go run ./cmd/api
```

The service listens on `http://localhost:8080` by default.

### 3. Run tests

```bash
make test
```

Equivalent direct command:

```bash
go test ./...
```

### 4. Build a binary

```bash
make build
```

That produces:

- `bin/agri-gate`

Run the built binary:

```bash
./bin/agri-gate
```

### 5. Clean build output

```bash
make clean
```

### 6. Format the code

```bash
make fmt
```

Equivalent direct command:

```bash
go fmt ./...
```

### 7. Run the built-in lint baseline

```bash
make lint
```

Equivalent direct command:

```bash
go vet ./...
```

## Docker workflow

Start the local stack:

```bash
make docker-up
```

Stop the local stack:

```bash
make docker-down
```

Follow API logs:

```bash
make docker-logs
```

Equivalent raw commands:

```bash
docker compose up --build
docker compose down
docker compose logs -f api
```

The compose stack includes:

- `api`
- `postgres`
- `clamav`

At the moment, the app itself only depends on the `api` container to function. `postgres` and `clamav` are there because they are part of the planned target architecture.

## How the current code works

Request flow for `POST /v1/scan/url`:

1. The HTTP handler receives JSON input.
2. The jobs service validates the request and creates a job.
3. The URL scanner applies deterministic checks.
4. A `ScanResult` is produced.
5. The job and its event are stored in memory.
6. The scan result is returned to the caller.

Current URL checks include:

- URL parsing
- HTTPS-only enforcement
- rejection of embedded credentials
- blocked localhost and internal/private hosts
- blocked dangerous download extensions such as `.exe` and `.zip`
- simple agriculture keyword matching from hostname and path

## Important limitations right now

- Job data is not persisted across restarts
- DNS lookup is used for host safety checks, but no live HTTP fetch is performed yet
- URL redirects are not followed yet
- the relevance scoring is intentionally simplistic
- there is no file scanning endpoint yet

## GoLand setup

In GoLand, verify:

- `File > Settings > Go > GOROOT` points to your installed Go SDK
- `File > Settings > Go > GOPATH` points to your Go workspace, or use the default

Recommended actions in GoLand:

- open the repo root as the project
- let GoLand detect `go.mod`
- use the terminal or Run Configurations to run `go test ./...`
- use GoLand formatting tools or `make fmt` before commits
- create a Run Configuration for package `./cmd/api` if you want one-click startup

You do not need any special project-local Go environment folder.

## Git workflow

You already ran:

```bash
git init
git remote add origin https://github.com/EU-FarmBook/agri-gate
```

To commit and push this scaffold:

```bash
git status
git add .
git commit -m "Scaffold initial agri-gate service"
git branch -M main
git push -u origin main
```

If Git asks for your identity first:

```bash
git config user.name "Pranav"
git config user.email "your-email@example.com"
```

## Documentation index

- Design and intended architecture: [docs/security-gate-design.md](docs/security-gate-design.md)
- Go onboarding for this repo: [docs/go-onboarding.md](docs/go-onboarding.md)

## Next recommended steps

The next engineering steps that make this scaffold more real are:

1. Add PostgreSQL-backed storage behind the existing storage boundary.
2. Implement live outbound URL fetches with timeout and redirect handling.
3. Add file upload scanning and ClamAV integration.
4. Add Google Web Risk integration.
5. Add structured logging and metrics.
