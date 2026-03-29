# Agri Gate

Agri Gate is an internal gateway service for validating URLs and files before downstream ingestion.

Its intended responsibilities are:

- security validation for URLs and uploaded files
- blocking unsafe or policy-violating inputs early
- agriculture relevance classification
- structured scan decisions for downstream services
- auditability of checks and outcomes

## Current Status

This repository contains an early runnable Go implementation.

Implemented:

- HTTP API
- synchronous `POST /v1/scan/url`
- deterministic URL validation and policy checks
- live outbound URL fetching with timeout-bound requests
- redirect-aware validation with maximum redirect enforcement
- response-based dangerous download detection from headers and final URL
- basic agriculture relevance scoring from URL text
- PostgreSQL-backed job and event persistence when `DATABASE_URL` is set
- in-memory fallback storage when `DATABASE_URL` is not set
- health, readiness, version, and job lookup endpoints
- Docker Compose scaffolding
- basic unit tests

Not implemented yet:

- file upload scanning
- ClamAV integration
- Google Web Risk integration
- batch submission and worker flow
- full AGROVOC-backed relevance engine

## API

Current endpoints:

- `GET /v1/health`
- `GET /v1/ready`
- `GET /v1/version`
- `POST /v1/scan/url`
- `GET /v1/jobs/{id}`

Example request:

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

## Requirements

- Go 1.25 or newer
- Docker and Docker Compose for containerized local development

## Configuration

The application currently reads:

- `APP_ENV`
- `APP_PORT`
- `APP_VERSION`
- `DATABASE_URL`
- `MAX_REDIRECTS`
- `HTTP_TIMEOUT_SECONDS`
- `ENABLE_HTML_EXTRACTION`

Create a local env file if needed:

```bash
cp .env.example .env
export $(grep -v '^#' .env | xargs)
```

Storage behavior:

- if `DATABASE_URL` is set, the application uses PostgreSQL
- if `DATABASE_URL` is empty, it uses the in-memory store

## Local Development

Run the API:

```bash
make run
```

Run tests:

```bash
make test
```

Format code:

```bash
make fmt
```

Run the built-in lint baseline:

```bash
make lint
```

Build the binary:

```bash
make build
```

Clean build output:

```bash
make clean
```

## Docker

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

The Compose stack includes:

- `api`
- `postgres`
- `clamav`

`postgres` is used by the API when `DATABASE_URL` is configured. `clamav` is included as part of the target architecture but is not yet integrated into the application.

## Repository Layout

```text
.
├── cmd/api
├── deploy/docker
├── deploy/postgres
├── docs
├── internal/config
├── internal/domain
├── internal/http
├── internal/jobs
├── internal/storage
├── internal/urlscan
├── pkg/types
├── .env.example
├── docker-compose.yml
├── go.mod
└── Makefile
```

## Current Behavior

Current URL checks include:

- URL parsing
- HTTPS-only enforcement
- rejection of embedded credentials
- blocking localhost and internal/private hosts
- live reachability checks using outbound HTTP requests
- redirect validation up to the configured maximum
- blocking dangerous download extensions such as `.exe` and `.zip`
- blocking attachment-style and blocked binary content types from HTTP responses
- simple agriculture keyword matching from hostname and path

For `POST /v1/scan/url`, the application validates the request, produces a `ScanResult`, stores the job and event, and returns the result synchronously.

## Limitations

- no file scanning endpoint yet
- no HTML content extraction yet
- relevance scoring is intentionally simplistic
- persistence is durable only when PostgreSQL is enabled

## Documentation

- Architecture and target design: [docs/security-gate-design.md](docs/security-gate-design.md)
- Go onboarding: [docs/go-onboarding.md](docs/go-onboarding.md)
- PostgreSQL persistence: [docs/postgres-persistence.md](docs/postgres-persistence.md)

## Next Steps

Recommended next engineering steps:

1. Add HTML extraction and richer text-based agriculture relevance scoring.
2. Add file upload scanning and ClamAV integration.
3. Add Google Web Risk integration.
4. Add structured logging and metrics.
5. Add explicit database migrations.
