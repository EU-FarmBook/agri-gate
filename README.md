# Agri Gate

Centralized security and agriculture-relevance gateway for files and URLs before downstream ingestion.

This repository now contains a runnable v0 scaffold of the intended service. The current implementation focuses on the first vertical slice:

- HTTP API in Go
- synchronous URL scan endpoint
- deterministic URL validation and policy checks
- basic agriculture relevance scoring
- in-memory job and event storage
- health, readiness, version, and job lookup endpoints
- Docker scaffolding for local development

What is not implemented yet:

- PostgreSQL persistence
- ClamAV integration
- Google Web Risk integration
- file upload scanning
- batch submission flows

## Current endpoints

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

## Run locally

Prerequisites:

- Go 1.22 or newer installed locally

Start the API:

```bash
cp .env.example .env
export $(grep -v '^#' .env | xargs)
go run ./cmd/api
```

The service listens on `http://localhost:8080` by default.

Example scan:

```bash
curl -sS -X POST http://localhost:8080/v1/scan/url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.fao.org"}'
```

## Run with Docker Compose

```bash
docker compose up --build
```

The compose stack includes placeholders for PostgreSQL and ClamAV because those are part of the planned architecture, but the current app version only requires the API container itself to function.

## Layout

```text
cmd/api
internal/config
internal/domain
internal/http
internal/jobs
internal/storage
internal/urlscan
pkg/types
deploy/docker
```

## Notes

- The current router uses the Go standard library to keep bootstrap friction low.
- The persistence layer is intentionally in-memory for now, but the storage boundary is already separated so PostgreSQL can replace it cleanly.
- Agriculture relevance is deterministic and lightweight for v0. It should later be replaced or enriched with AGROVOC-backed scoring.
