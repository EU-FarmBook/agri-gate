# Agri Gate

Agri Gate is a security screening service for URLs and uploaded files before downstream storage or ingestion.

Its purpose is narrow:

- determine whether a URL is safe to follow
- determine whether an uploaded file is safe to store

It is not responsible for semantic relevance checks or content moderation.

## Current Status

This repository contains an early runnable Go implementation.

Implemented:

- `POST /v1/scan/url`
- `POST /v1/scan/file`
- live URL fetches with timeout-bound requests
- redirect-aware URL validation with maximum redirect enforcement
- dangerous download detection from final URL path and HTTP response headers
- SSRF-oriented host blocking for localhost and internal/private addresses
- file size, MIME type, extension-aware MIME inference, and SHA-256 validation for uploads
- deterministic deep inspection for OOXML containers and PDFs
- OOXML macro, embedded object, and embedded executable detection
- PDF active-content and embedded-file indicator detection
- nested archive recursion with entry-count, depth, and expanded-size limits
- optional ClamAV-based malware scanning through `clamd`
- fail-fast config validation at startup
- request IDs and structured access logging
- optional bearer or `X-API-Key` authentication for non-public routes
- simple per-IP rate limiting for non-public routes
- PostgreSQL-backed job and event persistence when `DATABASE_URL` is set
- in-memory fallback storage when `DATABASE_URL` is not set
- health, readiness, version, and job lookup endpoints

Not implemented yet:

- Google Web Risk integration
- archive recursion and archive bomb controls
- deep inspection for legacy binary Office formats such as `.doc`, `.ppt`, and `.xls`
- low-level PDF parsing beyond token-based active-content detection
- batch submission and worker flow

## API

Current endpoints:

- `GET /`
- `GET /v1/health`
- `GET /v1/ready`
- `GET /v1/version`
- `GET /debug/test`
- `POST /v1/scan/url`
- `POST /v1/scan/file`
- `GET /v1/jobs/{id}`

Example URL request:

```json
{
  "url": "https://example.org"
}
```

Example URL call:

```bash
curl -sS -X POST http://localhost:8900/v1/scan/url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.org"}'
```

Example file call:

```bash
curl -sS -X POST http://localhost:8900/v1/scan/file \
  -F "file=@/path/to/file.pdf"
```

## Supported File Policy

The default MIME allowlist is aligned with the current frontend upload policy and covers:

- documents: PDF, TXT, CSV, TSV, DOC, DOCX, PPT, PPTX, XLS, XLSX
- images: JPEG, PNG
- audio: MP3, WAV, M4A
- video: MP4, AVI, MOV, WMV, MPEG, MKV, FLV, WEBM, 3GP, MPEG-TS-style payloads, and DVD/VOB-style content types where detectable

The exact allowlist is configurable through `ALLOWED_FILE_TYPES`.

## Requirements

- Go 1.25 or newer
- Docker and Docker Compose for containerized local development

## Configuration

The application reads:

- `APP_ENV`
- `APP_PORT`
- `APP_VERSION`
- `API_AUTH_TOKEN`
- `ENABLE_DEBUG_ROUTES`
- `RATE_LIMIT_RPM`
- `DATABASE_URL`
- `CLAMD_ADDR`
- `FILE_SCAN_ENABLED`
- `FILE_SCAN_STRICT`
- `MAX_FILE_SIZE_BYTES`
- `ALLOWED_FILE_TYPES`
- `MAX_ARCHIVE_DEPTH`
- `MAX_ARCHIVE_ENTRIES`
- `MAX_EXPANDED_BYTES`
- `MAX_REDIRECTS`
- `HTTP_TIMEOUT_SECONDS`

Create a local env file if needed:

```bash
cp .env.example .env
export $(grep -v '^#' .env | xargs)
```

`.env.example` is a template for local setup. The Go application does not automatically load `.env` files by itself. It reads environment variables from the running process, so local shell sessions must export them before `go run` or `make run`, unless you inject them through another tool such as Docker Compose, `direnv`, or a dotenv wrapper.

Storage behavior:

- if `DATABASE_URL` is set, the application uses PostgreSQL
- if `DATABASE_URL` is empty, it uses the in-memory store

File scanning behavior:

- if `CLAMD_ADDR` is set, the application attempts malware scanning through `clamd`
- if `CLAMD_ADDR` is empty, file scans still enforce size and MIME policy but skip malware scanning
- the default upload limit is `1073741824` bytes, about 1 GB

Security behavior:

- if `API_AUTH_TOKEN` is set, non-public routes require either `Authorization: Bearer <token>` or `X-API-Key: <token>`
- public routes are `/`, `/v1/health`, `/v1/ready`, and `/v1/version`
- if `RATE_LIMIT_RPM` is greater than zero, non-public routes are rate-limited per client IP in a one-minute window
- if `ENABLE_DEBUG_ROUTES=false`, `/debug/test` is not registered

## Local Development

```bash
make run
make test
make fmt
make lint
make build
make clean
```

If you use `.env` locally, export it into the shell before starting the app:

```bash
set -a
source .env
set +a
make run
```

Then open:

- `http://localhost:8900/`
- `http://localhost:8900/debug/test`
- `http://localhost:8900/v1/health`
- `http://localhost:8900/v1/ready`
- `http://localhost:8900/v1/version`

`/debug/test` is a built-in manual test page for browser-based URL and file scan requests. It is intended for development environments and can be disabled with `ENABLE_DEBUG_ROUTES=false`.

## Docker

```bash
make docker-up
make docker-up-detached
make docker-down
make docker-logs
```

The Compose stack includes `api`, `postgres`, and `clamav`. `postgres` is used when `DATABASE_URL` is configured. `clamav` is used when `CLAMD_ADDR` is configured. The host-exposed ports are `8900` for the API, `8901` for PostgreSQL, and `8902` for ClamAV.

If you want the stack in the background, use `make docker-up-detached`.

With Docker running, use the same browser URLs:

- `http://localhost:8900/`
- `http://localhost:8900/debug/test`
- `http://localhost:8900/v1/health`
- `http://localhost:8900/v1/ready`
- `http://localhost:8900/v1/version`

## Online Deployment

The repo now includes a Traefik-oriented production example in [deploy/online/docker-compose.online.yml](deploy/online/docker-compose.online.yml) and [deploy/online/.env.online.example](deploy/online/.env.online.example).

`APP_VERSION` does not have to stay `dev`. Set it explicitly in `.env`, `.env.online`, Docker, or CI/CD. A normal production value would look like:

```bash
APP_VERSION=1.0.0
```

Suggested deployment flow:

1. Build and push the image.

```bash
git push
make docker-build-image IMAGE=ghcr.io/eu-farmbook/agri-gate:latest
make docker-push-image IMAGE=ghcr.io/eu-farmbook/agri-gate:latest
```

2. On the server, create the deployment directory and copy the templates.

```bash
mkdir -p /opt/docker/agri_gate
cd /opt/docker/agri_gate
cp /path/to/repo/deploy/online/docker-compose.online.yml docker-compose.yml
cp /path/to/repo/deploy/online/.env.online.example .env.online
```

3. Edit `.env.online`.

- set a real `APP_VERSION`, for example `1.0.0`
- set a real `API_AUTH_TOKEN`
- set a real `POSTGRES_PASSWORD`
- keep `DATABASE_URL` aligned with that same password
- keep `ENABLE_DEBUG_ROUTES=false`

4. Start it.

```bash
docker pull ghcr.io/eu-farmbook/agri-gate:latest
docker compose pull
docker compose up -d
docker compose logs -f agri_gate
```

The example router uses `agrigate.nexavion.com`. Change the Traefik host rule if you want a different subdomain.

## Current Behavior

`POST /v1/scan/url` currently performs:

- URL parsing and HTTPS enforcement
- embedded credential rejection
- internal/private host blocking
- live reachability checks using outbound HTTP requests
- redirect validation up to the configured maximum
- dangerous download detection from URL path, `Content-Type`, and `Content-Disposition`
- optional API-token protection on non-public routes
- request ID response headers and structured access logs

`POST /v1/scan/file` currently performs:

- multipart upload handling with the `file` field
- size enforcement
- MIME detection and allowlist validation
- extension-aware MIME inference for OOXML formats
- deterministic OOXML container validation
- OOXML macro, embedded object, and embedded executable detection
- PDF active-content and embedded-file indicator detection
- nested archive inspection with recursion and decompression limits
- SHA-256 hashing
- optional ClamAV malware scanning
- optional API-token protection on non-public routes
- per-IP rate limiting on non-public routes
- oversize uploads return a structured `file_too_large` scan result

## Limitations

- legacy binary Office formats such as `.doc`, `.ppt`, and `.xls` are accepted by policy but are not deeply inspected yet
- nested archive inspection currently focuses on ZIP-based containers
- PDF inspection is currently token-based rather than a full object-graph parser
- rate limiting is currently in-memory and instance-local
- file scanning currently supports synchronous multipart uploads only
- persistence is durable only when PostgreSQL is enabled

## Documentation

- Architecture and target design: [docs/security-gate-design.md](docs/security-gate-design.md)
- Go notes: [docs/go-onboarding.md](docs/go-onboarding.md)
- PostgreSQL persistence: [docs/postgres-persistence.md](docs/postgres-persistence.md)

## Next Steps

Recommended next engineering steps:

1. Add deep inspection for legacy binary Office formats.
2. Add more robust PDF structure parsing and attachment inspection.
3. Add broader nested-container support beyond ZIP-based archives.
4. Add Google Web Risk integration for URL reputation.
5. Add explicit database migrations.
