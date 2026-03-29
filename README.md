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
- optional ClamAV-based malware scanning through `clamd`
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

- `GET /v1/health`
- `GET /v1/ready`
- `GET /v1/version`
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
curl -sS -X POST http://localhost:8080/v1/scan/url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.org"}'
```

Example file call:

```bash
curl -sS -X POST http://localhost:8080/v1/scan/file \
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
- `DATABASE_URL`
- `CLAMD_ADDR`
- `FILE_SCAN_ENABLED`
- `FILE_SCAN_STRICT`
- `MAX_FILE_SIZE_BYTES`
- `ALLOWED_FILE_TYPES`
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

## Local Development

```bash
make run
make test
make fmt
make lint
make build
make clean
```

## Docker

```bash
make docker-up
make docker-down
make docker-logs
```

The Compose stack includes `api`, `postgres`, and `clamav`. `postgres` is used when `DATABASE_URL` is configured. `clamav` is used when `CLAMD_ADDR` is configured.

## Current Behavior

`POST /v1/scan/url` currently performs:

- URL parsing and HTTPS enforcement
- embedded credential rejection
- internal/private host blocking
- live reachability checks using outbound HTTP requests
- redirect validation up to the configured maximum
- dangerous download detection from URL path, `Content-Type`, and `Content-Disposition`

`POST /v1/scan/file` currently performs:

- multipart upload handling with the `file` field
- size enforcement
- MIME detection and allowlist validation
- extension-aware MIME inference for OOXML formats
- deterministic OOXML container validation
- OOXML macro, embedded object, and embedded executable detection
- PDF active-content and embedded-file indicator detection
- SHA-256 hashing
- optional ClamAV malware scanning

## Limitations

- legacy binary Office formats such as `.doc`, `.ppt`, and `.xls` are accepted by policy but are not deeply inspected yet
- no archive recursion or nested container inspection yet
- PDF inspection is currently token-based rather than a full object-graph parser
- file scanning currently supports synchronous multipart uploads only
- persistence is durable only when PostgreSQL is enabled

## Documentation

- Architecture and target design: [docs/security-gate-design.md](docs/security-gate-design.md)
- Go notes: [docs/go-onboarding.md](docs/go-onboarding.md)
- PostgreSQL persistence: [docs/postgres-persistence.md](docs/postgres-persistence.md)

## Next Steps

Recommended next engineering steps:

1. Add archive inspection with recursion and decompression limits.
2. Add deep inspection for legacy binary Office formats.
3. Add more robust PDF structure parsing and attachment inspection.
4. Add Google Web Risk integration for URL reputation.
5. Add explicit database migrations.
