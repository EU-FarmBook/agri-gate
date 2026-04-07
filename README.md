# Agri Gate

Agri Gate is a security screening service for URLs and uploaded files before downstream storage or ingestion.

It answers two questions:

- is this URL safe to follow
- is this file safe to store

It is not a semantic moderation or relevance-classification service.

## Scope

Current capabilities:

- URL validation, HTTPS enforcement, and SSRF-style private-host blocking
- live URL fetches with redirect validation and dangerous-download detection
- file size and MIME policy enforcement
- SHA-256 hashing
- OOXML container inspection for macros, embedded objects, and embedded executables
- PDF active-content indicator checks
- nested ZIP-based archive inspection with recursion limits
- optional ClamAV malware scanning via `clamd`
- PostgreSQL-backed job persistence
- request IDs, structured access logs, optional API-token auth, and simple rate limiting

Current gaps:

- legacy binary Office inspection (`.doc`, `.ppt`, `.xls`)
- deeper PDF structure parsing
- reputation services such as Google Web Risk
- async worker/batch processing
- distributed rate limiting and richer auth models

## API

Routes:

- `GET /`
- `GET /v1/health`
- `GET /v1/ready`
- `GET /v1/version`
- `POST /v1/scan/url`
- `POST /v1/scan/file`
- `GET /v1/jobs/{id}`
- `GET /debug/test` when `ENABLE_DEBUG_ROUTES=true`

Public routes:

- `/`
- `/debug/test`
- `/v1/health`
- `/v1/ready`
- `/v1/version`

If `API_AUTH_TOKEN` is set, all other routes require either:

- `Authorization: Bearer YOUR_API_TOKEN`
- `X-API-Key: YOUR_API_TOKEN`

Typical response fields:

- `status`
- `reason_code`
- `reason`
- `details.scan_duration_ms`

## Usage

Production base URL:

```text
https://agrigate.nexavion.com
```

URL scan with `curl`:

```bash
curl -sS -X POST https://agrigate.nexavion.com/v1/scan/url \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_TOKEN' \
  -d '{"url":"https://example.org"}'
```

File scan with `curl`:

```bash
curl -sS -X POST https://agrigate.nexavion.com/v1/scan/file \
  -H 'Authorization: Bearer YOUR_API_TOKEN' \
  -F "file=@/absolute/path/to/file.pdf"
```

Python `requests` URL scan:

```python
import requests

response = requests.post(
    "https://agrigate.nexavion.com/v1/scan/url",
    headers={"Authorization": "Bearer YOUR_API_TOKEN"},
    json={"url": "https://example.org"},
    timeout=60,
)
print(response.status_code, response.json())
```

Python `requests` file scan:

```python
import os
import requests

path = "/absolute/path/to/file.pdf"
with open(path, "rb") as file_obj:
    response = requests.post(
        "https://agrigate.nexavion.com/v1/scan/file",
        headers={"Authorization": "Bearer YOUR_API_TOKEN"},
        files={"file": (os.path.basename(path), file_obj)},
        timeout=300,
    )
print(response.status_code, response.json())
```

A reusable example client is available at [examples/agri_gate_client.py](examples/agri_gate_client.py).

## Configuration

Main runtime variables:

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

Defaults worth knowing:

- default app port: `8900`
- default upload limit: `1073741824` bytes, about 1 GB
- `.env.example` is only a template; the Go process does not auto-load `.env`
- if `DATABASE_URL` is empty, the app falls back to in-memory storage
- if `CLAMD_ADDR` is empty, policy checks still run but malware scanning is skipped

Set a real version string in non-dev environments, for example:

```bash
APP_VERSION=1.0.0
```

## Local Run

Direct:

```bash
set -a
source .env
set +a
make run
```

Docker:

```bash
make docker-up
```

Useful local URLs:

- `http://localhost:8900/`
- `http://localhost:8900/debug/test`
- `http://localhost:8900/v1/health`

The debug console is a lightweight manual test UI. If enabled in production, the page is public but scan actions still require the API token entered into the page.

## Image And Deployment

Build and push:

```bash
make docker-publish-image IMAGE=ghcr.io/eu-farmbook/agri-gate:latest
```

For production deployment behind Traefik, use:

- [docs/deployment.md](docs/deployment.md)
- [deploy/online/docker-compose.online.yml](deploy/online/docker-compose.online.yml)
- [deploy/online/.env.online.example](deploy/online/.env.online.example)

## Development

Common commands:

```bash
make fmt
make lint
make test
make build
```

## Notes

- nested archive inspection is currently ZIP-focused
- PDF inspection is still heuristic rather than full structural parsing
- rate limiting is in-memory and instance-local

## Docs

- API contract: [docs/api.md](docs/api.md)
- Deployment: [docs/deployment.md](docs/deployment.md)
- Architecture: [docs/security-gate-design.md](docs/security-gate-design.md)
- PostgreSQL persistence: [docs/postgres-persistence.md](docs/postgres-persistence.md)
- Go notes: [docs/go-onboarding.md](docs/go-onboarding.md)
