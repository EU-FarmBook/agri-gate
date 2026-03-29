# Security Gate Design

## Goal

Build a centralized internal service that many other services can call to validate and scan files and URLs before ingestion.

This service should:
- accept files and URLs
- block obviously unsafe or policy-violating inputs early
- run live reputation and malware checks where configured
- classify agriculture relevance
- return structured decisions that are easy for downstream services to consume
- record both current state and a full audit trail

## Recommended stack

Primary recommendation:
- language: Go
- router: `chi`
- config: environment variables plus a small config package
- storage: PostgreSQL
- file malware scanning: ClamAV via `clamd`
- URL reputation: Google Web Risk
- packaging: Docker Compose for local development, containerized deployment in production

Why Go:
- strong fit for I/O-heavy services
- efficient concurrency
- lower memory use than Python under load
- straightforward streaming of uploads and downloads
- clean timeout and cancellation model
- simple Docker deployment

Framework ranking for this problem:
1. Go with `chi`
2. FastAPI
3. Rust
4. Django
5. Flask

FastAPI remains the best Python fallback if implementation speed and team familiarity matter more than runtime efficiency.

## Why not Django

Django is excellent for admin-heavy product applications, but this service is not primarily a CRUD platform. It is a scanning and policy gateway. The core workload is network I/O, stream handling, external scanner integration, policy evaluation, and structured response generation.

## High-level architecture

Suggested split:
- API layer
- URL security engine
- file security engine
- agriculture relevance engine
- policy and audit engine

Recommended Go layout:

```text
/cmd/api
/cmd/worker
/internal/http
/internal/config
/internal/domain
/internal/policy
/internal/urlscan
/internal/filescan
/internal/agri
/internal/webrisk
/internal/clamav
/internal/storage
/internal/audit
/internal/metrics
/internal/observability
/internal/jobs
/pkg/types
/deploy/docker
```

## Core decision model

Canonical statuses:
- `clean`
- `malicious`
- `error`
- `skipped`

Every result should also include:
- source scope: `url` or `file`
- primary engine
- checked timestamp
- quarantined flag
- escalation flag
- `reason_code`
- human-readable reason
- structured details

The service should store:
- current job/result state
- append-only event history for auditability

## URL security engine

The URL engine should be deterministic first, then reputation-enhanced.

### Always-on checks

These checks should run even if no external scanner is configured:
- URL parsing and normalization
- `https://` enforcement
- rejection of embedded credentials
- host safety checks
- redirect-aware validation
- reachability and broken-link detection
- dangerous direct-download detection
- shortened-link checks on both the input URL and final resolved URL

### Host and SSRF protections

Reject:
- localhost
- `.local`
- private IPs
- loopback
- link-local
- multicast
- reserved ranges
- internal-resolving hosts after DNS resolution

This should be enforced both before making requests and after following redirects.

### Redirect handling

Validate:
- original input URL
- every redirect hop
- final resolved URL

Block if:
- any hop is unsafe
- redirect depth exceeds the configured maximum
- the final URL resolves to an unsafe host or payload

### Reachability and broken URLs

Classify failures explicitly:
- DNS resolution failure
- timeout
- TLS error
- too many redirects
- 4xx or 5xx response
- blocked by policy

### Secure transport checks

At minimum:
- only `https://`
- standard TLS verification passes
- hostname validation passes

### Dangerous download detection

Treat a URL as a direct-download or auto-download risk when one or more of the following are true:
- final response is a binary payload rather than a webpage
- `Content-Disposition` is attachment
- final path clearly points to an executable, installer, archive, script, or disk image
- `Content-Type` indicates executable, archive, installer, or unsupported binary content
- redirect chain ends at a file-serving endpoint instead of a normal page

Likely blocked types:
- executables and installers: `.exe`, `.msi`, `.apk`, `.dmg`, `.pkg`, `.jar`
- scripts: `.bat`, `.cmd`, `.ps1`, `.sh`, `.js`
- archives and images: `.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.bz2`, `.xz`, `.iso`

Older dynamic page routes can remain allowed if they behave like webpages:
- `.php`
- `.asp`
- `.aspx`
- `.jsp`
- `.cgi`
- `.cfm`

### Google Web Risk

Use Google Web Risk for:
- malware
- social engineering
- unwanted software

Recommended policy:
- flagged result => `malicious`
- lookup error in strict mode => block as `error`
- lookup error in non-strict mode => record `error`, do not automatically block

### Browser-style auto-download detection

For v1, do not use full browser automation by default.

Use server-observable signals first:
- response content type
- content disposition
- final URL path
- redirect target

If deeper behavioral analysis is needed later, add a separate Playwright-based sandbox worker rather than mixing browser automation into the first version of the service.

## File security engine

### Ingress handling

On upload:
- enforce max size
- stream to temp file
- compute a hash while streaming
- sniff real MIME type
- compare extension and MIME

### Malware scanning

Preferred:
- ClamAV via `clamd`

Fallback:
- `clamscan`

Recommended behavior:
- clean => continue
- infected => `malicious`, block, quarantine
- scan error in strict mode => block as `error`
- scan error in non-strict mode => record `error`, do not automatically block

### File-type validation

Policy should validate:
- declared filename extension
- sniffed MIME type
- configured allowlist
- file size cap
- type-specific structural limits

### Type-specific checks

Examples:
- PDFs: page count, parseability, encryption presence, malformed structure
- Office docs: structural sanity, future option for macro detection
- images: dimensions, corruption checks
- audio/video: metadata probe, duration cap

## Agriculture relevance engine

Use deterministic domain scoring first, not an LLM-first design.

Primary source:
- AGROVOC

Optional enrichment:
- CABI-aligned taxonomies or curated domain dictionaries, subject to licensing and integration constraints

### Suggested relevance pipeline

1. Extract text safely from the page or file.
2. Normalize and tokenize.
3. Match against AGROVOC preferred labels and alternate labels.
4. Score title, headings, and body matches.
5. Penalize clearly non-agricultural topics.
6. Return one of:
   - `agri_relevant`
   - `uncertain`
   - `non_agri`

### Output should include

- score
- matched terms
- matched concept families
- concise explanation

## API shape

Recommended endpoints:
- `POST /v1/scan/url`
- `POST /v1/scan/file`
- `POST /v1/scan/batch/urls`
- `POST /v1/submit`
- `GET /v1/jobs/{id}`
- `GET /v1/health`
- `GET /v1/ready`
- `GET /v1/version`

Support:
- synchronous scans for quick requests
- asynchronous jobs for larger files or batches

## Example response shape

```json
{
  "status": "malicious",
  "scope": "url",
  "primary_engine": "webrisk",
  "checked_at": "2026-03-29T10:00:00Z",
  "quarantined": false,
  "escalation": false,
  "reason_code": "url_webrisk_flagged",
  "reason": "Google Web Risk flagged the URL for malware.",
  "details": {
    "input_url": "https://example.com/file.exe",
    "final_url": "https://cdn.example.com/file.exe",
    "reachable": true,
    "secure_transport": true,
    "dangerous_download": true,
    "content_type": "application/x-msdownload",
    "webrisk": {
      "status": "malicious",
      "threat_types": ["MALWARE"]
    },
    "agri_relevance": {
      "status": "non_agri",
      "score": 0.02,
      "matched_terms": []
    }
  }
}
```

## Persistence model

Suggested tables:
- `scan_jobs`
- `scan_artifacts`
- `scan_results`
- `scan_events`
- `quarantine_records`

Current state belongs on the job or result row. Full event history belongs in an append-only event table.

## Configuration

Recommended environment variables:
- `APP_ENV`
- `APP_PORT`
- `DATABASE_URL`
- `WEBRISK_API_KEY`
- `URL_SCAN_STRICT`
- `FILE_SCAN_STRICT`
- `FILE_SCAN_ENABLED`
- `CLAMD_ADDR`
- `MAX_URLS_PER_BATCH`
- `MAX_FILE_SIZE_BYTES`
- `MAX_REDIRECTS`
- `HTTP_TIMEOUT_SECONDS`
- `ALLOWED_FILE_TYPES`
- `AGROVOC_DATA_PATH`
- `AGRI_RELEVANCE_THRESHOLD`
- `ENABLE_HTML_EXTRACTION`

Security-sensitive defaults should be explicit and documented.

## Docker approach

Recommended local and production shape:
- app container
- PostgreSQL container
- ClamAV container

Prefer a ClamAV sidecar or dedicated scanner container over baking everything into the app image.

Advantages:
- cleaner separation
- easier signature refresh
- smaller app image
- better scanner lifecycle management

## Observability

Add from the beginning:
- structured logs
- Prometheus metrics
- request latency
- per-engine latency
- counts for `clean`, `malicious`, `error`, `skipped`
- reason-code counters
- scanner availability metrics

## v1 scope

Recommended first version:
- sync URL scan endpoint
- sync file scan endpoint
- batch URL endpoint
- PostgreSQL persistence
- Web Risk integration
- ClamAV integration
- deterministic URL validation
- redirect-aware checks
- dangerous payload detection
- AGROVOC relevance scoring
- event audit trail
- Docker Compose setup

Avoid in v1 unless clearly necessary:
- browser automation
- LLM-based relevance as the primary classifier
- detonation sandboxes
- distributed queueing complexity
- multi-engine antivirus abstractions
