# API Contract

This document describes how to call Agri Gate and how to interpret its responses.

Base URL in production:

```text
https://agrigate.nexavion.com
```

## Authentication

Protected routes require either:

- `Authorization: Bearer YOUR_API_TOKEN`
- `X-API-Key: YOUR_API_TOKEN`

Public routes:

- `GET /`
- `GET /debug/test` when enabled
- `GET /v1/health`
- `GET /v1/ready`
- `GET /v1/version`

## Endpoints

- `POST /v1/scan/url`
- `POST /v1/scan/file`
- `GET /v1/jobs/{id}`

## URL Scan

Request:

```http
POST /v1/scan/url
Content-Type: application/json
Authorization: Bearer YOUR_API_TOKEN
```

```json
{
  "url": "https://example.org"
}
```

`curl` example:

```bash
curl -sS -X POST https://agrigate.nexavion.com/v1/scan/url \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_TOKEN' \
  -d '{"url":"https://example.org"}'
```

Clean example:

```json
{
  "status": "clean",
  "scope": "url",
  "primary_engine": "url_fetch",
  "checked_at": "2026-03-29T20:18:00.838942049Z",
  "quarantined": false,
  "escalation": false,
  "reason_code": "url_validated",
  "reason": "URL passed validation and live fetch checks.",
  "details": {
    "content_disposition": "inline; filename=\"document.pdf\"",
    "content_type": "application/pdf",
    "dangerous_download": false,
    "final_url": "https://edepot.wur.nl/674508",
    "input_url": "https://edepot.wur.nl/674508",
    "reachable": true,
    "scan_duration_ms": 2217,
    "secure_transport": true,
    "status_code": 200
  }
}
```

HTTP error example:

```json
{
  "status": "error",
  "scope": "url",
  "primary_engine": "url_fetch",
  "checked_at": "2026-03-29T20:18:00.838942049Z",
  "quarantined": false,
  "escalation": false,
  "reason_code": "url_http_error",
  "reason": "URL returned HTTP 404.",
  "details": {
    "content_disposition": "",
    "content_type": "text/html; charset=utf-8",
    "dangerous_download": false,
    "final_url": "https://github.com/EU-FarmBook/agri-gate",
    "input_url": "https://github.com/EU-FarmBook/agri-gate",
    "reachable": true,
    "scan_duration_ms": 259,
    "secure_transport": true,
    "status_code": 404
  }
}
```

## File Scan

Request:

```http
POST /v1/scan/file
Authorization: Bearer YOUR_API_TOKEN
Content-Type: multipart/form-data
```

Form field:

- `file`: uploaded file content

`curl` example:

```bash
curl -sS -X POST https://agrigate.nexavion.com/v1/scan/file \
  -H 'Authorization: Bearer YOUR_API_TOKEN' \
  -F "file=@/absolute/path/to/file.pdf"
```

Clean example:

```json
{
  "status": "clean",
  "scope": "file",
  "primary_engine": "file_policy",
  "checked_at": "2026-03-29T20:18:00.838942049Z",
  "quarantined": false,
  "escalation": false,
  "reason_code": "file_validated",
  "reason": "File passed validation checks.",
  "details": {
    "deep_inspection": {
      "findings": [],
      "format": "pdf",
      "status": "clean"
    },
    "extension": ".pdf",
    "filename": "30-01 Dinner.pdf",
    "malware_scan": "clean",
    "mime_type": "application/pdf",
    "scan_duration_ms": 133,
    "sha256": "46a6eed90d2970b3d780738c07d7b78aa04e8407057a8b367e913e9f82643be0",
    "size_bytes": 212584
  }
}
```

Oversized upload example:

```json
{
  "status": "malicious",
  "scope": "file",
  "primary_engine": "file_policy",
  "checked_at": "2026-03-29T20:18:00.838942049Z",
  "quarantined": false,
  "escalation": false,
  "reason_code": "file_too_large",
  "reason": "Uploaded file exceeds the configured size limit.",
  "details": {
    "max_file_size_bytes": 1073741824
  }
}
```

## Response Fields

Top-level fields:

- `status`: overall decision
- `scope`: `url` or `file`
- `primary_engine`: main component that decided the result
- `checked_at`: UTC timestamp of the scan
- `quarantined`: whether the item should be treated as quarantined
- `escalation`: whether the result should be escalated
- `reason_code`: stable machine-readable explanation
- `reason`: human-readable explanation
- `details`: structured per-scan detail fields

Common `status` values:

- `clean`
- `malicious`
- `error`
- `skipped`

## Detail Fields

Common detail fields:

- `scan_duration_ms`: elapsed scan time in milliseconds

Typical URL detail fields:

- `input_url`
- `final_url`
- `status_code`
- `content_type`
- `content_disposition`
- `reachable`
- `secure_transport`
- `dangerous_download`

Typical file detail fields:

- `filename`
- `extension`
- `size_bytes`
- `mime_type`
- `sha256`
- `malware_scan`
- `deep_inspection`

## Reason Codes

Examples of URL reason codes:

- `url_validated`
- `url_http_error`
- `url_dangerous_download`
- `url_insecure_scheme`
- `url_fetch_error`

Examples of file reason codes:

- `file_validated`
- `file_too_large`
- `file_type_not_allowed`
- `file_malware_detected`
- `office_macro_detected`
- `office_embedded_object_detected`
- `office_embedded_executable_detected`
- `pdf_javascript_detected`

## Notes

- A URL scan validates and fetches the URL response. It does not yet download the final remote file and run the full file scanner on that body.
- `reachable: true` with `status: error` can happen when the remote server responded successfully at the HTTP transport level but returned an error status such as `404`.
- The exact fields inside `details` can vary by file type and scanner path.
