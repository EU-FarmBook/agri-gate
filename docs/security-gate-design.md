# Security Gate Design

## Goal

Build a centralized internal service that other systems can call to validate and scan URLs and files before ingestion.

The service should answer security-first questions such as:

- does the URL resolve successfully
- does it redirect somewhere unsafe
- does it serve or trigger harmful downloads
- does an uploaded file contain malware or embedded active content
- does the fetched or uploaded content contain harmful, malicious, or unsafe material

## Current Direction

The repository is now oriented around security and safety screening, not domain relevance classification.

The major capability areas are:

- URL resolution and redirect safety
- dangerous download detection
- file malware scanning
- file-type validation
- harmful-content analysis for text and media
- persistence and audit trail

## Recommended Stack

- language: Go
- router: `chi` or standard `net/http`
- storage: PostgreSQL
- file malware scanning: ClamAV via `clamd`
- URL reputation: Google Web Risk
- content extraction:
  - HTML parsing for webpages
  - document extraction for PDF, DOCX, PPTX, XLSX, TXT, CSV, TSV
  - OCR for images where needed
  - speech-to-text for audio and video where needed
- harmful-content classification:
  - text moderation/classification
  - image moderation
  - audio/video moderation after transcription or frame extraction

## High-Level Architecture

Suggested split:

- API layer
- URL security engine
- file security engine
- content extraction engine
- harmful-content classification engine
- policy and audit engine

Suggested Go layout:

```text
/cmd/api
/cmd/worker
/internal/http
/internal/config
/internal/domain
/internal/urlscan
/internal/filescan
/internal/extract
/internal/moderation
/internal/webrisk
/internal/clamav
/internal/storage
/internal/audit
/internal/jobs
```

## URL Security Engine

Always-on checks:

- URL parsing and normalization
- HTTPS enforcement
- rejection of embedded credentials
- host safety checks
- redirect-aware validation
- reachability detection
- dangerous direct-download detection

Host and SSRF protections:

- reject localhost
- reject `.local`
- reject private, loopback, link-local, multicast, and unspecified IP ranges
- enforce these checks both before fetch and across redirects

Redirect handling:

- validate the original URL
- validate every redirect hop
- block when redirect depth exceeds the configured maximum
- block when a redirect ends at an unsafe host or harmful payload

Dangerous download detection should use:

- final URL path and extension
- `Content-Disposition`
- `Content-Type`
- whether the target behaves like a download endpoint rather than a normal webpage

Blocked file families should include:

- executables and installers: `.exe`, `.msi`, `.apk`, `.dmg`, `.pkg`, `.jar`
- scripts: `.bat`, `.cmd`, `.ps1`, `.sh`, `.js`
- archives and disk images: `.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.bz2`, `.xz`, `.iso`

## File Security Engine

Supported upload families should include:

- documents: PDF, TXT, CSV, TSV, DOC, DOCX, PPT, PPTX, XLS, XLSX
- images: JPEG, PNG
- audio: MP3, WAV, M4A
- video: MP4, AVI, MOV, WMV, MPEG, MPG, MKV, FLV, WEBM, 3GP, MTS, M2TS, VOB, RMVB

Core file checks:

- max size enforcement
- filename and extension recording
- MIME detection
- allowlist validation
- SHA-256 hashing
- malware scanning

Malware scanning policy:

- clean => continue
- infected => `malicious`, block, quarantine
- scan error in strict mode => block as `error`
- scan error in non-strict mode => record the scanner failure and continue with policy result

Future deeper checks should include:

- PDF active-content and embedded-file detection
- Office macro and embedded-object detection
- archive recursion limits
- media container validation

## Harmful-Content Analysis

Malware scanning is not sufficient for harmful-content detection.

Separate analysis is needed for:

- violent or abusive text
- malicious or unsafe instructions
- harmful imagery
- harmful spoken content in audio and video

Suggested approach:

1. Extract text from webpages and supported documents.
2. Use OCR for images when text may be embedded.
3. Use transcription for audio and video.
4. Run moderation or classification over the extracted text and media.
5. Return structured policy results in addition to malware results.

## Persistence Model

Suggested tables:

- `scan_jobs`
- `scan_results`
- `scan_events`
- `scan_artifacts`
- `quarantine_records`

Current state belongs on the job or result row. Full event history belongs in an append-only event table.

## Current Repository Implementation

The current codebase already includes:

- sync URL scan endpoint
- sync file scan endpoint
- PostgreSQL-backed persistence when configured
- deterministic URL validation
- timeout-bound live URL fetching
- redirect-aware validation
- dangerous download detection from response headers and final URL
- file size and MIME validation for uploads
- optional ClamAV integration via `clamd`

It does not yet include:

- semantic harmful-content detection
- document content extraction
- OCR
- audio/video transcription
- Google Web Risk integration
