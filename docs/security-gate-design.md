# Security Gate Design

## Goal

Build a centralized internal service that other systems can call to decide:

- is this URL safe to follow
- is this file safe to store

The service is security-focused. It is not responsible for semantic relevance, moderation, transcription, or OCR.

## Core Questions

For URLs:

- does the URL resolve successfully
- does it redirect somewhere unsafe
- does it trigger a harmful download
- does it point to an internal or private network target

For files:

- is the file within size limits
- does its detected type match an allowed family
- does it contain malware
- does it contain obvious active content or embedded executable risk

## Recommended Stack

- language: Go
- router: `chi` or standard `net/http`
- storage: PostgreSQL
- file malware scanning: ClamAV via `clamd`
- URL reputation: Google Web Risk

## High-Level Architecture

Suggested split:

- API layer
- URL safety engine
- file safety engine
- policy and audit engine

Suggested Go layout:

```text
/cmd/api
/internal/http
/internal/config
/internal/domain
/internal/urlscan
/internal/filescan
/internal/storage
/internal/jobs
```

## URL Safety Engine

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

## File Safety Engine

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
- extension-aware MIME normalization for OOXML containers
- SHA-256 hashing
- malware scanning
- nested archive recursion limits

Malware scanning policy:

- clean: continue
- infected: `malicious`, block, quarantine
- scan error in strict mode: block as `error`
- scan error in non-strict mode: record the scanner failure and continue with policy result

Future deeper checks should include:

- media container validation
- deep inspection for legacy binary Office formats
- richer PDF parsing beyond token-based detection
- broader nested-container support beyond ZIP-based archives

## Persistence Model

Suggested tables:

- `scan_jobs`
- `scan_events`

Current state belongs on the job row. Full event history belongs in an append-only event table.

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
- OOXML MIME inference for `.docx`, `.pptx`, and `.xlsx`
- OOXML container validation for `.docx`, `.pptx`, and `.xlsx`
- OOXML macro, embedded object, and embedded executable detection
- PDF active-content and embedded-file indicator detection
- nested ZIP recursion with depth, entry-count, and expanded-size limits
- optional ClamAV integration via `clamd`

It does not yet include:

- Google Web Risk integration
- deep inspection for legacy binary Office formats
- full PDF object parsing
- broader nested-container support beyond ZIP-based archives
