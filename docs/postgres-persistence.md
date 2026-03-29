# PostgreSQL Persistence

This document describes the current database-backed persistence layer in `agri-gate`.

## What is implemented

When `DATABASE_URL` is set, the API uses PostgreSQL for job persistence.

When `DATABASE_URL` is not set, the API falls back to the in-memory store.

This means:

- local experimentation can still run without a database
- containerized and real environments can persist jobs and events in PostgreSQL

## Current storage model

The application stores:

- one row in `scan_jobs` per job
- one or more rows in `scan_events` per job

The schema is documented in [schema.sql](../deploy/postgres/schema.sql).

## Tables

### `scan_jobs`

Stores the current state of the job and its latest scan result.

Important columns:

- `id`
- `status`
- `scope`
- `submitted_at`
- `updated_at`
- `result_status`
- `result_scope`
- `result_primary_engine`
- `result_checked_at`
- `result_quarantined`
- `result_escalation`
- `result_reason_code`
- `result_reason`
- `result_details`
- `metadata`

### `scan_events`

Stores scan event history associated with a job.

Important columns:

- `id`
- `job_id`
- `timestamp`
- `status`
- `engine`
- `message`
- `details`

## How schema creation works

The app currently bootstraps the schema on startup with `CREATE TABLE IF NOT EXISTS`.

That logic lives in [postgres.go](../internal/storage/postgres.go).

This is acceptable for early development. Later, this should be replaced with explicit migrations.

## Runtime behavior

Application startup behavior:

1. If `DATABASE_URL` is empty, the app logs that it is using the in-memory store.
2. If `DATABASE_URL` is set, the app connects to PostgreSQL.
3. It pings the database.
4. It ensures the required schema exists.
5. If any of those steps fail, the app exits instead of silently falling back.

That fail-fast behavior is intentional so production misconfiguration is obvious.

## Current limitations

- schema management is embedded in application startup
- no migration system yet
- no integration tests against a real PostgreSQL instance yet
- `scan_results` is folded into `scan_jobs` rather than stored in a dedicated table
- event rows are rewritten on job save, which is acceptable for the current single-write workflow but should evolve as job updates become more complex

## Next likely improvements

1. Add a migration tool or SQL migration directory.
2. Add integration tests using Docker or a local PostgreSQL instance.
3. Split out result persistence further if the audit model becomes more complex.
