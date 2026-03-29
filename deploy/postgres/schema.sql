CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    scope TEXT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    result_status TEXT NOT NULL,
    result_scope TEXT NOT NULL,
    result_primary_engine TEXT NOT NULL,
    result_checked_at TIMESTAMPTZ NOT NULL,
    result_quarantined BOOLEAN NOT NULL,
    result_escalation BOOLEAN NOT NULL,
    result_reason_code TEXT NOT NULL,
    result_reason TEXT NOT NULL,
    result_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS scan_events (
    id BIGSERIAL PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    engine TEXT NOT NULL,
    message TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_scan_events_job_id ON scan_events(job_id);
