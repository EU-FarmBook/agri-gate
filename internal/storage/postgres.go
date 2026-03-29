package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"agri-gate/internal/domain"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresJobStore struct {
	db *sql.DB
}

func NewPostgresJobStore(ctx context.Context, databaseURL string) (*PostgresJobStore, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}

	store := &PostgresJobStore{db: db}
	if err := store.db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := store.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *PostgresJobStore) Save(ctx context.Context, job domain.Job) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	resultDetails, err := json.Marshal(job.Result.Details)
	if err != nil {
		return fmt.Errorf("marshal result details: %w", err)
	}

	metadata, err := json.Marshal(job.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO scan_jobs (
			id, status, scope, submitted_at, updated_at,
			result_status, result_scope, result_primary_engine, result_checked_at,
			result_quarantined, result_escalation, result_reason_code, result_reason,
			result_details, metadata
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13,
			$14::jsonb, $15::jsonb
		)
		ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			scope = EXCLUDED.scope,
			submitted_at = EXCLUDED.submitted_at,
			updated_at = EXCLUDED.updated_at,
			result_status = EXCLUDED.result_status,
			result_scope = EXCLUDED.result_scope,
			result_primary_engine = EXCLUDED.result_primary_engine,
			result_checked_at = EXCLUDED.result_checked_at,
			result_quarantined = EXCLUDED.result_quarantined,
			result_escalation = EXCLUDED.result_escalation,
			result_reason_code = EXCLUDED.result_reason_code,
			result_reason = EXCLUDED.result_reason,
			result_details = EXCLUDED.result_details,
			metadata = EXCLUDED.metadata
	`, job.ID, job.Status, job.Scope, job.SubmittedAt, job.UpdatedAt,
		job.Result.Status, job.Result.Scope, job.Result.PrimaryEngine, job.Result.CheckedAt,
		job.Result.Quarantined, job.Result.Escalation, job.Result.ReasonCode, job.Result.Reason,
		string(resultDetails), string(metadata))
	if err != nil {
		return fmt.Errorf("insert job: %w", err)
	}

	if _, err = tx.ExecContext(ctx, `DELETE FROM scan_events WHERE job_id = $1`, job.ID); err != nil {
		return fmt.Errorf("delete prior events: %w", err)
	}

	for _, event := range job.Events {
		details, marshalErr := json.Marshal(event.Details)
		if marshalErr != nil {
			return fmt.Errorf("marshal event details: %w", marshalErr)
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO scan_events (job_id, timestamp, status, engine, message, details)
			VALUES ($1, $2, $3, $4, $5, $6::jsonb)
		`, job.ID, event.Timestamp, event.Status, event.Engine, event.Message, string(details))
		if err != nil {
			return fmt.Errorf("insert event: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit job transaction: %w", err)
	}

	return nil
}

func (s *PostgresJobStore) Get(ctx context.Context, id string) (domain.Job, bool) {
	row := s.db.QueryRowContext(ctx, `
		SELECT
			id, status, scope, submitted_at, updated_at,
			result_status, result_scope, result_primary_engine, result_checked_at,
			result_quarantined, result_escalation, result_reason_code, result_reason,
			COALESCE(result_details, '{}'::jsonb), COALESCE(metadata, '{}'::jsonb)
		FROM scan_jobs
		WHERE id = $1
	`, id)

	var job domain.Job
	var resultDetailsRaw []byte
	var metadataRaw []byte
	err := row.Scan(
		&job.ID, &job.Status, &job.Scope, &job.SubmittedAt, &job.UpdatedAt,
		&job.Result.Status, &job.Result.Scope, &job.Result.PrimaryEngine, &job.Result.CheckedAt,
		&job.Result.Quarantined, &job.Result.Escalation, &job.Result.ReasonCode, &job.Result.Reason,
		&resultDetailsRaw, &metadataRaw,
	)
	if err != nil {
		return domain.Job{}, false
	}

	job.Result.Details = make(map[string]any)
	if err := json.Unmarshal(resultDetailsRaw, &job.Result.Details); err != nil {
		return domain.Job{}, false
	}

	job.Metadata = make(map[string]string)
	if err := json.Unmarshal(metadataRaw, &job.Metadata); err != nil {
		return domain.Job{}, false
	}

	job.Events = make([]domain.ScanEvent, 0)
	rows, err := s.db.QueryContext(ctx, `
		SELECT timestamp, status, engine, message, COALESCE(details, '{}'::jsonb)
		FROM scan_events
		WHERE job_id = $1
		ORDER BY timestamp ASC, id ASC
	`, id)
	if err != nil {
		return domain.Job{}, false
	}
	defer rows.Close()

	for rows.Next() {
		var event domain.ScanEvent
		var detailsRaw []byte
		if err := rows.Scan(&event.Timestamp, &event.Status, &event.Engine, &event.Message, &detailsRaw); err != nil {
			return domain.Job{}, false
		}

		event.Details = make(map[string]any)
		if err := json.Unmarshal(detailsRaw, &event.Details); err != nil {
			return domain.Job{}, false
		}

		job.Events = append(job.Events, event)
	}

	return job, rows.Err() == nil
}

func (s *PostgresJobStore) Close() error {
	return s.db.Close()
}

func (s *PostgresJobStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
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
	`)
	if err != nil {
		return fmt.Errorf("ensure schema: %w", err)
	}

	return nil
}
