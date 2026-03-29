package jobs

import (
	"context"
	"testing"
	"time"

	"agri-gate/internal/domain"
	"agri-gate/internal/storage"
)

type stubScanner struct {
	result domain.ScanResult
}

func (s stubScanner) Scan(_ context.Context, _ string, _ time.Time) domain.ScanResult {
	return s.result
}

type stubFileScanner struct {
	result domain.ScanResult
}

func (s stubFileScanner) Scan(_ context.Context, _ domain.FileScanInput, _ time.Time) domain.ScanResult {
	return s.result
}

func TestSubmitURLScanCreatesJob(t *testing.T) {
	now := time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC)
	service := NewService(
		storage.NewInMemoryJobStore(),
		stubScanner{
			result: domain.ScanResult{
				Status:        domain.StatusClean,
				Scope:         domain.ScopeURL,
				PrimaryEngine: "url_validator",
				CheckedAt:     now,
				ReasonCode:    "url_validated",
				Reason:        "URL passed deterministic validation.",
			},
		},
		stubFileScanner{},
		func() time.Time { return now },
	)

	job, err := service.SubmitURLScan(context.Background(), SubmitURLScanRequest{
		URL: "https://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if job.ID == "" {
		t.Fatal("expected generated job ID")
	}
	if len(job.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(job.Events))
	}
}

func TestSubmitFileScanCreatesJob(t *testing.T) {
	now := time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC)
	service := NewService(
		storage.NewInMemoryJobStore(),
		stubScanner{},
		stubFileScanner{
			result: domain.ScanResult{
				Status:        domain.StatusClean,
				Scope:         domain.ScopeFile,
				PrimaryEngine: "file_policy",
				CheckedAt:     now,
				ReasonCode:    "file_validated",
				Reason:        "File passed validation checks.",
			},
		},
		func() time.Time { return now },
	)

	job, err := service.SubmitFileScan(context.Background(), domain.FileScanInput{
		Filename: "test.txt",
		Content:  []byte("hello"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if job.Scope != domain.ScopeFile {
		t.Fatalf("expected file scope, got %q", job.Scope)
	}
}
