package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"agri-gate/internal/domain"
)

type URLScanner interface {
	Scan(context.Context, string, time.Time) domain.ScanResult
}

type FileScanner interface {
	Scan(context.Context, domain.FileScanInput, time.Time) domain.ScanResult
}

type JobStore interface {
	Save(context.Context, domain.Job) error
	Get(context.Context, string) (domain.Job, bool)
}

type Service struct {
	store       JobStore
	urlScanner  URLScanner
	fileScanner FileScanner
	now         func() time.Time
}

type SubmitURLScanRequest struct {
	URL string `json:"url"`
}

func NewService(store JobStore, urlScanner URLScanner, fileScanner FileScanner, now func() time.Time) *Service {
	return &Service{
		store:       store,
		urlScanner:  urlScanner,
		fileScanner: fileScanner,
		now:         now,
	}
}

func (s *Service) SubmitURLScan(ctx context.Context, req SubmitURLScanRequest) (domain.Job, error) {
	if strings.TrimSpace(req.URL) == "" {
		return domain.Job{}, errors.New("url is required")
	}

	now := s.now()
	result := s.urlScanner.Scan(ctx, req.URL, now)

	job := domain.Job{
		ID:          newJobID(),
		Status:      result.Status,
		Scope:       domain.ScopeURL,
		SubmittedAt: now,
		UpdatedAt:   now,
		Result:      result,
		Events: []domain.ScanEvent{
			{
				Timestamp: now,
				Status:    result.Status,
				Engine:    result.PrimaryEngine,
				Message:   result.Reason,
				Details:   result.Details,
			},
		},
	}

	if err := s.store.Save(ctx, job); err != nil {
		return domain.Job{}, err
	}

	return job, nil
}

func (s *Service) SubmitFileScan(ctx context.Context, input domain.FileScanInput) (domain.Job, error) {
	if s.fileScanner == nil {
		return domain.Job{}, errors.New("file scanner is not configured")
	}
	if strings.TrimSpace(input.Filename) == "" {
		return domain.Job{}, errors.New("filename is required")
	}
	if len(input.Content) == 0 {
		return domain.Job{}, errors.New("file content is required")
	}

	now := s.now()
	result := s.fileScanner.Scan(ctx, input, now)

	job := domain.Job{
		ID:          newJobID(),
		Status:      result.Status,
		Scope:       domain.ScopeFile,
		SubmittedAt: now,
		UpdatedAt:   now,
		Result:      result,
		Events: []domain.ScanEvent{
			{
				Timestamp: now,
				Status:    result.Status,
				Engine:    result.PrimaryEngine,
				Message:   result.Reason,
				Details:   result.Details,
			},
		},
	}

	if err := s.store.Save(ctx, job); err != nil {
		return domain.Job{}, err
	}

	return job, nil
}

func (s *Service) GetJob(ctx context.Context, id string) (domain.Job, bool) {
	return s.store.Get(ctx, id)
}

func newJobID() string {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "job-fallback"
	}
	return "job_" + hex.EncodeToString(bytes[:])
}
