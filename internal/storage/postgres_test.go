package storage

import (
	"context"
	"testing"

	"agri-gate/internal/domain"
)

func TestInMemoryStoreRoundTrip(t *testing.T) {
	store := NewInMemoryJobStore()
	job := domain.Job{ID: "job_1", Status: domain.StatusClean}

	if err := store.Save(context.Background(), job); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	got, ok := store.Get(context.Background(), "job_1")
	if !ok {
		t.Fatal("expected job to be found")
	}
	if got.ID != job.ID {
		t.Fatalf("expected %q, got %q", job.ID, got.ID)
	}
}
