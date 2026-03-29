package storage

import (
	"context"
	"sync"

	"agri-gate/internal/domain"
)

type InMemoryJobStore struct {
	mu   sync.RWMutex
	jobs map[string]domain.Job
}

func NewInMemoryJobStore() *InMemoryJobStore {
	return &InMemoryJobStore{
		jobs: make(map[string]domain.Job),
	}
}

func (s *InMemoryJobStore) Save(_ context.Context, job domain.Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.jobs[job.ID] = job
	return nil
}

func (s *InMemoryJobStore) Get(_ context.Context, id string) (domain.Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, ok := s.jobs[id]
	return job, ok
}
