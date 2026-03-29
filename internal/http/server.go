package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"agri-gate/internal/config"
	"agri-gate/internal/jobs"
)

type Server struct {
	config     config.Config
	jobs       *jobs.Service
	logger     *log.Logger
}

func NewServer(cfg config.Config, jobsSvc *jobs.Service, logger *log.Logger) http.Handler {
	server := &Server{
		config: cfg,
		jobs:   jobsSvc,
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", server.handleHealth)
	mux.HandleFunc("/v1/ready", server.handleReady)
	mux.HandleFunc("/v1/version", server.handleVersion)
	mux.HandleFunc("/v1/scan/url", server.handleScanURL)
	mux.HandleFunc("/v1/jobs/", server.handleGetJob)

	return server.withLogging(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "agri-gate",
		"env":     s.config.AppEnv,
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ready",
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.config.AppVersion,
	})
}

func (s *Server) handleScanURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	var req jobs.SubmitURLScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_json",
		})
		return
	}

	job, err := s.jobs.SubmitURLScan(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid_request",
			"message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, job.Result)
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	jobID := strings.TrimPrefix(r.URL.Path, "/v1/jobs/")
	if jobID == "" || strings.Contains(jobID, "/") {
		http.NotFound(w, r)
		return
	}

	job, ok := s.jobs.GetJob(r.Context(), jobID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "job_not_found",
		})
		return
	}

	writeJSON(w, http.StatusOK, job)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
		"error": "method_not_allowed",
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
