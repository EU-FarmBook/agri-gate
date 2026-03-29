package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agri-gate/internal/config"
	"agri-gate/internal/filescan"
	httpapi "agri-gate/internal/http"
	"agri-gate/internal/jobs"
	"agri-gate/internal/storage"
	"agri-gate/internal/urlscan"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	store, cleanup, err := newJobStore(context.Background(), cfg, logger)
	if err != nil {
		logger.Fatalf("storage initialization failed: %v", err)
	}
	defer cleanup()

	scanner := urlscan.NewScannerWithConfig(urlscan.Config{
		MaxRedirects: cfg.MaxRedirects,
		Timeout:      cfg.HTTPTimeout,
	})
	fileScanner := filescan.NewScanner(filescan.Config{
		Enabled:           cfg.FileScanEnabled,
		Strict:            cfg.FileScanStrict,
		MaxFileSizeBytes:  cfg.MaxFileSizeBytes,
		AllowedFileTypes:  cfg.AllowedFileTypes,
		MaxArchiveDepth:   cfg.MaxArchiveDepth,
		MaxArchiveEntries: cfg.MaxArchiveEntries,
		MaxExpandedBytes:  cfg.MaxExpandedBytes,
		ClamdAddr:         cfg.ClamdAddr,
	})
	jobService := jobs.NewService(store, scanner, fileScanner, cfg.Clock)

	server := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           httpapi.NewServer(cfg, jobService, logger),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Printf("listening on %s", cfg.ListenAddr())
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("server failed: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	logger.Printf("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Printf("graceful shutdown failed: %v", err)
	}
}

func newJobStore(ctx context.Context, cfg config.Config, logger *log.Logger) (jobs.JobStore, func(), error) {
	if cfg.DatabaseURL == "" {
		logger.Printf("DATABASE_URL not set, using in-memory job store")
		return storage.NewInMemoryJobStore(), func() {}, nil
	}

	var lastErr error
	for attempt := 1; attempt <= 15; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		store, err := storage.NewPostgresJobStore(attemptCtx, cfg.DatabaseURL)
		cancel()
		if err == nil {
			logger.Printf("using PostgreSQL job store")
			return store, func() {
				if err := store.Close(); err != nil {
					logger.Printf("postgres close failed: %v", err)
				}
			}, nil
		}

		lastErr = err
		logger.Printf("postgres initialization attempt %d/15 failed: %v", attempt, err)
		if attempt < 15 {
			time.Sleep(2 * time.Second)
		}
	}

	return nil, nil, fmt.Errorf("connect postgres store after retries: %w", lastErr)
}
