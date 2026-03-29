package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agri-gate/internal/config"
	httpapi "agri-gate/internal/http"
	"agri-gate/internal/jobs"
	"agri-gate/internal/storage"
	"agri-gate/internal/urlscan"
)

func main() {
	cfg := config.Load()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	store := storage.NewInMemoryJobStore()
	scanner := urlscan.NewScanner()
	jobService := jobs.NewService(store, scanner, cfg.Clock)

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
