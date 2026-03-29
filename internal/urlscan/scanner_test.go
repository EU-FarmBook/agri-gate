package urlscan

import (
	"context"
	"testing"
	"time"

	"agri-gate/internal/domain"
)

func TestScanRejectsInsecureScheme(t *testing.T) {
	scanner := NewScanner()

	result := scanner.Scan(context.Background(), "http://example.com", time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "url_insecure_scheme" {
		t.Fatalf("expected insecure scheme reason, got %q", result.ReasonCode)
	}
}

func TestScanRejectsDangerousDownload(t *testing.T) {
	scanner := NewScanner()

	result := scanner.Scan(context.Background(), "https://example.com/file.exe", time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "url_dangerous_download" {
		t.Fatalf("expected dangerous download reason, got %q", result.ReasonCode)
	}
}

func TestScanAcceptsBasicHTTPSURL(t *testing.T) {
	scanner := NewScanner()

	result := scanner.Scan(context.Background(), "https://www.fao.org/fishery", time.Now().UTC())
	if result.Status != domain.StatusClean {
		t.Fatalf("expected clean status, got %q", result.Status)
	}
}
