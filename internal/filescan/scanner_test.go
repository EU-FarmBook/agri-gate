package filescan

import (
	"context"
	"errors"
	"testing"
	"time"

	"agri-gate/internal/domain"
)

type stubMalwareScanner struct {
	verdict Verdict
	err     error
}

func (s stubMalwareScanner) Scan(context.Context, string, []byte) (Verdict, error) {
	if s.err != nil {
		return Verdict{}, s.err
	}
	return s.verdict, nil
}

func TestScanRejectsTooLargeFile(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:          true,
		MaxFileSizeBytes: 3,
		AllowedFileTypes: []string{"text/plain"},
	})

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "test.txt",
		Content:  []byte("hello"),
	}, time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "file_too_large" {
		t.Fatalf("expected size rejection, got %q", result.ReasonCode)
	}
}

func TestScanRejectsUnsupportedType(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:          true,
		MaxFileSizeBytes: 1024,
		AllowedFileTypes: []string{"application/pdf"},
	})

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "test.txt",
		Content:  []byte("hello"),
	}, time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "file_type_not_allowed" {
		t.Fatalf("expected type rejection, got %q", result.ReasonCode)
	}
}

func TestScanReturnsCleanWithoutMalwareScanner(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:          true,
		MaxFileSizeBytes: 1024,
		AllowedFileTypes: []string{"text/plain; charset=utf-8", "text/plain"},
	})

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "test.txt",
		Content:  []byte("hello"),
	}, time.Now().UTC())
	if result.Status != domain.StatusClean {
		t.Fatalf("expected clean status, got %q", result.Status)
	}
}

func TestScanReturnsMaliciousWhenInfected(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:          true,
		MaxFileSizeBytes: 1024,
		AllowedFileTypes: []string{"text/plain; charset=utf-8", "text/plain"},
	})
	scanner.malwareScanner = stubMalwareScanner{verdict: Verdict{Infected: true, Threat: "Eicar-Test-Signature"}}

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "test.txt",
		Content:  []byte("hello"),
	}, time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "file_malware_detected" {
		t.Fatalf("expected malware detection, got %q", result.ReasonCode)
	}
}

func TestScanReturnsErrorInStrictModeOnMalwareScanFailure(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:          true,
		Strict:           true,
		MaxFileSizeBytes: 1024,
		AllowedFileTypes: []string{"text/plain; charset=utf-8", "text/plain"},
	})
	scanner.malwareScanner = stubMalwareScanner{err: errors.New("clamd unavailable")}

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "test.txt",
		Content:  []byte("hello"),
	}, time.Now().UTC())
	if result.Status != domain.StatusError {
		t.Fatalf("expected error status, got %q", result.Status)
	}
	if result.ReasonCode != "file_scan_error" {
		t.Fatalf("expected file scan error, got %q", result.ReasonCode)
	}
}
