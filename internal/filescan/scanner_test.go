package filescan

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"strings"
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
		Enabled:           true,
		MaxFileSizeBytes:  3,
		AllowedFileTypes:  []string{"text/plain"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
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
		Enabled:           true,
		MaxFileSizeBytes:  1024,
		AllowedFileTypes:  []string{"application/pdf"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
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
		Enabled:           true,
		MaxFileSizeBytes:  1024,
		AllowedFileTypes:  []string{"text/plain; charset=utf-8", "text/plain"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
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
		Enabled:           true,
		MaxFileSizeBytes:  1024,
		AllowedFileTypes:  []string{"text/plain; charset=utf-8", "text/plain"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
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
		Enabled:           true,
		Strict:            true,
		MaxFileSizeBytes:  1024,
		AllowedFileTypes:  []string{"text/plain; charset=utf-8", "text/plain"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
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

func TestInferMIMETypeUsesOOXMLExtensionForZipPayloads(t *testing.T) {
	got := inferMIMEType("manual.docx", "application/zip")
	want := "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestScanRejectsOOXMLMacros(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:           true,
		MaxFileSizeBytes:  1024 * 1024,
		AllowedFileTypes:  []string{"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
	})

	content := buildZipFile(t, map[string]string{
		"[Content_Types].xml":          `<Types></Types>`,
		"word/document.xml":            `<w:document></w:document>`,
		"word/vbaProject.bin":          "macro",
		"word/_rels/document.xml.rels": `<Relationships></Relationships>`,
	})

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "macro.docx",
		Content:  content,
	}, time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "office_macro_detected" {
		t.Fatalf("expected macro detection, got %q", result.ReasonCode)
	}
}

func TestScanRejectsOOXMLEmbeddedObjects(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:           true,
		MaxFileSizeBytes:  1024 * 1024,
		AllowedFileTypes:  []string{"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
	})

	content := buildZipFile(t, map[string]string{
		"[Content_Types].xml":            `<Types></Types>`,
		"word/document.xml":              `<w:document></w:document>`,
		"word/embeddings/oleObject1.bin": "embedded",
	})

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "embedded.docx",
		Content:  content,
	}, time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "office_embedded_object_detected" {
		t.Fatalf("expected embedded object detection, got %q", result.ReasonCode)
	}
}

func TestScanRejectsInvalidOOXMLContainer(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:           true,
		MaxFileSizeBytes:  1024 * 1024,
		AllowedFileTypes:  []string{"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
	})

	content := buildZipFile(t, map[string]string{
		"payload.txt": "not a real docx",
	})

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "broken.docx",
		Content:  content,
	}, time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "file_invalid_container" {
		t.Fatalf("expected invalid container detection, got %q", result.ReasonCode)
	}
}

func TestScanRejectsPDFActiveContent(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:           true,
		MaxFileSizeBytes:  1024 * 1024,
		AllowedFileTypes:  []string{"application/pdf"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
	})

	content := []byte("%PDF-1.7\n1 0 obj\n<< /OpenAction 2 0 R /JavaScript 3 0 R >>\nendobj\n")
	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "scripted.pdf",
		Content:  content,
	}, time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "pdf_javascript_detected" && result.ReasonCode != "pdf_open_action_detected" {
		t.Fatalf("expected PDF active content detection, got %q", result.ReasonCode)
	}
}

func TestScanAcceptsSimpleOOXMLDocument(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:           true,
		MaxFileSizeBytes:  1024 * 1024,
		AllowedFileTypes:  []string{"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
	})

	content := buildZipFile(t, map[string]string{
		"[Content_Types].xml":          `<Types></Types>`,
		"word/document.xml":            `<w:document></w:document>`,
		"word/_rels/document.xml.rels": `<Relationships></Relationships>`,
	})

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "clean.docx",
		Content:  content,
	}, time.Now().UTC())
	if result.Status != domain.StatusClean {
		t.Fatalf("expected clean status, got %q", result.Status)
	}
}

func buildZipFile(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, body := range files {
		fileWriter, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", name, err)
		}
		if _, err := fileWriter.Write([]byte(body)); err != nil {
			t.Fatalf("write zip entry %q: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

func TestScanRejectsNestedExecutableInArchive(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:           true,
		MaxFileSizeBytes:  1024 * 1024,
		AllowedFileTypes:  []string{"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
	})

	nested := buildZipFile(t, map[string]string{
		"payload.exe": "MZ",
	})
	content := buildZipFileBytes(t, map[string][]byte{
		"[Content_Types].xml":   []byte(`<Types></Types>`),
		"word/document.xml":     []byte(`<w:document></w:document>`),
		"word/media/nested.zip": nested,
	})

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "nested.docx",
		Content:  content,
	}, time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "nested_executable_detected" {
		t.Fatalf("expected nested executable detection, got %q", result.ReasonCode)
	}
}

func TestScanRejectsNestedArchiveDepthLimit(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:           true,
		MaxFileSizeBytes:  1024 * 1024,
		AllowedFileTypes:  []string{"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		MaxArchiveDepth:   1,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  10 * 1024 * 1024,
	})

	level2 := buildZipFile(t, map[string]string{
		"payload.txt": "ok",
	})
	level1 := buildZipFileBytes(t, map[string][]byte{
		"inner.zip": level2,
	})
	content := buildZipFileBytes(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<Types></Types>`),
		"word/document.xml":   []byte(`<w:document></w:document>`),
		"word/media/a.zip":    level1,
	})

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "depth.docx",
		Content:  content,
	}, time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "archive_limits_exceeded" {
		t.Fatalf("expected archive limit detection, got %q", result.ReasonCode)
	}
}

func TestScanRejectsExpandedArchiveLimit(t *testing.T) {
	scanner := NewScanner(Config{
		Enabled:           true,
		MaxFileSizeBytes:  1024 * 1024,
		AllowedFileTypes:  []string{"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		MaxArchiveDepth:   3,
		MaxArchiveEntries: 2048,
		MaxExpandedBytes:  64,
	})

	content := buildZipFile(t, map[string]string{
		"[Content_Types].xml": strings.Repeat("A", 40),
		"word/document.xml":   strings.Repeat("B", 80),
	})

	result := scanner.Scan(context.Background(), domain.FileScanInput{
		Filename: "large.docx",
		Content:  content,
	}, time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "archive_limits_exceeded" {
		t.Fatalf("expected archive limit detection, got %q", result.ReasonCode)
	}
}

func buildZipFileBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, body := range files {
		fileWriter, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", name, err)
		}
		if _, err := fileWriter.Write(body); err != nil {
			t.Fatalf("write zip entry %q: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}
