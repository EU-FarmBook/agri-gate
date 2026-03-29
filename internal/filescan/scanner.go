package filescan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"agri-gate/internal/domain"
)

type MalwareScanner interface {
	Scan(context.Context, string, []byte) (Verdict, error)
}

type Verdict struct {
	Clean    bool
	Infected bool
	Threat   string
}

type Config struct {
	Enabled          bool
	Strict           bool
	MaxFileSizeBytes int64
	AllowedFileTypes []string
	ClamdAddr        string
}

type Scanner struct {
	enabled          bool
	strict           bool
	maxFileSize      int64
	allowedFileTypes map[string]struct{}
	malwareScanner   MalwareScanner
}

func NewScanner(cfg Config) *Scanner {
	allowed := make(map[string]struct{}, len(cfg.AllowedFileTypes))
	for _, item := range cfg.AllowedFileTypes {
		allowed[normalizeMIME(item)] = struct{}{}
	}

	var malwareScanner MalwareScanner
	if cfg.ClamdAddr != "" {
		malwareScanner = NewClamdScanner(cfg.ClamdAddr)
	}

	return &Scanner{
		enabled:          cfg.Enabled,
		strict:           cfg.Strict,
		maxFileSize:      cfg.MaxFileSizeBytes,
		allowedFileTypes: allowed,
		malwareScanner:   malwareScanner,
	}
}

func (s *Scanner) Scan(ctx context.Context, input domain.FileScanInput, now time.Time) domain.ScanResult {
	size := int64(len(input.Content))
	filename := input.Filename
	ext := strings.ToLower(filepath.Ext(filename))
	mimeType := inferMIMEType(filename, normalizeMIME(http.DetectContentType(input.Content)))
	hash := sha256.Sum256(input.Content)

	details := map[string]any{
		"filename":      filename,
		"extension":     ext,
		"size_bytes":    size,
		"mime_type":     mimeType,
		"sha256":        hex.EncodeToString(hash[:]),
		"malware_scan":  "skipped",
		"allowed_types": sortedKeys(s.allowedFileTypes),
	}

	if !s.enabled {
		return result(now, domain.StatusSkipped, "file_policy", "file_scan_disabled", "File scanning is disabled.", details)
	}

	if size == 0 {
		return result(now, domain.StatusError, "file_policy", "file_empty", "Uploaded file is empty.", details)
	}

	if s.maxFileSize > 0 && size > s.maxFileSize {
		return result(now, domain.StatusMalicious, "file_policy", "file_too_large", "Uploaded file exceeds the configured size limit.", details)
	}

	if _, ok := s.allowedFileTypes[mimeType]; !ok {
		return result(now, domain.StatusMalicious, "file_policy", "file_type_not_allowed", "Uploaded file type is not allowed.", details)
	}

	if s.malwareScanner == nil {
		details["malware_scan"] = "not_configured"
	} else {
		verdict, err := s.malwareScanner.Scan(ctx, filename, input.Content)
		if err != nil {
			details["malware_scan"] = "error"
			details["malware_scan_error"] = err.Error()
			if s.strict {
				return result(now, domain.StatusError, "clamav", "file_scan_error", "Malware scan failed.", details)
			}
		} else if verdict.Infected {
			details["malware_scan"] = "infected"
			details["threat"] = verdict.Threat
			return domain.ScanResult{
				Status:        domain.StatusMalicious,
				Scope:         domain.ScopeFile,
				PrimaryEngine: "clamav",
				CheckedAt:     now,
				Quarantined:   true,
				Escalation:    true,
				ReasonCode:    "file_malware_detected",
				Reason:        "Malware detected in uploaded file.",
				Details:       details,
			}
		}
		if details["malware_scan"] == "skipped" {
			details["malware_scan"] = "clean"
		}
	}

	return result(now, domain.StatusClean, "file_policy", "file_validated", "File passed validation checks.", details)
}

func result(now time.Time, status, engine, code, reason string, details map[string]any) domain.ScanResult {
	return domain.ScanResult{
		Status:        status,
		Scope:         domain.ScopeFile,
		PrimaryEngine: engine,
		CheckedAt:     now,
		Quarantined:   false,
		Escalation:    false,
		ReasonCode:    code,
		Reason:        reason,
		Details:       details,
	}
}

type ClamdScanner struct {
	addr string
}

func NewClamdScanner(addr string) *ClamdScanner {
	return &ClamdScanner{addr: addr}
}

func (c *ClamdScanner) Scan(ctx context.Context, filename string, content []byte) (Verdict, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return Verdict{}, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write([]byte("zINSTREAM\000")); err != nil {
		return Verdict{}, err
	}

	reader := bytes.NewReader(content)
	buffer := make([]byte, 32*1024)
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			header := []byte{
				byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
			}
			if _, err := conn.Write(header); err != nil {
				return Verdict{}, err
			}
			if _, err := conn.Write(buffer[:n]); err != nil {
				return Verdict{}, err
			}
		}
		if readErr != nil {
			break
		}
	}

	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return Verdict{}, err
	}

	reply := make([]byte, 4096)
	n, err := conn.Read(reply)
	if err != nil {
		return Verdict{}, err
	}

	response := string(reply[:n])
	switch {
	case strings.Contains(response, "FOUND"):
		threat := strings.TrimSpace(strings.TrimSuffix(strings.SplitN(response, "FOUND", 2)[0], ":"))
		return Verdict{Infected: true, Threat: threat}, nil
	case strings.Contains(response, "OK"):
		return Verdict{Clean: true}, nil
	default:
		return Verdict{}, fmt.Errorf("unexpected clamd response: %s", strings.TrimSpace(response))
	}
}

func sortedKeys(items map[string]struct{}) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	return keys
}

func normalizeMIME(value string) string {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(value))
	if err == nil && mediaType != "" {
		return strings.ToLower(mediaType)
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func inferMIMEType(filename, detected string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch {
	case detected == "application/zip" || detected == "application/octet-stream":
		switch ext {
		case ".docx":
			return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
		case ".pptx":
			return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
		case ".xlsx":
			return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
		}
	}
	return detected
}
