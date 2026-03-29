package filescan

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"net/http"
	"path"
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
	Enabled           bool
	Strict            bool
	MaxFileSizeBytes  int64
	AllowedFileTypes  []string
	MaxArchiveDepth   int
	MaxArchiveEntries int
	MaxExpandedBytes  int64
	ClamdAddr         string
}

type Scanner struct {
	enabled           bool
	strict            bool
	maxFileSize       int64
	maxArchiveDepth   int
	maxArchiveEntries int
	maxExpandedBytes  uint64
	allowedFileTypes  map[string]struct{}
	malwareScanner    MalwareScanner
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
		enabled:           cfg.Enabled,
		strict:            cfg.Strict,
		maxFileSize:       cfg.MaxFileSizeBytes,
		maxArchiveDepth:   max(1, cfg.MaxArchiveDepth),
		maxArchiveEntries: max(1, cfg.MaxArchiveEntries),
		maxExpandedBytes:  normalizeExpandedLimit(cfg.MaxExpandedBytes, cfg.MaxFileSizeBytes),
		allowedFileTypes:  allowed,
		malwareScanner:    malwareScanner,
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

	limits := inspectionLimits{
		MaxDepth:    s.maxArchiveDepth,
		MaxEntries:  s.maxArchiveEntries,
		MaxExpanded: s.maxExpandedBytes,
	}

	if inspection, blocked := inspectContainer(filename, mimeType, input.Content, limits); blocked {
		details["deep_inspection"] = inspection.Details
		return result(now, domain.StatusMalicious, inspection.Engine, inspection.Code, inspection.Reason, details)
	} else if inspection.Details != nil {
		details["deep_inspection"] = inspection.Details
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

type inspectionResult struct {
	Engine  string
	Code    string
	Reason  string
	Details map[string]any
}

type inspectionLimits struct {
	MaxDepth    int
	MaxEntries  int
	MaxExpanded uint64
}

type inspectionState struct {
	Entries  int
	Expanded uint64
}

func inspectContainer(filename, mimeType string, content []byte, limits inspectionLimits) (inspectionResult, bool) {
	ext := strings.ToLower(filepath.Ext(filename))
	switch {
	case mimeType == "application/pdf" || ext == ".pdf":
		return inspectPDF(content)
	case isOOXMLMime(mimeType) || isOOXMLExt(ext):
		return inspectOOXML(content, ext, limits)
	default:
		return inspectionResult{}, false
	}
}

func inspectPDF(content []byte) (inspectionResult, bool) {
	lower := bytes.ToLower(content)
	indicators := []struct {
		token string
		code  string
		text  string
	}{
		{token: "/javascript", code: "pdf_javascript_detected", text: "PDF contains JavaScript."},
		{token: "/js", code: "pdf_javascript_detected", text: "PDF contains JavaScript."},
		{token: "/openaction", code: "pdf_open_action_detected", text: "PDF contains an automatic open action."},
		{token: "/launch", code: "pdf_launch_action_detected", text: "PDF contains a launch action."},
		{token: "/embeddedfile", code: "pdf_embedded_file_detected", text: "PDF contains embedded files."},
		{token: "/richmedia", code: "pdf_rich_media_detected", text: "PDF contains rich media content."},
		{token: "/submitform", code: "pdf_submit_form_detected", text: "PDF contains form submission actions."},
		{token: "/importdata", code: "pdf_import_data_detected", text: "PDF contains data import actions."},
		{token: "/aa", code: "pdf_additional_actions_detected", text: "PDF contains additional actions."},
	}

	findings := make([]string, 0, len(indicators))
	for _, indicator := range indicators {
		if bytes.Contains(lower, []byte(indicator.token)) {
			findings = append(findings, indicator.code)
			return inspectionResult{
				Engine: "pdf_inspection",
				Code:   indicator.code,
				Reason: indicator.text,
				Details: map[string]any{
					"status":   "blocked",
					"format":   "pdf",
					"findings": findings,
				},
			}, true
		}
	}

	return inspectionResult{
		Details: map[string]any{
			"status":   "clean",
			"format":   "pdf",
			"findings": []string{},
		},
	}, false
}

func inspectOOXML(content []byte, ext string, limits inspectionLimits) (inspectionResult, bool) {
	readerAt := bytes.NewReader(content)
	zr, err := zip.NewReader(readerAt, int64(len(content)))
	if err != nil {
		return inspectionResult{
			Engine: "container_inspection",
			Code:   "file_invalid_container",
			Reason: "Office container is invalid or unreadable.",
			Details: map[string]any{
				"status": "blocked",
				"format": "ooxml",
				"error":  err.Error(),
			},
		}, true
	}

	state := &inspectionState{}
	findings := make([]string, 0, 4)
	var hasContentTypes bool
	var hasWordDir bool
	var hasExcelDir bool
	var hasPowerPointDir bool

	for _, file := range zr.File {
		name := normalizeZipEntryName(file.Name)
		state.Entries++
		state.Expanded += file.UncompressedSize64

		if state.Entries > limits.MaxEntries {
			findings = append(findings, "too_many_entries")
			return ooxmlBlocked("archive_limits_exceeded", "Office container has too many embedded entries.", findings, state), true
		}
		if state.Expanded > limits.MaxExpanded {
			findings = append(findings, "expanded_size_limit")
			return ooxmlBlocked("archive_limits_exceeded", "Office container expands beyond the configured inspection limit.", findings, state), true
		}

		switch {
		case name == "[content_types].xml":
			hasContentTypes = true
		case strings.HasPrefix(name, "word/"):
			hasWordDir = true
		case strings.HasPrefix(name, "xl/"):
			hasExcelDir = true
		case strings.HasPrefix(name, "ppt/"):
			hasPowerPointDir = true
		}

		if strings.Contains(name, "../") || strings.HasPrefix(name, "/") {
			findings = append(findings, "path_traversal_entry")
			return ooxmlBlocked("file_invalid_container", "Office container has unsafe entry paths.", findings, state), true
		}
		if isOOXMLMacroPath(name) {
			findings = append(findings, "macro_content")
			return ooxmlBlocked("office_macro_detected", "Office document contains macro content.", findings, state), true
		}
		if isOOXMLEmbeddedObjectPath(name) {
			findings = append(findings, "embedded_object")
			return ooxmlBlocked("office_embedded_object_detected", "Office document contains embedded objects or controls.", findings, state), true
		}
		if hasDangerousEmbeddedExtension(name) {
			findings = append(findings, "embedded_executable")
			return ooxmlBlocked("office_embedded_executable_detected", "Office document contains an embedded executable or scriptable payload.", findings, state), true
		}
		if shouldInspectNestedArchive(name, file) {
			data, err := readZipEntry(file, limits.MaxExpanded)
			if err != nil {
				findings = append(findings, "nested_archive_read_error")
				return ooxmlBlocked("file_invalid_container", "Embedded archive could not be inspected.", findings, state), true
			}
			if nested, blocked := inspectNestedArchive(name, data, 1, limits, state); blocked {
				return nested, true
			}
		}
	}

	if len(zr.File) == 0 {
		findings = append(findings, "empty_container")
		return ooxmlBlocked("file_invalid_container", "Office container is empty.", findings, state), true
	}

	if !hasContentTypes {
		findings = append(findings, "missing_content_types")
		return ooxmlBlocked("file_invalid_container", "Office container is missing required OOXML metadata.", findings, state), true
	}

	switch ext {
	case ".docx":
		if !hasWordDir {
			findings = append(findings, "missing_word_dir")
			return ooxmlBlocked("file_invalid_container", "Word document container is missing required word content.", findings, state), true
		}
	case ".xlsx":
		if !hasExcelDir {
			findings = append(findings, "missing_excel_dir")
			return ooxmlBlocked("file_invalid_container", "Excel document container is missing required workbook content.", findings, state), true
		}
	case ".pptx":
		if !hasPowerPointDir {
			findings = append(findings, "missing_powerpoint_dir")
			return ooxmlBlocked("file_invalid_container", "PowerPoint document container is missing required presentation content.", findings, state), true
		}
	}

	return inspectionResult{
		Details: map[string]any{
			"status":             "clean",
			"format":             "ooxml",
			"entries":            state.Entries,
			"uncompressed_bytes": state.Expanded,
			"findings":           []string{},
		},
	}, false
}

func ooxmlBlocked(code, reason string, findings []string, state *inspectionState) inspectionResult {
	return inspectionResult{
		Engine: "container_inspection",
		Code:   code,
		Reason: reason,
		Details: map[string]any{
			"status":             "blocked",
			"format":             "ooxml",
			"entries":            state.Entries,
			"uncompressed_bytes": state.Expanded,
			"findings":           findings,
		},
	}
}

func inspectNestedArchive(name string, content []byte, depth int, limits inspectionLimits, state *inspectionState) (inspectionResult, bool) {
	if depth >= limits.MaxDepth {
		return archiveBlocked("archive_limits_exceeded", "Nested archive depth exceeds the configured inspection limit.", []string{"max_depth_exceeded"}, name, depth+1, state), true
	}

	zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return inspectionResult{}, false
	}

	for _, file := range zr.File {
		entryName := normalizeZipEntryName(file.Name)
		state.Entries++
		state.Expanded += file.UncompressedSize64

		if state.Entries > limits.MaxEntries {
			return archiveBlocked("archive_limits_exceeded", "Nested archive has too many entries.", []string{"too_many_entries"}, entryName, depth+1, state), true
		}
		if state.Expanded > limits.MaxExpanded {
			return archiveBlocked("archive_limits_exceeded", "Nested archive expands beyond the configured inspection limit.", []string{"expanded_size_limit"}, entryName, depth+1, state), true
		}
		if strings.Contains(entryName, "../") || strings.HasPrefix(entryName, "/") {
			return archiveBlocked("file_invalid_container", "Nested archive has unsafe entry paths.", []string{"path_traversal_entry"}, entryName, depth+1, state), true
		}
		if hasDangerousEmbeddedExtension(entryName) {
			return archiveBlocked("nested_executable_detected", "Nested archive contains an executable or scriptable payload.", []string{"embedded_executable"}, entryName, depth+1, state), true
		}
		if shouldInspectNestedArchive(entryName, file) {
			data, err := readZipEntry(file, limits.MaxExpanded)
			if err != nil {
				return archiveBlocked("file_invalid_container", "Nested archive entry could not be inspected.", []string{"nested_archive_read_error"}, entryName, depth+1, state), true
			}
			if nested, blocked := inspectNestedArchive(entryName, data, depth+1, limits, state); blocked {
				return nested, true
			}
		}
	}

	return inspectionResult{}, false
}

func archiveBlocked(code, reason string, findings []string, entry string, depth int, state *inspectionState) inspectionResult {
	return inspectionResult{
		Engine: "container_inspection",
		Code:   code,
		Reason: reason,
		Details: map[string]any{
			"status":             "blocked",
			"format":             "archive",
			"entries":            state.Entries,
			"uncompressed_bytes": state.Expanded,
			"findings":           findings,
			"entry":              entry,
			"depth":              depth,
		},
	}
}

func isOOXMLMime(mimeType string) bool {
	switch mimeType {
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return true
	default:
		return false
	}
}

func isOOXMLExt(ext string) bool {
	switch ext {
	case ".docx", ".pptx", ".xlsx":
		return true
	default:
		return false
	}
}

func normalizeZipEntryName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.ToLower(path.Clean(name))
	name = strings.TrimPrefix(name, "./")
	return name
}

func isOOXMLMacroPath(name string) bool {
	return strings.HasSuffix(name, "vbaproject.bin") ||
		strings.Contains(name, "/macros/") ||
		strings.Contains(name, "customui/")
}

func isOOXMLEmbeddedObjectPath(name string) bool {
	return strings.Contains(name, "/embeddings/") ||
		strings.Contains(name, "/activeX/") ||
		strings.Contains(name, "/controls/") ||
		strings.Contains(name, "oleobject")
}

func hasDangerousEmbeddedExtension(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".exe", ".dll", ".msi", ".bat", ".cmd", ".com", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".scr", ".jar", ".apk", ".dmg", ".pkg", ".sh":
		return true
	default:
		return false
	}
}

func shouldInspectNestedArchive(name string, file *zip.File) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".zip", ".jar", ".apk":
		return true
	}
	return file.UncompressedSize64 >= 4
}

func readZipEntry(file *zip.File, maxExpanded uint64) ([]byte, error) {
	if file.UncompressedSize64 > maxExpanded {
		return nil, fmt.Errorf("zip entry exceeds inspection size limit")
	}

	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(rc); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func normalizeExpandedLimit(configured, fileSize int64) uint64 {
	if configured > 0 {
		return uint64(configured)
	}
	if fileSize > 0 {
		return uint64(fileSize) * 20
	}
	return 200 * 1024 * 1024
}
