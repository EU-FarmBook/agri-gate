package urlscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"agri-gate/internal/domain"
)

var errTooManyRedirects = errors.New("too many redirects")

type lookupIPFunc func(context.Context, string) ([]net.IP, error)

type Scanner struct {
	client       *http.Client
	maxRedirects int
	timeout      time.Duration
	lookupIP     lookupIPFunc
}

type Config struct {
	MaxRedirects int
	Timeout      time.Duration
}

func NewScanner() *Scanner {
	return NewScannerWithConfig(Config{
		MaxRedirects: 5,
		Timeout:      10 * time.Second,
	})
}

func NewScannerWithConfig(cfg Config) *Scanner {
	if cfg.MaxRedirects <= 0 {
		cfg.MaxRedirects = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	scanner := &Scanner{
		maxRedirects: cfg.MaxRedirects,
		timeout:      cfg.Timeout,
		lookupIP:     defaultLookupIP,
	}
	scanner.client = &http.Client{
		Timeout: scanner.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= scanner.maxRedirects {
				return errTooManyRedirects
			}
			if err := validateParsedURL(req.Context(), req.URL, scanner.lookupIP); err != nil {
				return err
			}
			return nil
		},
	}

	return scanner
}

func (s *Scanner) Scan(ctx context.Context, rawURL string, now time.Time) domain.ScanResult {
	input := strings.TrimSpace(rawURL)

	parsed, err := url.Parse(input)
	if err != nil {
		return result(now, domain.StatusError, "url_validator", "url_invalid", "URL could not be parsed.", map[string]any{
			"input_url": input,
		})
	}

	if parsed.Scheme != "https" {
		return result(now, domain.StatusMalicious, "url_validator", "url_insecure_scheme", "Only HTTPS URLs are allowed.", map[string]any{
			"input_url": input,
			"scheme":    parsed.Scheme,
		})
	}

	if parsed.User != nil {
		return result(now, domain.StatusMalicious, "url_validator", "url_embedded_credentials", "Embedded URL credentials are not allowed.", map[string]any{
			"input_url": input,
		})
	}

	host := parsed.Hostname()
	if host == "" {
		return result(now, domain.StatusError, "url_validator", "url_missing_host", "URL host is required.", map[string]any{
			"input_url": input,
		})
	}

	if err := validateParsedURL(ctx, parsed, s.lookupIP); err != nil {
		return blockedURLResult(now, input, parsed, err)
	}

	if dangerousDownload(parsed) {
		return result(now, domain.StatusMalicious, "url_policy", "url_dangerous_download", "The URL looks like a direct download of a blocked file type.", map[string]any{
			"input_url":          input,
			"final_url":          input,
			"dangerous_download": true,
			"content_type":       "unknown",
			"agri_relevance":     agriRelevance(parsed),
		})
	}

	resp, err := s.fetch(ctx, parsed)
	if err != nil {
		return requestErrorResult(now, input, parsed, err)
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 1)

	finalURL := resp.Request.URL
	if err := validateParsedURL(ctx, finalURL, s.lookupIP); err != nil {
		return blockedURLResult(now, input, finalURL, err)
	}

	detection := detectDownloadRisk(finalURL, resp.Header)
	details := map[string]any{
		"input_url":           input,
		"final_url":           finalURL.String(),
		"reachable":           true,
		"secure_transport":    finalURL.Scheme == "https",
		"dangerous_download":  detection.Dangerous,
		"content_type":        headerValue(resp.Header, "Content-Type"),
		"content_disposition": headerValue(resp.Header, "Content-Disposition"),
		"status_code":         resp.StatusCode,
		"agri_relevance":      agriRelevance(finalURL),
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return result(now, domain.StatusError, "url_fetch", "url_http_error", fmt.Sprintf("URL returned HTTP %d.", resp.StatusCode), details)
	}

	if detection.Dangerous {
		return result(now, domain.StatusMalicious, "url_fetch", "url_dangerous_download", detection.Reason, details)
	}

	return result(now, domain.StatusClean, "url_fetch", "url_validated", "URL passed validation and live fetch checks.", details)
}

func result(now time.Time, status, engine, reasonCode, reason string, details map[string]any) domain.ScanResult {
	return domain.ScanResult{
		Status:        status,
		Scope:         domain.ScopeURL,
		PrimaryEngine: engine,
		CheckedAt:     now,
		Quarantined:   false,
		Escalation:    false,
		ReasonCode:    reasonCode,
		Reason:        reason,
		Details:       details,
	}
}

func validateParsedURL(ctx context.Context, parsed *url.URL, lookupIP lookupIPFunc) error {
	if parsed == nil {
		return errors.New("missing_url")
	}
	if parsed.Scheme != "https" {
		return errors.New("insecure_scheme")
	}
	if parsed.User != nil {
		return errors.New("embedded_credentials")
	}
	host := parsed.Hostname()
	if host == "" {
		return errors.New("missing_host")
	}
	if unsafeHost(ctx, host, lookupIP) {
		return errors.New("unsafe_host")
	}
	return nil
}

func unsafeHost(ctx context.Context, host string, lookupIP lookupIPFunc) bool {
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") {
		return true
	}

	if ip, err := netip.ParseAddr(lowerHost); err == nil {
		return blockedIP(ip)
	}

	ips, err := lookupIP(ctx, lowerHost)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok && blockedIP(addr) {
			return true
		}
	}

	return false
}

func defaultLookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func blockedIP(ip netip.Addr) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

func dangerousDownload(parsed *url.URL) bool {
	ext := strings.ToLower(path.Ext(parsed.Path))
	switch ext {
	case ".exe", ".msi", ".apk", ".dmg", ".pkg", ".jar", ".bat", ".cmd", ".ps1", ".sh", ".js", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso":
		return true
	default:
		return false
	}
}

type downloadDetection struct {
	Dangerous bool
	Reason    string
}

func detectDownloadRisk(parsed *url.URL, header http.Header) downloadDetection {
	contentDisposition := strings.ToLower(headerValue(header, "Content-Disposition"))
	if strings.Contains(contentDisposition, "attachment") {
		return downloadDetection{
			Dangerous: true,
			Reason:    "The URL resolved to an attachment download.",
		}
	}

	if dangerousDownload(parsed) {
		return downloadDetection{
			Dangerous: true,
			Reason:    "The URL resolved to a blocked file type.",
		}
	}

	contentType := strings.ToLower(headerValue(header, "Content-Type"))
	for _, blocked := range []string{
		"application/octet-stream",
		"application/x-msdownload",
		"application/x-dosexec",
		"application/x-ms-installer",
		"application/x-apple-diskimage",
		"application/java-archive",
		"application/zip",
		"application/x-rar-compressed",
		"application/x-7z-compressed",
		"application/x-tar",
		"application/gzip",
		"application/x-bzip2",
		"application/x-xz",
		"application/x-iso9660-image",
		"application/x-sh",
		"text/javascript",
		"application/javascript",
	} {
		if strings.Contains(contentType, blocked) {
			return downloadDetection{
				Dangerous: true,
				Reason:    "The URL resolved to a blocked content type.",
			}
		}
	}

	return downloadDetection{}
}

func headerValue(header http.Header, key string) string {
	return strings.TrimSpace(header.Get(key))
}

func blockedURLResult(now time.Time, input string, parsed *url.URL, err error) domain.ScanResult {
	code := "url_invalid"
	reason := "URL validation failed."
	details := map[string]any{"input_url": input}
	if parsed != nil {
		details["final_url"] = parsed.String()
		details["host"] = parsed.Hostname()
	}

	switch err.Error() {
	case "insecure_scheme":
		code = "url_insecure_scheme"
		reason = "Only HTTPS URLs are allowed."
	case "embedded_credentials":
		code = "url_embedded_credentials"
		reason = "Embedded URL credentials are not allowed."
	case "missing_host":
		code = "url_missing_host"
		reason = "URL host is required."
	case "unsafe_host":
		code = "url_unsafe_host"
		reason = "The URL resolves to a blocked or internal host."
	}

	return result(now, domain.StatusMalicious, "url_validator", code, reason, details)
}

func requestErrorResult(now time.Time, input string, parsed *url.URL, err error) domain.ScanResult {
	details := map[string]any{
		"input_url": input,
	}
	if parsed != nil {
		details["final_url"] = parsed.String()
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return result(now, domain.StatusError, "url_fetch", "url_timeout", "URL fetch timed out.", details)
	}
	if errors.Is(err, errTooManyRedirects) {
		return result(now, domain.StatusError, "url_fetch", "url_too_many_redirects", "URL exceeded the maximum redirect depth.", details)
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		switch {
		case errors.Is(urlErr.Err, errTooManyRedirects):
			return result(now, domain.StatusError, "url_fetch", "url_too_many_redirects", "URL exceeded the maximum redirect depth.", details)
		case errors.Is(urlErr.Err, context.DeadlineExceeded):
			return result(now, domain.StatusError, "url_fetch", "url_timeout", "URL fetch timed out.", details)
		default:
			return result(now, domain.StatusError, "url_fetch", "url_unreachable", "URL could not be reached.", details)
		}
	}

	return result(now, domain.StatusError, "url_fetch", "url_unreachable", "URL could not be reached.", details)
}

func (s *Scanner) fetch(ctx context.Context, parsed *url.URL) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func agriRelevance(parsed *url.URL) map[string]any {
	text := strings.ToLower(parsed.Hostname() + " " + parsed.Path)
	terms := []string{
		"agri", "agro", "farm", "farming", "crop", "soil", "livestock", "irrigation", "tractor", "seed", "fao", "agriculture",
	}

	matches := make([]string, 0, 4)
	for _, term := range terms {
		if strings.Contains(text, term) {
			matches = append(matches, term)
		}
	}

	score := 0.05
	if len(matches) > 0 {
		score = 0.2 + (float64(len(matches)) * 0.12)
		if score > 0.99 {
			score = 0.99
		}
	}

	status := "non_agri"
	explanation := "No agriculture-related terms were matched."
	if len(matches) > 0 {
		status = "agri_relevant"
		explanation = "Matched agriculture-related terms in the URL."
	}

	return map[string]any{
		"status":        status,
		"score":         score,
		"matched_terms": matches,
		"explanation":   explanation,
	}
}
