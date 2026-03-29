package urlscan

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"agri-gate/internal/domain"
)

type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Scan(_ context.Context, rawURL string, now time.Time) domain.ScanResult {
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

	if unsafeHost(host) {
		return result(now, domain.StatusMalicious, "url_validator", "url_unsafe_host", "The URL resolves to a blocked or internal host.", map[string]any{
			"input_url": input,
			"host":      host,
		})
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

	return result(now, domain.StatusClean, "url_validator", "url_validated", "URL passed deterministic validation.", map[string]any{
		"input_url":          input,
		"final_url":          input,
		"reachable":          nil,
		"secure_transport":   true,
		"dangerous_download": false,
		"agri_relevance":     agriRelevance(parsed),
	})
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

func unsafeHost(host string) bool {
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") {
		return true
	}

	if ip, err := netip.ParseAddr(lowerHost); err == nil {
		return blockedIP(ip)
	}

	ips, err := net.LookupIP(lowerHost)
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
