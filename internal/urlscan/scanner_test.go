package urlscan

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestScanRejectsDangerousDownloadByPath(t *testing.T) {
	scanner := NewScanner()

	result := scanner.Scan(context.Background(), "https://example.com/file.exe", time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "url_dangerous_download" {
		t.Fatalf("expected dangerous download reason, got %q", result.ReasonCode)
	}
}

func TestScanAcceptsFetchedHTTPSURL(t *testing.T) {
	server := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer server.Close()

	scanner, targetURL := newTestScanner(t, server, 5, 2*time.Second)

	result := scanner.Scan(context.Background(), targetURL+"/agriculture", time.Now().UTC())
	if result.Status != domain.StatusClean {
		t.Fatalf("expected clean status, got %q", result.Status)
	}
	if result.PrimaryEngine != "url_fetch" {
		t.Fatalf("expected url_fetch primary engine, got %q", result.PrimaryEngine)
	}
}

func TestScanRejectsDangerousDownloadByResponseHeaders(t *testing.T) {
	server := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=archive.zip")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner, targetURL := newTestScanner(t, server, 5, 2*time.Second)

	result := scanner.Scan(context.Background(), targetURL+"/download", time.Now().UTC())
	if result.Status != domain.StatusMalicious {
		t.Fatalf("expected malicious status, got %q", result.Status)
	}
	if result.ReasonCode != "url_dangerous_download" {
		t.Fatalf("expected dangerous download reason, got %q", result.ReasonCode)
	}
}

func TestScanRejectsTooManyRedirects(t *testing.T) {
	server := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer server.Close()

	scanner, targetURL := newTestScanner(t, server, 1, 2*time.Second)

	result := scanner.Scan(context.Background(), targetURL, time.Now().UTC())
	if result.Status != domain.StatusError {
		t.Fatalf("expected error status, got %q", result.Status)
	}
	if result.ReasonCode != "url_too_many_redirects" {
		t.Fatalf("expected too many redirects reason, got %q", result.ReasonCode)
	}
}

func TestScanClassifiesHTTPErrorResponses(t *testing.T) {
	server := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	scanner, targetURL := newTestScanner(t, server, 5, 2*time.Second)

	result := scanner.Scan(context.Background(), targetURL+"/missing", time.Now().UTC())
	if result.Status != domain.StatusError {
		t.Fatalf("expected error status, got %q", result.Status)
	}
	if result.ReasonCode != "url_http_error" {
		t.Fatalf("expected HTTP error reason, got %q", result.ReasonCode)
	}
}

func newTLSServer(handler http.Handler) *httptest.Server {
	server := httptest.NewTLSServer(handler)
	return server
}

func newTestScanner(t *testing.T, server *httptest.Server, maxRedirects int, timeout time.Duration) (*Scanner, string) {
	t.Helper()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	targetHost := "example.test"
	targetURL := "https://" + targetHost
	dialAddress := serverURL.Host

	scanner := NewScannerWithConfig(Config{
		MaxRedirects: maxRedirects,
		Timeout:      timeout,
	})

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == targetHost+":443" {
				addr = dialAddress
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, addr)
		},
	}
	scanner.client = &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	scanner.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= scanner.maxRedirects {
			return errTooManyRedirects
		}
		if err := validateParsedURL(req.Context(), req.URL, scanner.lookupIP); err != nil {
			return err
		}
		return nil
	}
	scanner.lookupIP = func(context.Context, string) ([]net.IP, error) {
		return nil, nil
	}
	return scanner, targetURL
}
