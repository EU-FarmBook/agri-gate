package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"agri-gate/internal/config"
	"agri-gate/internal/domain"
	"agri-gate/internal/jobs"
)

type Server struct {
	config  config.Config
	jobs    *jobs.Service
	logger  *log.Logger
	limiter *rateLimiter
}

func NewServer(cfg config.Config, jobsSvc *jobs.Service, logger *log.Logger) http.Handler {
	server := &Server{
		config:  cfg,
		jobs:    jobsSvc,
		logger:  logger,
		limiter: newRateLimiter(cfg.RateLimitRPM, time.Now),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleIndex)
	mux.HandleFunc("/v1/health", server.handleHealth)
	mux.HandleFunc("/v1/ready", server.handleReady)
	mux.HandleFunc("/v1/version", server.handleVersion)
	mux.HandleFunc("/v1/scan/url", server.handleScanURL)
	mux.HandleFunc("/v1/scan/file", server.handleScanFile)
	mux.HandleFunc("/v1/jobs/", server.handleGetJob)
	if cfg.EnableDebugRoutes {
		mux.HandleFunc("/debug/test", server.handleDebugTest)
	}

	var handler http.Handler = mux
	handler = server.withRateLimit(handler)
	handler = server.withAuth(handler)
	handler = server.withRequestID(handler)
	handler = server.withLogging(handler)
	return handler
}

type contextKey string

const requestIDKey contextKey = "request_id"

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service": "agri-gate",
		"version": s.config.AppVersion,
		"status":  "ok",
		"routes": map[string]string{
			"health":    "/v1/health",
			"ready":     "/v1/ready",
			"version":   "/v1/version",
			"scan_url":  "/v1/scan/url",
			"scan_file": "/v1/scan/file",
		},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "agri-gate",
		"env":     s.config.AppEnv,
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ready",
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.config.AppVersion,
	})
}

func (s *Server) handleScanURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	var req jobs.SubmitURLScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_json",
		})
		return
	}

	job, err := s.jobs.SubmitURLScan(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid_request",
			"message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, job.Result)
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	jobID := strings.TrimPrefix(r.URL.Path, "/v1/jobs/")
	if jobID == "" || strings.Contains(jobID, "/") {
		http.NotFound(w, r)
		return
	}

	job, ok := s.jobs.GetJob(r.Context(), jobID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "job_not_found",
		})
		return
	}

	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleScanFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxFileSizeBytes+1024*1024)
	if err := r.ParseMultipartForm(s.config.MaxFileSizeBytes + 1024*1024); err != nil {
		if isRequestTooLarge(err) {
			writeJSON(w, http.StatusRequestEntityTooLarge, domain.ScanResult{
				Status:        domain.StatusMalicious,
				Scope:         domain.ScopeFile,
				PrimaryEngine: "file_policy",
				CheckedAt:     s.config.Clock(),
				Quarantined:   false,
				Escalation:    false,
				ReasonCode:    "file_too_large",
				Reason:        "Uploaded file exceeds the configured size limit.",
				Details: map[string]any{
					"max_file_size_bytes": s.config.MaxFileSizeBytes,
				},
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid_multipart",
			"message": err.Error(),
		})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "missing_file",
			"message": "multipart field 'file' is required",
		})
		return
	}
	defer file.Close()

	content, err := io.ReadAll(io.LimitReader(file, s.config.MaxFileSizeBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "file_read_error",
			"message": err.Error(),
		})
		return
	}

	job, err := s.jobs.SubmitFileScan(r.Context(), domain.FileScanInput{
		Filename: header.Filename,
		Content:  content,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid_request",
			"message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, job.Result)
}

func (s *Server) handleDebugTest(w http.ResponseWriter, r *http.Request) {
	if !s.config.EnableDebugRoutes || r.URL.Path != "/debug/test" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, debugTestPage)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		s.logger.Printf("request_id=%s method=%s path=%s status=%d bytes=%d duration_ms=%d remote_ip=%s",
			requestIDFromContext(r.Context()),
			r.Method,
			r.URL.Path,
			recorder.status,
			recorder.bytes,
			time.Since(start).Milliseconds(),
			clientIP(r),
		)
	})
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := newRequestID()
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.APIAuthToken == "" || isPublicRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		if token := extractAuthToken(r); token == s.config.APIAuthToken {
			next.ServeHTTP(w, r)
			return
		}

		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "unauthorized",
		})
	})
}

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.limiter == nil || s.limiter.limit <= 0 || isPublicRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		if !s.limiter.Allow(clientIP(r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": "rate_limited",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	n, err := r.ResponseWriter.Write(p)
	r.bytes += n
	return n, err
}

type rateLimiter struct {
	limit int
	now   func() time.Time
	mu    sync.Mutex
	byIP  map[string]*rateBucket
}

type rateBucket struct {
	windowStart time.Time
	count       int
}

func newRateLimiter(limit int, now func() time.Time) *rateLimiter {
	if limit <= 0 {
		return &rateLimiter{limit: 0}
	}
	return &rateLimiter{
		limit: limit,
		now:   now,
		byIP:  make(map[string]*rateBucket),
	}
}

func (l *rateLimiter) Allow(ip string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}

	now := l.now().UTC()
	window := now.Truncate(time.Minute)

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.byIP[ip]
	if !ok || !bucket.windowStart.Equal(window) {
		l.byIP[ip] = &rateBucket{windowStart: window, count: 1}
		for key, value := range l.byIP {
			if value.windowStart.Before(window) {
				delete(l.byIP, key)
			}
		}
		return true
	}

	if bucket.count >= l.limit {
		return false
	}
	bucket.count++
	return true
}

func requestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(b[:])
}

func extractAuthToken(r *http.Request) string {
	if token := strings.TrimSpace(r.Header.Get("X-API-Key")); token != "" {
		return token
	}

	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func isPublicRoute(path string) bool {
	switch path {
	case "/", "/v1/health", "/v1/ready", "/v1/version":
		return true
	default:
		return false
	}
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if parsed, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return parsed.Addr().String()
	}
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		return host[:idx]
	}
	return host
}

func isRequestTooLarge(err error) bool {
	return errors.Is(err, http.ErrBodyReadAfterClose) || strings.Contains(strings.ToLower(err.Error()), "request body too large")
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
		"error": "method_not_allowed",
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

const debugTestPage = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Scan Console</title>
  <style>
    :root {
      --bg: #f4f1e8;
      --panel: #fffdf7;
      --text: #1f2a1f;
      --muted: #5f6b5f;
      --accent: #2f6b3b;
      --border: #d8d1c2;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      background: linear-gradient(180deg, #efe8d7 0%, var(--bg) 100%);
      color: var(--text);
    }
    main {
      max-width: 960px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }
    h1, h2 { margin: 0 0 12px; }
    p { color: var(--muted); line-height: 1.5; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 20px;
      margin-top: 24px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 20px;
      box-shadow: 0 10px 30px rgba(35, 30, 20, 0.06);
    }
    label {
      display: block;
      margin: 14px 0 6px;
      font-size: 14px;
      font-weight: 700;
    }
    input, button, textarea {
      width: 100%;
      font: inherit;
      border-radius: 12px;
    }
    input, textarea {
      padding: 12px 14px;
      border: 1px solid var(--border);
      background: #fff;
    }
    button {
      margin-top: 16px;
      padding: 12px 14px;
      border: 0;
      background: var(--accent);
      color: #fff;
      cursor: pointer;
    }
    button:disabled {
      opacity: 0.7;
      cursor: wait;
    }
    pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      background: #1e241f;
      color: #e8f0e8;
      padding: 16px;
      border-radius: 14px;
      min-height: 240px;
      overflow: auto;
    }
    .quick-links {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin: 18px 0 0;
    }
    .quick-links a {
      color: var(--accent);
      text-decoration: none;
      font-weight: 700;
    }
  </style>
</head>
<body>
  <main>
    <h1>Security Scan Console</h1>
    <p>Use this page for quick manual testing of the live API from your browser. It is a local debug surface intended for development environments.</p>
    <div class="quick-links">
      <a href="/v1/health" target="_blank" rel="noreferrer">Health</a>
      <a href="/v1/ready" target="_blank" rel="noreferrer">Ready</a>
      <a href="/v1/version" target="_blank" rel="noreferrer">Version</a>
    </div>

    <section class="card" style="margin-top: 20px;">
      <h2>Access Token</h2>
      <p>Optional. If API token protection is enabled, enter the token here to authorize scan requests from this page.</p>
      <label for="token-input">Bearer Token</label>
      <input id="token-input" type="password" placeholder="Paste API token if required">
    </section>

    <div class="grid">
      <section class="card">
        <h2>URL Scan</h2>
        <p>Submit a public HTTPS URL and inspect the JSON result.</p>
        <form id="url-form">
          <label for="url-input">URL</label>
          <input id="url-input" name="url" type="url" placeholder="https://example.org" required>
          <button id="url-submit" type="submit">Scan URL</button>
        </form>
      </section>

      <section class="card">
        <h2>File Scan</h2>
        <p>Upload a file and inspect the JSON result returned by the scanner.</p>
        <form id="file-form">
          <label for="file-input">File</label>
          <input id="file-input" name="file" type="file" required>
          <button id="file-submit" type="submit">Scan File</button>
        </form>
      </section>
    </div>

    <section class="card" style="margin-top: 20px;">
      <h2>Response</h2>
      <pre id="output">No request sent yet.</pre>
    </section>
  </main>

  <script>
    const output = document.getElementById("output");

    function render(value) {
      output.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
    }

    async function readJSON(response) {
      const text = await response.text();
      try {
        return JSON.parse(text);
      } catch (_) {
        return { status: response.status, body: text };
      }
    }

    document.getElementById("url-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = document.getElementById("url-submit");
      button.disabled = true;
      render("Scanning URL...");
      try {
        const url = document.getElementById("url-input").value;
        const token = document.getElementById("token-input").value.trim();
        const headers = { "Content-Type": "application/json" };
        if (token) {
          headers["Authorization"] = "Bearer " + token;
        }
        const response = await fetch("/v1/scan/url", {
          method: "POST",
          headers,
          body: JSON.stringify({ url })
        });
        render(await readJSON(response));
      } catch (error) {
        render({ error: String(error) });
      } finally {
        button.disabled = false;
      }
    });

    document.getElementById("file-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = document.getElementById("file-submit");
      const fileInput = document.getElementById("file-input");
      if (!fileInput.files.length) {
        render({ error: "Select a file first." });
        return;
      }
      button.disabled = true;
      render("Scanning file...");
      try {
        const formData = new FormData();
        formData.append("file", fileInput.files[0]);
        const token = document.getElementById("token-input").value.trim();
        const headers = {};
        if (token) {
          headers["Authorization"] = "Bearer " + token;
        }
        const response = await fetch("/v1/scan/file", {
          method: "POST",
          headers,
          body: formData
        });
        render(await readJSON(response));
      } catch (error) {
        render({ error: String(error) });
      } finally {
        button.disabled = false;
      }
    });
  </script>
</body>
</html>
`
