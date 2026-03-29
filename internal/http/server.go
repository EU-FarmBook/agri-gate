package httpapi

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"agri-gate/internal/config"
	"agri-gate/internal/domain"
	"agri-gate/internal/jobs"
)

type Server struct {
	config config.Config
	jobs   *jobs.Service
	logger *log.Logger
}

func NewServer(cfg config.Config, jobsSvc *jobs.Service, logger *log.Logger) http.Handler {
	server := &Server{
		config: cfg,
		jobs:   jobsSvc,
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", server.handleHealth)
	mux.HandleFunc("/v1/ready", server.handleReady)
	mux.HandleFunc("/v1/version", server.handleVersion)
	mux.HandleFunc("/v1/scan/url", server.handleScanURL)
	mux.HandleFunc("/v1/scan/file", server.handleScanFile)
	mux.HandleFunc("/v1/jobs/", server.handleGetJob)
	mux.HandleFunc("/debug/test", server.handleDebugTest)

	return server.withLogging(mux)
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
		s.logger.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
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
  <title>Agri Gate Test Page</title>
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
    <h1>Agri Gate Test Page</h1>
    <p>Use this page for quick manual testing of the live API from your browser. It is a local debug surface, not a production UI.</p>
    <div class="quick-links">
      <a href="/v1/health" target="_blank" rel="noreferrer">Health</a>
      <a href="/v1/ready" target="_blank" rel="noreferrer">Ready</a>
      <a href="/v1/version" target="_blank" rel="noreferrer">Version</a>
    </div>

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
        const response = await fetch("/v1/scan/url", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
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
        const response = await fetch("/v1/scan/file", {
          method: "POST",
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
