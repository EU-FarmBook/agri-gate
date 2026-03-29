package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv            string
	AppPort           string
	AppVersion        string
	DatabaseURL       string
	APIAuthToken      string
	EnableDebugRoutes bool
	RateLimitRPM      int
	ClamdAddr         string
	FileScanEnabled   bool
	FileScanStrict    bool
	MaxFileSizeBytes  int64
	AllowedFileTypes  []string
	MaxArchiveDepth   int
	MaxArchiveEntries int
	MaxExpandedBytes  int64
	MaxRedirects      int
	HTTPTimeout       time.Duration
	Clock             func() time.Time
}

func Load() Config {
	appEnv := getEnv("APP_ENV", "development")

	return Config{
		AppEnv:            appEnv,
		AppPort:           getEnv("APP_PORT", "8900"),
		AppVersion:        getEnv("APP_VERSION", "dev"),
		DatabaseURL:       getEnv("DATABASE_URL", ""),
		APIAuthToken:      strings.TrimSpace(os.Getenv("API_AUTH_TOKEN")),
		EnableDebugRoutes: getEnvBool("ENABLE_DEBUG_ROUTES", appEnv == "development"),
		RateLimitRPM:      getEnvInt("RATE_LIMIT_RPM", 120),
		ClamdAddr:         getEnv("CLAMD_ADDR", ""),
		FileScanEnabled:   getEnvBool("FILE_SCAN_ENABLED", true),
		FileScanStrict:    getEnvBool("FILE_SCAN_STRICT", false),
		MaxFileSizeBytes:  getEnvInt64("MAX_FILE_SIZE_BYTES", 1024*1024*1024),
		AllowedFileTypes: getEnvCSV("ALLOWED_FILE_TYPES", []string{
			"application/pdf",
			"text/plain",
			"text/csv",
			"text/tab-separated-values",
			"application/msword",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			"application/vnd.ms-powerpoint",
			"application/vnd.openxmlformats-officedocument.presentationml.presentation",
			"application/vnd.ms-excel",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			"image/jpeg",
			"image/png",
			"audio/mpeg",
			"audio/wav",
			"audio/x-wav",
			"audio/mp4",
			"audio/x-m4a",
			"video/mp4",
			"video/x-msvideo",
			"video/quicktime",
			"video/x-ms-wmv",
			"video/mpeg",
			"video/x-matroska",
			"video/x-flv",
			"video/webm",
			"video/3gpp",
			"video/mp2t",
			"video/dvd",
		}),
		MaxArchiveDepth:   getEnvInt("MAX_ARCHIVE_DEPTH", 3),
		MaxArchiveEntries: getEnvInt("MAX_ARCHIVE_ENTRIES", 2048),
		MaxExpandedBytes:  getEnvInt64("MAX_EXPANDED_BYTES", 200*1024*1024),
		MaxRedirects:      getEnvInt("MAX_REDIRECTS", 5),
		HTTPTimeout:       time.Duration(getEnvInt("HTTP_TIMEOUT_SECONDS", 10)) * time.Second,
		Clock:             time.Now().UTC,
	}
}

func (c Config) ListenAddr() string {
	return ":" + c.AppPort
}

func (c Config) Validate() error {
	if _, err := strconv.Atoi(c.AppPort); err != nil {
		return fmt.Errorf("APP_PORT must be numeric")
	}
	if c.HTTPTimeout <= 0 {
		return fmt.Errorf("HTTP_TIMEOUT_SECONDS must be greater than zero")
	}
	if c.MaxFileSizeBytes <= 0 {
		return fmt.Errorf("MAX_FILE_SIZE_BYTES must be greater than zero")
	}
	if c.MaxArchiveDepth <= 0 {
		return fmt.Errorf("MAX_ARCHIVE_DEPTH must be greater than zero")
	}
	if c.MaxArchiveEntries <= 0 {
		return fmt.Errorf("MAX_ARCHIVE_ENTRIES must be greater than zero")
	}
	if c.MaxExpandedBytes <= 0 {
		return fmt.Errorf("MAX_EXPANDED_BYTES must be greater than zero")
	}
	if c.MaxRedirects <= 0 {
		return fmt.Errorf("MAX_REDIRECTS must be greater than zero")
	}
	if c.RateLimitRPM < 0 {
		return fmt.Errorf("RATE_LIMIT_RPM cannot be negative")
	}
	if len(c.AllowedFileTypes) == 0 {
		return fmt.Errorf("ALLOWED_FILE_TYPES must not be empty")
	}
	return nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvInt64(key string, fallback int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvCSV(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			items = append(items, part)
		}
	}
	if len(items) == 0 {
		return fallback
	}
	return items
}
