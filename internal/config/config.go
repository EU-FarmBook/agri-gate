package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	AppEnv             string
	AppPort            string
	AppVersion         string
	MaxRedirects       int
	HTTPTimeout        time.Duration
	EnableHTMLExtract  bool
	Clock              func() time.Time
}

func Load() Config {
	return Config{
		AppEnv:            getEnv("APP_ENV", "development"),
		AppPort:           getEnv("APP_PORT", "8080"),
		AppVersion:        getEnv("APP_VERSION", "dev"),
		MaxRedirects:      getEnvInt("MAX_REDIRECTS", 5),
		HTTPTimeout:       time.Duration(getEnvInt("HTTP_TIMEOUT_SECONDS", 10)) * time.Second,
		EnableHTMLExtract: getEnvBool("ENABLE_HTML_EXTRACTION", false),
		Clock:             time.Now().UTC,
	}
}

func (c Config) ListenAddr() string {
	return ":" + c.AppPort
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
