package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	// Database
	PostgresHost     string
	PostgresPort     int
	PostgresUser     string
	PostgresPassword string
	PostgresDB       string

	// Server
	BackendPort int
	LogLevel    string

	// CORS (when set, AllowCredentials is true; required for cookie-based auth)
	CORSOrigins string // comma-separated, e.g. "http://localhost:3000,https://vultrack.example.com"

	// Triage
	TriageCVSSThreshold float64

	// OIDC (optional; when disabled, no user auth is required)
	OIDCEnabled      bool
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCScopes       string // default: "openid profile email"
	OIDCFrontendURL  string // redirect after login, e.g. http://localhost:3000

	// Scan queue
	ScanWorkers    int
	ScanTimeoutSec int
	ScanMaxRetries int
	ScanQueueSize  int

	// Jira (optional; when disabled, no tickets are created)
	JiraEnabled    bool
	JiraBaseURL    string
	JiraUserEmail  string
	JiraAPIToken   string
	JiraProjectKey string
	JiraIssueType  string

	// Agent JWT signing secret for v2 API (HS256).
	// If empty, a random secret is generated on startup — tokens will be invalidated on restart.
	JWTSecret string

	// SMTP (optional; when disabled, no emails are sent)
	SMTPEnabled  bool
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string // empty = unauthenticated
	SMTPPassword string
	SMTPFrom     string // sender address, e.g. "VulTrack <vultrack@example.com>"
	SMTPTLSMode  string // "none", "starttls", "tls"
	SMTPHeloHost string // EHLO hostname (default: OS hostname; "localhost" is rejected by many relays)

	// AI assessment (optional; the feature is inactive when no API key is set).
	// The API key is intentionally ENV-only and never exposed via the admin UI.
	AIAPIKey         string // ANTHROPIC_API_KEY
	AIWorkers        int    // number of concurrent AI assessment workers
	AIMaxRetries     int    // retries per assessment on transient errors
	AIRequestTimeout int    // per-request timeout in seconds
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if it exists (ignore error if not found)
	// Try current directory first, then parent directory
	if err := godotenv.Load(); err != nil {
		_ = godotenv.Load("../.env")
	}

	cfg := &Config{
		// Database defaults
		PostgresHost:     getEnv("POSTGRES_HOST", "localhost"),
		PostgresPort:     getEnvAsInt("POSTGRES_PORT", 5432),
		PostgresUser:     getEnv("POSTGRES_USER", "vultrack"),
		PostgresPassword: getEnv("POSTGRES_PASSWORD", "vultrack"),
		PostgresDB:       getEnv("POSTGRES_DB", "vultrack"),

		// Server defaults
		BackendPort: getEnvAsInt("BACKEND_PORT", 8080),
		LogLevel:    getEnv("LOG_LEVEL", "debug"),

		// CORS (empty = allow all origins without credentials)
		CORSOrigins: getEnv("CORS_ORIGINS", ""),

		// Triage defaults
		TriageCVSSThreshold: getEnvAsFloat("TRIAGE_CVSS_THRESHOLD", 7.0),

		// OIDC defaults (disabled; no user auth when false)
		OIDCEnabled:      getEnvAsBool("OIDC_ENABLED", false),
		OIDCIssuer:       getEnv("OIDC_ISSUER", ""),
		OIDCClientID:     getEnv("OIDC_CLIENT_ID", ""),
		OIDCClientSecret: getEnv("OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:  getEnv("OIDC_REDIRECT_URL", ""),
		OIDCScopes:       getEnv("OIDC_SCOPES", "openid profile email"),
		OIDCFrontendURL:  getEnv("OIDC_FRONTEND_URL", "/"),

		// Scan queue defaults
		ScanWorkers:    getEnvAsInt("SCAN_WORKERS", 5),
		ScanTimeoutSec: getEnvAsInt("SCAN_TIMEOUT", 600), // 10 minutes
		ScanMaxRetries: getEnvAsInt("SCAN_MAX_RETRIES", 3),
		ScanQueueSize:  getEnvAsInt("SCAN_QUEUE_SIZE", 500),

		// Jira defaults (disabled)
		JiraEnabled:    getEnvAsBool("JIRA_ENABLED", false),
		JiraBaseURL:    getEnv("JIRA_BASE_URL", ""),
		JiraUserEmail:  getEnv("JIRA_USER_EMAIL", ""),
		JiraAPIToken:   getEnv("JIRA_API_TOKEN", ""),
		JiraProjectKey: getEnv("JIRA_PROJECT_KEY", ""),
		JiraIssueType:  getEnv("JIRA_ISSUE_TYPE", "Task"),

		// Agent JWT secret
		JWTSecret: getEnv("JWT_SECRET", ""),

		// SMTP defaults (disabled)
		SMTPEnabled:  getEnvAsBool("SMTP_ENABLED", false),
		SMTPHost:     getEnv("SMTP_HOST", ""),
		SMTPPort:     getEnvAsInt("SMTP_PORT", 587),
		SMTPUser:     getEnv("SMTP_USER", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:     getEnv("SMTP_FROM", ""),
		SMTPTLSMode:  getEnv("SMTP_TLS", "starttls"),
		SMTPHeloHost: getEnv("SMTP_HELO_HOST", ""),

		// AI assessment defaults (disabled until ANTHROPIC_API_KEY is set)
		AIAPIKey:         getEnv("ANTHROPIC_API_KEY", ""),
		AIWorkers:        getEnvAsInt("AI_ASSESSMENT_WORKERS", 2),
		AIMaxRetries:     getEnvAsInt("AI_ASSESSMENT_MAX_RETRIES", 2),
		AIRequestTimeout: getEnvAsInt("AI_ASSESSMENT_TIMEOUT", 60),
	}

	return cfg, nil
}

// AIConfigured reports whether the AI assessment feature has the credentials it
// needs to run. When false, the feature stays inactive and the admin UI shows a
// warning that ANTHROPIC_API_KEY is not set.
func (c *Config) AIConfigured() bool {
	return c.AIAPIKey != ""
}

// DatabaseURL returns the PostgreSQL connection string
func (c *Config) DatabaseURL() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=disable",
		c.PostgresUser,
		c.PostgresPassword,
		c.PostgresHost,
		c.PostgresPort,
		c.PostgresDB,
	)
}

// Helper functions to read environment variables with defaults

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getEnvAsFloat(key string, defaultValue float64) float64 {
	if value, exists := os.LookupEnv(key); exists {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}
	return defaultValue
}
