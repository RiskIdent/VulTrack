package services

import (
	"context"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// SettingsService handles application settings
type SettingsService struct {
	db *pgxpool.Pool
}

// NewSettingsService creates a new SettingsService
func NewSettingsService(db *pgxpool.Pool) *SettingsService {
	return &SettingsService{db: db}
}

// DB returns the database pool (for use by handlers that need direct queries)
func (s *SettingsService) DB() *pgxpool.Pool {
	return s.db
}

// GetAll returns all settings
func (s *SettingsService) GetAll(ctx context.Context) ([]models.Setting, error) {
	query := `
		SELECT key, value, COALESCE(description, ''), updated_at
		FROM settings
		ORDER BY key
	`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var settings []models.Setting
	for rows.Next() {
		var setting models.Setting
		err := rows.Scan(&setting.Key, &setting.Value, &setting.Description, &setting.UpdatedAt)
		if err != nil {
			return nil, err
		}
		settings = append(settings, setting)
	}

	return settings, nil
}

// Get returns a single setting by key
func (s *SettingsService) Get(ctx context.Context, key string) (*models.Setting, error) {
	query := `
		SELECT key, value, COALESCE(description, ''), updated_at
		FROM settings
		WHERE key = $1
	`

	var setting models.Setting
	err := s.db.QueryRow(ctx, query, key).Scan(
		&setting.Key, &setting.Value, &setting.Description, &setting.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &setting, nil
}

// GetValue returns just the value of a setting
func (s *SettingsService) GetValue(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

// GetFloat returns a setting value as float64
func (s *SettingsService) GetFloat(ctx context.Context, key string) (float64, error) {
	value, err := s.GetValue(ctx, key)
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(value, 64)
}

// GetBool returns a setting value as bool
func (s *SettingsService) GetBool(ctx context.Context, key string) (bool, error) {
	value, err := s.GetValue(ctx, key)
	if err != nil {
		return false, err
	}
	return strconv.ParseBool(value)
}

// Set updates or creates a setting
func (s *SettingsService) Set(ctx context.Context, key, value string) error {
	query := `
		INSERT INTO settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key)
		DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
	`
	_, err := s.db.Exec(ctx, query, key, value)
	return err
}

// SetMultiple updates multiple settings at once
func (s *SettingsService) SetMultiple(ctx context.Context, settings map[string]string) error {
	for key, value := range settings {
		if err := s.Set(ctx, key, value); err != nil {
			return err
		}
	}
	return nil
}

// GetIntWithDefault returns a setting as int, falling back to defaultValue on any error.
func (s *SettingsService) GetIntWithDefault(ctx context.Context, key string, defaultValue int) int {
	value, err := s.GetValue(ctx, key)
	if err != nil {
		return defaultValue
	}
	intVal, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return intVal
}

// GetTriageCVSSThreshold returns the configured CVSS threshold for triage
func (s *SettingsService) GetTriageCVSSThreshold(ctx context.Context) (float64, error) {
	threshold, err := s.GetFloat(ctx, "triage_cvss_threshold")
	if err != nil {
		return 7.0, nil // Default value
	}
	return threshold, nil
}

// BuildTriageOptions assembles the triage-queue filter from the configured
// settings (filter mode, vendor severities / CVSS threshold, include-unrated).
// It is the single source of truth shared by the REST API and the MCP interface
// so both produce exactly the same triage queue, including the VEX
// "not affected" filter. Limit/Offset are left zero for the caller to set.
func (s *SettingsService) BuildTriageOptions(ctx context.Context) (TriageFilterOptions, error) {
	mode, _ := s.GetValue(ctx, "triage_filter_mode")
	if mode == "" {
		mode = "cvss"
	}

	opts := TriageFilterOptions{Mode: mode}

	// Hide VEX 'not affected' findings unless explicitly disabled in settings.
	// Mirrors the UI, which treats settings['triage_hide_vex_not_affected'] !== 'false'.
	hideVex, _ := s.GetValue(ctx, "triage_hide_vex_not_affected")
	opts.HideVexNotAffected = hideVex != "false"

	if mode == "vendor_severity" {
		severitiesStr, _ := s.GetValue(ctx, "triage_vendor_severities")
		if severitiesStr == "" {
			severitiesStr = "critical,high"
		}
		severities := strings.Split(severitiesStr, ",")
		for i := range severities {
			severities[i] = strings.TrimSpace(strings.ToLower(severities[i]))
		}
		opts.VendorSeverities = severities

		includeUnrated, _ := s.GetValue(ctx, "triage_include_unrated")
		opts.IncludeUnrated = includeUnrated == "true"
	} else {
		threshold, _ := s.GetTriageCVSSThreshold(ctx)
		opts.CVSSThreshold = threshold
	}

	return opts, nil
}

// ResetResult contains the counts of deleted records
type ResetResult struct {
	ServersDeleted        int
	FindingsDeleted       int
	AssessmentsDeleted    int
	ServerGroupsDeleted   int
	AgentsDeleted         int
	EnrollmentKeysDeleted int
}

// ResetSystem clears all operational data while preserving vulnerability data sources
// Tables preserved: oval_*, cve_catalog, cve_references, exploits, sync_status, settings, reason_templates, users
// Tables cleared: servers (cascade: findings, server_packages), assessments, server_groups, enrollment_keys, registered_agents
func (s *SettingsService) ResetSystem(ctx context.Context) (*ResetResult, error) {
	result := &ResetResult{}

	// Start a transaction
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Count records before deletion for reporting
	tx.QueryRow(ctx, `SELECT COUNT(*) FROM servers`).Scan(&result.ServersDeleted)
	tx.QueryRow(ctx, `SELECT COUNT(*) FROM findings`).Scan(&result.FindingsDeleted)
	tx.QueryRow(ctx, `SELECT COUNT(*) FROM assessments`).Scan(&result.AssessmentsDeleted)
	tx.QueryRow(ctx, `SELECT COUNT(*) FROM server_groups`).Scan(&result.ServerGroupsDeleted)
	tx.QueryRow(ctx, `SELECT COUNT(*) FROM registered_agents`).Scan(&result.AgentsDeleted)
	tx.QueryRow(ctx, `SELECT COUNT(*) FROM enrollment_keys`).Scan(&result.EnrollmentKeysDeleted)

	// Delete in order respecting foreign key constraints
	// server_group_members will cascade from servers and server_groups
	// findings and server_packages will cascade from servers

	// 1. Delete registered agents (references servers and enrollment_keys)
	_, err = tx.Exec(ctx, `DELETE FROM registered_agents`)
	if err != nil {
		return nil, err
	}

	// 2. Delete enrollment keys
	_, err = tx.Exec(ctx, `DELETE FROM enrollment_keys`)
	if err != nil {
		return nil, err
	}

	// 3. Delete assessments
	_, err = tx.Exec(ctx, `DELETE FROM assessments`)
	if err != nil {
		return nil, err
	}

	// 4. Delete server groups (will cascade delete server_group_members)
	_, err = tx.Exec(ctx, `DELETE FROM server_groups`)
	if err != nil {
		return nil, err
	}

	// 5. Delete servers (will cascade delete findings, server_packages, server_group_members)
	_, err = tx.Exec(ctx, `DELETE FROM servers`)
	if err != nil {
		return nil, err
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return result, nil
}

// ResetFindingsOnly deletes all findings only. Servers, packages, assessments, agents, etc. are preserved.
// Use this to clear old findings so only new scan results remain.
func (s *SettingsService) ResetFindingsOnly(ctx context.Context) (findingsDeleted int, err error) {
	err = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM findings`).Scan(&findingsDeleted)
	if err != nil {
		return 0, err
	}
	_, err = s.db.Exec(ctx, `DELETE FROM findings`)
	if err != nil {
		return 0, err
	}
	return findingsDeleted, nil
}
