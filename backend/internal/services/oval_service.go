package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// OVALService handles OVAL-related operations
type OVALService struct {
	db *pgxpool.Pool
}

// NewOVALService creates a new OVALService
func NewOVALService(db *pgxpool.Pool) *OVALService {
	return &OVALService{db: db}
}

// ============================================================================
// DISTRIBUTIONS
// ============================================================================

// GetDistributions returns all known OVAL distributions
func (s *OVALService) GetDistributions(ctx context.Context) ([]models.OVALDistribution, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, name, display_name, url_template, COALESCE(url_template_cve, ''), package_manager, versions
		FROM oval_distributions
		ORDER BY display_name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var distributions []models.OVALDistribution
	for rows.Next() {
		var d models.OVALDistribution
		var versionsJSON []byte
		err := rows.Scan(&d.ID, &d.Name, &d.DisplayName, &d.URLTemplate, &d.URLTemplateCve, &d.PackageManager, &versionsJSON)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(versionsJSON, &d.Versions); err != nil {
			return nil, fmt.Errorf("failed to parse versions JSON: %w", err)
		}
		distributions = append(distributions, d)
	}

	return distributions, nil
}

// GetDistributionByName returns a distribution by name
func (s *OVALService) GetDistributionByName(ctx context.Context, name string) (*models.OVALDistribution, error) {
	var d models.OVALDistribution
	var versionsJSON []byte
	err := s.db.QueryRow(ctx, `
		SELECT id, name, display_name, url_template, COALESCE(url_template_cve, ''), package_manager, versions
		FROM oval_distributions
		WHERE name = $1
	`, name).Scan(&d.ID, &d.Name, &d.DisplayName, &d.URLTemplate, &d.URLTemplateCve, &d.PackageManager, &versionsJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(versionsJSON, &d.Versions); err != nil {
		return nil, fmt.Errorf("failed to parse versions JSON: %w", err)
	}
	return &d, nil
}

// ============================================================================
// SOURCES (user-enabled OVAL feeds)
// ============================================================================

// GetSources returns all OVAL sources with optional filter
func (s *OVALService) GetSources(ctx context.Context, enabledOnly bool) ([]models.OVALSource, error) {
	query := `
		SELECT id, distribution, version, COALESCE(source_type, 'usn'), codename, url, is_enabled, 
		       last_sync_at, sync_status, sync_error,
		       created_at, updated_at
		FROM oval_sources
	`
	if enabledOnly {
		query += " WHERE is_enabled = true"
	}
	query += " ORDER BY distribution, version, source_type"

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sources []models.OVALSource
	for rows.Next() {
		var src models.OVALSource
		var lastSyncStatus, lastSyncError *string
		err := rows.Scan(
			&src.ID, &src.Distribution, &src.Version, &src.SourceType, &src.Codename, &src.URL,
			&src.IsEnabled, &src.LastSyncAt, &lastSyncStatus, &lastSyncError,
			&src.CreatedAt, &src.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if lastSyncStatus != nil {
			src.LastSyncStatus = *lastSyncStatus
		}
		if lastSyncError != nil {
			src.LastSyncError = *lastSyncError
		}
		sources = append(sources, src)
	}

	// Get definition counts
	for i := range sources {
		count, err := s.GetDefinitionCount(ctx, sources[i].ID)
		if err == nil {
			sources[i].DefinitionCount = count
		}
	}

	return sources, nil
}

// GetSourceByID returns an OVAL source by ID
func (s *OVALService) GetSourceByID(ctx context.Context, id int64) (*models.OVALSource, error) {
	var src models.OVALSource
	var lastSyncStatus, lastSyncError *string
	err := s.db.QueryRow(ctx, `
		SELECT id, distribution, version, COALESCE(source_type, 'usn'), codename, url, is_enabled, 
		       last_sync_at, sync_status, sync_error,
		       created_at, updated_at
		FROM oval_sources
		WHERE id = $1
	`, id).Scan(
		&src.ID, &src.Distribution, &src.Version, &src.SourceType, &src.Codename, &src.URL,
		&src.IsEnabled, &src.LastSyncAt, &lastSyncStatus, &lastSyncError,
		&src.CreatedAt, &src.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if lastSyncStatus != nil {
		src.LastSyncStatus = *lastSyncStatus
	}
	if lastSyncError != nil {
		src.LastSyncError = *lastSyncError
	}
	return &src, nil
}

// GetSourceByDistroVersion returns the first source (USN preferred) for a distribution and version.
// Use GetSourcesByDistroVersion when all sources (USN + CVE) are needed.
func (s *OVALService) GetSourceByDistroVersion(ctx context.Context, distribution, version string) (*models.OVALSource, error) {
	sources, err := s.GetSourcesByDistroVersion(ctx, distribution, version)
	if err != nil || len(sources) == 0 {
		return nil, err
	}
	return &sources[0], nil
}

// GetSourcesByDistroVersion returns all OVAL sources for a distribution and version (e.g. USN + CVE).
func (s *OVALService) GetSourcesByDistroVersion(ctx context.Context, distribution, version string) ([]models.OVALSource, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, distribution, version, COALESCE(source_type, 'usn'), codename, url, is_enabled, 
		       last_sync_at, sync_status, sync_error,
		       created_at, updated_at
		FROM oval_sources
		WHERE distribution = $1 AND version = $2
		ORDER BY source_type
	`, distribution, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sources []models.OVALSource
	for rows.Next() {
		var src models.OVALSource
		var lastSyncStatus, lastSyncError *string
		err := rows.Scan(
			&src.ID, &src.Distribution, &src.Version, &src.SourceType, &src.Codename, &src.URL,
			&src.IsEnabled, &src.LastSyncAt, &lastSyncStatus, &lastSyncError,
			&src.CreatedAt, &src.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if lastSyncStatus != nil {
			src.LastSyncStatus = *lastSyncStatus
		}
		if lastSyncError != nil {
			src.LastSyncError = *lastSyncError
		}
		sources = append(sources, src)
	}
	return sources, nil
}

// CreateSource creates a new OVAL source
func (s *OVALService) CreateSource(ctx context.Context, distribution, version, sourceType, codename, url, packageManager string) (*models.OVALSource, error) {
	if sourceType == "" {
		sourceType = "usn"
	}
	var src models.OVALSource
	var syncStatus, syncError *string
	err := s.db.QueryRow(ctx, `
		INSERT INTO oval_sources (distribution, version, source_type, codename, url, package_manager, is_enabled)
		VALUES ($1, $2, $3, $4, $5, $6, true)
		RETURNING id, distribution, version, source_type, codename, url, is_enabled, 
		          last_sync_at, sync_status, sync_error, created_at, updated_at
	`, distribution, version, sourceType, codename, url, packageManager).Scan(
		&src.ID, &src.Distribution, &src.Version, &src.SourceType, &src.Codename, &src.URL,
		&src.IsEnabled, &src.LastSyncAt, &syncStatus, &syncError,
		&src.CreatedAt, &src.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OVAL source: %w", err)
	}
	if syncStatus != nil {
		src.LastSyncStatus = *syncStatus
	}
	if syncError != nil {
		src.LastSyncError = *syncError
	}
	return &src, nil
}

// EnableSource creates or enables OVAL source(s) for a distribution version.
// For distributions with url_template_cve (e.g. Ubuntu), both USN and CVE sources are created/enabled.
func (s *OVALService) EnableSource(ctx context.Context, distribution, version string) (*models.OVALSource, error) {
	distro, err := s.GetDistributionByName(ctx, distribution)
	if err != nil {
		return nil, err
	}
	if distro == nil {
		return nil, fmt.Errorf("unknown distribution: %s", distribution)
	}

	var codename string
	var found bool
	for _, v := range distro.Versions {
		if v.Version == version {
			codename = v.Codename
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("unknown version %s for distribution %s", version, distribution)
	}

	existing, err := s.GetSourcesByDistroVersion(ctx, distribution, version)
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		// Enable all existing sources for this distro+version
		for i := range existing {
			_, err = s.db.Exec(ctx, `
				UPDATE oval_sources SET is_enabled = true, updated_at = NOW() WHERE id = $1
			`, existing[i].ID)
			if err != nil {
				return nil, err
			}
			existing[i].IsEnabled = true
		}
		return &existing[0], nil
	}

	// Create USN source
	usnURL := strings.ReplaceAll(distro.URLTemplate, "{version}", version)
	usnURL = strings.ReplaceAll(usnURL, "{codename}", codename)
	usnSource, err := s.CreateSource(ctx, distribution, version, "usn", codename, usnURL, distro.PackageManager)
	if err != nil {
		return nil, err
	}

	// Create CVE source if template is set
	if distro.URLTemplateCve != "" {
		cveURL := strings.ReplaceAll(distro.URLTemplateCve, "{version}", version)
		cveURL = strings.ReplaceAll(cveURL, "{codename}", codename)
		_, err = s.CreateSource(ctx, distribution, version, "cve", codename, cveURL, distro.PackageManager)
		if err != nil {
			return nil, err
		}
	}

	return usnSource, nil
}

// DisableSource disables an OVAL source
func (s *OVALService) DisableSource(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `
		UPDATE oval_sources SET is_enabled = false, updated_at = NOW() WHERE id = $1
	`, id)
	return err
}

// DeleteSource deletes an OVAL source and all its data
func (s *OVALService) DeleteSource(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM oval_sources WHERE id = $1`, id)
	return err
}

// UpdateSyncStatus updates the sync status of a source
func (s *OVALService) UpdateSyncStatus(ctx context.Context, id int64, status string, errorMsg string) error {
	_, err := s.db.Exec(ctx, `
		UPDATE oval_sources 
		SET last_sync_at = NOW(), sync_status = $2, sync_error = $3, updated_at = NOW()
		WHERE id = $1
	`, id, status, errorMsg)
	return err
}

// ============================================================================
// DEFINITIONS
// ============================================================================

// OVALDefinitionFilter represents filter criteria for OVAL definitions
type OVALDefinitionFilter struct {
	Distribution *string
	Version      *string
	Codename     *string
	CVEID        *string
	Severity     *string
	SourceType   *string // "usn" or "cve"
	Package      *string
	Search       *string // Fulltext search in title/description
	HasExploit   *bool   // when true, only definitions with at least one CVE that has an exploit in ExploitDB
	Limit        int
	Offset       int
	SortBy       string // "cveId", "severity", "createdAt"
	SortOrder    string // "asc", "desc"
}

// OVALTestWithDetails represents an OVAL test with object and state information
type OVALTestWithDetails struct {
	ID           int64    `json:"id"`
	OvalID       string   `json:"ovalId"`
	TestType     string   `json:"testType"`
	Comment      string   `json:"comment"`
	PackageName  string   `json:"packageName"`  // First package (for backwards compatibility)
	PackageNames []string `json:"packageNames"` // All packages tested by this test
	EVROperation string   `json:"evrOperation"`
	EVRValue     string   `json:"evrValue"`
}

// OVALDefinitionWithSource represents an OVAL definition with source information
type OVALDefinitionWithSource struct {
	models.OVALDefinition
	Distribution     string                `json:"distribution"`
	Version          string                `json:"version"`
	Codename         string                `json:"codename"`
	SourceType       string                `json:"sourceType"` // 'usn' or 'cve'
	AffectedPackages []string              `json:"affectedPackages"`
	Tests            []OVALTestWithDetails `json:"tests,omitempty"` // Only populated in detail view
	// ExploitDB enrichment (only in detail view when definition has CVE IDs)
	HasExploit      bool  `json:"hasExploit"`
	ExploitCount    int   `json:"exploitCount,omitempty"`
	ExploitIDs      []int `json:"exploitIds,omitempty"`
	VerifiedExploit bool  `json:"verifiedExploit,omitempty"`
}

// GetDefinitions returns OVAL definitions with filtering and pagination.
// Excludes applicability/inventory definitions (no CVE IDs) so the OVAL Database UI only shows real vulnerabilities.
func (s *OVALService) GetDefinitions(ctx context.Context, filter OVALDefinitionFilter) ([]OVALDefinitionWithSource, int, error) {
	// Build WHERE clause: only definitions that have at least one CVE (exclude "is Ubuntu X installed?" etc.)
	whereConditions := []string{"od.cve_ids IS NOT NULL AND cardinality(od.cve_ids) > 0"}
	args := []interface{}{}
	argIndex := 1

	if filter.Distribution != nil && *filter.Distribution != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("os.distribution = $%d", argIndex))
		args = append(args, *filter.Distribution)
		argIndex++
	}

	if filter.Version != nil && *filter.Version != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("os.version = $%d", argIndex))
		args = append(args, *filter.Version)
		argIndex++
	}

	if filter.Codename != nil && *filter.Codename != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("os.codename = $%d", argIndex))
		args = append(args, *filter.Codename)
		argIndex++
	}

	if filter.CVEID != nil && *filter.CVEID != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("$%d = ANY(od.cve_ids)", argIndex))
		args = append(args, *filter.CVEID)
		argIndex++
	}

	if filter.Severity != nil && *filter.Severity != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("LOWER(od.severity) = LOWER($%d)", argIndex))
		args = append(args, *filter.Severity)
		argIndex++
	}

	if filter.SourceType != nil && *filter.SourceType != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("COALESCE(os.source_type, 'usn') = $%d", argIndex))
		args = append(args, *filter.SourceType)
		argIndex++
	}

	if filter.Package != nil && *filter.Package != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("EXISTS (SELECT 1 FROM oval_criteria_tests oct JOIN oval_tests ot ON oct.test_id = ot.id JOIN oval_objects oo ON ot.source_id = oo.source_id WHERE oct.criteria_id IN (SELECT id FROM oval_criteria WHERE definition_id = od.id) AND oo.name ILIKE $%d)", argIndex))
		args = append(args, "%"+*filter.Package+"%")
		argIndex++
	}

	if filter.Search != nil && *filter.Search != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("(od.title ILIKE $%d OR od.description ILIKE $%d OR EXISTS (SELECT 1 FROM unnest(od.cve_ids) AS cve WHERE cve ILIKE $%d))", argIndex, argIndex, argIndex))
		args = append(args, "%"+*filter.Search+"%")
		argIndex++
	}

	if filter.HasExploit != nil && *filter.HasExploit {
		whereConditions = append(whereConditions, "EXISTS (SELECT 1 FROM exploits e WHERE e.cve_ids IS NOT NULL AND array_length(e.cve_ids, 1) > 0 AND e.cve_ids && od.cve_ids)")
	}

	whereClause := strings.Join(whereConditions, " AND ")

	// Build ORDER BY
	orderBy := "od.created_at DESC"
	if filter.SortBy != "" {
		switch filter.SortBy {
		case "cveId":
			orderBy = "od.cve_ids[1]"
		case "severity":
			orderBy = "od.severity"
		case "createdAt":
			orderBy = "od.created_at"
		}
	}
	if filter.SortOrder == "asc" {
		orderBy += " ASC"
	} else {
		orderBy += " DESC"
	}

	// Get total count
	var total int
	countQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT od.id)
		FROM oval_definitions od
		JOIN oval_sources os ON od.source_id = os.id
		WHERE %s
	`, whereClause)
	err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get definitions with affected packages
	query := fmt.Sprintf(`
		SELECT DISTINCT
			od.id, od.source_id, od.oval_id, od.class, od.title, od.description,
			od.severity, od.cve_ids, od.created_at,
			os.distribution, os.version, os.codename, COALESCE(os.source_type, 'usn')
		FROM oval_definitions od
		JOIN oval_sources os ON od.source_id = os.id
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIndex, argIndex+1)
	args = append(args, filter.Limit, filter.Offset)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var definitions []OVALDefinitionWithSource
	for rows.Next() {
		var def OVALDefinitionWithSource
		err := rows.Scan(
			&def.ID, &def.SourceID, &def.OvalID, &def.Class, &def.Title, &def.Description,
			&def.Severity, &def.CVEIDs, &def.CreatedAt,
			&def.Distribution, &def.Version, &def.Codename, &def.SourceType,
		)
		if err != nil {
			return nil, 0, err
		}

		// Get affected packages for this definition
		packages, err := s.getAffectedPackages(ctx, def.ID)
		if err == nil {
			def.AffectedPackages = packages
		}

		definitions = append(definitions, def)
	}

	return definitions, total, nil
}

// getAffectedPackages returns all package names affected by a definition
func (s *OVALService) getAffectedPackages(ctx context.Context, definitionID int64) ([]string, error) {
	// Check if definition has criteria
	var hasCriteria bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM oval_criteria WHERE definition_id = $1)
	`, definitionID).Scan(&hasCriteria)
	if err != nil {
		return nil, err
	}

	if !hasCriteria {
		// Definition has no criteria, return empty list
		return []string{}, nil
	}

	// Get all tests linked to this definition via criteria
	testRows, err := s.db.Query(ctx, `
		SELECT DISTINCT ot.id, ot.oval_id, ot.source_id, ot.test_type
		FROM oval_criteria_tests oct
		JOIN oval_tests ot ON oct.test_id = ot.id
		WHERE oct.criteria_id IN (SELECT id FROM oval_criteria WHERE definition_id = $1)
	`, definitionID)
	if err != nil {
		return nil, err
	}
	defer testRows.Close()

	type testInfo struct {
		id       int64
		ovalID   string
		sourceID int64
		testType string
	}
	var tests []testInfo
	hasKernelTests := false
	hasPackageTests := false
	for testRows.Next() {
		var t testInfo
		if err := testRows.Scan(&t.id, &t.ovalID, &t.sourceID, &t.testType); err != nil {
			return nil, err
		}
		tests = append(tests, t)
		if t.testType == "uname_test" || t.testType == "variable_test" {
			hasKernelTests = true
		} else {
			hasPackageTests = true
		}
	}

	if len(tests) == 0 {
		return []string{}, nil
	}

	// If only kernel tests and no package tests, return "Kernel"
	if hasKernelTests && !hasPackageTests {
		return []string{"Kernel"}, nil
	}

	// Extract object OVAL IDs from test OVAL IDs using heuristic
	// Test: oval:namespace:tst:123 -> Object: oval:namespace:obj:123
	// Also handle var_ref expanded objects: oval:namespace:obj:123:pkgname
	objectOvalIDs := make(map[string]bool)
	sourceIDs := make(map[int64]bool)

	for _, test := range tests {
		sourceIDs[test.sourceID] = true

		// Parse test OVAL ID: oval:namespace:tst:123
		parts := strings.Split(test.ovalID, ":")
		if len(parts) >= 4 && parts[2] == "tst" {
			// Build object OVAL ID: oval:namespace:obj:123
			objOvalID := fmt.Sprintf("%s:%s:obj:%s", parts[0], parts[1], parts[3])
			objectOvalIDs[objOvalID] = true
		}
	}

	if len(objectOvalIDs) == 0 {
		return []string{}, nil
	}

	// Get package names from objects matching the derived OVAL IDs
	// We need to match both exact OVAL IDs and prefix matches (for var_ref expansion)
	objectIDList := make([]string, 0, len(objectOvalIDs))
	for id := range objectOvalIDs {
		objectIDList = append(objectIDList, id)
	}

	sourceIDList := make([]int64, 0, len(sourceIDs))
	for id := range sourceIDs {
		sourceIDList = append(sourceIDList, id)
	}

	// Build query with proper array handling
	query := `
		SELECT DISTINCT oo.name
		FROM oval_objects oo
		WHERE oo.source_id = ANY($1::bigint[])
		AND (
			oo.oval_id = ANY($2::text[])
			OR EXISTS (
				SELECT 1 FROM unnest($2::text[]) AS base_id
				WHERE oo.oval_id LIKE base_id || ':%'
			)
		)
		AND oo.name IS NOT NULL
		ORDER BY oo.name
	`
	rows, err := s.db.Query(ctx, query, sourceIDList, objectIDList)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packages []string
	for rows.Next() {
		var pkg string
		if err := rows.Scan(&pkg); err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}

	// If no packages found but kernel tests exist, return "Kernel"
	if len(packages) == 0 && hasKernelTests {
		return []string{"Kernel"}, nil
	}

	return packages, nil
}

// GetDefinitionByID returns a single OVAL definition with full details including tests
func (s *OVALService) GetDefinitionByID(ctx context.Context, id int64) (*OVALDefinitionWithSource, error) {
	var def OVALDefinitionWithSource
	err := s.db.QueryRow(ctx, `
		SELECT od.id, od.source_id, od.oval_id, od.class, od.title, od.description,
		       od.severity, od.cve_ids, od.created_at,
		       os.distribution, os.version, os.codename, COALESCE(os.source_type, 'usn')
		FROM oval_definitions od
		JOIN oval_sources os ON od.source_id = os.id
		WHERE od.id = $1
	`, id).Scan(
		&def.ID, &def.SourceID, &def.OvalID, &def.Class, &def.Title, &def.Description,
		&def.Severity, &def.CVEIDs, &def.CreatedAt,
		&def.Distribution, &def.Version, &def.Codename, &def.SourceType,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	// Get affected packages
	packages, err := s.getAffectedPackages(ctx, def.ID)
	if err == nil {
		def.AffectedPackages = packages
	}

	// Get tests with details
	tests, err := s.getDefinitionTests(ctx, def.ID)
	if err == nil {
		def.Tests = tests
	}

	// Enrich with ExploitDB data for definition's CVE IDs
	if len(def.CVEIDs) > 0 {
		if exploitCount, exploitIDs, verified := s.getExploitInfoForCVEs(ctx, def.CVEIDs); exploitCount > 0 {
			def.HasExploit = true
			def.ExploitCount = exploitCount
			def.ExploitIDs = exploitIDs
			def.VerifiedExploit = verified
		}
	}

	return &def, nil
}

// getExploitInfoForCVEs returns exploit count, exploit IDs (edb_id), and whether any is verified for the given CVE IDs.
func (s *OVALService) getExploitInfoForCVEs(ctx context.Context, cveIDs []string) (count int, exploitIDs []int, hasVerified bool) {
	if len(cveIDs) == 0 {
		return 0, nil, false
	}
	rows, err := s.db.Query(ctx, `
		SELECT edb_id, verified FROM exploits
		WHERE cve_ids && $1::text[]
	`, cveIDs)
	if err != nil {
		return 0, nil, false
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var edbID int
		var verified bool
		if err := rows.Scan(&edbID, &verified); err != nil {
			continue
		}
		ids = append(ids, edbID)
		if verified {
			hasVerified = true
		}
	}
	return len(ids), ids, hasVerified
}

// getDefinitionTests returns all tests for a definition with object and state details
func (s *OVALService) getDefinitionTests(ctx context.Context, definitionID int64) ([]OVALTestWithDetails, error) {
	// Check if definition has criteria
	var hasCriteria bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM oval_criteria WHERE definition_id = $1)
	`, definitionID).Scan(&hasCriteria)
	if err != nil {
		return nil, err
	}

	if !hasCriteria {
		// Definition has no criteria, return empty list
		return []OVALTestWithDetails{}, nil
	}

	// First, get all tests linked to this definition
	testRows, err := s.db.Query(ctx, `
		SELECT DISTINCT ot.id, ot.oval_id, ot.test_type, COALESCE(ot.comment, ''), ot.source_id
		FROM oval_criteria_tests oct
		JOIN oval_tests ot ON oct.test_id = ot.id
		WHERE oct.criteria_id IN (SELECT id FROM oval_criteria WHERE definition_id = $1)
		ORDER BY ot.id
	`, definitionID)
	if err != nil {
		return nil, err
	}
	defer testRows.Close()

	type testInfo struct {
		id       int64
		ovalID   string
		testType string
		comment  string
		sourceID int64
	}
	var tests []testInfo
	for testRows.Next() {
		var t testInfo
		if err := testRows.Scan(&t.id, &t.ovalID, &t.testType, &t.comment, &t.sourceID); err != nil {
			return nil, err
		}
		tests = append(tests, t)
	}

	if len(tests) == 0 {
		return []OVALTestWithDetails{}, nil
	}

	// Load all objects and states for the source(s) to match them
	sourceIDs := make(map[int64]bool)
	for _, t := range tests {
		sourceIDs[t.sourceID] = true
	}
	sourceIDList := make([]int64, 0, len(sourceIDs))
	for id := range sourceIDs {
		sourceIDList = append(sourceIDList, id)
	}

	// Load all objects
	objectRows, err := s.db.Query(ctx, `
		SELECT id, oval_id, name FROM oval_objects WHERE source_id = ANY($1::bigint[])
	`, sourceIDList)
	if err != nil {
		return nil, err
	}
	defer objectRows.Close()

	objects := make(map[string]string)           // exact oval_id -> name
	objectsByPrefix := make(map[string][]string) // base_oval_id -> list of names
	for objectRows.Next() {
		var id int64
		var ovalID, name string
		if err := objectRows.Scan(&id, &ovalID, &name); err != nil {
			return nil, err
		}
		objects[ovalID] = name

		// Also index by prefix for var_ref expansion
		colonCount := strings.Count(ovalID, ":")
		if colonCount >= 4 {
			lastColon := strings.LastIndex(ovalID, ":")
			if lastColon > 0 {
				baseID := ovalID[:lastColon]
				objectsByPrefix[baseID] = append(objectsByPrefix[baseID], name)
			}
		}
	}

	// Load all states
	stateRows, err := s.db.Query(ctx, `
		SELECT id, oval_id, evr_operation, evr_value FROM oval_states WHERE source_id = ANY($1::bigint[])
	`, sourceIDList)
	if err != nil {
		return nil, err
	}
	defer stateRows.Close()

	type stateData struct {
		operation string
		value     string
	}
	states := make(map[string]stateData)
	for stateRows.Next() {
		var id int64
		var ovalID, op, val string
		if err := stateRows.Scan(&id, &ovalID, &op, &val); err != nil {
			return nil, err
		}
		states[ovalID] = stateData{operation: op, value: val}
	}

	// Match tests to objects and states using OVAL ID heuristic
	result := make([]OVALTestWithDetails, 0, len(tests))
	for _, test := range tests {
		testDetail := OVALTestWithDetails{
			ID:       test.id,
			OvalID:   test.ovalID,
			TestType: test.testType,
			Comment:  test.comment,
		}

		// Parse test OVAL ID: oval:namespace:tst:123
		parts := strings.Split(test.ovalID, ":")
		if len(parts) >= 4 && parts[2] == "tst" {
			// Build object OVAL ID: oval:namespace:obj:123
			objOvalID := fmt.Sprintf("%s:%s:obj:%s", parts[0], parts[1], parts[3])

			// Try exact match first
			if name, ok := objects[objOvalID]; ok {
				testDetail.PackageName = name
				testDetail.PackageNames = []string{name}
			} else if names, ok := objectsByPrefix[objOvalID]; ok && len(names) > 0 {
				// Multiple packages from var_ref expansion
				testDetail.PackageNames = names
				testDetail.PackageName = names[0] // First package for backwards compatibility
			}

			// Build state OVAL ID: oval:namespace:ste:123
			steOvalID := fmt.Sprintf("%s:%s:ste:%s", parts[0], parts[1], parts[3])
			if st, ok := states[steOvalID]; ok {
				testDetail.EVROperation = st.operation
				testDetail.EVRValue = st.value
			}
		}

		result = append(result, testDetail)
	}

	return result, nil
}

// GetDefinitionCount returns the number of definitions for a source
func (s *OVALService) GetDefinitionCount(ctx context.Context, sourceID int64) (int, error) {
	var count int
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM oval_definitions WHERE source_id = $1
	`, sourceID).Scan(&count)
	return count, err
}

// ClearSourceData deletes all OVAL data for a source (before re-sync)
func (s *OVALService) ClearSourceData(ctx context.Context, sourceID int64) error {
	// Due to CASCADE, deleting definitions will delete criteria, and deleting tests/objects/states
	_, err := s.db.Exec(ctx, `DELETE FROM oval_definitions WHERE source_id = $1`, sourceID)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `DELETE FROM oval_tests WHERE source_id = $1`, sourceID)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `DELETE FROM oval_objects WHERE source_id = $1`, sourceID)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `DELETE FROM oval_states WHERE source_id = $1`, sourceID)
	return err
}

// ============================================================================
// SYNC STATUS
// ============================================================================

// CreateSyncStatus creates a new sync status record
func (s *OVALService) CreateSyncStatus(ctx context.Context, syncType string, sourceName string) (*models.SyncStatus, error) {
	var status models.SyncStatus
	var errorMessage *string
	err := s.db.QueryRow(ctx, `
		INSERT INTO sync_status (source_type, source_name, status, last_sync_at)
		VALUES ($1, $2, 'syncing', NOW())
		ON CONFLICT (source_type, source_name) DO UPDATE SET
			status = 'syncing', last_sync_at = NOW(), updated_at = NOW()
		RETURNING id, source_type, source_name, status, last_sync_at, error_message, records_processed
	`, syncType, sourceName).Scan(
		&status.ID, &status.SyncType, &status.SourceName, &status.Status,
		&status.StartedAt, &errorMessage, &status.ItemsProcessed,
	)
	if err != nil {
		return nil, err
	}
	if errorMessage != nil {
		status.ErrorMessage = *errorMessage
	}
	return &status, nil
}

// UpdateSyncProgress updates the progress of a sync operation
func (s *OVALService) UpdateSyncProgress(ctx context.Context, syncID int64, recordsProcessed int) error {
	_, err := s.db.Exec(ctx, `
		UPDATE sync_status SET records_processed = $2, updated_at = NOW() WHERE id = $1
	`, syncID, recordsProcessed)
	return err
}

// CompleteSyncStatus marks a sync as completed
func (s *OVALService) CompleteSyncStatus(ctx context.Context, syncID int64, status string, errorMsg string) error {
	_, err := s.db.Exec(ctx, `
		UPDATE sync_status 
		SET status = $2, error_message = $3, updated_at = NOW()
		WHERE id = $1
	`, syncID, status, errorMsg)
	return err
}

// GetLatestSyncStatus returns the latest sync status for each type
func (s *OVALService) GetLatestSyncStatus(ctx context.Context) ([]models.SyncStatus, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, source_type, COALESCE(source_name, ''), status, 
		       last_sync_at, records_processed, COALESCE(error_message, '')
		FROM sync_status
		ORDER BY source_type, source_name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statuses []models.SyncStatus
	for rows.Next() {
		var st models.SyncStatus
		err := rows.Scan(
			&st.ID, &st.SyncType, &st.SourceName, &st.Status,
			&st.StartedAt, &st.ItemsProcessed, &st.ErrorMessage,
		)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, st)
	}
	return statuses, nil
}

// GetRunningSyncs returns all currently running syncs
func (s *OVALService) GetRunningSyncs(ctx context.Context) ([]models.SyncStatus, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, source_type, COALESCE(source_name, ''), status, 
		       last_sync_at, records_processed, COALESCE(error_message, '')
		FROM sync_status
		WHERE status = 'syncing'
		ORDER BY last_sync_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statuses []models.SyncStatus
	for rows.Next() {
		var st models.SyncStatus
		err := rows.Scan(
			&st.ID, &st.SyncType, &st.SourceName, &st.Status,
			&st.StartedAt, &st.ItemsProcessed, &st.ErrorMessage,
		)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, st)
	}
	return statuses, nil
}

// ============================================================================
// BULK INSERT METHODS (for parser)
// ============================================================================

// InsertDefinition inserts an OVAL definition and returns its ID
func (s *OVALService) InsertDefinition(ctx context.Context, tx pgx.Tx, sourceID int64, ovalID, class, title, description, severity string, cveIDs []string) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO oval_definitions (source_id, oval_id, class, title, description, severity, cve_ids)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (source_id, oval_id) DO UPDATE SET
			class = EXCLUDED.class, title = EXCLUDED.title, description = EXCLUDED.description,
			severity = EXCLUDED.severity, cve_ids = EXCLUDED.cve_ids
		RETURNING id
	`, sourceID, ovalID, class, title, description, severity, cveIDs).Scan(&id)
	return id, err
}

// InsertTest inserts an OVAL test
func (s *OVALService) InsertTest(ctx context.Context, tx pgx.Tx, sourceID int64, ovalID, testType string, objectOvalID, stateOvalID, comment string) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO oval_tests (source_id, oval_id, test_type, comment)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (source_id, oval_id) DO UPDATE SET
			test_type = EXCLUDED.test_type, comment = EXCLUDED.comment
		RETURNING id
	`, sourceID, ovalID, testType, comment).Scan(&id)
	return id, err
}

// InsertObject inserts an OVAL object
func (s *OVALService) InsertObject(ctx context.Context, tx pgx.Tx, sourceID int64, ovalID, objectType, name string) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO oval_objects (source_id, oval_id, object_type, name)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (source_id, oval_id) DO UPDATE SET
			object_type = EXCLUDED.object_type, name = EXCLUDED.name
		RETURNING id
	`, sourceID, ovalID, objectType, name).Scan(&id)
	return id, err
}

// InsertState inserts an OVAL state
func (s *OVALService) InsertState(ctx context.Context, tx pgx.Tx, sourceID int64, ovalID, stateType, evrOperation, evrValue string) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO oval_states (source_id, oval_id, state_type, evr_operation, evr_value)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (source_id, oval_id) DO UPDATE SET
			state_type = EXCLUDED.state_type, evr_operation = EXCLUDED.evr_operation, evr_value = EXCLUDED.evr_value
		RETURNING id
	`, sourceID, ovalID, stateType, evrOperation, evrValue).Scan(&id)
	return id, err
}

// InsertCriteria inserts OVAL criteria
func (s *OVALService) InsertCriteria(ctx context.Context, tx pgx.Tx, definitionID int64, parentID *int64, operator string, negate bool, comment string) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO oval_criteria (definition_id, parent_id, operator, negate, comment)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, definitionID, parentID, operator, negate, comment).Scan(&id)
	return id, err
}

// LinkCriteriaToTest links criteria to a test with its criterion comment
func (s *OVALService) LinkCriteriaToTest(ctx context.Context, tx pgx.Tx, criteriaID, testID int64, negate bool, comment string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO oval_criteria_tests (criteria_id, test_id, negate, comment)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING
	`, criteriaID, testID, negate, comment)
	return err
}

// UpdateTestReferences updates object_id and state_id references after all objects/states are inserted
func (s *OVALService) UpdateTestReferences(ctx context.Context, tx pgx.Tx, sourceID int64) error {
	// This will be called after parsing to resolve object/state references
	// For now, we store the oval_ids and resolve them in the scanner
	return nil
}

// BeginTx starts a new transaction
func (s *OVALService) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return s.db.Begin(ctx)
}

// GetDB returns the database pool (for syncer to use)
func (s *OVALService) GetDB() *pgxpool.Pool {
	return s.db
}
