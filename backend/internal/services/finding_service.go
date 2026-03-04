package services

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// FindingService handles finding-related operations
type FindingService struct {
	db *pgxpool.Pool
}

// NewFindingService creates a new FindingService
func NewFindingService(db *pgxpool.Pool) *FindingService {
	return &FindingService{db: db}
}

// FindingFilter defines filter options for querying findings
type FindingFilter struct {
	ServerID        *int64
	CVEID           *string
	Severity        *string
	MinCVSS         *float64
	Search          string // free-text search across cve_id, package_name, server_name
	IncludeResolved bool
	SortBy          string // column to sort by (cveId, serverName, packageName, cvss3Score, severity, fixState, fixedIn, firstSeenAt)
	SortOrder       string // asc or desc
	Limit           int
	Offset          int
}

// GetAll returns findings with optional filters (lightweight list view, no exploit/description data).
func (s *FindingService) GetAll(ctx context.Context, filter FindingFilter) ([]models.Finding, int, error) {
	// Base WHERE clause (shared between COUNT and SELECT)
	baseWhere := ` WHERE 1=1`
	args := []interface{}{}
	argIndex := 1

	if filter.ServerID != nil {
		baseWhere += ` AND f.server_id = $` + strconv.Itoa(argIndex)
		args = append(args, *filter.ServerID)
		argIndex++
	}
	if filter.CVEID != nil {
		baseWhere += ` AND f.cve_id = $` + strconv.Itoa(argIndex)
		args = append(args, *filter.CVEID)
		argIndex++
	}
	if filter.Severity != nil {
		baseWhere += ` AND f.severity = $` + strconv.Itoa(argIndex)
		args = append(args, *filter.Severity)
		argIndex++
	}
	if filter.MinCVSS != nil {
		baseWhere += ` AND COALESCE(cve.cvss3_score, f.cvss3_score) >= $` + strconv.Itoa(argIndex)
		args = append(args, *filter.MinCVSS)
		argIndex++
	}
	if !filter.IncludeResolved {
		baseWhere += ` AND f.resolved_at IS NULL`
	}
	if filter.Search != "" {
		searchPattern := "%" + filter.Search + "%"
		baseWhere += ` AND (f.cve_id ILIKE $` + strconv.Itoa(argIndex) +
			` OR f.package_name ILIKE $` + strconv.Itoa(argIndex) +
			` OR srv.name ILIKE $` + strconv.Itoa(argIndex) +
			` OR COALESCE(f.severity, '') ILIKE $` + strconv.Itoa(argIndex) +
			` OR COALESCE(f.fix_state, '') ILIKE $` + strconv.Itoa(argIndex) +
			` OR COALESCE(f.fixed_in, '') ILIKE $` + strconv.Itoa(argIndex) + `)`
		args = append(args, searchPattern)
		argIndex++
	}

	// Lightweight COUNT (no exploit join)
	countFrom := `FROM findings f JOIN servers srv ON f.server_id = srv.id LEFT JOIN cve_catalog cve ON f.cve_id = cve.cve_id`
	var total int
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) `+countFrom+baseWhere, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Build ORDER BY clause
	orderBy := findingsOrderBy(filter.SortBy, filter.SortOrder)

	// Lightweight SELECT (scores only, no descriptions, no exploit join)
	selectQuery := `
		SELECT 
			f.id, f.server_id, f.cve_id, f.package_name, COALESCE(f.package_version, ''),
			COALESCE(f.fix_state, ''), COALESCE(f.fixed_in, ''), f.cvss3_score, 
			COALESCE(f.severity, ''), COALESCE(f.source_link, ''),
			COALESCE(f.source_type, ''),
			f.first_seen_at, f.last_seen_at, f.resolved_at, f.created_at, f.updated_at,
			srv.name as server_name,
			cve.cvss3_score,
			COALESCE(cve.cvss3_severity, '')
	` + countFrom + baseWhere + orderBy

	if filter.Limit > 0 {
		selectQuery += ` LIMIT $` + strconv.Itoa(argIndex)
		args = append(args, filter.Limit)
		argIndex++

		selectQuery += ` OFFSET $` + strconv.Itoa(argIndex)
		args = append(args, filter.Offset)
	}

	rows, err := s.db.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		err := rows.Scan(
			&f.ID, &f.ServerID, &f.CVEID, &f.PackageName, &f.PackageVersion,
			&f.FixState, &f.FixedIn, &f.CVSS3Score, &f.Severity, &f.SourceLink,
			&f.SourceType,
			&f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt,
			&f.ServerName,
			&f.NVDCvss3Score, &f.CVSS3Severity,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan error: %w", err)
		}
		findings = append(findings, f)
	}

	return findings, total, nil
}

// findingsOrderBy returns a safe ORDER BY clause for the findings list.
func findingsOrderBy(sortBy, sortOrder string) string {
	dir := "DESC"
	if sortOrder == "asc" {
		dir = "ASC"
	}

	nulls := "NULLS LAST"
	if dir == "ASC" {
		nulls = "NULLS FIRST"
	}

	col := "COALESCE(cve.cvss3_score, f.cvss3_score)" // default
	switch sortBy {
	case "cveId":
		col = "f.cve_id"
	case "serverName":
		col = "srv.name"
	case "packageName":
		col = "f.package_name"
	case "severity":
		col = "f.severity"
	case "fixState":
		col = "f.fix_state"
	case "fixedIn":
		col = "f.fixed_in"
	case "firstSeenAt":
		col = "f.first_seen_at"
	case "cvss3Score":
		col = "COALESCE(cve.cvss3_score, f.cvss3_score)"
	}

	return fmt.Sprintf(` ORDER BY %s %s %s, f.id DESC`, col, dir, nulls)
}

// TriageFilterOptions defines filter options for the triage queue
type TriageFilterOptions struct {
	Mode             string   // "cvss" or "vendor_severity"
	CVSSThreshold    float64  // Used when Mode == "cvss"
	VendorSeverities []string // Used when Mode == "vendor_severity"
	IncludeUnrated   bool     // Include findings without vendor severity
	Limit            int
	Offset           int
}

// GetTriageQueue returns findings that need assessment based on filter options
func (s *FindingService) GetTriageQueue(ctx context.Context, opts TriageFilterOptions) ([]models.Finding, int, error) {
	// Build the filter condition based on mode
	var filterCondition string
	var args []interface{}
	argIndex := 1

	if opts.Mode == "vendor_severity" {
		// Build severity filter
		if len(opts.VendorSeverities) > 0 {
			placeholders := ""
			for i, sev := range opts.VendorSeverities {
				if i > 0 {
					placeholders += ", "
				}
				placeholders += fmt.Sprintf("$%d", argIndex)
				args = append(args, sev)
				argIndex++
			}
			filterCondition = fmt.Sprintf("LOWER(f.severity) IN (%s)", placeholders)

			if opts.IncludeUnrated {
				filterCondition = fmt.Sprintf("(%s OR f.severity IS NULL OR f.severity = '')", filterCondition)
			}
		} else if opts.IncludeUnrated {
			// Only unrated
			filterCondition = "(f.severity IS NULL OR f.severity = '')"
		} else {
			// No severities selected and not including unrated - return empty
			return []models.Finding{}, 0, nil
		}
	} else {
		// CVSS mode (default) - use NVD CVSS score with fallback
		filterCondition = fmt.Sprintf("COALESCE(cve.cvss3_score, f.cvss3_score) >= $%d", argIndex)
		args = append(args, opts.CVSSThreshold)
		argIndex++
	}

	baseQuery := fmt.Sprintf(`
		FROM findings f
		JOIN servers srv ON f.server_id = srv.id
		LEFT JOIN cve_catalog cve ON f.cve_id = cve.cve_id
		LEFT JOIN assessments a ON f.cve_id = a.cve_id
		WHERE f.resolved_at IS NULL
		AND %s
		AND (a.id IS NULL OR a.status = 'pending')
	`, filterCondition)

	// Count total
	var total int
	err := s.db.QueryRow(ctx, `SELECT COUNT(DISTINCT f.cve_id) `+baseQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get unique CVEs with their findings
	limitPlaceholder := fmt.Sprintf("$%d", argIndex)
	offsetPlaceholder := fmt.Sprintf("$%d", argIndex+1)
	args = append(args, opts.Limit, opts.Offset)

	selectQuery := fmt.Sprintf(`
		SELECT DISTINCT ON (f.cve_id)
			f.id, f.server_id, f.cve_id, f.package_name, COALESCE(f.package_version, ''),
			COALESCE(f.fix_state, ''), COALESCE(f.fixed_in, ''), f.cvss3_score, 
			COALESCE(f.severity, ''), COALESCE(f.summary, ''), COALESCE(f.source_link, ''),
			COALESCE(f.source_type, ''),
			f.first_seen_at, f.last_seen_at, f.resolved_at, f.created_at, f.updated_at,
			srv.name as server_name,
			COALESCE(cve.description, ''),
			cve.cvss3_score
		%s
		ORDER BY f.cve_id, COALESCE(cve.cvss3_score, f.cvss3_score) DESC NULLS LAST
		LIMIT %s OFFSET %s
	`, baseQuery, limitPlaceholder, offsetPlaceholder)

	rows, err := s.db.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		err := rows.Scan(
			&f.ID, &f.ServerID, &f.CVEID, &f.PackageName, &f.PackageVersion,
			&f.FixState, &f.FixedIn, &f.CVSS3Score, &f.Severity, &f.Summary, &f.SourceLink,
			&f.SourceType,
			&f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt,
			&f.ServerName,
			&f.NVDDescription,
			&f.NVDCvss3Score,
		)
		if err != nil {
			return nil, 0, err
		}
		findings = append(findings, f)
	}

	return findings, total, nil
}

// GetByID returns a finding by ID with full NVD, OVAL, and ExploitDB enrichment (for detail views).
func (s *FindingService) GetByID(ctx context.Context, id int64) (*models.Finding, error) {
	query := `
		SELECT 
			f.id, f.server_id, f.cve_id, f.package_name, COALESCE(f.package_version, ''),
			COALESCE(f.fix_state, ''), COALESCE(f.fixed_in, ''), f.cvss3_score,
			COALESCE(f.severity, ''), COALESCE(f.summary, ''), COALESCE(f.source_link, ''),
			COALESCE(f.source_type, ''),
			f.first_seen_at, f.last_seen_at, f.resolved_at, f.created_at, f.updated_at,
			srv.name as server_name,
			-- NVD enrichment (full)
			COALESCE(cve.description, ''),
			cve.cvss3_score,
			COALESCE(cve.cvss3_vector, ''),
			COALESCE(cve.cvss3_severity, ''),
			cve.cvss2_score,
			COALESCE(cve.cwe_ids, '{}'),
			cve.published_at,
			-- OVAL description (preferred over NVD)
			COALESCE(oval_desc.description, ''),
			-- ExploitDB enrichment
			COALESCE(exp.exploit_count, 0)::int,
			COALESCE(exp.exploit_ids, ARRAY[]::int[]),
			COALESCE(exp.has_verified, false)
		FROM findings f
		JOIN servers srv ON f.server_id = srv.id
		LEFT JOIN cve_catalog cve ON f.cve_id = cve.cve_id
		LEFT JOIN LATERAL (
			SELECT od.description
			FROM oval_definitions od
			WHERE f.cve_id = ANY(od.cve_ids)
			ORDER BY od.id DESC
			LIMIT 1
		) oval_desc ON true
		LEFT JOIN LATERAL (
			SELECT 
				COUNT(*) as exploit_count,
				ARRAY_AGG(e.edb_id) as exploit_ids,
				BOOL_OR(e.verified) as has_verified
			FROM exploits e 
			WHERE f.cve_id = ANY(e.cve_ids)
		) exp ON true
		WHERE f.id = $1
	`

	var f models.Finding
	var exploitCount int
	var exploitIDs []int32
	var hasVerified bool
	var ovalDescription string

	err := s.db.QueryRow(ctx, query, id).Scan(
		&f.ID, &f.ServerID, &f.CVEID, &f.PackageName, &f.PackageVersion,
		&f.FixState, &f.FixedIn, &f.CVSS3Score, &f.Severity, &f.Summary, &f.SourceLink,
		&f.SourceType,
		&f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt,
		&f.ServerName,
		// NVD
		&f.NVDDescription, &f.NVDCvss3Score, &f.CVSS3Vector, &f.CVSS3Severity, &f.CVSS2Score, &f.CWEIDs, &f.CVEPublishedAt,
		// OVAL
		&ovalDescription,
		// ExploitDB
		&exploitCount, &exploitIDs, &hasVerified,
	)
	if err != nil {
		return nil, err
	}

	// Set description: OVAL preferred, NVD fallback
	if ovalDescription != "" {
		f.Description = ovalDescription
	} else if f.NVDDescription != "" {
		f.Description = f.NVDDescription
	}

	f.ExploitCount = exploitCount
	f.HasExploit = exploitCount > 0
	f.VerifiedExploit = hasVerified
	if len(exploitIDs) > 0 {
		f.ExploitIDs = make([]int, len(exploitIDs))
		for i, eid := range exploitIDs {
			f.ExploitIDs[i] = int(eid)
		}
	}

	return &f, nil
}

// Upsert creates or updates a finding
func (s *FindingService) Upsert(ctx context.Context, f *models.Finding) (*models.Finding, bool, error) {
	// Check if exists first to determine if new or updated
	var existingID int64
	err := s.db.QueryRow(ctx,
		`SELECT id FROM findings WHERE server_id = $1 AND cve_id = $2 AND package_name = $3`,
		f.ServerID, f.CVEID, f.PackageName,
	).Scan(&existingID)

	isNew := err != nil // Not found = new

	sourceType := f.SourceType
	if sourceType == "" {
		sourceType = "usn" // default for manual/API upserts
	}
	query := `
		INSERT INTO findings (
			server_id, cve_id, package_name, package_version, fix_state, fixed_in,
			cvss3_score, severity, summary, source_link, source_type, first_seen_at, last_seen_at, resolved_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL, NOW())
		ON CONFLICT (server_id, cve_id, package_name)
		DO UPDATE SET
			package_version = EXCLUDED.package_version,
			fix_state = EXCLUDED.fix_state,
			fixed_in = EXCLUDED.fixed_in,
			cvss3_score = EXCLUDED.cvss3_score,
			severity = EXCLUDED.severity,
			summary = EXCLUDED.summary,
			source_link = EXCLUDED.source_link,
			source_type = EXCLUDED.source_type,
			last_seen_at = EXCLUDED.last_seen_at,
			resolved_at = NULL,
			updated_at = NOW()
		RETURNING id, server_id, cve_id, package_name, package_version, fix_state, fixed_in,
			cvss3_score, severity, summary, source_link, COALESCE(source_type, ''), first_seen_at, last_seen_at, resolved_at, created_at, updated_at
	`

	var result models.Finding
	err = s.db.QueryRow(ctx, query,
		f.ServerID, f.CVEID, f.PackageName, f.PackageVersion, f.FixState, f.FixedIn,
		f.CVSS3Score, f.Severity, f.Summary, f.SourceLink, sourceType, f.FirstSeenAt, f.LastSeenAt,
	).Scan(
		&result.ID, &result.ServerID, &result.CVEID, &result.PackageName, &result.PackageVersion,
		&result.FixState, &result.FixedIn, &result.CVSS3Score, &result.Severity, &result.Summary, &result.SourceLink, &result.SourceType,
		&result.FirstSeenAt, &result.LastSeenAt, &result.ResolvedAt, &result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		return nil, false, err
	}

	return &result, isNew, nil
}

// MarkResolved marks findings as resolved if they're not in the current scan
func (s *FindingService) MarkResolved(ctx context.Context, serverID int64, activeKeys []string, resolvedAt time.Time) (int, error) {
	if len(activeKeys) == 0 {
		// No active findings, mark all as resolved
		result, err := s.db.Exec(ctx,
			`UPDATE findings SET resolved_at = $1, updated_at = NOW() 
			 WHERE server_id = $2 AND resolved_at IS NULL`,
			resolvedAt, serverID,
		)
		if err != nil {
			return 0, err
		}
		return int(result.RowsAffected()), nil
	}

	// Mark findings as resolved if they're not in the active keys list
	result, err := s.db.Exec(ctx,
		`UPDATE findings SET resolved_at = $1, updated_at = NOW()
		 WHERE server_id = $2 AND resolved_at IS NULL
		 AND (cve_id || '|' || package_name) != ALL($3)`,
		resolvedAt, serverID, activeKeys,
	)
	if err != nil {
		return 0, err
	}

	return int(result.RowsAffected()), nil
}

// GetServersByCVE returns all servers affected by a specific CVE
func (s *FindingService) GetServersByCVE(ctx context.Context, cveID string) ([]models.Finding, error) {
	query := `
		SELECT 
			f.id, f.server_id, f.cve_id, f.package_name, f.package_version,
			f.fix_state, f.fixed_in, f.cvss3_score, f.severity, f.summary, f.source_link,
			COALESCE(f.source_type, ''),
			f.first_seen_at, f.last_seen_at, f.resolved_at, f.created_at, f.updated_at,
			srv.name as server_name
		FROM findings f
		JOIN servers srv ON f.server_id = srv.id
		WHERE f.cve_id = $1 AND f.resolved_at IS NULL
		ORDER BY srv.name
	`

	rows, err := s.db.Query(ctx, query, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		err := rows.Scan(
			&f.ID, &f.ServerID, &f.CVEID, &f.PackageName, &f.PackageVersion,
			&f.FixState, &f.FixedIn, &f.CVSS3Score, &f.Severity, &f.Summary, &f.SourceLink,
			&f.SourceType,
			&f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt,
			&f.ServerName,
		)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}

	return findings, nil
}

