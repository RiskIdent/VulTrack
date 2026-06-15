package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// AssessmentService handles assessment-related operations
type AssessmentService struct {
	db *pgxpool.Pool
}

// NewAssessmentService creates a new AssessmentService
func NewAssessmentService(db *pgxpool.Pool) *AssessmentService {
	return &AssessmentService{db: db}
}

// AssessmentFilter defines filter options for querying assessments.
type AssessmentFilter struct {
	Search          string  // free-text across cve_id, comment, assessed_by
	Status          string  // "relevant", "not_relevant", "accepted_risk" or empty = all
	FindingActive   *bool   // true = only active, false = only resolved, nil = all
	HasFixAvailable *bool   // true = fix available, false = no fix, nil = all
	MinCVSS         float64 // 0 = no filter
	Severity        string  // vendor severity filter (e.g. "critical")
	SortBy          string  // cveId, status, cvss3Score, severity, assessedAt, affectedServers
	SortOrder       string  // asc or desc
	Limit           int
	Offset          int
}

// GetAll returns assessments with finding aggregation, filtered and paginated server-side.
func (s *AssessmentService) GetAll(ctx context.Context, filter AssessmentFilter) ([]models.Assessment, int, error) {
	// ── Base CTE: enrich all assessments with finding aggregates ──
	baseCTE := `
		WITH enriched AS (
			SELECT
				a.id, a.cve_id, a.status, a.comment, COALESCE(a.ticket_url, '') as ticket_url,
				a.assessed_by, a.assessed_at, a.created_at, a.updated_at,
				COALESCE(f.cvss3_score, 0) AS cvss3_score,
				COALESCE(f.severity, '')   AS severity,
				COALESCE(f.summary, '')    AS summary,
				COALESCE(f.source_link, '') AS source_link,
				COALESCE(fc.active_count, 0)        AS affected_servers,
				COALESCE(fc.active_count, 0) > 0    AS finding_active,
				COALESCE(fc.fix_available, false)    AS has_fix_available
			FROM assessments a
			LEFT JOIN LATERAL (
				SELECT cvss3_score, severity, summary, source_link
				FROM findings
				WHERE cve_id = a.cve_id
				ORDER BY cvss3_score DESC NULLS LAST
				LIMIT 1
			) f ON true
			LEFT JOIN LATERAL (
				SELECT
					COUNT(*) FILTER (WHERE resolved_at IS NULL) AS active_count,
					BOOL_OR(fix_state = 'fix_available') AS fix_available
				FROM findings
				WHERE cve_id = a.cve_id
			) fc ON true
		)
	`

	// ── Build WHERE on the enriched CTE ──
	where := " WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if filter.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, filter.Status)
		idx++
	}

	if filter.Search != "" {
		pattern := "%" + strings.ToLower(filter.Search) + "%"
		where += fmt.Sprintf(" AND (cve_id ILIKE $%d OR comment ILIKE $%d OR assessed_by ILIKE $%d)", idx, idx, idx)
		args = append(args, pattern)
		idx++
	}

	if filter.FindingActive != nil {
		where += fmt.Sprintf(" AND finding_active = $%d", idx)
		args = append(args, *filter.FindingActive)
		idx++
	}

	if filter.HasFixAvailable != nil {
		where += fmt.Sprintf(" AND has_fix_available = $%d", idx)
		args = append(args, *filter.HasFixAvailable)
		idx++
	}

	if filter.MinCVSS > 0 {
		where += fmt.Sprintf(" AND cvss3_score >= $%d", idx)
		args = append(args, filter.MinCVSS)
		idx++
	}

	if filter.Severity != "" {
		where += fmt.Sprintf(" AND LOWER(severity) = LOWER($%d)", idx)
		args = append(args, filter.Severity)
		idx++
	}

	// ── Count total matching rows ──
	countQuery := baseCTE + " SELECT COUNT(*) FROM enriched" + where
	var total int
	err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count assessments: %w", err)
	}

	// ── Fetch paginated results ──
	orderBy := assessmentOrderBy(filter.SortBy, filter.SortOrder)

	dataQuery := baseCTE + `
		SELECT id, cve_id, status, comment, ticket_url,
			assessed_by, assessed_at, created_at, updated_at,
			cvss3_score, severity, summary, source_link,
			affected_servers, finding_active, has_fix_available
		FROM enriched` + where + orderBy + fmt.Sprintf(" LIMIT $%d OFFSET $%d", idx, idx+1)
	dataArgs := append(args, filter.Limit, filter.Offset)

	rows, err := s.db.Query(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query assessments: %w", err)
	}
	defer rows.Close()

	var assessments []models.Assessment
	for rows.Next() {
		var a models.Assessment
		err := rows.Scan(
			&a.ID, &a.CVEID, &a.Status, &a.Comment, &a.TicketURL, &a.AssessedBy,
			&a.AssessedAt, &a.CreatedAt, &a.UpdatedAt,
			&a.CVSS3Score, &a.Severity, &a.Summary, &a.SourceLink,
			&a.AffectedServers, &a.FindingActive, &a.HasFixAvailable,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan assessment: %w", err)
		}
		assessments = append(assessments, a)
	}

	return assessments, total, nil
}

// assessmentOrderBy returns a safe ORDER BY clause.
// Column names must match the enriched CTE output (no table alias).
func assessmentOrderBy(sortBy, sortOrder string) string {
	col := "assessed_at"
	switch sortBy {
	case "cveId":
		col = "cve_id"
	case "status":
		col = "status"
	case "assessedAt":
		col = "assessed_at"
	}

	dir := "DESC"
	if strings.EqualFold(sortOrder, "asc") {
		dir = "ASC"
	}

	return fmt.Sprintf(" ORDER BY %s %s", col, dir)
}

// GetByCVE returns an assessment by CVE ID
func (s *AssessmentService) GetByCVE(ctx context.Context, cveID string) (*models.Assessment, error) {
	query := `
		SELECT id, cve_id, status, comment, COALESCE(ticket_url, ''), assessed_by, assessed_at, created_at, updated_at
		FROM assessments
		WHERE cve_id = $1
	`

	var a models.Assessment
	err := s.db.QueryRow(ctx, query, cveID).Scan(
		&a.ID, &a.CVEID, &a.Status, &a.Comment, &a.TicketURL, &a.AssessedBy,
		&a.AssessedAt, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &a, nil
}

// Upsert creates or updates an assessment
func (s *AssessmentService) Upsert(ctx context.Context, a *models.Assessment) (*models.Assessment, error) {
	query := `
		INSERT INTO assessments (cve_id, status, comment, ticket_url, assessed_by, assessed_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (cve_id)
		DO UPDATE SET
			status = EXCLUDED.status,
			comment = EXCLUDED.comment,
			-- Preserve an existing Jira ticket link when the caller doesn't supply
			-- one (e.g. updates via the MCP interface or the REST update path),
			-- instead of wiping it with an empty value.
			ticket_url = COALESCE(NULLIF(EXCLUDED.ticket_url, ''), assessments.ticket_url),
			assessed_by = EXCLUDED.assessed_by,
			assessed_at = NOW(),
			updated_at = NOW()
		RETURNING id, cve_id, status, comment, COALESCE(ticket_url, ''), assessed_by, assessed_at, created_at, updated_at
	`

	var result models.Assessment
	err := s.db.QueryRow(ctx, query,
		a.CVEID, a.Status, a.Comment, a.TicketURL, a.AssessedBy,
	).Scan(
		&result.ID, &result.CVEID, &result.Status, &result.Comment, &result.TicketURL,
		&result.AssessedBy, &result.AssessedAt, &result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// BulkUpsert creates or updates multiple assessments at once
func (s *AssessmentService) BulkUpsert(ctx context.Context, assessments []models.Assessment) error {
	for _, a := range assessments {
		_, err := s.Upsert(ctx, &a)
		if err != nil {
			return err
		}
	}
	return nil
}

// Delete removes an assessment
func (s *AssessmentService) Delete(ctx context.Context, cveID string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM assessments WHERE cve_id = $1`, cveID)
	return err
}

// GetStats returns assessment statistics
func (s *AssessmentService) GetStats(ctx context.Context) (map[string]int, error) {
	query := `
		SELECT status, COUNT(*) as count
		FROM assessments
		GROUP BY status
	`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		stats[status] = count
	}

	return stats, nil
}
