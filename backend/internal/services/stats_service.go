package services

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StatsService handles statistics-related operations
type StatsService struct {
	db *pgxpool.Pool
}

// NewStatsService creates a new StatsService
func NewStatsService(db *pgxpool.Pool) *StatsService {
	return &StatsService{db: db}
}

// DashboardStats contains overview statistics for the dashboard
type DashboardStats struct {
	TotalServers       int            `json:"totalServers"`
	TotalFindings      int            `json:"totalFindings"`
	ActiveFindings     int            `json:"activeFindings"`
	ResolvedFindings   int            `json:"resolvedFindings"`
	CriticalFindings   int            `json:"criticalFindings"`
	HighFindings       int            `json:"highFindings"`
	PendingAssessments int            `json:"pendingAssessments"`
	SeverityBreakdown  map[string]int `json:"severityBreakdown"`
}

// GetDashboardStats returns overview statistics
func (s *StatsService) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	stats := &DashboardStats{
		SeverityBreakdown: make(map[string]int),
	}

	// Get server count
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM servers`).Scan(&stats.TotalServers)
	if err != nil {
		return nil, err
	}

	// Get finding counts
	err = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM findings`).Scan(&stats.TotalFindings)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM findings WHERE resolved_at IS NULL`).Scan(&stats.ActiveFindings)
	if err != nil {
		return nil, err
	}

	stats.ResolvedFindings = stats.TotalFindings - stats.ActiveFindings

	// Get severity counts for active findings (case-insensitive)
	err = s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM findings WHERE resolved_at IS NULL AND LOWER(severity) = 'critical'`,
	).Scan(&stats.CriticalFindings)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM findings WHERE resolved_at IS NULL AND LOWER(severity) = 'high'`,
	).Scan(&stats.HighFindings)
	if err != nil {
		return nil, err
	}

	// Get pending assessments count (CVEs with high score that haven't been assessed)
	err = s.db.QueryRow(ctx, `
		SELECT COUNT(DISTINCT f.cve_id)
		FROM findings f
		LEFT JOIN assessments a ON f.cve_id = a.cve_id
		WHERE f.resolved_at IS NULL
		AND f.cvss3_score >= 7.0
		AND (a.id IS NULL OR a.status = 'pending')
	`).Scan(&stats.PendingAssessments)
	if err != nil {
		return nil, err
	}

	// Get severity breakdown (normalize to lowercase)
	rows, err := s.db.Query(ctx, `
		SELECT COALESCE(LOWER(severity), 'unknown'), COUNT(*)
		FROM findings
		WHERE resolved_at IS NULL
		GROUP BY LOWER(severity)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		stats.SeverityBreakdown[severity] = count
	}

	return stats, nil
}

// TopServer represents a server with the most findings
type TopServer struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FindingsCount int    `json:"findingsCount"`
	CriticalCount int    `json:"criticalCount"`
	HighCount     int    `json:"highCount"`
}

// GetTopServers returns servers with the most active findings
func (s *StatsService) GetTopServers(ctx context.Context, limit int) ([]TopServer, error) {
	query := `
		SELECT 
			s.id, s.name,
			COUNT(f.id) as findings_count,
			COUNT(f.id) FILTER (WHERE LOWER(f.severity) = 'critical') as critical_count,
			COUNT(f.id) FILTER (WHERE LOWER(f.severity) = 'high') as high_count
		FROM servers s
		LEFT JOIN findings f ON s.id = f.server_id AND f.resolved_at IS NULL
		GROUP BY s.id
		ORDER BY findings_count DESC
		LIMIT $1
	`

	rows, err := s.db.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []TopServer
	for rows.Next() {
		var srv TopServer
		if err := rows.Scan(&srv.ID, &srv.Name, &srv.FindingsCount, &srv.CriticalCount, &srv.HighCount); err != nil {
			return nil, err
		}
		servers = append(servers, srv)
	}

	return servers, nil
}

// TopCVE represents a CVE affecting the most servers
type TopCVE struct {
	CVEID        string   `json:"cveId"`
	CVSS3Score   *float64 `json:"cvss3Score"`
	Severity     string   `json:"severity"`
	SourceLink   *string  `json:"sourceLink"`
	ServerCount  int      `json:"serverCount"`
	PackageCount int      `json:"packageCount"`
}

// GetTopCVEs returns CVEs affecting the most servers
func (s *StatsService) GetTopCVEs(ctx context.Context, limit int) ([]TopCVE, error) {
	query := `
		SELECT 
			f.cve_id,
			COALESCE(MAX(cve.cvss3_score), MAX(f.cvss3_score)) as cvss3_score,
			MAX(f.severity) as severity,
			MAX(f.source_link) FILTER (WHERE f.source_link IS NOT NULL AND f.source_link != '') as source_link,
			COUNT(DISTINCT f.server_id) as server_count,
			COUNT(DISTINCT f.package_name) as package_count
		FROM findings f
		LEFT JOIN cve_catalog cve ON f.cve_id = cve.cve_id
		WHERE f.resolved_at IS NULL
		GROUP BY f.cve_id
		ORDER BY server_count DESC, cvss3_score DESC NULLS LAST
		LIMIT $1
	`

	rows, err := s.db.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cves []TopCVE
	for rows.Next() {
		var cve TopCVE
		if err := rows.Scan(&cve.CVEID, &cve.CVSS3Score, &cve.Severity, &cve.SourceLink, &cve.ServerCount, &cve.PackageCount); err != nil {
			return nil, err
		}
		cves = append(cves, cve)
	}

	return cves, nil
}

// TrendDataPoint represents a data point for trend charts
type TrendDataPoint struct {
	Date          string `json:"date"`
	TotalFindings int    `json:"totalFindings"`
	NewFindings   int    `json:"newFindings"`
	ResolvedCount int    `json:"resolvedCount"`
}

// GetFindingsTrend returns finding counts over time
func (s *StatsService) GetFindingsTrend(ctx context.Context, days int) ([]TrendDataPoint, error) {
	query := `
		WITH dates AS (
			SELECT generate_series(
				CURRENT_DATE - $1::int * INTERVAL '1 day',
				CURRENT_DATE,
				INTERVAL '1 day'
			)::date as date
		),
		new_findings AS (
			SELECT DATE(first_seen_at) as date, COUNT(*) as count
			FROM findings
			WHERE first_seen_at >= CURRENT_DATE - $1::int * INTERVAL '1 day'
			GROUP BY DATE(first_seen_at)
		),
		resolved_findings AS (
			SELECT DATE(resolved_at) as date, COUNT(*) as count
			FROM findings
			WHERE resolved_at >= CURRENT_DATE - $1::int * INTERVAL '1 day'
			GROUP BY DATE(resolved_at)
		)
		SELECT 
			d.date::text,
			COALESCE(nf.count, 0) as new_findings,
			COALESCE(rf.count, 0) as resolved_count
		FROM dates d
		LEFT JOIN new_findings nf ON d.date = nf.date
		LEFT JOIN resolved_findings rf ON d.date = rf.date
		ORDER BY d.date
	`

	rows, err := s.db.Query(ctx, query, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trend []TrendDataPoint
	for rows.Next() {
		var dp TrendDataPoint
		if err := rows.Scan(&dp.Date, &dp.NewFindings, &dp.ResolvedCount); err != nil {
			return nil, err
		}
		trend = append(trend, dp)
	}

	return trend, nil
}

// AssessmentBySeverity represents assessment counts for a specific severity
type AssessmentBySeverity struct {
	Severity     string `json:"severity"`
	Pending      int    `json:"pending"`
	Relevant     int    `json:"relevant"`
	NotRelevant  int    `json:"notRelevant"`
	AcceptedRisk int    `json:"acceptedRisk"`
	Total        int    `json:"total"`
}

// GetAssessmentStatsBySeverity returns assessment statistics grouped by severity
func (s *StatsService) GetAssessmentStatsBySeverity(ctx context.Context) ([]AssessmentBySeverity, error) {
	query := `
		WITH finding_assessments AS (
			SELECT 
				LOWER(COALESCE(f.severity, 'unknown')) as severity,
				COALESCE(a.status, 'pending') as status
			FROM findings f
			LEFT JOIN assessments a ON f.cve_id = a.cve_id
			WHERE f.resolved_at IS NULL
		)
		SELECT 
			severity,
			COUNT(*) FILTER (WHERE status = 'pending') as pending,
			COUNT(*) FILTER (WHERE status = 'relevant') as relevant,
			COUNT(*) FILTER (WHERE status = 'not_relevant') as not_relevant,
			COUNT(*) FILTER (WHERE status = 'accepted_risk') as accepted_risk,
			COUNT(*) as total
		FROM finding_assessments
		GROUP BY severity
		ORDER BY 
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END
	`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []AssessmentBySeverity
	for rows.Next() {
		var stat AssessmentBySeverity
		if err := rows.Scan(
			&stat.Severity, &stat.Pending, &stat.Relevant,
			&stat.NotRelevant, &stat.AcceptedRisk, &stat.Total,
		); err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}

	return stats, nil
}
