package services

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
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
	PendingAssessments int            `json:"pendingAssessments"` // CVEs in the triage queue
	SeverityBreakdown  map[string]int `json:"severityBreakdown"`
}

// GetDashboardStats returns overview statistics. PendingAssessments is the size
// of the triage queue under the given options (see BuildTriageOptions); it stays
// zero when triage is nil.
func (s *StatsService) GetDashboardStats(ctx context.Context, triage *TriageFilterOptions) (*DashboardStats, error) {
	stats := &DashboardStats{
		SeverityBreakdown: make(map[string]int),
	}

	// Get server count
	err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM servers`).Scan(&stats.TotalServers)
	if err != nil {
		return nil, err
	}

	// All finding counts in one pass over the table (it holds millions of rows;
	// these were five separate scans).
	rows, err := s.db.Query(ctx, `
		SELECT COALESCE(LOWER(severity), 'unknown') AS sev,
		       COUNT(*) AS total,
		       COUNT(*) FILTER (WHERE resolved_at IS NULL) AS active
		FROM findings
		GROUP BY 1
	`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		var total, active int
		if err := rows.Scan(&sev, &total, &active); err != nil {
			rows.Close()
			return nil, err
		}
		stats.TotalFindings += total
		stats.ActiveFindings += active
		if active > 0 {
			stats.SeverityBreakdown[sev] += active
		}
		switch sev {
		case "critical":
			stats.CriticalFindings = active
		case "high":
			stats.HighFindings = active
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	stats.ResolvedFindings = stats.TotalFindings - stats.ActiveFindings

	// Pending assessments: the CVEs in the triage queue, filtered exactly as the
	// Triage page filters them. Callers that only need the other numbers pass nil.
	if triage != nil {
		stats.PendingAssessments, err = countTriageQueue(ctx, s.db, *triage)
		if err != nil {
			return nil, err
		}
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
	models.ThreatIntel
}

// GetTopCVEs returns CVEs affecting the most servers
func (s *StatsService) GetTopCVEs(ctx context.Context, limit int) ([]TopCVE, error) {
	// Ranked on a pre-aggregation (one row per CVE and server) joined to the
	// catalog only after grouping; the descriptive columns are then read for the
	// returned rows alone. Aggregating every finding with two COUNT(DISTINCT)s and
	// a catalog join per row took seconds on millions of findings.
	query := `
		WITH per_server AS (
			SELECT cve_id, server_id, MAX(cvss3_score) AS cvss
			FROM findings
			WHERE resolved_at IS NULL
			GROUP BY cve_id, server_id
		), ranked AS (
			SELECT p.cve_id, COUNT(*) AS server_count,
			       COALESCE(MAX(cve.cvss3_score), MAX(p.cvss)) AS cvss3_score
			FROM per_server p
			LEFT JOIN cve_catalog cve ON cve.cve_id = p.cve_id
			GROUP BY p.cve_id
			ORDER BY server_count DESC, cvss3_score DESC NULLS LAST, p.cve_id
			LIMIT $1
		)
		SELECT r.cve_id, r.cvss3_score, d.severity, d.source_link, r.server_count, d.package_count
		FROM ranked r
		CROSS JOIN LATERAL (
			SELECT COALESCE(MAX(f.severity), '') AS severity,
			       MAX(f.source_link) FILTER (WHERE f.source_link IS NOT NULL AND f.source_link != '') AS source_link,
			       COUNT(DISTINCT f.package_name) AS package_count
			FROM findings f
			WHERE f.cve_id = r.cve_id AND f.resolved_at IS NULL
		) d
		ORDER BY r.server_count DESC, r.cvss3_score DESC NULLS LAST, r.cve_id
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	cveIDs := make([]string, len(cves))
	for i := range cves {
		cveIDs[i] = cves[i].CVEID
	}
	intel, err := loadThreatIntel(ctx, s.db, cveIDs)
	if err != nil {
		return nil, err
	}
	for i := range cves {
		cves[i].ThreatIntel = intel[cves[i].CVEID]
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
