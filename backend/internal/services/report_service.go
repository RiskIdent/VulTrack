package services

import (
	"bytes"
	"context"
	"fmt"
	stdimage "image"
	stdcolor "image/color"
	"image/png"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/image"
	"github.com/johnfercher/maroto/v2/pkg/components/page"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/extension"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"
	"github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"
)

// ReportService handles report generation
type ReportService struct {
	db *pgxpool.Pool
}

// NewReportService creates a new ReportService
func NewReportService(db *pgxpool.Pool) *ReportService {
	return &ReportService{db: db}
}

// ReportRequest defines the parameters for generating a report
type ReportRequest struct {
	ServerIDs  []int64   `json:"serverIds"`
	GroupIDs   []int64   `json:"groupIds"`
	StartDate  time.Time `json:"startDate"`
	EndDate    time.Time `json:"endDate"`
	ReportType string    `json:"reportType"`
	// Selectable content sections
	IncludeSeverityChart bool `json:"includeSeverityChart"`
	IncludeTrendChart    bool `json:"includeTrendChart"`
	IncludeTopCVEs       bool `json:"includeTopCVEs"`
	IncludeFullCVEList   bool `json:"includeFullCVEList"`
}

// ReportData contains the data for the report
type ReportData struct {
	Title                string
	GeneratedAt          time.Time
	StartDate            time.Time
	EndDate              time.Time
	ServerNames          []string
	GroupNames           []string
	ServerStats          []ServerStat
	AssessmentBySeverity []AssessmentBySeverityStat
	TotalServers         int
	TotalFindings        int
	ActiveFindings       int
	ResolvedFindings     int
	SeverityCounts       map[string]int
	TopCVEs              []TopCVEData
	AllCVEs              []CVEDetail
	TrendData            []TrendPoint
	AssessmentStats      map[string]int
	VexStats             VexStats
	// Content flags
	IncludeSeverityChart bool
	IncludeTrendChart    bool
	IncludeTopCVEs       bool
	IncludeFullCVEList   bool
}

// AssessmentBySeverityStat represents assessment counts for a severity level
type AssessmentBySeverityStat struct {
	Severity     string
	Pending      int
	Relevant     int
	NotRelevant  int
	AcceptedRisk int
	Total        int
}

// ServerStat represents per-server statistics
type ServerStat struct {
	Name     string
	Critical int
	High     int
	Medium   int
	Low      int
}

// VexStats summarises VEX status counts for the report
type VexStats struct {
	NotAffected int
	Fixed       int
	Affected    int
	Total       int
}

// TopCVEData represents a CVE for the report
type TopCVEData struct {
	CVEID          string
	CVSS3Score     float64 // NVD CVSS score (preferred)
	NVDSeverity    string  // NVD severity derived from CVSS
	VendorSeverity string  // Vendor severity from OVAL
	ServerCount    int
	PackageCount   int
	VexStatus      string // dominant VEX status for this CVE
}

// CVEDetail represents a CVE with full details
type CVEDetail struct {
	CVEID          string
	CVSS3Score     float64 // NVD CVSS score (preferred)
	NVDSeverity    string  // NVD severity derived from CVSS
	VendorSeverity string  // Vendor severity from OVAL
	Summary        string
	ServerCount    int
	FirstSeen      time.Time
	VexStatus      string // dominant VEX status for this CVE
}

// TrendPoint represents a data point in the trend chart
type TrendPoint struct {
	Date          time.Time
	ActiveCount   int
	NewCount      int
	ResolvedCount int
}

// GenerateVulnerabilitySummary generates a PDF vulnerability summary report
func (s *ReportService) GenerateVulnerabilitySummary(ctx context.Context, req ReportRequest) ([]byte, error) {
	// Gather report data
	data, err := s.gatherReportData(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to gather report data: %w", err)
	}

	data.Title = "Vulnerability Summary Report"
	data.IncludeSeverityChart = req.IncludeSeverityChart
	data.IncludeTrendChart = req.IncludeTrendChart
	data.IncludeTopCVEs = req.IncludeTopCVEs
	data.IncludeFullCVEList = req.IncludeFullCVEList

	// Generate PDF
	return s.generatePDF(data)
}

// gatherReportData collects all data needed for the report
func (s *ReportService) gatherReportData(ctx context.Context, req ReportRequest) (*ReportData, error) {
	data := &ReportData{
		GeneratedAt:     time.Now(),
		StartDate:       req.StartDate,
		EndDate:         req.EndDate,
		SeverityCounts:  make(map[string]int),
		AssessmentStats: make(map[string]int),
	}

	// Build server filter
	serverIDs := req.ServerIDs

	// If group IDs are specified, get servers from those groups
	if len(req.GroupIDs) > 0 {
		groupServerIDs, groupNames, err := s.getServersFromGroups(ctx, req.GroupIDs)
		if err != nil {
			return nil, err
		}
		serverIDs = append(serverIDs, groupServerIDs...)
		data.GroupNames = groupNames
	}

	// Remove duplicates from serverIDs
	serverIDs = uniqueInt64Slice(serverIDs)

	// Get server names (always resolve to actual server names)
	if len(serverIDs) > 0 {
		serverNames, err := s.getServerNames(ctx, serverIDs)
		if err != nil {
			return nil, err
		}
		data.ServerNames = serverNames
		data.TotalServers = len(serverNames)
	} else {
		// All servers - get all names
		serverNames, count, err := s.getAllServerNames(ctx)
		if err != nil {
			return nil, err
		}
		data.ServerNames = serverNames
		data.TotalServers = count
	}

	// Get findings statistics
	stats, err := s.getFindingsStats(ctx, serverIDs, req.StartDate, req.EndDate)
	if err != nil {
		return nil, err
	}
	data.TotalFindings = stats.Total
	data.ActiveFindings = stats.Active
	data.ResolvedFindings = stats.Resolved
	data.SeverityCounts = stats.SeverityCounts

	// Get top CVEs
	if req.IncludeTopCVEs {
		topCVEs, err := s.getTopCVEs(ctx, serverIDs, req.StartDate, req.EndDate, 10)
		if err != nil {
			return nil, err
		}
		data.TopCVEs = topCVEs
	}

	// Get all CVEs if full list requested
	if req.IncludeFullCVEList {
		allCVEs, err := s.getAllCVEs(ctx, serverIDs, req.StartDate, req.EndDate)
		if err != nil {
			return nil, err
		}
		data.AllCVEs = allCVEs
	}

	// Get trend data if chart requested
	if req.IncludeTrendChart {
		trendData, err := s.getTrendData(ctx, serverIDs, req.StartDate, req.EndDate)
		if err != nil {
			return nil, err
		}
		data.TrendData = trendData
	}

	// Get per-server statistics for executive summary
	serverStats, err := s.getServerStats(ctx, serverIDs, req.StartDate, req.EndDate)
	if err != nil {
		return nil, err
	}
	data.ServerStats = serverStats

	// Get assessment statistics by severity for executive summary
	assessmentBySeverity, err := s.getAssessmentStatsBySeverity(ctx, serverIDs, req.StartDate, req.EndDate)
	if err != nil {
		return nil, err
	}
	data.AssessmentBySeverity = assessmentBySeverity

	// Get VEX status summary
	vexStats, err := s.getVexStats(ctx, serverIDs, req.StartDate, req.EndDate)
	if err != nil {
		return nil, err
	}
	data.VexStats = vexStats

	return data, nil
}

func (s *ReportService) getVexStats(ctx context.Context, serverIDs []int64, startDate, endDate time.Time) (VexStats, error) {
	whereClause := "WHERE vex_status IS NOT NULL"
	args := []interface{}{}
	argIndex := 1

	if len(serverIDs) > 0 {
		whereClause += fmt.Sprintf(" AND server_id = ANY($%d)", argIndex)
		args = append(args, serverIDs)
		argIndex++
	}
	if !endDate.IsZero() {
		whereClause += fmt.Sprintf(" AND first_seen_at <= $%d", argIndex)
		args = append(args, endDate)
		argIndex++
	}
	if !startDate.IsZero() {
		whereClause += fmt.Sprintf(" AND (resolved_at IS NULL OR resolved_at >= $%d)", argIndex)
		args = append(args, startDate)
	}

	query := fmt.Sprintf(`
		SELECT
			COUNT(*) FILTER (WHERE vex_status = 'not_affected'),
			COUNT(*) FILTER (WHERE vex_status = 'fixed'),
			COUNT(*) FILTER (WHERE vex_status = 'affected'),
			COUNT(*)
		FROM findings
		%s
	`, whereClause)

	var stats VexStats
	err := s.db.QueryRow(ctx, query, args...).Scan(
		&stats.NotAffected, &stats.Fixed, &stats.Affected, &stats.Total,
	)
	return stats, err
}

type findingsStats struct {
	Total          int
	Active         int
	Resolved       int
	SeverityCounts map[string]int
}

func (s *ReportService) getServersFromGroups(ctx context.Context, groupIDs []int64) ([]int64, []string, error) {
	if len(groupIDs) == 0 {
		return nil, nil, nil
	}

	query := `
		SELECT DISTINCT sgm.server_id, sg.name
		FROM server_group_members sgm
		JOIN server_groups sg ON sgm.group_id = sg.id
		WHERE sgm.group_id = ANY($1)
	`

	rows, err := s.db.Query(ctx, query, groupIDs)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var serverIDs []int64
	groupNamesMap := make(map[string]bool)

	for rows.Next() {
		var serverID int64
		var groupName string
		if err := rows.Scan(&serverID, &groupName); err != nil {
			return nil, nil, err
		}
		serverIDs = append(serverIDs, serverID)
		groupNamesMap[groupName] = true
	}

	var groupNames []string
	for name := range groupNamesMap {
		groupNames = append(groupNames, name)
	}

	return serverIDs, groupNames, nil
}

func (s *ReportService) getServerNames(ctx context.Context, serverIDs []int64) ([]string, error) {
	if len(serverIDs) == 0 {
		return nil, nil
	}

	query := `SELECT name FROM servers WHERE id = ANY($1) ORDER BY name`
	rows, err := s.db.Query(ctx, query, serverIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}

	return names, nil
}

func (s *ReportService) getAllServerNames(ctx context.Context) ([]string, int, error) {
	query := `SELECT name FROM servers ORDER BY name`
	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, 0, err
		}
		names = append(names, name)
	}

	return names, len(names), nil
}

func (s *ReportService) getServerStats(ctx context.Context, serverIDs []int64, startDate, endDate time.Time) ([]ServerStat, error) {
	query := `
		SELECT 
			s.name,
			COUNT(CASE WHEN LOWER(f.severity) = 'critical' AND f.resolved_at IS NULL THEN 1 END) as critical,
			COUNT(CASE WHEN LOWER(f.severity) = 'high' AND f.resolved_at IS NULL THEN 1 END) as high,
			COUNT(CASE WHEN LOWER(f.severity) = 'medium' AND f.resolved_at IS NULL THEN 1 END) as medium,
			COUNT(CASE WHEN LOWER(f.severity) = 'low' AND f.resolved_at IS NULL THEN 1 END) as low
		FROM servers s
		LEFT JOIN findings f ON s.id = f.server_id
			AND f.first_seen_at <= $2
			AND (f.resolved_at IS NULL OR f.resolved_at >= $1)
	`

	args := []interface{}{startDate, endDate}
	argIdx := 3

	if len(serverIDs) > 0 {
		query += fmt.Sprintf(" WHERE s.id = ANY($%d)", argIdx)
		args = append(args, serverIDs)
	}

	query += " GROUP BY s.id, s.name ORDER BY s.name"

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []ServerStat
	for rows.Next() {
		var stat ServerStat
		if err := rows.Scan(&stat.Name, &stat.Critical, &stat.High, &stat.Medium, &stat.Low); err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}

	return stats, nil
}

func (s *ReportService) getAssessmentStatsBySeverity(ctx context.Context, serverIDs []int64, startDate, endDate time.Time) ([]AssessmentBySeverityStat, error) {
	query := `
		WITH finding_assessments AS (
			SELECT 
				LOWER(COALESCE(f.severity, 'unknown')) as severity,
				COALESCE(a.status, 'pending') as status
			FROM findings f
			LEFT JOIN assessments a ON f.cve_id = a.cve_id
			WHERE f.resolved_at IS NULL
	`

	args := []interface{}{}
	argIdx := 1

	if len(serverIDs) > 0 {
		query += fmt.Sprintf(" AND f.server_id = ANY($%d)", argIdx)
		args = append(args, serverIDs)
		argIdx++
	}

	// Active during the report period
	if !endDate.IsZero() {
		query += fmt.Sprintf(" AND f.first_seen_at <= $%d", argIdx)
		args = append(args, endDate)
		argIdx++
	}

	if !startDate.IsZero() {
		query += fmt.Sprintf(" AND (f.resolved_at IS NULL OR f.resolved_at >= $%d)", argIdx)
		args = append(args, startDate)
	}

	query += `
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

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []AssessmentBySeverityStat
	for rows.Next() {
		var stat AssessmentBySeverityStat
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

func (s *ReportService) getFindingsStats(ctx context.Context, serverIDs []int64, startDate, endDate time.Time) (*findingsStats, error) {
	stats := &findingsStats{
		SeverityCounts: make(map[string]int),
	}

	// Build WHERE clause
	whereClause := "WHERE 1=1"
	args := []interface{}{}
	argIndex := 1

	if len(serverIDs) > 0 {
		whereClause += fmt.Sprintf(" AND server_id = ANY($%d)", argIndex)
		args = append(args, serverIDs)
		argIndex++
	}

	// "Active during the report period": first_seen_at <= endDate AND (resolved_at IS NULL OR resolved_at >= startDate)
	if !endDate.IsZero() {
		whereClause += fmt.Sprintf(" AND first_seen_at <= $%d", argIndex)
		args = append(args, endDate)
		argIndex++
	}

	if !startDate.IsZero() {
		whereClause += fmt.Sprintf(" AND (resolved_at IS NULL OR resolved_at >= $%d)", argIndex)
		args = append(args, startDate)
		argIndex++
	}

	// Total findings
	var total int
	err := s.db.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM findings %s`, whereClause), args...).Scan(&total)
	if err != nil {
		return nil, err
	}
	stats.Total = total

	// Active findings
	var active int
	err = s.db.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM findings %s AND resolved_at IS NULL`, whereClause), args...).Scan(&active)
	if err != nil {
		return nil, err
	}
	stats.Active = active
	stats.Resolved = total - active

	// Severity counts
	sevQuery := fmt.Sprintf(`
		SELECT LOWER(COALESCE(severity, 'unknown')), COUNT(*) 
		FROM findings %s AND resolved_at IS NULL
		GROUP BY LOWER(COALESCE(severity, 'unknown'))
	`, whereClause)

	rows, err := s.db.Query(ctx, sevQuery, args...)
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
		stats.SeverityCounts[severity] = count
	}

	return stats, nil
}

func (s *ReportService) getTopCVEs(ctx context.Context, serverIDs []int64, startDate, endDate time.Time, limit int) ([]TopCVEData, error) {
	// Active during the report period
	whereClause := "WHERE f.resolved_at IS NULL"
	args := []interface{}{}
	argIndex := 1

	if len(serverIDs) > 0 {
		whereClause += fmt.Sprintf(" AND f.server_id = ANY($%d)", argIndex)
		args = append(args, serverIDs)
		argIndex++
	}

	if !endDate.IsZero() {
		whereClause += fmt.Sprintf(" AND f.first_seen_at <= $%d", argIndex)
		args = append(args, endDate)
		argIndex++
	}

	query := fmt.Sprintf(`
		SELECT
			f.cve_id,
			COALESCE(MAX(cve.cvss3_score), MAX(f.cvss3_score), 0) as max_cvss,
			MAX(COALESCE(f.severity, '')) as vendor_severity,
			COUNT(DISTINCT f.server_id) as server_count,
			COUNT(DISTINCT f.package_name) as package_count,
			CASE
				WHEN bool_or(f.vex_status = 'affected')            THEN 'affected'
				WHEN bool_or(f.vex_status = 'under_investigation') THEN 'under_investigation'
				WHEN bool_or(f.vex_status = 'fixed')               THEN 'fixed'
				WHEN bool_or(f.vex_status = 'not_affected')        THEN 'not_affected'
				ELSE ''
			END as vex_status
		FROM findings f
		LEFT JOIN cve_catalog cve ON f.cve_id = cve.cve_id
		%s
		GROUP BY f.cve_id
		ORDER BY max_cvss DESC, server_count DESC
		LIMIT $%d
	`, whereClause, argIndex)
	args = append(args, limit)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cves []TopCVEData
	for rows.Next() {
		var cve TopCVEData
		if err := rows.Scan(&cve.CVEID, &cve.CVSS3Score, &cve.VendorSeverity, &cve.ServerCount, &cve.PackageCount, &cve.VexStatus); err != nil {
			return nil, err
		}
		// Derive NVD severity from CVSS score
		cve.NVDSeverity = cvssToSeverity(cve.CVSS3Score)
		cves = append(cves, cve)
	}

	return cves, nil
}

// cvssToSeverity converts CVSS 3.x score to severity string
func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score >= 0.1:
		return "Low"
	default:
		return "None"
	}
}

func (s *ReportService) getAllCVEs(ctx context.Context, serverIDs []int64, startDate, endDate time.Time) ([]CVEDetail, error) {
	// Active during the report period
	whereClause := "WHERE f.resolved_at IS NULL"
	args := []interface{}{}
	argIndex := 1

	if len(serverIDs) > 0 {
		whereClause += fmt.Sprintf(" AND f.server_id = ANY($%d)", argIndex)
		args = append(args, serverIDs)
		argIndex++
	}

	if !endDate.IsZero() {
		whereClause += fmt.Sprintf(" AND f.first_seen_at <= $%d", argIndex)
		args = append(args, endDate)
		argIndex++
	}

	query := fmt.Sprintf(`
		SELECT
			f.cve_id,
			COALESCE(MAX(cve.cvss3_score), MAX(f.cvss3_score), 0) as max_cvss,
			MAX(COALESCE(f.severity, '')) as vendor_severity,
			COALESCE(MAX(cve.description), MAX(f.summary), '') as summary,
			COUNT(DISTINCT f.server_id) as server_count,
			MIN(f.first_seen_at) as first_seen,
			CASE
				WHEN bool_or(f.vex_status = 'affected')            THEN 'affected'
				WHEN bool_or(f.vex_status = 'under_investigation') THEN 'under_investigation'
				WHEN bool_or(f.vex_status = 'fixed')               THEN 'fixed'
				WHEN bool_or(f.vex_status = 'not_affected')        THEN 'not_affected'
				ELSE ''
			END as vex_status
		FROM findings f
		LEFT JOIN cve_catalog cve ON f.cve_id = cve.cve_id
		%s
		GROUP BY f.cve_id
		ORDER BY max_cvss DESC, server_count DESC
	`, whereClause)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cves []CVEDetail
	for rows.Next() {
		var cve CVEDetail
		if err := rows.Scan(&cve.CVEID, &cve.CVSS3Score, &cve.VendorSeverity, &cve.Summary, &cve.ServerCount, &cve.FirstSeen, &cve.VexStatus); err != nil {
			return nil, err
		}
		// Derive NVD severity from CVSS score
		cve.NVDSeverity = cvssToSeverity(cve.CVSS3Score)
		cves = append(cves, cve)
	}

	return cves, nil
}

func (s *ReportService) getTrendData(ctx context.Context, serverIDs []int64, startDate, endDate time.Time) ([]TrendPoint, error) {
	// queryDailyByDate returns a map of date string → count for the given date column.
	queryDailyByDate := func(dateCol string) (map[string]int, error) {
		args := []interface{}{startDate, endDate}
		serverFilter := ""
		if len(serverIDs) > 0 {
			serverFilter = " AND server_id = ANY($3)"
			args = append(args, serverIDs)
		}

		q := fmt.Sprintf(`
			SELECT DATE(%s) AS d, COUNT(*) AS cnt
			FROM findings
			WHERE %s >= $1 AND %s <= $2 AND %s IS NOT NULL%s
			GROUP BY DATE(%s)
			ORDER BY 1
		`, dateCol, dateCol, dateCol, dateCol, serverFilter, dateCol)

		rows, err := s.db.Query(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		result := make(map[string]int)
		for rows.Next() {
			var d time.Time
			var cnt int
			if err := rows.Scan(&d, &cnt); err != nil {
				return nil, err
			}
			result[d.Format("2006-01-02")] = cnt
		}
		return result, rows.Err()
	}

	newByDate, err := queryDailyByDate("first_seen_at")
	if err != nil {
		return nil, err
	}
	resolvedByDate, err := queryDailyByDate("resolved_at")
	if err != nil {
		return nil, err
	}

	var trendData []TrendPoint
	for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
		dateStr := d.Format("2006-01-02")
		trendData = append(trendData, TrendPoint{
			Date:          d,
			NewCount:      newByDate[dateStr],
			ResolvedCount: resolvedByDate[dateStr],
		})
	}
	return trendData, nil
}

// generatePDF creates the PDF document
func (s *ReportService) generatePDF(data *ReportData) ([]byte, error) {
	cfg := config.NewBuilder().
		WithPageNumber(props.PageNumber{
			Pattern: "Generated by VulTrack  |  Page {current} of {total}",
			Place:   props.Bottom,
			Size:    8,
		}).
		WithLeftMargin(15).
		WithTopMargin(15).
		WithRightMargin(15).
		WithBottomMargin(18).
		Build()

	m := maroto.New(cfg)

	// Add header (always included)
	s.addHeader(m, data)

	// Add executive summary with server stats table (always included)
	s.addExecutiveSummary(m, data)

	// If no findings exist for this period, add a notice and skip data sections
	if data.TotalFindings == 0 {
		m.AddRow(10, col.New(12))
		m.AddRow(12,
			col.New(12).Add(
				text.New("No findings were recorded for the selected report period.", props.Text{
					Size:  12,
					Style: fontstyle.Bold,
					Align: align.Center,
				}),
			),
		)
		m.AddRow(8,
			col.New(12).Add(
				text.New(
					fmt.Sprintf("Period: %s to %s. This may indicate that no vulnerabilities were active during this time frame, or that vulnerability scans have not yet been performed for the servers in scope.",
						data.StartDate.Format("2006-01-02"),
						data.EndDate.Format("2006-01-02"),
					),
					props.Text{
						Size:  9,
						Align: align.Center,
					},
				),
			),
		)
	} else {
		// Add severity chart if requested (on new page to ensure it fits)
		if data.IncludeSeverityChart {
			severityPage := page.New()
			s.addSeverityChartToPage(severityPage, data)
			m.AddPages(severityPage)
		}

		// Add trend chart if requested (on new page to ensure it fits)
		if data.IncludeTrendChart && len(data.TrendData) > 0 {
			trendPage := page.New()
			s.addTrendChartToPage(trendPage, data)
			m.AddPages(trendPage)
		}

		// Add top CVEs table if requested
		if data.IncludeTopCVEs && len(data.TopCVEs) > 0 {
			s.addTopCVEsTable(m, data)
		}

		// Add full CVE list if requested (always on new page)
		if data.IncludeFullCVEList && len(data.AllCVEs) > 0 {
			// Add empty page to force page break, then add CVE list directly to maroto
			// This allows using AddAutoRow for dynamic text heights
			m.AddPages(page.New())
			s.addFullCVEList(m, data)
		}
	}

	// Generate PDF
	doc, err := m.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	pdfBytes := doc.GetBytes()
	return pdfBytes, nil
}

func (s *ReportService) addHeader(m core.Maroto, data *ReportData) {
	m.AddRow(15,
		col.New(12).Add(
			text.New(data.Title, props.Text{
				Size:  18,
				Style: fontstyle.Bold,
				Align: align.Center,
			}),
		),
	)

	// Date range
	dateRange := fmt.Sprintf("Report Period: %s to %s",
		data.StartDate.Format("2006-01-02"),
		data.EndDate.Format("2006-01-02"),
	)
	m.AddRow(8,
		col.New(12).Add(
			text.New(dateRange, props.Text{
				Size:  10,
				Align: align.Center,
			}),
		),
	)

	// Spacer
	m.AddRow(10, col.New(12))
}

func (s *ReportService) addExecutiveSummary(m core.Maroto, data *ReportData) {
	// Shared table style colours
	headerBg := &props.Color{Red: 41, Green: 82, Blue: 148}
	headerText := &props.Color{Red: 255, Green: 255, Blue: 255}
	zebraOdd := &props.Color{Red: 245, Green: 248, Blue: 253}
	totalsBg := &props.Color{Red: 225, Green: 232, Blue: 245}
	headerCell := &props.Cell{BackgroundColor: headerBg, BorderType: border.Full, BorderColor: headerBg}

	// Section title
	m.AddRow(10,
		col.New(12).Add(
			text.New("Executive Summary", props.Text{Size: 14, Style: fontstyle.Bold}),
		),
	)

	// Summary stats in a row
	m.AddRow(8,
		col.New(3).Add(text.New(fmt.Sprintf("Total Findings: %d", data.TotalFindings), props.Text{Size: 10})),
		col.New(3).Add(text.New(fmt.Sprintf("Active: %d", data.ActiveFindings), props.Text{Size: 10, Style: fontstyle.Bold})),
		col.New(3).Add(text.New(fmt.Sprintf("Resolved: %d", data.ResolvedFindings), props.Text{Size: 10})),
		col.New(3).Add(text.New(fmt.Sprintf("Servers: %d", data.TotalServers), props.Text{Size: 10})),
	)

	// VEX status overview (only if there is any VEX data)
	if data.VexStats.Total > 0 {
		m.AddRow(5, col.New(12))
		m.AddRow(8,
			col.New(12).Add(text.New("Vendor Assessment (VEX)", props.Text{Size: 11, Style: fontstyle.Bold})),
		)
		m.AddRow(7,
			col.New(4).Add(text.New("Not Affected (vendor confirmed)", props.Text{Size: 9})),
			col.New(2).Add(text.New(fmt.Sprintf("%d findings", data.VexStats.NotAffected), props.Text{Size: 9, Style: fontstyle.Bold})),
			col.New(3).Add(text.New("Fixed (patch available)", props.Text{Size: 9})),
			col.New(3).Add(text.New(fmt.Sprintf("%d findings", data.VexStats.Fixed), props.Text{Size: 9, Style: fontstyle.Bold})),
		)
		if data.VexStats.Affected > 0 {
			m.AddRow(7,
				col.New(4).Add(text.New("Confirmed Affected", props.Text{Size: 9})),
				col.New(8).Add(text.New(fmt.Sprintf("%d findings", data.VexStats.Affected), props.Text{Size: 9, Style: fontstyle.Bold})),
			)
		}
	}

	// Spacer
	m.AddRow(5, col.New(12))

	// --- Server statistics table ---
	if len(data.ServerStats) > 0 {
		m.AddRow(8,
			col.New(12).Add(text.New("Servers in Scope", props.Text{Size: 11, Style: fontstyle.Bold})),
		)

		m.AddRow(7,
			col.New(4).Add(text.New("Server", props.Text{Size: 9, Style: fontstyle.Bold, Color: headerText})),
			col.New(2).Add(text.New("Critical", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
			col.New(2).Add(text.New("High", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
			col.New(2).Add(text.New("Medium", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
			col.New(2).Add(text.New("Low", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
		).WithStyle(headerCell)

		for i, stat := range data.ServerStats {
			rowBg := &props.Color{Red: 255, Green: 255, Blue: 255}
			if i%2 == 1 {
				rowBg = zebraOdd
			}
			rowCell := &props.Cell{BackgroundColor: rowBg, BorderType: border.Full, BorderColor: headerBg}
			m.AddRow(6,
				col.New(4).Add(text.New(stat.Name, props.Text{Size: 8})),
				col.New(2).Add(text.New(fmt.Sprintf("%d", stat.Critical), props.Text{Size: 8, Align: align.Center})),
				col.New(2).Add(text.New(fmt.Sprintf("%d", stat.High), props.Text{Size: 8, Align: align.Center})),
				col.New(2).Add(text.New(fmt.Sprintf("%d", stat.Medium), props.Text{Size: 8, Align: align.Center})),
				col.New(2).Add(text.New(fmt.Sprintf("%d", stat.Low), props.Text{Size: 8, Align: align.Center})),
			).WithStyle(rowCell)
		}
	}

	// Spacer
	m.AddRow(8, col.New(12))

	// --- Assessment statistics by severity table ---
	if len(data.AssessmentBySeverity) > 0 {
		m.AddRow(8,
			col.New(12).Add(text.New("Assessment Status by Severity", props.Text{Size: 11, Style: fontstyle.Bold})),
		)

		m.AddRow(7,
			col.New(2).Add(text.New("Severity", props.Text{Size: 9, Style: fontstyle.Bold, Color: headerText})),
			col.New(2).Add(text.New("Pending", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
			col.New(2).Add(text.New("Relevant", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
			col.New(2).Add(text.New("Not Relevant", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
			col.New(2).Add(text.New("Accepted", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
			col.New(2).Add(text.New("Total", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
		).WithStyle(headerCell)

		var totalPending, totalRelevant, totalNotRelevant, totalAccepted, grandTotal int
		for i, stat := range data.AssessmentBySeverity {
			rowBg := &props.Color{Red: 255, Green: 255, Blue: 255}
			if i%2 == 1 {
				rowBg = zebraOdd
			}
			rowCell := &props.Cell{BackgroundColor: rowBg, BorderType: border.Full, BorderColor: headerBg}
			m.AddRow(6,
				col.New(2).Add(text.New(capitalizeFirst(stat.Severity), props.Text{Size: 8})),
				col.New(2).Add(text.New(fmt.Sprintf("%d", stat.Pending), props.Text{Size: 8, Align: align.Center})),
				col.New(2).Add(text.New(fmt.Sprintf("%d", stat.Relevant), props.Text{Size: 8, Align: align.Center})),
				col.New(2).Add(text.New(fmt.Sprintf("%d", stat.NotRelevant), props.Text{Size: 8, Align: align.Center})),
				col.New(2).Add(text.New(fmt.Sprintf("%d", stat.AcceptedRisk), props.Text{Size: 8, Align: align.Center})),
				col.New(2).Add(text.New(fmt.Sprintf("%d", stat.Total), props.Text{Size: 8, Align: align.Center})),
			).WithStyle(rowCell)
			totalPending += stat.Pending
			totalRelevant += stat.Relevant
			totalNotRelevant += stat.NotRelevant
			totalAccepted += stat.AcceptedRisk
			grandTotal += stat.Total
		}

		// Totals row
		totalsCell := &props.Cell{BackgroundColor: totalsBg, BorderType: border.Full, BorderColor: headerBg}
		m.AddRow(7,
			col.New(2).Add(text.New("Total", props.Text{Size: 9, Style: fontstyle.Bold})),
			col.New(2).Add(text.New(fmt.Sprintf("%d", totalPending), props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center})),
			col.New(2).Add(text.New(fmt.Sprintf("%d", totalRelevant), props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center})),
			col.New(2).Add(text.New(fmt.Sprintf("%d", totalNotRelevant), props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center})),
			col.New(2).Add(text.New(fmt.Sprintf("%d", totalAccepted), props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center})),
			col.New(2).Add(text.New(fmt.Sprintf("%d", grandTotal), props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center})),
		).WithStyle(totalsCell)
	}

	// Spacer
	m.AddRow(10, col.New(12))
}

func (s *ReportService) addSeverityChartToPage(p core.Page, data *ReportData) {
	// Section title
	p.Add(row.New(10).Add(
		col.New(12).Add(
			text.New("Severity Distribution", props.Text{
				Size:  14,
				Style: fontstyle.Bold,
			}),
		),
	))

	// Generate pie chart
	chartBytes, err := s.generateSeverityPieChart(data)
	if err == nil && len(chartBytes) > 0 {
		// Centered chart - full width, large size
		p.Add(row.New(120).Add(
			col.New(12).Add(
				image.NewFromBytes(chartBytes, extension.Png, props.Rect{
					Center:  true,
					Percent: 85,
				}),
			),
		))
	}

	// Spacer
	p.Add(row.New(5).Add(col.New(12)))

	// Legend below the chart - centered
	legendRows := s.buildSeverityLegendRows(data)
	for _, r := range legendRows {
		p.Add(r)
	}
}

func (s *ReportService) buildSeverityLegendRows(data *ReportData) []core.Row {
	severities := []struct {
		name  string
		color props.Color
	}{
		{"Critical", props.Color{Red: 220, Green: 53, Blue: 69}},
		{"High", props.Color{Red: 255, Green: 140, Blue: 0}},
		{"Medium", props.Color{Red: 255, Green: 193, Blue: 7}},
		{"Low", props.Color{Red: 40, Green: 167, Blue: 69}},
	}

	// Calculate total for percentages
	total := 0
	for _, sev := range severities {
		total += data.SeverityCounts[strings.ToLower(sev.name)]
	}

	var rows []core.Row

	for _, sev := range severities {
		count := data.SeverityCounts[strings.ToLower(sev.name)]
		percentage := float64(0)
		if total > 0 {
			percentage = float64(count) / float64(total) * 100
		}

		legendText := fmt.Sprintf("%s: %d (%.1f%%)", sev.name, count, percentage)

		// Generate a small colored square image for the legend
		colorBlock := s.generateColorBlock(sev.color)

		// Create a centered row with color block image and text
		r := row.New(8).Add(
			// Left spacer for centering
			col.New(3),
			// Color block as small image - aligned to bottom
			col.New(1).Add(
				image.NewFromBytes(colorBlock, extension.Png, props.Rect{
					Center:  true,
					Percent: 40,
					Top:     4, // Push down to align with text baseline
				}),
			),
			// Legend text
			col.New(4).Add(
				text.New(legendText, props.Text{
					Size:  11,
					Align: align.Left,
					Top:   1, // Slight adjustment for alignment
				}),
			),
			// Right spacer for centering
			col.New(4),
		)
		rows = append(rows, r)
	}

	return rows
}

// generateColorBlock creates a small colored square PNG image
func (s *ReportService) generateColorBlock(c props.Color) []byte {
	const size = 20

	// Create a simple PNG with a colored square
	// Using image/png and image/color
	img := createColoredSquare(size, c.Red, c.Green, c.Blue)

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

// createColoredSquare creates a colored square image
func createColoredSquare(size int, r, g, b int) *stdimage.RGBA {
	img := stdimage.NewRGBA(stdimage.Rect(0, 0, size, size))
	col := stdcolor.RGBA{R: uint8(r), G: uint8(g), B: uint8(b), A: 255}

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.Set(x, y, col)
		}
	}

	return img
}

func (s *ReportService) generateSeverityPieChart(data *ReportData) ([]byte, error) {
	// Define colors for severities
	colors := map[string]drawing.Color{
		"critical": drawing.Color{R: 220, G: 53, B: 69, A: 255},
		"high":     drawing.Color{R: 255, G: 140, B: 0, A: 255},
		"medium":   drawing.Color{R: 255, G: 193, B: 7, A: 255},
		"low":      drawing.Color{R: 40, G: 167, B: 69, A: 255},
		"unknown":  drawing.Color{R: 128, G: 128, B: 128, A: 255},
	}

	var values []chart.Value
	severities := []string{"critical", "high", "medium", "low"}

	for _, sev := range severities {
		count := data.SeverityCounts[sev]
		if count > 0 {
			values = append(values, chart.Value{
				Label: "", // No labels on pie chart - legend only
				Value: float64(count),
				Style: chart.Style{
					FillColor:   colors[sev],
					StrokeColor: drawing.ColorWhite,
					StrokeWidth: 2,
				},
			})
		}
	}

	if len(values) == 0 {
		return nil, fmt.Errorf("no data for pie chart")
	}

	pie := chart.PieChart{
		Width:  500,
		Height: 400,
		Values: values,
		Background: chart.Style{
			FillColor: drawing.ColorWhite,
		},
	}

	var buf bytes.Buffer
	if err := pie.Render(chart.PNG, &buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *ReportService) addTrendChartToPage(p core.Page, data *ReportData) {
	// Section title
	p.Add(row.New(10).Add(
		col.New(12).Add(
			text.New("Findings Trend", props.Text{
				Size:  14,
				Style: fontstyle.Bold,
			}),
		),
	))

	// Generate trend chart - full width
	chartBytes, err := s.generateTrendChart(data)
	if err == nil && len(chartBytes) > 0 {
		p.Add(row.New(100).Add(
			col.New(12).Add(
				image.NewFromBytes(chartBytes, extension.Png, props.Rect{
					Center:  true,
					Percent: 90,
				}),
			),
		))
	}

	// Spacer
	p.Add(row.New(5).Add(col.New(12)))

	// Legend below the chart
	legendRows := s.buildTrendLegendRows()
	for _, r := range legendRows {
		p.Add(r)
	}
}

func (s *ReportService) buildTrendLegendRows() []core.Row {
	items := []struct {
		name  string
		color props.Color
	}{
		{"New Findings", props.Color{Red: 220, Green: 53, Blue: 69}},
		{"Resolved Findings", props.Color{Red: 40, Green: 167, Blue: 69}},
	}

	var rows []core.Row

	for _, item := range items {
		// Generate a small colored square image for the legend
		colorBlock := s.generateColorBlock(item.color)

		// Create a centered row with color block image and text
		r := row.New(8).Add(
			// Left spacer for centering
			col.New(3),
			// Color block as small image
			col.New(1).Add(
				image.NewFromBytes(colorBlock, extension.Png, props.Rect{
					Center:  true,
					Percent: 40,
					Top:     4,
				}),
			),
			// Legend text
			col.New(4).Add(
				text.New(item.name, props.Text{
					Size:  11,
					Align: align.Left,
				}),
			),
			// Right spacer for centering
			col.New(4),
		)
		rows = append(rows, r)
	}

	return rows
}

func (s *ReportService) generateTrendChart(data *ReportData) ([]byte, error) {
	if len(data.TrendData) == 0 {
		return nil, fmt.Errorf("no trend data")
	}

	var xValues []time.Time
	var newValues []float64
	var resolvedValues []float64

	for _, point := range data.TrendData {
		xValues = append(xValues, point.Date)
		newValues = append(newValues, float64(point.NewCount))
		resolvedValues = append(resolvedValues, float64(point.ResolvedCount))
	}

	// Use Catmull-Rom spline interpolation for smooth curves
	smoothX, smoothNew := catmullRomInterpolate(xValues, newValues, 12)
	_, smoothResolved := catmullRomInterpolate(xValues, resolvedValues, 12)

	red := drawing.Color{R: 220, G: 53, B: 69, A: 255}
	green := drawing.Color{R: 40, G: 167, B: 69, A: 255}

	graph := chart.Chart{
		Width:  700,
		Height: 350,
		Background: chart.Style{
			FillColor: drawing.ColorWhite,
			Padding: chart.Box{
				Top:    10,
				Left:   20,
				Right:  10,
				Bottom: 10,
			},
		},
		XAxis: chart.XAxis{
			Style: chart.Style{
				FontSize: 8,
			},
		},
		YAxis: chart.YAxis{
			Name: "New Findings",
			NameStyle: chart.Style{
				FontSize:  8,
				FontColor: red,
			},
			Style: chart.Style{
				FontSize:  8,
				FontColor: red,
			},
		},
		YAxisSecondary: chart.YAxis{
			Name: "Resolved Findings",
			NameStyle: chart.Style{
				FontSize:  8,
				FontColor: green,
			},
			Style: chart.Style{
				FontSize:  8,
				FontColor: green,
			},
		},
		Series: []chart.Series{
			chart.TimeSeries{
				Name:    "New Findings",
				XValues: smoothX,
				YValues: smoothNew,
				Style: chart.Style{
					StrokeColor: red,
					StrokeWidth: 2,
				},
			},
			chart.TimeSeries{
				Name:    "Resolved Findings",
				YAxis:   chart.YAxisSecondary,
				XValues: smoothX,
				YValues: smoothResolved,
				Style: chart.Style{
					StrokeColor: green,
					StrokeWidth: 2,
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := graph.Render(chart.PNG, &buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// catmullRomInterpolate generates smooth curve points using Catmull-Rom spline interpolation.
// steps controls how many intermediate points are inserted between each pair of data points.
func catmullRomInterpolate(xs []time.Time, ys []float64, steps int) ([]time.Time, []float64) {
	n := len(xs)
	if n <= 1 {
		return xs, ys
	}

	xf := make([]float64, n)
	for i, t := range xs {
		xf[i] = float64(t.UnixNano())
	}

	var outX []time.Time
	var outY []float64

	for i := 0; i < n-1; i++ {
		i0 := i - 1
		if i0 < 0 {
			i0 = 0
		}
		i3 := i + 2
		if i3 >= n {
			i3 = n - 1
		}

		p0x, p1x, p2x, p3x := xf[i0], xf[i], xf[i+1], xf[i3]
		p0y, p1y, p2y, p3y := ys[i0], ys[i], ys[i+1], ys[i3]

		for j := 0; j <= steps; j++ {
			t := float64(j) / float64(steps)
			t2 := t * t
			t3 := t2 * t

			rx := 0.5 * ((2*p1x) + (-p0x+p2x)*t + (2*p0x-5*p1x+4*p2x-p3x)*t2 + (-p0x+3*p1x-3*p2x+p3x)*t3)
			ry := 0.5 * ((2*p1y) + (-p0y+p2y)*t + (2*p0y-5*p1y+4*p2y-p3y)*t2 + (-p0y+3*p1y-3*p2y+p3y)*t3)

			outX = append(outX, time.Unix(0, int64(rx)))
			outY = append(outY, ry)
		}
	}

	outX = append(outX, xs[n-1])
	outY = append(outY, ys[n-1])

	return outX, outY
}

func (s *ReportService) addTopCVEsTable(m core.Maroto, data *ReportData) {
	headerBg := &props.Color{Red: 41, Green: 82, Blue: 148}
	headerText := &props.Color{Red: 255, Green: 255, Blue: 255}
	zebraOdd := &props.Color{Red: 245, Green: 248, Blue: 253}
	headerCell := &props.Cell{BackgroundColor: headerBg, BorderType: border.Full, BorderColor: headerBg}

	// Spacer before section
	m.AddRow(15, col.New(12))

	m.AddRow(10,
		col.New(12).Add(text.New("Top 10 Most Widespread CVEs", props.Text{Size: 14, Style: fontstyle.Bold})),
	)

	m.AddRow(8,
		col.New(3).Add(text.New("CVE ID", props.Text{Size: 9, Style: fontstyle.Bold, Color: headerText})),
		col.New(1).Add(text.New("CVSS", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
		col.New(2).Add(text.New("Severity", props.Text{Size: 9, Style: fontstyle.Bold, Color: headerText})),
		col.New(1).Add(text.New("Servers", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
		col.New(1).Add(text.New("Pkgs", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center, Color: headerText})),
		col.New(4).Add(text.New("VEX Status (Vendor)", props.Text{Size: 9, Style: fontstyle.Bold, Color: headerText})),
	).WithStyle(headerCell)

	for i, cve := range data.TopCVEs {
		rowBg := &props.Color{Red: 255, Green: 255, Blue: 255}
		if i%2 == 1 {
			rowBg = zebraOdd
		}
		rowCell := &props.Cell{BackgroundColor: rowBg, BorderType: border.Full, BorderColor: headerBg}
		vexLabel := formatVexStatus(cve.VexStatus)
		m.AddRow(7,
			col.New(3).Add(text.New(cve.CVEID, props.Text{Size: 8})),
			col.New(1).Add(text.New(fmt.Sprintf("%.1f", cve.CVSS3Score), props.Text{Size: 8, Align: align.Center})),
			col.New(2).Add(text.New(cve.NVDSeverity, props.Text{Size: 8})),
			col.New(1).Add(text.New(fmt.Sprintf("%d", cve.ServerCount), props.Text{Size: 8, Align: align.Center})),
			col.New(1).Add(text.New(fmt.Sprintf("%d", cve.PackageCount), props.Text{Size: 8, Align: align.Center})),
			col.New(4).Add(text.New(vexLabel, props.Text{Size: 8})),
		).WithStyle(rowCell)
	}

	// Spacer
	m.AddRow(10, col.New(12))
}

func (s *ReportService) addFullCVEList(m core.Maroto, data *ReportData) {
	headerBg := &props.Color{Red: 41, Green: 82, Blue: 148}
	headerText := &props.Color{Red: 255, Green: 255, Blue: 255}
	zebraOdd := &props.Color{Red: 245, Green: 248, Blue: 253}
	headerCell := &props.Cell{BackgroundColor: headerBg, BorderType: border.Full, BorderColor: headerBg}

	m.AddRow(10,
		col.New(12).Add(text.New(fmt.Sprintf("Complete CVE List (%d CVEs)", len(data.AllCVEs)), props.Text{
			Size:  14,
			Style: fontstyle.Bold,
		})),
	)

	// Column header row
	m.AddRow(8,
		col.New(3).Add(text.New("CVE ID", props.Text{Size: 8, Style: fontstyle.Bold, Color: headerText, Top: 1.5})),
		col.New(1).Add(text.New("CVSS", props.Text{Size: 8, Style: fontstyle.Bold, Align: align.Center, Color: headerText, Top: 1.5})),
		col.New(2).Add(text.New("Severity", props.Text{Size: 8, Style: fontstyle.Bold, Color: headerText, Top: 1.5})),
		col.New(1).Add(text.New("Servers", props.Text{Size: 8, Style: fontstyle.Bold, Align: align.Center, Color: headerText, Top: 1.5})),
		col.New(2).Add(text.New("First Seen", props.Text{Size: 8, Style: fontstyle.Bold, Color: headerText, Top: 1.5})),
		col.New(3).Add(text.New("VEX Status", props.Text{Size: 8, Style: fontstyle.Bold, Color: headerText, Top: 1.5})),
	).WithStyle(headerCell)

	for i, cve := range data.AllCVEs {
		rowBg := &props.Color{Red: 255, Green: 255, Blue: 255}
		if i%2 == 1 {
			rowBg = zebraOdd
		}
		rowCell := &props.Cell{BackgroundColor: rowBg, BorderType: border.Full, BorderColor: headerBg}
		vexLabel := formatVexStatus(cve.VexStatus)

		m.AddRow(8,
			col.New(3).Add(text.New(cve.CVEID, props.Text{Size: 7.5, Style: fontstyle.Bold, Top: 1.5})),
			col.New(1).Add(text.New(fmt.Sprintf("%.1f", cve.CVSS3Score), props.Text{Size: 7.5, Align: align.Center, Top: 1.5})),
			col.New(2).Add(text.New(cve.NVDSeverity, props.Text{Size: 7.5, Top: 1.5})),
			col.New(1).Add(text.New(fmt.Sprintf("%d", cve.ServerCount), props.Text{Size: 7.5, Align: align.Center, Top: 1.5})),
			col.New(2).Add(text.New(cve.FirstSeen.Format("2006-01-02"), props.Text{Size: 7.5, Top: 1.5})),
			col.New(3).Add(text.New(vexLabel, props.Text{Size: 7.5, Top: 1.5})),
		).WithStyle(rowCell)

		if cve.Summary != "" {
			summaryCell := &props.Cell{BackgroundColor: rowBg, BorderType: border.Full, BorderColor: headerBg}
			m.AddAutoRow(
				col.New(1),
				col.New(11).Add(text.New(cve.Summary+"\n", props.Text{Size: 6.5, Top: 1, Left: 1})),
			).WithStyle(summaryCell)
		}
	}

	// Spacer
	m.AddRow(10, col.New(12))
}

// Helper functions
func uniqueInt64Slice(slice []int64) []int64 {
	seen := make(map[int64]bool)
	result := []int64{}
	for _, v := range slice {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	if s[0] >= 'a' && s[0] <= 'z' {
		return string(s[0]-32) + s[1:]
	}
	return s
}

// formatVexStatus converts a raw vex_status value to a human-readable label.
func formatVexStatus(status string) string {
	switch status {
	case "not_affected":
		return "Not Affected"
	case "fixed":
		return "Fixed"
	case "affected":
		return "Affected"
	case "under_investigation":
		return "Under Investigation"
	default:
		return "—"
	}
}
