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

// TopCVEData represents a CVE for the report
type TopCVEData struct {
	CVEID          string
	CVSS3Score     float64 // NVD CVSS score (preferred)
	NVDSeverity    string  // NVD severity derived from CVSS
	VendorSeverity string  // Vendor severity from OVAL
	ServerCount    int
	PackageCount   int
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

	return data, nil
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
			COUNT(DISTINCT f.package_name) as package_count
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
		if err := rows.Scan(&cve.CVEID, &cve.CVSS3Score, &cve.VendorSeverity, &cve.ServerCount, &cve.PackageCount); err != nil {
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
			MIN(f.first_seen_at) as first_seen
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
		if err := rows.Scan(&cve.CVEID, &cve.CVSS3Score, &cve.VendorSeverity, &cve.Summary, &cve.ServerCount, &cve.FirstSeen); err != nil {
			return nil, err
		}
		// Derive NVD severity from CVSS score
		cve.NVDSeverity = cvssToSeverity(cve.CVSS3Score)
		cves = append(cves, cve)
	}

	return cves, nil
}

func (s *ReportService) getTrendData(ctx context.Context, serverIDs []int64, startDate, endDate time.Time) ([]TrendPoint, error) {
	// Generate daily data points
	whereClause := ""
	args := []interface{}{}
	argIndex := 1

	if len(serverIDs) > 0 {
		whereClause = fmt.Sprintf(" AND server_id = ANY($%d)", argIndex)
		args = append(args, serverIDs)
		argIndex++
	}

	// Get new findings per day
	newQuery := fmt.Sprintf(`
		SELECT DATE(first_seen_at) as date, COUNT(*) as count
		FROM findings
		WHERE first_seen_at >= $%d AND first_seen_at <= $%d %s
		GROUP BY DATE(first_seen_at)
		ORDER BY date
	`, argIndex, argIndex+1, whereClause)
	args = append(args, startDate, endDate)

	rows, err := s.db.Query(ctx, newQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	newByDate := make(map[string]int)
	for rows.Next() {
		var date time.Time
		var count int
		if err := rows.Scan(&date, &count); err != nil {
			return nil, err
		}
		newByDate[date.Format("2006-01-02")] = count
	}

	// Generate trend points for each day in range
	var trendData []TrendPoint
	for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
		dateStr := d.Format("2006-01-02")
		point := TrendPoint{
			Date:     d,
			NewCount: newByDate[dateStr],
		}
		trendData = append(trendData, point)
	}

	return trendData, nil
}

// generatePDF creates the PDF document
func (s *ReportService) generatePDF(data *ReportData) ([]byte, error) {
	cfg := config.NewBuilder().
		WithPageNumber().
		WithLeftMargin(15).
		WithTopMargin(15).
		WithRightMargin(15).
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

	// Add footer
	s.addFooter(m, data)

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
	// Section title
	m.AddRow(10,
		col.New(12).Add(
			text.New("Executive Summary", props.Text{
				Size:  14,
				Style: fontstyle.Bold,
			}),
		),
	)

	// Summary stats in a row
	m.AddRow(8,
		col.New(3).Add(
			text.New(fmt.Sprintf("Total Findings: %d", data.TotalFindings), props.Text{Size: 10}),
		),
		col.New(3).Add(
			text.New(fmt.Sprintf("Active: %d", data.ActiveFindings), props.Text{Size: 10, Style: fontstyle.Bold}),
		),
		col.New(3).Add(
			text.New(fmt.Sprintf("Resolved: %d", data.ResolvedFindings), props.Text{Size: 10}),
		),
		col.New(3).Add(
			text.New(fmt.Sprintf("Servers: %d", data.TotalServers), props.Text{Size: 10}),
		),
	)

	// Spacer
	m.AddRow(5, col.New(12))

	// Server statistics table
	if len(data.ServerStats) > 0 {
		m.AddRow(8,
			col.New(12).Add(
				text.New("Servers in Scope", props.Text{
					Size:  11,
					Style: fontstyle.Bold,
				}),
			),
		)

		// Table header
		grayBg := props.Color{Red: 240, Green: 240, Blue: 240}
		m.AddRow(7,
			col.New(4).Add(
				text.New("Server", props.Text{Size: 9, Style: fontstyle.Bold}),
			),
			col.New(2).Add(
				text.New("Critical", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New("High", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New("Medium", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New("Low", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
		).WithStyle(&props.Cell{BackgroundColor: &grayBg})

		// Table rows
		for _, stat := range data.ServerStats {
			m.AddRow(6,
				col.New(4).Add(
					text.New(stat.Name, props.Text{Size: 8}),
				),
				col.New(2).Add(
					text.New(fmt.Sprintf("%d", stat.Critical), props.Text{Size: 8, Align: align.Center}),
				),
				col.New(2).Add(
					text.New(fmt.Sprintf("%d", stat.High), props.Text{Size: 8, Align: align.Center}),
				),
				col.New(2).Add(
					text.New(fmt.Sprintf("%d", stat.Medium), props.Text{Size: 8, Align: align.Center}),
				),
				col.New(2).Add(
					text.New(fmt.Sprintf("%d", stat.Low), props.Text{Size: 8, Align: align.Center}),
				),
			)
		}
	}

	// Spacer
	m.AddRow(10, col.New(12))

	// Assessment statistics by severity table
	if len(data.AssessmentBySeverity) > 0 {
		m.AddRow(8,
			col.New(12).Add(
				text.New("Assessment Status by Severity", props.Text{
					Size:  11,
					Style: fontstyle.Bold,
				}),
			),
		)

		// Table header
		grayBg := props.Color{Red: 240, Green: 240, Blue: 240}
		m.AddRow(7,
			col.New(2).Add(
				text.New("Severity", props.Text{Size: 9, Style: fontstyle.Bold}),
			),
			col.New(2).Add(
				text.New("Pending", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New("Relevant", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New("Not Relevant", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New("Accepted", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New("Total", props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
		).WithStyle(&props.Cell{BackgroundColor: &grayBg})

		// Table rows
		var totalPending, totalRelevant, totalNotRelevant, totalAccepted, grandTotal int
		for _, stat := range data.AssessmentBySeverity {
			m.AddRow(6,
				col.New(2).Add(
					text.New(capitalizeFirst(stat.Severity), props.Text{Size: 8}),
				),
				col.New(2).Add(
					text.New(fmt.Sprintf("%d", stat.Pending), props.Text{Size: 8, Align: align.Center}),
				),
				col.New(2).Add(
					text.New(fmt.Sprintf("%d", stat.Relevant), props.Text{Size: 8, Align: align.Center}),
				),
				col.New(2).Add(
					text.New(fmt.Sprintf("%d", stat.NotRelevant), props.Text{Size: 8, Align: align.Center}),
				),
				col.New(2).Add(
					text.New(fmt.Sprintf("%d", stat.AcceptedRisk), props.Text{Size: 8, Align: align.Center}),
				),
				col.New(2).Add(
					text.New(fmt.Sprintf("%d", stat.Total), props.Text{Size: 8, Align: align.Center}),
				),
			)
			totalPending += stat.Pending
			totalRelevant += stat.Relevant
			totalNotRelevant += stat.NotRelevant
			totalAccepted += stat.AcceptedRisk
			grandTotal += stat.Total
		}

		// Totals row
		m.AddRow(7,
			col.New(2).Add(
				text.New("Total", props.Text{Size: 9, Style: fontstyle.Bold}),
			),
			col.New(2).Add(
				text.New(fmt.Sprintf("%d", totalPending), props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New(fmt.Sprintf("%d", totalRelevant), props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New(fmt.Sprintf("%d", totalNotRelevant), props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New(fmt.Sprintf("%d", totalAccepted), props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
			col.New(2).Add(
				text.New(fmt.Sprintf("%d", grandTotal), props.Text{Size: 9, Style: fontstyle.Bold, Align: align.Center}),
			),
		).WithStyle(&props.Cell{BackgroundColor: &grayBg})
	}

	// Spacer
	m.AddRow(10, col.New(12))
}

func (s *ReportService) addSeverityChart(m core.Maroto, data *ReportData) {
	// Section title
	m.AddRow(10,
		col.New(12).Add(
			text.New("Severity Distribution", props.Text{
				Size:  14,
				Style: fontstyle.Bold,
			}),
		),
	)

	// Generate pie chart
	chartBytes, err := s.generateSeverityPieChart(data)
	if err == nil && len(chartBytes) > 0 {
		// Centered chart - full width, large size
		m.AddRow(120,
			col.New(12).Add(
				image.NewFromBytes(chartBytes, extension.Png, props.Rect{
					Center:  true,
					Percent: 85,
				}),
			),
		)
	}

	// Legend below the chart - centered
	m.AddRow(5, col.New(12)) // Spacer
	legendRows := s.buildSeverityLegendRows(data)
	for _, r := range legendRows {
		m.AddRows(r)
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

func (s *ReportService) addTrendChart(m core.Maroto, data *ReportData) {
	// Section title
	m.AddRow(10,
		col.New(12).Add(
			text.New("Findings Trend", props.Text{
				Size:  14,
				Style: fontstyle.Bold,
			}),
		),
	)

	// Generate trend chart - full width
	chartBytes, err := s.generateTrendChart(data)
	if err == nil && len(chartBytes) > 0 {
		m.AddRow(100,
			col.New(12).Add(
				image.NewFromBytes(chartBytes, extension.Png, props.Rect{
					Center:  true,
					Percent: 90,
				}),
			),
		)
	}

	// Legend below the chart
	m.AddRow(5, col.New(12)) // Spacer
	legendRows := s.buildTrendLegendRows()
	for _, r := range legendRows {
		m.AddRows(r)
	}

	// Spacer
	m.AddRow(10, col.New(12))
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

	graph := chart.Chart{
		Width:  700,
		Height: 350,
		Background: chart.Style{
			FillColor: drawing.ColorWhite,
		},
		XAxis: chart.XAxis{
			Style: chart.Style{
				FontSize: 8,
			},
		},
		YAxis: chart.YAxis{
			Style: chart.Style{
				FontSize: 8,
			},
		},
		Series: []chart.Series{
			chart.TimeSeries{
				XValues: xValues,
				YValues: newValues,
				Style: chart.Style{
					StrokeColor: drawing.Color{R: 220, G: 53, B: 69, A: 255}, // Red for new
					StrokeWidth: 2,
				},
			},
			chart.TimeSeries{
				XValues: xValues,
				YValues: resolvedValues,
				Style: chart.Style{
					StrokeColor: drawing.Color{R: 40, G: 167, B: 69, A: 255}, // Green for resolved
					StrokeWidth: 2,
				},
			},
		},
	}

	// No legend on chart - will be added separately in PDF

	var buf bytes.Buffer
	if err := graph.Render(chart.PNG, &buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *ReportService) addTopCVEsTable(m core.Maroto, data *ReportData) {
	// Spacer before section
	m.AddRow(15, col.New(12))

	// Section title
	m.AddRow(10,
		col.New(12).Add(
			text.New("Top 10 Most Widespread CVEs", props.Text{
				Size:  14,
				Style: fontstyle.Bold,
			}),
		),
	)

	// Table header
	m.AddRow(8,
		col.New(3).Add(text.New("CVE ID", props.Text{Size: 9, Style: fontstyle.Bold})),
		col.New(1).Add(text.New("CVSS", props.Text{Size: 9, Style: fontstyle.Bold})),
		col.New(2).Add(text.New("Severity", props.Text{Size: 9, Style: fontstyle.Bold})),
		col.New(2).Add(text.New("Vendor Severity", props.Text{Size: 9, Style: fontstyle.Bold})),
		col.New(2).Add(text.New("Servers", props.Text{Size: 9, Style: fontstyle.Bold})),
		col.New(2).Add(text.New("Packages", props.Text{Size: 9, Style: fontstyle.Bold})),
	)

	// Table rows
	for _, cve := range data.TopCVEs {
		m.AddRow(7,
			col.New(3).Add(text.New(cve.CVEID, props.Text{Size: 8})),
			col.New(1).Add(text.New(fmt.Sprintf("%.1f", cve.CVSS3Score), props.Text{Size: 8})),
			col.New(2).Add(text.New(cve.NVDSeverity, props.Text{Size: 8})),
			col.New(2).Add(text.New(capitalizeFirst(cve.VendorSeverity), props.Text{Size: 8})),
			col.New(2).Add(text.New(fmt.Sprintf("%d", cve.ServerCount), props.Text{Size: 8})),
			col.New(2).Add(text.New(fmt.Sprintf("%d", cve.PackageCount), props.Text{Size: 8})),
		)
	}

	// Spacer
	m.AddRow(10, col.New(12))
}

func (s *ReportService) addFullCVEList(m core.Maroto, data *ReportData) {
	// Section title
	m.AddRow(10,
		col.New(12).Add(
			text.New(fmt.Sprintf("Complete CVE List (%d CVEs)", len(data.AllCVEs)), props.Text{
				Size:  14,
				Style: fontstyle.Bold,
			}),
		),
	)

	// Add each CVE
	for _, cve := range data.AllCVEs {
		// CVE header line
		m.AddRow(7,
			col.New(3).Add(text.New(cve.CVEID, props.Text{Size: 9, Style: fontstyle.Bold})),
			col.New(2).Add(text.New(fmt.Sprintf("CVSS: %.1f (%s)", cve.CVSS3Score, cve.NVDSeverity), props.Text{Size: 8})),
			col.New(2).Add(text.New(fmt.Sprintf("Vendor: %s", capitalizeFirst(cve.VendorSeverity)), props.Text{Size: 8})),
			col.New(2).Add(text.New(fmt.Sprintf("%d servers", cve.ServerCount), props.Text{Size: 8})),
			col.New(3).Add(text.New(cve.FirstSeen.Format("2006-01-02"), props.Text{Size: 8})),
		)

		// Full summary - use AutoRow for automatic height
		if cve.Summary != "" {
			m.AddAutoRow(
				col.New(12).Add(text.New(cve.Summary, props.Text{Size: 7})),
			)
		}

		// Small spacer between CVEs
		m.AddRow(4, col.New(12))
	}

	// Spacer
	m.AddRow(10, col.New(12))
}

func (s *ReportService) addFullCVEListToPage(p core.Page, data *ReportData) {
	// Section title
	p.Add(row.New(10).Add(
		col.New(12).Add(
			text.New(fmt.Sprintf("Complete CVE List (%d CVEs)", len(data.AllCVEs)), props.Text{
				Size:  14,
				Style: fontstyle.Bold,
			}),
		),
	))

	// Add each CVE
	for _, cve := range data.AllCVEs {
		// CVE header line
		p.Add(row.New(7).Add(
			col.New(3).Add(text.New(cve.CVEID, props.Text{Size: 9, Style: fontstyle.Bold})),
			col.New(2).Add(text.New(fmt.Sprintf("CVSS: %.1f (%s)", cve.CVSS3Score, cve.NVDSeverity), props.Text{Size: 8})),
			col.New(2).Add(text.New(fmt.Sprintf("Vendor: %s", capitalizeFirst(cve.VendorSeverity)), props.Text{Size: 8})),
			col.New(2).Add(text.New(fmt.Sprintf("%d servers", cve.ServerCount), props.Text{Size: 8})),
			col.New(3).Add(text.New(cve.FirstSeen.Format("2006-01-02"), props.Text{Size: 8})),
		))

		// Full summary without truncation
		if cve.Summary != "" {
			// Calculate approximate row height based on text length
			lines := (len(cve.Summary) / 100) + 1
			rowHeight := float64(lines * 4)
			if rowHeight < 6 {
				rowHeight = 6
			}
			p.Add(row.New(rowHeight).Add(
				col.New(12).Add(text.New(cve.Summary, props.Text{Size: 7})),
			))
		}

		// Small spacer between CVEs
		p.Add(row.New(4).Add(col.New(12)))
	}
}

func (s *ReportService) addFooter(m core.Maroto, data *ReportData) {
	m.AddRow(8,
		col.New(12).Add(
			text.New(
				fmt.Sprintf("Generated by VulTrack on %s", data.GeneratedAt.Format("2006-01-02 15:04:05")),
				props.Text{
					Size:  8,
					Align: align.Center,
				},
			),
		),
	)
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

func splitString(s string, maxLen int) []string {
	var result []string
	for len(s) > maxLen {
		// Find a good break point
		breakPoint := maxLen
		for i := maxLen; i > 0; i-- {
			if s[i] == ' ' || s[i] == ',' {
				breakPoint = i + 1
				break
			}
		}
		result = append(result, s[:breakPoint])
		s = s[breakPoint:]
	}
	if len(s) > 0 {
		result = append(result, s)
	}
	return result
}
