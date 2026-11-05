package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
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

// vendorActionableCondition keeps only findings the vendor still means to fix
// or already has: 'affected' and 'fix_available'. It drops 'will_not_fix'
// (Canonical decided to ignore the CVE, from OVAL or VEX) and 'deferred'.
// Rows without a fix_state predate the column and count as 'affected'.
//
// It deliberately looks at fix_state rather than vex_status: the scan rewrites
// fix_state on every run, so a finding reappears as soon as the vendor changes
// its mind, whereas vex_status is never cleared once set.
const vendorActionableCondition = `COALESCE(NULLIF(f.fix_state, ''), 'affected') IN ('affected', 'fix_available')`

// FindingFilter defines filter options for querying findings
type FindingFilter struct {
	ServerID  *int64
	CVEID     *string
	Severity  *string
	MinCVSS   *float64
	VexStatus *string // filter by vex_status value (e.g. 'not_affected')
	// HideVendorAccepted drops findings the vendor will not fix or has deferred
	// (see vendorActionableCondition).
	HideVendorAccepted bool
	KEVOnly            bool     // only CVEs listed in CISA KEV
	MinEPSS            *float64 // only CVEs with an EPSS score >= this probability (0-1)
	Search             string   // free-text search across cve_id, package_name, server_name
	IncludeResolved    bool
	SortBy             string // column to sort by (cveId, serverName, packageName, cvss3Score, severity, fixState, fixedIn, firstSeenAt, epss)
	SortOrder          string // asc or desc
	Limit              int
	Offset             int
}

// GetAll returns findings with optional filters (lightweight list view, no exploit/description data).
func (s *FindingService) GetAll(ctx context.Context, filter FindingFilter) ([]models.Finding, int, error) {
	baseWhere, args := findingsWhere(filter)
	argIndex := len(args) + 1

	// Lightweight COUNT (no exploit join)
	countFrom := `FROM findings f JOIN servers srv ON f.server_id = srv.id LEFT JOIN cve_catalog cve ON f.cve_id = cve.cve_id`
	if needsThreatIntelJoin(filter) {
		countFrom += threatIntelJoins
	}
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
			COALESCE(f.fix_state, ''), COALESCE(f.fixed_in, ''), COALESCE(f.fix_pocket, ''), f.cvss3_score,
			COALESCE(f.severity, ''), COALESCE(f.source_link, ''),
			COALESCE(f.source_type, ''),
			f.first_seen_at, f.last_seen_at, f.resolved_at, f.created_at, f.updated_at,
			srv.name as server_name,
			cve.cvss3_score,
			COALESCE(cve.cvss3_severity, ''),
			f.vex_status, f.vex_justification
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
		if err := rows.Scan(
			&f.ID, &f.ServerID, &f.CVEID, &f.PackageName, &f.PackageVersion,
			&f.FixState, &f.FixedIn, &f.FixPocket, &f.CVSS3Score, &f.Severity, &f.SourceLink,
			&f.SourceType,
			&f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt,
			&f.ServerName,
			&f.NVDCvss3Score, &f.CVSS3Severity,
			&f.VexStatus, &f.VexJustification,
		); err != nil {
			return nil, 0, fmt.Errorf("scan error: %w", err)
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	cveIDs := make([]string, len(findings))
	for i := range findings {
		cveIDs[i] = findings[i].CVEID
	}
	intel, err := loadThreatIntel(ctx, s.db, cveIDs)
	if err != nil {
		return nil, 0, err
	}
	for i := range findings {
		findings[i].ThreatIntel = intel[findings[i].CVEID]
	}

	return findings, total, nil
}

// findingsWhere builds the WHERE clause shared by GetAll and GetAllGrouped and
// the arguments it binds. It may reference f (findings), srv (servers), cve
// (cve_catalog), kev (kev_entries) and ep (epss_scores).
func findingsWhere(filter FindingFilter) (string, []any) {
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
	if filter.VexStatus != nil {
		baseWhere += ` AND f.vex_status = $` + strconv.Itoa(argIndex)
		args = append(args, *filter.VexStatus)
		argIndex++
	}
	if filter.HideVendorAccepted {
		baseWhere += ` AND ` + vendorActionableCondition
	}
	if filter.KEVOnly {
		baseWhere += ` AND kev.cve_id IS NOT NULL`
	}
	if filter.MinEPSS != nil {
		baseWhere += ` AND ep.epss >= $` + strconv.Itoa(argIndex)
		args = append(args, *filter.MinEPSS)
		argIndex++
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
	_ = argIndex
	return baseWhere, args
}

// threatIntelJoins adds the KEV listing and EPSS score of a finding's CVE. Both
// are primary-key lookups; Postgres drops either join when a query does not
// reference it.
const threatIntelJoins = `
		LEFT JOIN kev_entries kev ON kev.cve_id = f.cve_id
		LEFT JOIN epss_scores ep ON ep.cve_id = f.cve_id`

// threatIntelColumns selects the fields scanned by threatIntelDest.
const threatIntelColumns = `kev.cve_id IS NOT NULL, kev.date_added, kev.due_date,
			COALESCE(kev.known_ransomware_use, false), ep.epss::float8, ep.percentile::float8`

// needsThreatIntelJoin reports whether a findings query must join KEV and EPSS
// itself, because it filters or sorts by them. Otherwise the signals are
// attached to the page afterwards (attachThreatIntel), which keeps them off the
// millions of rows the query scans before it sorts and limits.
func needsThreatIntelJoin(filter FindingFilter) bool {
	return filter.KEVOnly || filter.MinEPSS != nil || filter.SortBy == "epss"
}

// loadThreatIntel returns the KEV and EPSS data of the given CVEs.
func loadThreatIntel(ctx context.Context, db *pgxpool.Pool, cveIDs []string) (map[string]models.ThreatIntel, error) {
	out := make(map[string]models.ThreatIntel, len(cveIDs))
	if len(cveIDs) == 0 {
		return out, nil
	}
	rows, err := db.Query(ctx, `
		SELECT f.cve_id, `+threatIntelColumns+`
		FROM (SELECT DISTINCT unnest($1::text[]) AS cve_id) f`+threatIntelJoins, cveIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var t models.ThreatIntel
		if err := rows.Scan(append([]any{&id}, threatIntelDest(&t)...)...); err != nil {
			return nil, err
		}
		out[id] = t
	}
	return out, rows.Err()
}

func threatIntelDest(t *models.ThreatIntel) []any {
	return []any{&t.InKEV, &t.KEVDateAdded, &t.KEVDueDate, &t.KEVRansomware, &t.EPSS, &t.EPSSPercentile}
}

// GetAllGrouped returns findings aggregated by (server_id, cve_id). Each row contains
// the per-package details as a JSON array. Pagination is over groups, not raw findings.
//
// Sorting in grouped mode supports cveId, serverName, cvss3Score, severity, firstSeenAt.
// Package-level sort fields (packageName, fixState, fixedIn) fall back to cvss3Score —
// they have no meaning at the group level.
func (s *FindingService) GetAllGrouped(ctx context.Context, filter FindingFilter) ([]models.GroupedFinding, int, error) {
	baseWhere, args := findingsWhere(filter)
	argIndex := len(args) + 1

	from := `FROM findings f
		JOIN servers srv ON f.server_id = srv.id
		LEFT JOIN cve_catalog cve ON f.cve_id = cve.cve_id`
	if needsThreatIntelJoin(filter) {
		from += threatIntelJoins
	}

	orderBy := groupedFindingsOrderBy(filter.SortBy, filter.SortOrder)

	// Step 1: the page of group keys, ranked by the sort columns only, with the
	// number of groups from the same pass (COUNT(*) OVER () runs before LIMIT).
	// Building the per-package JSON for every group and discarding all but one
	// page took ~30 s on millions of findings.
	keyQuery := `SELECT f.server_id, f.cve_id, COUNT(*) OVER () ` + from + baseWhere + `
		GROUP BY f.server_id, srv.name, f.cve_id` + orderBy
	keyArgs := append([]any{}, args...)
	if filter.Limit > 0 {
		keyQuery += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, len(keyArgs)+1, len(keyArgs)+2)
		keyArgs = append(keyArgs, filter.Limit, filter.Offset)
	}
	keyRows, err := s.db.Query(ctx, keyQuery, keyArgs...)
	if err != nil {
		return nil, 0, err
	}
	total := -1
	var pageServers []int64
	var pageCVEs []string
	for keyRows.Next() {
		var sid int64
		var cve string
		if err := keyRows.Scan(&sid, &cve, &total); err != nil {
			keyRows.Close()
			return nil, 0, err
		}
		pageServers = append(pageServers, sid)
		pageCVEs = append(pageCVEs, cve)
	}
	keyRows.Close()
	if err := keyRows.Err(); err != nil {
		return nil, 0, err
	}
	if total < 0 {
		// An empty page (e.g. offset past the end) carries no count; count apart.
		if err := s.db.QueryRow(ctx,
			`SELECT COUNT(*) FROM (SELECT 1 `+from+baseWhere+` GROUP BY f.server_id, f.cve_id) g`, args...,
		).Scan(&total); err != nil {
			return nil, 0, err
		}
	}
	if len(pageServers) == 0 {
		return []models.GroupedFinding{}, total, nil
	}

	// Step 2: the details of those groups only, with the same filters so the
	// package lists match what the groups were ranked on.
	args = append(args, pageServers, pageCVEs)
	baseWhere += fmt.Sprintf(` AND (f.server_id, f.cve_id) IN (SELECT * FROM unnest($%d::bigint[], $%d::text[]))`, argIndex, argIndex+1)
	argIndex += 2

	selectQuery := `
		SELECT
			f.server_id,
			srv.name AS server_name,
			f.cve_id,
			COALESCE(MAX(f.severity), '') AS severity,
			MAX(f.cvss3_score) AS finding_cvss,
			MAX(cve.cvss3_score) AS nvd_cvss,
			COALESCE(MAX(f.source_link), '') AS source_link,
			COALESCE(MAX(f.source_type), '') AS source_type,
			COUNT(*)::int AS package_count,
			SUM(CASE WHEN f.resolved_at IS NULL THEN 1 ELSE 0 END)::int AS active_count,
			BOOL_AND(f.resolved_at IS NOT NULL) AS all_resolved,
			MIN(f.first_seen_at) AS earliest_first_seen,
			MAX(f.last_seen_at) AS latest_last_seen,
			COALESCE(
				ARRAY_AGG(DISTINCT f.fix_state) FILTER (WHERE f.fix_state IS NOT NULL AND f.fix_state != ''),
				'{}'
			) AS fix_states,
			COALESCE(
				ARRAY_AGG(DISTINCT f.vex_status) FILTER (WHERE f.vex_status IS NOT NULL),
				'{}'
			) AS vex_statuses,
			JSONB_AGG(JSONB_BUILD_OBJECT(
				'id', f.id,
				'name', f.package_name,
				'version', COALESCE(f.package_version, ''),
				'fixedIn', COALESCE(f.fixed_in, ''),
				'fixState', COALESCE(f.fix_state, ''),
				'fixPocket', COALESCE(f.fix_pocket, ''),
				-- Cast naive timestamps to timestamptz so JSON gets a proper RFC 3339
				-- offset suffix. Without this, Go's time.Time JSON unmarshal fails on
				-- the offset-less form Postgres emits for "timestamp without time zone".
				-- pgx writes/reads these columns as UTC by convention, so 'UTC' matches.
				'firstSeenAt', f.first_seen_at AT TIME ZONE 'UTC',
				'lastSeenAt', f.last_seen_at AT TIME ZONE 'UTC',
				'resolvedAt', f.resolved_at AT TIME ZONE 'UTC',
				'vexStatus', f.vex_status,
				'vexJustification', f.vex_justification
			) ORDER BY f.package_name) AS packages
	` + from + baseWhere + `
		GROUP BY f.server_id, srv.name, f.cve_id
	` + orderBy
	_ = argIndex

	rows, err := s.db.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var groups []models.GroupedFinding
	for rows.Next() {
		var g models.GroupedFinding
		var packagesJSON []byte
		err := rows.Scan(
			&g.ServerID, &g.ServerName, &g.CVEID,
			&g.Severity,
			&g.CVSS3Score, &g.NVDCvss3Score,
			&g.SourceLink, &g.SourceType,
			&g.PackageCount, &g.ActiveCount, &g.AllResolved,
			&g.EarliestFirstSeen, &g.LatestLastSeen,
			&g.FixStates, &g.VexStatuses,
			&packagesJSON,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan grouped finding: %w", err)
		}
		if len(packagesJSON) > 0 {
			if err := json.Unmarshal(packagesJSON, &g.Packages); err != nil {
				return nil, 0, fmt.Errorf("unmarshal packages: %w", err)
			}
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	cveIDs := make([]string, len(groups))
	for i := range groups {
		cveIDs[i] = groups[i].CVEID
	}
	intel, err := loadThreatIntel(ctx, s.db, cveIDs)
	if err != nil {
		return nil, 0, err
	}
	for i := range groups {
		groups[i].ThreatIntel = intel[groups[i].CVEID]
	}

	return groups, total, nil
}

// groupedFindingsOrderBy returns an ORDER BY clause for the grouped findings query.
// Package-level sort fields fall back to CVSS — they don't have a single value per group.
func groupedFindingsOrderBy(sortBy, sortOrder string) string {
	dir := "DESC"
	if sortOrder == "asc" {
		dir = "ASC"
	}
	nulls := "NULLS LAST"
	if dir == "ASC" {
		nulls = "NULLS FIRST"
	}

	col := "MAX(COALESCE(cve.cvss3_score, f.cvss3_score))"
	switch sortBy {
	case "cveId":
		col = "f.cve_id"
	case "serverName":
		col = "srv.name"
	case "severity":
		col = "MAX(f.severity)"
	case "firstSeenAt":
		col = "MIN(f.first_seen_at)"
	case "epss":
		col = "MAX(ep.epss)"
	}

	return fmt.Sprintf(` ORDER BY %s %s %s, f.cve_id ASC, srv.name ASC`, col, dir, nulls)
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
	case "epss":
		col = "ep.epss"
	}

	return fmt.Sprintf(` ORDER BY %s %s %s, f.id DESC`, col, dir, nulls)
}

// TriageFilterOptions defines filter options for the triage queue
type TriageFilterOptions struct {
	Mode               string   // "cvss" or "vendor_severity"
	CVSSThreshold      float64  // Used when Mode == "cvss"
	VendorSeverities   []string // Used when Mode == "vendor_severity"
	IncludeUnrated     bool     // Include findings without vendor severity
	HideVexNotAffected bool     // When true, exclude findings with vex_status = 'not_affected'
	HideVendorAccepted bool     // When true, only findings the vendor still means to fix count (see vendorActionableCondition)
	// AutoActiveRules are the rules whose automated decisions take effect
	// (AutoAssessmentConfig.ActiveRuleIDs). A (server, CVE) pair dismissed by
	// such a decision, and not blocked by a guard, leaves the queue. Empty when
	// automation is off or in shadow mode; the queue is then as before.
	AutoActiveRules []string
	Limit           int
	Offset          int
}

// triageQueueFrom builds the FROM/WHERE part shared by the triage queue and its
// count, and the arguments it binds. ok is false when the options select
// nothing at all (vendor-severity mode with no severity and no unrated).
func triageQueueFrom(opts TriageFilterOptions) (from string, args []any, ok bool) {
	var filterCondition string
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
			// No severities selected and not including unrated
			return "", nil, false
		}
	} else {
		// CVSS mode (default) - use NVD CVSS score with fallback
		filterCondition = fmt.Sprintf("COALESCE(cve.cvss3_score, f.cvss3_score) >= $%d", argIndex)
		args = append(args, opts.CVSSThreshold)
	}

	notAffectedClause := ""
	if opts.HideVexNotAffected {
		notAffectedClause = "\n\t\tAND (f.vex_status IS NULL OR f.vex_status != 'not_affected')"
	}
	// Applied per finding, before the queue groups by CVE: a CVE stays in the
	// queue as long as any one of its findings is still actionable.
	if opts.HideVendorAccepted {
		notAffectedClause += "\n\t\tAND " + vendorActionableCondition
	}

	// A human decision for this server takes it out of the queue; 'manual' only
	// switches automation off and keeps it in. Written as NOT EXISTS so Postgres
	// runs an anti-join against the (small) decision tables instead of joining
	// and sorting every finding.
	decisionClause := `
		AND NOT EXISTS (SELECT 1 FROM assessment_overrides o
		                WHERE o.server_id = f.server_id AND o.cve_id = f.cve_id AND o.status <> 'manual')`
	if len(opts.AutoActiveRules) > 0 {
		args = append(args, opts.AutoActiveRules)
		decisionClause += fmt.Sprintf(`
		AND NOT EXISTS (SELECT 1 FROM auto_decisions d
		                WHERE d.server_id = f.server_id AND d.cve_id = f.cve_id
		                  AND cardinality(d.guards) = 0 AND d.rule_ids <@ $%d::text[]
		                  AND NOT EXISTS (SELECT 1 FROM assessment_overrides o2
		                                  WHERE o2.server_id = d.server_id AND o2.cve_id = d.cve_id))`, len(args))
	}

	from = fmt.Sprintf(`
		FROM findings f
		JOIN servers srv ON f.server_id = srv.id
		LEFT JOIN cve_catalog cve ON f.cve_id = cve.cve_id
		LEFT JOIN assessments a ON f.cve_id = a.cve_id
		WHERE f.resolved_at IS NULL
		AND %s
		AND (a.id IS NULL OR a.status = 'pending')%s%s
	`, filterCondition, notAffectedClause, decisionClause)
	return from, args, true
}

// CountTriageQueue returns the number of CVEs in the triage queue, the same
// number GetTriageQueue reports as its total.
func (s *FindingService) CountTriageQueue(ctx context.Context, opts TriageFilterOptions) (int, error) {
	return countTriageQueue(ctx, s.db, opts)
}

func countTriageQueue(ctx context.Context, db *pgxpool.Pool, opts TriageFilterOptions) (int, error) {
	baseQuery, args, ok := triageQueueFrom(opts)
	if !ok {
		return 0, nil
	}
	var total int
	err := db.QueryRow(ctx, `SELECT COUNT(DISTINCT f.cve_id) `+baseQuery, args...).Scan(&total)
	return total, err
}

// GetTriageQueue returns findings that need assessment based on filter options
func (s *FindingService) GetTriageQueue(ctx context.Context, opts TriageFilterOptions) ([]models.Finding, int, error) {
	baseQuery, args, ok := triageQueueFrom(opts)
	if !ok {
		return []models.Finding{}, 0, nil
	}
	argIndex := len(args) + 1

	total, err := countTriageQueue(ctx, s.db, opts)
	if err != nil {
		return nil, 0, err
	}

	// Get unique CVEs with their findings
	limitPlaceholder := fmt.Sprintf("$%d", argIndex)
	offsetPlaceholder := fmt.Sprintf("$%d", argIndex+1)
	args = append(args, opts.Limit, opts.Offset)

	// One row per CVE (its highest-scoring finding), ordered by priority: KEV
	// listing first, then EPSS, then CVSS. The UI loads a bounded number of CVEs,
	// so the order decides which ones it sees when the queue is larger. KEV and
	// EPSS are joined after DISTINCT ON has reduced the findings to one row per
	// CVE, not to every finding.
	selectQuery := fmt.Sprintf(`
		SELECT q.id, q.server_id, q.cve_id, q.package_name, q.package_version, q.fix_state, q.fixed_in,
		       q.cvss3_score, q.severity, q.summary, q.source_link, q.source_type,
		       q.first_seen_at, q.last_seen_at, q.resolved_at, q.created_at, q.updated_at,
		       q.server_name, q.nvd_description, q.nvd_cvss, q.vex_status, q.vex_justification,
		       `+threatIntelColumns+`
		FROM (
			SELECT DISTINCT ON (f.cve_id)
				f.id, f.server_id, f.cve_id, f.package_name, COALESCE(f.package_version, '') AS package_version,
				COALESCE(f.fix_state, '') AS fix_state, COALESCE(f.fixed_in, '') AS fixed_in, f.cvss3_score,
				COALESCE(f.severity, '') AS severity, COALESCE(f.summary, '') AS summary,
				COALESCE(f.source_link, '') AS source_link, COALESCE(f.source_type, '') AS source_type,
				f.first_seen_at, f.last_seen_at, f.resolved_at, f.created_at, f.updated_at,
				srv.name AS server_name,
				COALESCE(cve.description, '') AS nvd_description,
				cve.cvss3_score AS nvd_cvss,
				f.vex_status, f.vex_justification,
				COALESCE(cve.cvss3_score, f.cvss3_score) AS priority_cvss
			%s
			ORDER BY f.cve_id, COALESCE(cve.cvss3_score, f.cvss3_score) DESC NULLS LAST
		) q`+strings.ReplaceAll(threatIntelJoins, "f.cve_id", "q.cve_id")+`
		ORDER BY (kev.cve_id IS NOT NULL) DESC, ep.epss DESC NULLS LAST, q.priority_cvss DESC NULLS LAST, q.cve_id
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
			&f.VexStatus, &f.VexJustification,
			&f.InKEV, &f.KEVDateAdded, &f.KEVDueDate, &f.KEVRansomware, &f.EPSS, &f.EPSSPercentile,
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
			COALESCE(f.fix_state, ''), COALESCE(f.fixed_in, ''), COALESCE(f.fix_pocket, ''), f.cvss3_score,
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
			-- Ubuntu package feed triage information
			COALESCE(ubuntu.ubuntu_priority, ''),
			COALESCE(ubuntu.notes, ARRAY[]::text[]),
			COALESCE(ubuntu.mitigation, ''),
			-- ExploitDB enrichment
			COALESCE(exp.exploit_count, 0)::int,
			COALESCE(exp.exploit_ids, ARRAY[]::int[]),
			COALESCE(exp.has_verified, false),
			-- VEX enrichment
			f.vex_status, f.vex_justification,
			-- CISA KEV and FIRST EPSS
			` + threatIntelColumns + `
		FROM findings f
		JOIN servers srv ON f.server_id = srv.id
		LEFT JOIN cve_catalog cve ON f.cve_id = cve.cve_id` + threatIntelJoins + `
		-- OVAL descriptions are release-specific (they name the Ubuntu release, the
		-- USN and the fixed package versions), so the definition must come from an
		-- OVAL source matching this server's distribution release. Without that
		-- filter the newest definition for the CVE won — typically from whichever
		-- release synced last — and a 24.04 finding could be described with 26.04
		-- update instructions. The finding's own source type is preferred so a USN
		-- finding keeps its advisory text.
		LEFT JOIN LATERAL (
			SELECT od.description
			FROM oval_definitions od
			JOIN oval_sources os ON os.id = od.source_id
			WHERE f.cve_id = ANY(od.cve_ids)
			  AND os.distribution = LOWER(srv.os_family)
			  AND (
			    os.version = srv.os_release
			    OR (COALESCE(srv.os_codename, '') <> '' AND os.codename = srv.os_codename)
			  )
			ORDER BY (COALESCE(os.source_type, 'usn') = COALESCE(f.source_type, 'usn')) DESC,
			         od.id DESC
			LIMIT 1
		) oval_desc ON true
		-- Canonical's own triage information for this CVE on this server's release.
		-- ubuntu_priority reflects real-world impact where CVSS often does not,
		-- and notes/mitigation are free-text guidance nothing else provides.
		LEFT JOIN LATERAL (
			SELECT m.ubuntu_priority, m.notes, m.mitigation
			FROM pkg_cve_metadata m
			JOIN oval_sources os ON os.id = m.source_id
			WHERE m.cve_id = f.cve_id
			  AND os.distribution = LOWER(srv.os_family)
			  AND (
			    os.version = srv.os_release
			    OR (COALESCE(srv.os_codename, '') <> '' AND os.codename = srv.os_codename)
			  )
			LIMIT 1
		) ubuntu ON true
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

	dest := []any{
		&f.ID, &f.ServerID, &f.CVEID, &f.PackageName, &f.PackageVersion,
		&f.FixState, &f.FixedIn, &f.FixPocket, &f.CVSS3Score, &f.Severity, &f.Summary, &f.SourceLink,
		&f.SourceType,
		&f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt,
		&f.ServerName,
		// NVD
		&f.NVDDescription, &f.NVDCvss3Score, &f.CVSS3Vector, &f.CVSS3Severity, &f.CVSS2Score, &f.CWEIDs, &f.CVEPublishedAt,
		// OVAL
		&ovalDescription,
		// Ubuntu package feed
		&f.UbuntuPriority, &f.UbuntuNotes, &f.UbuntuMitigation,
		// ExploitDB
		&exploitCount, &exploitIDs, &hasVerified,
		// VEX
		&f.VexStatus, &f.VexJustification,
	}
	err := s.db.QueryRow(ctx, query, id).Scan(append(dest, threatIntelDest(&f.ThreatIntel)...)...)
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
			f.fix_state, f.fixed_in, COALESCE(f.fix_pocket, ''), f.cvss3_score, f.severity, f.summary, f.source_link,
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
			&f.FixState, &f.FixedIn, &f.FixPocket, &f.CVSS3Score, &f.Severity, &f.Summary, &f.SourceLink,
			&f.SourceType,
			&f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt,
			&f.ServerName,
		)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}

	return findings, rows.Err()
}

// TriageQueueCVEIDs returns up to limit CVEs of the triage queue in queue
// order (KEV, EPSS, CVSS) that still have a server no rule has decided:
// candidates for the AI precondition analysis. Decisions of excludeRule (the
// AI stage itself) and decisions blocked by a guard do not count as decided.
func (s *FindingService) TriageQueueCVEIDs(ctx context.Context, opts TriageFilterOptions, excludeRule string, limit int) ([]string, error) {
	baseQuery, args, ok := triageQueueFrom(opts)
	if !ok {
		return []string{}, nil
	}
	args = append(args, excludeRule, limit)
	q := fmt.Sprintf(`
		SELECT q.cve_id FROM (
			SELECT DISTINCT ON (f.cve_id) f.cve_id, COALESCE(cve.cvss3_score, f.cvss3_score) AS priority_cvss
			%s
			  AND NOT EXISTS (SELECT 1 FROM auto_decisions d
			                  WHERE d.server_id = f.server_id AND d.cve_id = f.cve_id
			                    AND cardinality(d.guards) = 0 AND NOT ($%d = ANY(d.rule_ids)))
			ORDER BY f.cve_id
		) q`+strings.ReplaceAll(threatIntelJoins, "f.cve_id", "q.cve_id")+`
		ORDER BY (kev.cve_id IS NOT NULL) DESC, ep.epss DESC NULLS LAST, q.priority_cvss DESC NULLS LAST, q.cve_id
		LIMIT $%d`, baseQuery, len(args)-1, len(args))
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
