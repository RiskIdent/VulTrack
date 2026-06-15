// Package mcp exposes VulTrack's data and triage actions over the Model Context
// Protocol so that AI agents can read findings/stats and perform triage actions.
//
// Two server instances are built: a read-only server (only query tools) and a
// read-write server (query tools plus mutating tools). The HTTP layer routes an
// authenticated request to one or the other based on the API token's read-only
// flag, so a read-only token can never even see the write tools.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/models"
	"github.com/vultrack/vultrack/internal/scanqueue"
	"github.com/vultrack/vultrack/internal/services"
)

// serverName / serverVersion identify this MCP server to clients.
const (
	serverName    = "vultrack"
	serverVersion = "1.0.0"
)

// Deps holds the services and shared logic the MCP tools delegate to. These are
// the same service objects (and, where settings or side-effects are involved,
// the same code paths) the REST handlers use, so the MCP interface behaves
// identically to the UI — including admin-configured triage settings and Jira
// ticket creation.
type Deps struct {
	ServerService      *services.ServerService
	FindingService     *services.FindingService
	AssessmentService  *services.AssessmentService
	StatsService       *services.StatsService
	ServerGroupService *services.ServerGroupService
	SettingsService    *services.SettingsService
	ScanQueue          *scanqueue.Queue

	// UpsertAssessment performs the same create-or-update assessment logic as the
	// REST API — status validation plus Jira ticket creation when relevant. It is
	// injected by the handler layer so the MCP write path shares that behaviour.
	UpsertAssessment func(ctx context.Context, cveID, status, comment, assessedBy string) (*models.Assessment, error)
}

// BuildServers constructs the read-only and read-write MCP servers.
func BuildServers(d Deps) (readOnly, readWrite *mcpsdk.Server) {
	readOnly = mcpsdk.NewServer(&mcpsdk.Implementation{Name: serverName, Version: serverVersion, Title: "VulTrack (read-only)"}, nil)
	readWrite = mcpsdk.NewServer(&mcpsdk.Implementation{Name: serverName, Version: serverVersion, Title: "VulTrack"}, nil)

	registerReadTools(readOnly, d)
	registerReadTools(readWrite, d)
	registerWriteTools(readWrite, d)

	return readOnly, readWrite
}

// jsonResult marshals v to a JSON text content block.
func jsonResult(v any) (*mcpsdk.CallToolResult, any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode result: %w", err)
	}
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: string(b)}},
	}, nil, nil
}

// paginatedResult wraps a page of items with pagination metadata so the agent
// knows whether more results exist. To retrieve everything, the agent repeats
// the call with offset += limit while hasMore is true. total is always the full
// count, independent of limit.
func paginatedResult(extra map[string]any, total, limit, offset int) (*mcpsdk.CallToolResult, any, error) {
	m := map[string]any{
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"hasMore": offset+limit < total,
	}
	for k, v := range extra {
		m[k] = v
	}
	return jsonResult(m)
}

// emptyInput is the input type for tools that take no arguments.
type emptyInput struct{}

// clampLimit applies a sane default and ceiling to a caller-supplied limit.
func clampLimit(limit, def, max int) int {
	if limit <= 0 {
		return def
	}
	if limit > max {
		return max
	}
	return limit
}

// triageFilterInfo describes the effective triage configuration (the admin
// settings that determine which findings appear in the triage queue) so the
// agent can explain the result and reconcile it with the UI.
func triageFilterInfo(opts services.TriageFilterOptions) map[string]any {
	info := map[string]any{
		"mode":               opts.Mode,
		"hideVexNotAffected": opts.HideVexNotAffected,
	}
	if opts.Mode == "vendor_severity" {
		info["vendorSeverities"] = opts.VendorSeverities
		info["includeUnrated"] = opts.IncludeUnrated
	} else {
		info["cvssThreshold"] = opts.CVSSThreshold
	}
	return info
}

// ----------------------------------------------------------------------------
// Read tools (registered on both the read-only and read-write servers)
// ----------------------------------------------------------------------------

type getServerInput struct {
	ServerID int64 `json:"serverId" jsonschema:"the numeric ID of the server"`
}

type listFindingsInput struct {
	ServerID        int64   `json:"serverId,omitempty" jsonschema:"filter by server ID (0 = all servers)"`
	CVEID           string  `json:"cveId,omitempty" jsonschema:"filter by CVE ID, e.g. CVE-2024-1234"`
	Severity        string  `json:"severity,omitempty" jsonschema:"filter by severity: critical, high, medium, low, negligible"`
	MinCVSS         float64 `json:"minCvss,omitempty" jsonschema:"only findings with CVSS score >= this value"`
	VexStatus       string  `json:"vexStatus,omitempty" jsonschema:"filter by VEX status: not_affected, will_not_fix, under_investigation"`
	Search          string  `json:"search,omitempty" jsonschema:"free-text search across CVE, package and server name"`
	IncludeResolved bool    `json:"includeResolved,omitempty" jsonschema:"include resolved findings (default false)"`
	Limit           int     `json:"limit,omitempty" jsonschema:"max results per call (default 50, max 500)"`
	Offset          int     `json:"offset,omitempty" jsonschema:"results to skip for pagination; increase by limit to fetch the next page"`
}

type getFindingInput struct {
	FindingID int64 `json:"findingId" jsonschema:"the numeric ID of the finding"`
}

type cveInput struct {
	CVEID string `json:"cveId" jsonschema:"the CVE ID, e.g. CVE-2024-1234"`
}

type listTriageInput struct {
	Limit  int `json:"limit,omitempty" jsonschema:"max results per call (default 50, max 500)"`
	Offset int `json:"offset,omitempty" jsonschema:"results to skip for pagination; increase by limit to fetch the next page"`
}

type listAssessmentsInput struct {
	Search   string  `json:"search,omitempty" jsonschema:"free-text search across CVE, comment and author"`
	Status   string  `json:"status,omitempty" jsonschema:"filter by status: relevant, not_relevant, accepted_risk"`
	MinCVSS  float64 `json:"minCvss,omitempty" jsonschema:"only assessments with CVSS score >= this value"`
	Severity string  `json:"severity,omitempty" jsonschema:"filter by vendor severity, e.g. critical"`
	Limit    int     `json:"limit,omitempty" jsonschema:"max results per call (default 50, max 200)"`
	Offset   int     `json:"offset,omitempty" jsonschema:"results to skip for pagination; increase by limit to fetch the next page"`
}

type daysInput struct {
	Days int `json:"days,omitempty" jsonschema:"number of days to look back (default 30)"`
}

type limitInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"max results to return (default 10)"`
}

type groupInput struct {
	GroupID int64 `json:"groupId" jsonschema:"the numeric ID of the server group"`
}

func registerReadTools(s *mcpsdk.Server, d Deps) {
	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "list_servers",
		Description: "List all monitored servers with their vulnerability status.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ emptyInput) (*mcpsdk.CallToolResult, any, error) {
		servers, err := d.ServerService.GetAll(ctx)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(map[string]any{"servers": servers, "total": len(servers)})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_server",
		Description: "Get a single server by its ID.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in getServerInput) (*mcpsdk.CallToolResult, any, error) {
		server, err := d.ServerService.GetByID(ctx, in.ServerID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("server %d not found", in.ServerID)
		}
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(server)
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "list_findings",
		Description: "Search and filter vulnerability findings across all servers. " +
			"`severity` is the vendor severity (from the OVAL/distro source); `cvss3Score` is the NVD CVSS score — they can differ. " +
			"By default only unresolved findings are returned (set includeResolved=true to include fixed ones), sorted by CVSS descending. " +
			"The response echoes the effective filter (including defaults) in `appliedFilter`. " +
			"Paginated: returns at most `limit` findings per call (default 50, max 500) plus the full `total`. " +
			"When the response field `hasMore` is true, call again with `offset` increased by `limit` to fetch all results.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in listFindingsInput) (*mcpsdk.CallToolResult, any, error) {
		filter := services.FindingFilter{
			Search:          in.Search,
			IncludeResolved: in.IncludeResolved,
			SortBy:          "cvss3Score", // same defaults as the REST API / UI
			SortOrder:       "desc",
			Limit:           clampLimit(in.Limit, 50, 500),
			Offset:          in.Offset,
		}
		if in.ServerID > 0 {
			filter.ServerID = &in.ServerID
		}
		if in.CVEID != "" {
			filter.CVEID = &in.CVEID
		}
		if in.Severity != "" {
			filter.Severity = &in.Severity
		}
		if in.MinCVSS > 0 {
			filter.MinCVSS = &in.MinCVSS
		}
		if in.VexStatus != "" {
			filter.VexStatus = &in.VexStatus
		}
		findings, total, err := d.FindingService.GetAll(ctx, filter)
		if err != nil {
			return nil, nil, err
		}
		applied := map[string]any{
			"includeResolved": filter.IncludeResolved,
			"sortBy":          filter.SortBy,
			"sortOrder":       filter.SortOrder,
		}
		if filter.ServerID != nil {
			applied["serverId"] = *filter.ServerID
		}
		if filter.CVEID != nil {
			applied["cveId"] = *filter.CVEID
		}
		if filter.Severity != nil {
			applied["severity"] = *filter.Severity
		}
		if filter.MinCVSS != nil {
			applied["minCvss"] = *filter.MinCVSS
		}
		if filter.VexStatus != nil {
			applied["vexStatus"] = *filter.VexStatus
		}
		if filter.Search != "" {
			applied["search"] = filter.Search
		}
		return paginatedResult(map[string]any{"findings": findings, "appliedFilter": applied}, total, filter.Limit, filter.Offset)
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_finding",
		Description: "Get a single vulnerability finding by its ID.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in getFindingInput) (*mcpsdk.CallToolResult, any, error) {
		finding, err := d.FindingService.GetByID(ctx, in.FindingID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("finding %d not found", in.FindingID)
		}
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(finding)
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_cve",
		Description: "Get details for a CVE including the affected servers and any existing assessment.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in cveInput) (*mcpsdk.CallToolResult, any, error) {
		findings, err := d.FindingService.GetServersByCVE(ctx, in.CVEID)
		if err != nil {
			return nil, nil, err
		}
		if len(findings) == 0 {
			return nil, nil, fmt.Errorf("CVE %s not found", in.CVEID)
		}
		assessment, _ := d.AssessmentService.GetByCVE(ctx, in.CVEID)
		return jsonResult(map[string]any{
			"cveId":       in.CVEID,
			"findings":    findings,
			"serverCount": len(findings),
			"assessment":  assessment,
		})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "list_cve_servers",
		Description: "List all servers affected by a given CVE.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in cveInput) (*mcpsdk.CallToolResult, any, error) {
		findings, err := d.FindingService.GetServersByCVE(ctx, in.CVEID)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(map[string]any{"cveId": in.CVEID, "findings": findings, "total": len(findings)})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "list_triage_queue",
		Description: "List the triage queue exactly as configured in VulTrack's admin settings. " +
			"The queue composition is admin-controlled: filter mode (vendor severities or CVSS threshold), " +
			"whether unrated findings are included, and whether VEX 'not affected' findings are hidden. " +
			"The response `filter` object reports the exact settings that produced the result, so the count " +
			"can be reconciled with the UI. Returns the same findings as the UI. " +
			"Paginated: returns at most `limit` findings per call (default 50, max 500) plus the full `total`. " +
			"When `hasMore` is true, call again with `offset` increased by `limit` to fetch all results.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in listTriageInput) (*mcpsdk.CallToolResult, any, error) {
		// Build the filter from the configured triage settings — same source of
		// truth as the REST API, so the result matches the UI's triage queue.
		opts, err := d.SettingsService.BuildTriageOptions(ctx)
		if err != nil {
			return nil, nil, err
		}
		opts.Limit = clampLimit(in.Limit, 50, 500)
		opts.Offset = in.Offset

		findings, total, err := d.FindingService.GetTriageQueue(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		return paginatedResult(map[string]any{"findings": findings, "filter": triageFilterInfo(opts)}, total, opts.Limit, opts.Offset)
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "list_assessments",
		Description: "List CVE assessments (triage decisions) with optional filters. " +
			"Paginated: returns at most `limit` assessments per call (default 50, max 200) plus the full `total`. " +
			"When `hasMore` is true, call again with `offset` increased by `limit` to fetch all results.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in listAssessmentsInput) (*mcpsdk.CallToolResult, any, error) {
		filter := services.AssessmentFilter{
			Search:    in.Search,
			Status:    in.Status,
			MinCVSS:   in.MinCVSS,
			Severity:  in.Severity,
			SortBy:    "assessedAt", // same defaults as the REST API / UI
			SortOrder: "desc",
			Limit:     clampLimit(in.Limit, 50, 200),
			Offset:    in.Offset,
		}
		assessments, total, err := d.AssessmentService.GetAll(ctx, filter)
		if err != nil {
			return nil, nil, err
		}
		applied := map[string]any{
			"sortBy":    filter.SortBy,
			"sortOrder": filter.SortOrder,
		}
		if filter.Search != "" {
			applied["search"] = filter.Search
		}
		if filter.Status != "" {
			applied["status"] = filter.Status
		}
		if filter.Severity != "" {
			applied["severity"] = filter.Severity
		}
		if filter.MinCVSS > 0 {
			applied["minCvss"] = filter.MinCVSS
		}
		return paginatedResult(map[string]any{"assessments": assessments, "appliedFilter": applied}, total, filter.Limit, filter.Offset)
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "get_triage_config",
		Description: "Get the admin-configured triage settings that determine which findings appear in the " +
			"triage queue: filter mode (cvss or vendor_severity), vendor severities or CVSS threshold, whether " +
			"unrated findings are included, and whether VEX 'not affected' findings are hidden. Useful for " +
			"explaining or reconciling the triage queue count with the UI.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ emptyInput) (*mcpsdk.CallToolResult, any, error) {
		opts, err := d.SettingsService.BuildTriageOptions(ctx)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(triageFilterInfo(opts))
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_dashboard_stats",
		Description: "Get the dashboard overview statistics for the whole vulnerability landscape.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ emptyInput) (*mcpsdk.CallToolResult, any, error) {
		stats, err := d.StatsService.GetDashboardStats(ctx)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(stats)
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_severity_stats",
		Description: "Get the breakdown of findings by severity.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ emptyInput) (*mcpsdk.CallToolResult, any, error) {
		stats, err := d.StatsService.GetDashboardStats(ctx)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(map[string]any{"breakdown": stats.SeverityBreakdown})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_trend_stats",
		Description: "Get the trend of findings over time.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in daysInput) (*mcpsdk.CallToolResult, any, error) {
		days := in.Days
		if days <= 0 {
			days = 30
		}
		trend, err := d.StatsService.GetFindingsTrend(ctx, days)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(map[string]any{"trend": trend})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_top_servers",
		Description: "Get the servers with the most vulnerabilities.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in limitInput) (*mcpsdk.CallToolResult, any, error) {
		servers, err := d.StatsService.GetTopServers(ctx, clampLimit(in.Limit, 10, 100))
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(map[string]any{"servers": servers})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_top_cves",
		Description: "Get the CVEs affecting the most servers.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in limitInput) (*mcpsdk.CallToolResult, any, error) {
		cves, err := d.StatsService.GetTopCVEs(ctx, clampLimit(in.Limit, 10, 100))
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(map[string]any{"cves": cves})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_assessments_by_severity",
		Description: "Get the count of assessments grouped by severity.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ emptyInput) (*mcpsdk.CallToolResult, any, error) {
		stats, err := d.StatsService.GetAssessmentStatsBySeverity(ctx)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(map[string]any{"assessmentsBySeverity": stats})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "list_server_groups",
		Description: "List all server groups.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ emptyInput) (*mcpsdk.CallToolResult, any, error) {
		groups, err := d.ServerGroupService.GetAll(ctx)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(map[string]any{"groups": groups, "total": len(groups)})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_server_group",
		Description: "Get a single server group by its ID.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in groupInput) (*mcpsdk.CallToolResult, any, error) {
		group, err := d.ServerGroupService.GetByID(ctx, in.GroupID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("server group %d not found", in.GroupID)
		}
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(group)
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "get_server_group_members",
		Description: "List the servers that belong to a server group.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in groupInput) (*mcpsdk.CallToolResult, any, error) {
		members, err := d.ServerGroupService.GetMembers(ctx, in.GroupID)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(map[string]any{"members": members, "total": len(members)})
	})
}

// ----------------------------------------------------------------------------
// Write tools (registered only on the read-write server)
// ----------------------------------------------------------------------------

type upsertAssessmentInput struct {
	CVEID      string `json:"cveId" jsonschema:"the CVE ID to assess, e.g. CVE-2024-1234"`
	Status     string `json:"status" jsonschema:"assessment status: pending, relevant, not_relevant or accepted_risk"`
	Comment    string `json:"comment,omitempty" jsonschema:"rationale for the assessment"`
	AssessedBy string `json:"assessedBy,omitempty" jsonschema:"who performed the assessment (e.g. the agent name)"`
}

type deleteAssessmentInput struct {
	CVEID string `json:"cveId" jsonschema:"the CVE ID whose assessment should be deleted"`
}

type triggerScanInput struct {
	ServerID int64 `json:"serverId" jsonschema:"the numeric ID of the server to scan"`
}

type createServerGroupInput struct {
	Name        string `json:"name" jsonschema:"name of the new server group"`
	Description string `json:"description,omitempty" jsonschema:"description of the group"`
	Color       string `json:"color,omitempty" jsonschema:"hex color for the group, e.g. #4ade80"`
}

type updateServerGroupInput struct {
	GroupID     int64  `json:"groupId" jsonschema:"the numeric ID of the server group to update"`
	Name        string `json:"name" jsonschema:"new name of the group"`
	Description string `json:"description,omitempty" jsonschema:"new description"`
	Color       string `json:"color,omitempty" jsonschema:"new hex color, e.g. #4ade80"`
}

type setGroupMembersInput struct {
	GroupID   int64   `json:"groupId" jsonschema:"the numeric ID of the server group"`
	ServerIDs []int64 `json:"serverIds" jsonschema:"the complete set of server IDs that should belong to the group"`
}

func registerWriteTools(s *mcpsdk.Server, d Deps) {
	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "upsert_assessment",
		Description: "Create or update the triage assessment for a CVE (relevance status and rationale). " +
			"When the status is set to \"relevant\" and Jira is enabled, a Jira ticket is created — exactly as in the UI.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in upsertAssessmentInput) (*mcpsdk.CallToolResult, any, error) {
		// Delegate to the shared handler logic (validation + Jira ticket creation).
		result, err := d.UpsertAssessment(ctx, in.CVEID, in.Status, in.Comment, in.AssessedBy)
		if err != nil {
			return nil, nil, err
		}
		prefix, desc := tokenAudit(ctx)
		log.Info().Str("source", "mcp").Str("tokenPrefix", prefix).Str("tokenDescription", desc).
			Str("cveId", in.CVEID).Str("status", in.Status).Msg("MCP: assessment upserted")
		return jsonResult(result)
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "delete_assessment",
		Description: "Delete the triage assessment for a CVE.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in deleteAssessmentInput) (*mcpsdk.CallToolResult, any, error) {
		if in.CVEID == "" {
			return nil, nil, fmt.Errorf("cveId is required")
		}
		if err := d.AssessmentService.Delete(ctx, in.CVEID); err != nil {
			return nil, nil, err
		}
		prefix, desc := tokenAudit(ctx)
		log.Info().Str("source", "mcp").Str("tokenPrefix", prefix).Str("tokenDescription", desc).
			Str("cveId", in.CVEID).Msg("MCP: assessment deleted")
		return jsonResult(map[string]any{"deleted": true, "cveId": in.CVEID})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "trigger_server_scan",
		Description: "Enqueue a vulnerability scan for a server.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in triggerScanInput) (*mcpsdk.CallToolResult, any, error) {
		if d.ScanQueue == nil {
			return nil, nil, fmt.Errorf("scan queue not available")
		}
		server, err := d.ServerService.GetByID(ctx, in.ServerID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("server %d not found", in.ServerID)
		}
		if err != nil {
			return nil, nil, err
		}
		jobID, err := d.ScanQueue.Enqueue(server.ID, server.Name, "mcp")
		if err != nil {
			return nil, nil, err
		}
		prefix, desc := tokenAudit(ctx)
		log.Info().Str("source", "mcp").Str("tokenPrefix", prefix).Str("tokenDescription", desc).
			Int64("serverId", in.ServerID).Str("jobId", jobID).Msg("MCP: scan enqueued")
		return jsonResult(map[string]any{"message": "Scan enqueued", "jobId": jobID})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "create_server_group",
		Description: "Create a new server group.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in createServerGroupInput) (*mcpsdk.CallToolResult, any, error) {
		if in.Name == "" {
			return nil, nil, fmt.Errorf("name is required")
		}
		group, err := d.ServerGroupService.Create(ctx, &models.ServerGroup{
			Name:        in.Name,
			Description: in.Description,
			Color:       in.Color,
		})
		if err != nil {
			return nil, nil, err
		}
		prefix, desc := tokenAudit(ctx)
		log.Info().Str("source", "mcp").Str("tokenPrefix", prefix).Str("tokenDescription", desc).
			Int64("groupId", group.ID).Str("name", group.Name).Msg("MCP: server group created")
		return jsonResult(group)
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "update_server_group",
		Description: "Update an existing server group's name, description or color.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in updateServerGroupInput) (*mcpsdk.CallToolResult, any, error) {
		if in.Name == "" {
			return nil, nil, fmt.Errorf("name is required")
		}
		group, err := d.ServerGroupService.Update(ctx, &models.ServerGroup{
			ID:          in.GroupID,
			Name:        in.Name,
			Description: in.Description,
			Color:       in.Color,
		})
		if err != nil {
			return nil, nil, err
		}
		prefix, desc := tokenAudit(ctx)
		log.Info().Str("source", "mcp").Str("tokenPrefix", prefix).Str("tokenDescription", desc).
			Int64("groupId", in.GroupID).Msg("MCP: server group updated")
		return jsonResult(group)
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "delete_server_group",
		Description: "Delete a server group.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in groupInput) (*mcpsdk.CallToolResult, any, error) {
		if err := d.ServerGroupService.Delete(ctx, in.GroupID); err != nil {
			return nil, nil, err
		}
		prefix, desc := tokenAudit(ctx)
		log.Info().Str("source", "mcp").Str("tokenPrefix", prefix).Str("tokenDescription", desc).
			Int64("groupId", in.GroupID).Msg("MCP: server group deleted")
		return jsonResult(map[string]any{"deleted": true, "groupId": in.GroupID})
	})

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "set_server_group_members",
		Description: "Replace the full set of servers that belong to a server group.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in setGroupMembersInput) (*mcpsdk.CallToolResult, any, error) {
		if err := d.ServerGroupService.SetMembers(ctx, in.GroupID, in.ServerIDs); err != nil {
			return nil, nil, err
		}
		prefix, desc := tokenAudit(ctx)
		log.Info().Str("source", "mcp").Str("tokenPrefix", prefix).Str("tokenDescription", desc).
			Int64("groupId", in.GroupID).Int("memberCount", len(in.ServerIDs)).Msg("MCP: server group members set")
		return jsonResult(map[string]any{"updated": true, "groupId": in.GroupID, "memberCount": len(in.ServerIDs)})
	})
}
