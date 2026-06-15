package handlers

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/config"
	"github.com/vultrack/vultrack/internal/exploitdb"
	"github.com/vultrack/vultrack/internal/jira"
	"github.com/vultrack/vultrack/internal/models"
	"github.com/vultrack/vultrack/internal/nvd"
	"github.com/vultrack/vultrack/internal/oidc"
	"github.com/vultrack/vultrack/internal/oval"
	"github.com/vultrack/vultrack/internal/scanner"
	"github.com/vultrack/vultrack/internal/scanqueue"
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/session"
	"github.com/vultrack/vultrack/internal/vex"
)

// Handler contains all HTTP handlers
type Handler struct {
	app                   *fiber.App
	cfg                   *config.Config
	serverService         *services.ServerService
	findingService        *services.FindingService
	assessmentService     *services.AssessmentService
	statsService          *services.StatsService
	reasonTemplateService *services.ReasonTemplateService
	settingsService       *services.SettingsService
	serverGroupService    *services.ServerGroupService
	reportService         *services.ReportService
	// New services for agent-based architecture
	enrollmentService *services.EnrollmentService
	agentService      *services.AgentService
	packageService    *services.PackageService

	// OVAL services
	ovalService *services.OVALService
	ovalSyncer  *oval.Syncer

	// NVD syncer
	nvdSyncer *nvd.Syncer

	// ExploitDB syncer
	exploitDBSyncer *exploitdb.Syncer

	// VEX service + syncer
	vexService *services.VEXService
	vexSyncer  *vex.Syncer

	// Scanner
	scanner   *scanner.Scanner
	scanQueue *scanqueue.Queue

	// Report schedules
	reportScheduleService *services.ReportScheduleService
	reportScheduler       interface{ RunNow(ctx context.Context, id int64) error }

	// Jira integration
	jiraClient *jira.Client

	// OIDC auth
	oidcProvider  *oidc.Provider
	sessionStore  *session.Store
	userService   *services.UserService

	// API tokens for the MCP interface
	apiTokenService *services.APITokenService

	// JWT signing secret for v2 agent API
	jwtSecret []byte
}

// New creates a new Handler
func New(
	cfg *config.Config,
	serverService *services.ServerService,
	findingService *services.FindingService,
	assessmentService *services.AssessmentService,
	statsService *services.StatsService,
	reasonTemplateService *services.ReasonTemplateService,
	settingsService *services.SettingsService,
	serverGroupService *services.ServerGroupService,
	reportService *services.ReportService,
	// New services for agent-based architecture
	enrollmentService *services.EnrollmentService,
	agentService *services.AgentService,
	packageService *services.PackageService,
	// OVAL services
	ovalService *services.OVALService,
	ovalSyncer *oval.Syncer,
	// NVD syncer
	nvdSyncer *nvd.Syncer,
	// ExploitDB syncer
	exploitDBSyncer *exploitdb.Syncer,
	// VEX service + syncer
	vexService *services.VEXService,
	vexSyncer *vex.Syncer,
	// Scanner
	vulnScanner *scanner.Scanner,
	// Scan queue
	scanQ *scanqueue.Queue,
	// Report schedules
	reportScheduleService *services.ReportScheduleService,
	reportScheduler interface{ RunNow(ctx context.Context, id int64) error },
	// Jira integration (nil-safe when disabled)
	jiraClient *jira.Client,
	// OIDC auth (nil and stores nil when OIDC disabled)
	oidcProvider *oidc.Provider,
	sessionStore *session.Store,
	userService *services.UserService,
	// API tokens for the MCP interface
	apiTokenService *services.APITokenService,
) *Handler {
	// Resolve the JWT signing secret.
	// If JWT_SECRET is not configured we generate a random one and warn — tokens
	// issued this way will be invalidated on the next restart.
	jwtSecret := []byte(cfg.JWTSecret)
	if len(jwtSecret) == 0 {
		log.Warn().Msg("JWT_SECRET is not set — generating a random secret. " +
			"Agent v2 access tokens will be invalidated on restart. " +
			"Set JWT_SECRET in your environment for production use.")
		jwtSecret = make([]byte, 32)
		if _, err := rand.Read(jwtSecret); err != nil {
			log.Fatal().Err(err).Msg("Failed to generate random JWT secret")
		}
	}

	h := &Handler{
		cfg:                   cfg,
		serverService:         serverService,
		findingService:        findingService,
		assessmentService:     assessmentService,
		statsService:          statsService,
		reasonTemplateService: reasonTemplateService,
		settingsService:       settingsService,
		serverGroupService:    serverGroupService,
		reportService:         reportService,
		enrollmentService:     enrollmentService,
		agentService:          agentService,
		packageService:        packageService,
		ovalService:           ovalService,
		ovalSyncer:            ovalSyncer,
		nvdSyncer:             nvdSyncer,
		exploitDBSyncer:       exploitDBSyncer,
		vexService:            vexService,
		vexSyncer:             vexSyncer,
		scanner:               vulnScanner,
		scanQueue:             scanQ,
		reportScheduleService: reportScheduleService,
		reportScheduler:       reportScheduler,
		jiraClient:            jiraClient,
		oidcProvider:          oidcProvider,
		sessionStore:          sessionStore,
		userService:           userService,
		apiTokenService:       apiTokenService,
		jwtSecret:             jwtSecret,
	}

	// Create Fiber app
	// ProxyHeader enables reading the real client IP from X-Forwarded-For header
	// when running behind a reverse proxy (nginx, traefik, etc.)
	app := fiber.New(fiber.Config{
		ErrorHandler:            h.errorHandler,
		EnableTrustedProxyCheck: true,
		TrustedProxies:          []string{"127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		ProxyHeader:             fiber.HeaderXForwardedFor,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${method} ${path} (${latency})\n",
	}))
	corsConfig := cors.Config{
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Enrollment-Key,X-Agent-Token",
		AllowCredentials: false,
	}
	if cfg.CORSOrigins != "" {
		origins := strings.Split(cfg.CORSOrigins, ",")
		for i := range origins {
			origins[i] = strings.TrimSpace(origins[i])
		}
		corsConfig.AllowOrigins = strings.Join(origins, ",")
		corsConfig.AllowCredentials = true
	} else {
		corsConfig.AllowOrigins = "*"
	}
	app.Use(cors.New(corsConfig))

	// API routes
	api := app.Group("/api/v1")

	// Health check and metrics (no auth)
	api.Get("/health", h.healthCheck)
	app.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

	// Auth routes (no auth middleware)
	api.Get("/auth/login", h.authLogin)
	api.Get("/auth/callback", h.authCallback)
	api.Post("/auth/logout", h.authLogout)
	api.Get("/auth/me", h.authMe)

	// ========================================================================
	// AGENT API v1 — registered BEFORE the protected group so that
	// requireAuth middleware (empty-prefix group) does not intercept them.
	// ========================================================================
	api.Post("/agent/enroll", h.enrollAgent)
	api.Post("/agent/report", h.receiveAgentReport)

	// ========================================================================
	// AGENT API v2 — standard Authorization: Bearer header, JWT access tokens,
	// rotating refresh tokens. Old clients continue using v1 unchanged.
	// ========================================================================
	apiv2 := app.Group("/api/v2")
	apiv2.Post("/agent/enroll", h.enrollAgentV2)
	apiv2.Post("/agent/token", h.refreshAgentToken)
	apiv2.Post("/agent/report", h.receiveAgentReportV2)

	// ========================================================================
	// MCP API — Model Context Protocol interface for AI agents.
	// Authenticated by an API token (always required, regardless of OIDC).
	// A read-only token is routed to a server exposing only query tools; a
	// read-write token additionally gets the mutating tools.
	// ========================================================================
	h.registerMCPRoutes(app)

	// Protected API routes (require valid session when OIDC enabled)
	protected := api.Group("", h.requireAuth)

	// Dashboard
	protected.Get("/dashboard", h.getDashboard)

	// Servers
	protected.Get("/servers", h.getServers)
	protected.Get("/servers/:id", h.getServer)
	protected.Get("/servers/:id/findings", h.getServerFindings)

	// Findings
	protected.Get("/findings", h.getFindings)
	protected.Get("/findings/triage", h.getTriageQueue)
	protected.Get("/findings/:id", h.getFinding)

	// CVEs
	protected.Get("/cves/:id", h.getCVE)
	protected.Get("/cves/:id/servers", h.getCVEServers)

	// Assessments
	protected.Get("/assessments", h.getAssessments)
	protected.Post("/assessments", h.createAssessment)
	protected.Put("/assessments/:cveId", h.updateAssessment)
	protected.Delete("/assessments/:cveId", h.deleteAssessment)

	// Reason Templates
	protected.Get("/reason-templates", h.getReasonTemplates)
	protected.Post("/reason-templates", h.createReasonTemplate)
	protected.Put("/reason-templates/:id", h.updateReasonTemplate)
	protected.Delete("/reason-templates/:id", h.deleteReasonTemplate)

	// Admin routes (require admin role)
	admin := protected.Group("/admin", h.requireAdmin)

	// Admin - Settings
	admin.Get("/settings", h.getSettings)
	admin.Put("/settings", h.updateSettings)

	// Admin - Users
	admin.Get("/users", h.getAdminUsers)
	admin.Patch("/users/:id", h.patchAdminUser)

	// Admin - API Tokens (MCP interface)
	admin.Get("/api-tokens", h.getAPITokens)
	admin.Post("/api-tokens", h.createAPIToken)
	admin.Delete("/api-tokens/:id", h.deleteAPIToken)

	// Admin - Server Groups
	admin.Get("/server-groups", h.getServerGroups)
	admin.Post("/server-groups", h.createServerGroup)
	admin.Get("/server-groups/:id", h.getServerGroup)
	admin.Put("/server-groups/:id", h.updateServerGroup)
	admin.Delete("/server-groups/:id", h.deleteServerGroup)
	admin.Get("/server-groups/:id/members", h.getServerGroupMembers)
	admin.Put("/server-groups/:id/members", h.setServerGroupMembers)
	admin.Post("/server-groups/:id/members", h.addServerGroupMember)
	admin.Delete("/server-groups/:id/members/:serverId", h.removeServerGroupMember)

	// Server groups for a specific server
	protected.Get("/servers/:id/groups", h.getServerGroupsForServer)
	protected.Put("/servers/:id/groups", h.setServerGroups)

	// Statistics
	protected.Get("/stats/severity", h.getSeverityStats)
	protected.Get("/stats/trend", h.getTrendStats)
	protected.Get("/stats/top-servers", h.getTopServers)
	protected.Get("/stats/top-cves", h.getTopCVEs)
	protected.Get("/stats/assessments-by-severity", h.getAssessmentsBySeverity)

	// Reports
	protected.Post("/reports/generate", h.generateReport)

	// Report Schedules
	protected.Get("/report-schedules", h.getReportSchedules)
	protected.Post("/report-schedules", h.createReportSchedule)
	protected.Get("/report-schedules/:id", h.getReportSchedule)
	protected.Put("/report-schedules/:id", h.updateReportSchedule)
	protected.Delete("/report-schedules/:id", h.deleteReportSchedule)
	protected.Post("/report-schedules/:id/toggle", h.toggleReportSchedule)
	protected.Post("/report-schedules/:id/run-now", h.runReportScheduleNow)

	// Scan Jobs
	protected.Get("/scans", h.getScans)
	protected.Get("/scans/stats", h.getScanStats)
	protected.Post("/scans/:id/cancel", h.cancelScan)
	protected.Post("/scans/:id/retry", h.retryScan)

	// Server packages and scanning
	protected.Get("/servers/:id/packages", h.getServerPackages)
	protected.Post("/servers/:id/scan", h.triggerServerScan)

	// Admin: Servers
	admin.Delete("/servers/:id", h.deleteServer)

	// Admin: Enrollment Keys
	admin.Get("/enrollment-keys", h.getEnrollmentKeys)
	admin.Post("/enrollment-keys", h.createEnrollmentKey)
	admin.Put("/enrollment-keys/:id", h.updateEnrollmentKey)
	admin.Delete("/enrollment-keys/:id", h.deleteEnrollmentKey)

	// Admin: Registered Agents
	admin.Get("/agents", h.getRegisteredAgents)
	admin.Put("/agents/:id/approve", h.approveAgent)
	admin.Put("/agents/:id/revoke", h.revokeAgent)
	admin.Delete("/agents/:id", h.deleteAgent)

	// Admin: OVAL Management
	admin.Get("/oval/distributions", h.getOVALDistributions)
	admin.Get("/oval/sources", h.getOVALSources)
	admin.Post("/oval/sources", h.enableOVALSource)
	admin.Put("/oval/sources/:id/disable", h.disableOVALSource)
	admin.Delete("/oval/sources/:id", h.deleteOVALSource)
	admin.Post("/oval/sources/:id/sync", h.triggerOVALSync)
	admin.Post("/oval/sync-all", h.triggerOVALSyncAll)

	// OVAL Database (public browsing — not admin-restricted)
	protected.Get("/oval/definitions", h.getOVALDefinitions)
	protected.Get("/oval/definitions/:id", h.getOVALDefinitionByID)

	// Admin: NVD Management
	admin.Post("/nvd/sync", h.triggerNVDSync)
	admin.Get("/nvd/status", h.getNVDStatus)

	// Admin: ExploitDB Management
	admin.Post("/exploitdb/sync", h.triggerExploitDBSync)
	admin.Get("/exploitdb/status", h.getExploitDBStatus)

	// Admin: VEX Management
	admin.Post("/vex/sync", h.triggerVEXSync)
	admin.Get("/vex/status", h.getVEXStatus)

	// Admin: Sync Status
	admin.Get("/sync/status", h.getSyncStatus)

	// Admin: System Reset
	admin.Post("/system/reset", h.resetSystem)

	h.app = app
	return h
}

// Start starts the HTTP server
func (h *Handler) Start() error {
	addr := fmt.Sprintf(":%d", h.cfg.BackendPort)
	log.Info().Str("addr", addr).Msg("Starting HTTP server")
	return h.app.Listen(addr)
}

// Shutdown gracefully shuts down the server
func (h *Handler) Shutdown() error {
	return h.app.ShutdownWithTimeout(30 * time.Second)
}

// Error handler
func (h *Handler) errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}
	return c.Status(code).JSON(fiber.Map{
		"error": err.Error(),
	})
}

// Health check
func (h *Handler) healthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

// Dashboard
func (h *Handler) getDashboard(c *fiber.Ctx) error {
	ctx := c.Context()
	stats, err := h.statsService.GetDashboardStats(ctx)
	if err != nil {
		return err
	}
	return c.JSON(stats)
}

// Servers
func (h *Handler) getServers(c *fiber.Ctx) error {
	ctx := c.Context()
	servers, err := h.serverService.GetAll(ctx)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"servers": servers,
		"total":   len(servers),
	})
}

func (h *Handler) getServer(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}

	ctx := c.Context()
	server, err := h.serverService.GetByID(ctx, id)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Server not found")
	}

	return c.JSON(server)
}

func (h *Handler) getServerFindings(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}

	filter := services.FindingFilter{
		ServerID:        &id,
		IncludeResolved: c.QueryBool("includeResolved", false),
		Limit:           c.QueryInt("limit", 100),
		Offset:          c.QueryInt("offset", 0),
	}

	ctx := c.Context()
	findings, total, err := h.findingService.GetAll(ctx, filter)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"findings": findings,
		"total":    total,
		"limit":    filter.Limit,
		"offset":   filter.Offset,
	})
}

// Findings
func (h *Handler) getFindings(c *fiber.Ctx) error {
	filter := services.FindingFilter{
		IncludeResolved: c.QueryBool("includeResolved", false),
		Search:          c.Query("search"),
		SortBy:          c.Query("sortBy", "cvss3Score"),
		SortOrder:       c.Query("sortOrder", "desc"),
		Limit:           c.QueryInt("limit", 50),
		Offset:          c.QueryInt("offset", 0),
	}

	if cveId := c.Query("cveId"); cveId != "" {
		filter.CVEID = &cveId
	}

	if severity := c.Query("severity"); severity != "" {
		filter.Severity = &severity
	}

	if minCVSS := c.QueryFloat("minCvss", 0); minCVSS > 0 {
		filter.MinCVSS = &minCVSS
	}

	if vexStatus := c.Query("vexStatus"); vexStatus != "" {
		filter.VexStatus = &vexStatus
	}

	ctx := c.Context()

	if c.QueryBool("grouped", false) {
		groups, total, err := h.findingService.GetAllGrouped(ctx, filter)
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{
			"groups": groups,
			"total":  total,
			"limit":  filter.Limit,
			"offset": filter.Offset,
		})
	}

	findings, total, err := h.findingService.GetAll(ctx, filter)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"findings": findings,
		"total":    total,
		"limit":    filter.Limit,
		"offset":   filter.Offset,
	})
}

func (h *Handler) getTriageQueue(c *fiber.Ctx) error {
	ctx := c.Context()

	// Resolve the configured triage filter (shared with the MCP interface).
	opts, _ := h.settingsService.BuildTriageOptions(ctx)

	// Apply request overrides on top of the configured defaults.
	opts.Limit = c.QueryInt("limit", 50)
	opts.Offset = c.QueryInt("offset", 0)
	opts.HideVexNotAffected = c.QueryBool("hideVexNotAffected", opts.HideVexNotAffected)

	// Build response info
	filterInfo := make(map[string]interface{})
	filterInfo["mode"] = opts.Mode

	if opts.Mode == "vendor_severity" {
		filterInfo["severities"] = opts.VendorSeverities
		filterInfo["includeUnrated"] = opts.IncludeUnrated
	} else {
		// Allow CVSS threshold override via query parameter.
		opts.CVSSThreshold = c.QueryFloat("minCvss", opts.CVSSThreshold)
		filterInfo["threshold"] = opts.CVSSThreshold
	}

	findings, total, err := h.findingService.GetTriageQueue(ctx, opts)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"findings": findings,
		"total":    total,
		"limit":    opts.Limit,
		"offset":   opts.Offset,
		"filter":   filterInfo,
	})
}

func (h *Handler) getFinding(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid finding ID")
	}

	ctx := c.Context()
	finding, err := h.findingService.GetByID(ctx, id)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Finding not found")
	}

	return c.JSON(finding)
}

// CVEs
func (h *Handler) getCVE(c *fiber.Ctx) error {
	cveID := c.Params("id")

	ctx := c.Context()
	findings, err := h.findingService.GetServersByCVE(ctx, cveID)
	if err != nil {
		return err
	}

	if len(findings) == 0 {
		return fiber.NewError(fiber.StatusNotFound, "CVE not found")
	}

	// Get assessment if exists
	assessment, _ := h.assessmentService.GetByCVE(ctx, cveID)

	return c.JSON(fiber.Map{
		"cveId":       cveID,
		"findings":    findings,
		"serverCount": len(findings),
		"assessment":  assessment,
	})
}

func (h *Handler) getCVEServers(c *fiber.Ctx) error {
	cveID := c.Params("id")

	ctx := c.Context()
	findings, err := h.findingService.GetServersByCVE(ctx, cveID)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"cveId":    cveID,
		"findings": findings,
		"total":    len(findings),
	})
}

// Assessments
func (h *Handler) getAssessments(c *fiber.Ctx) error {
	ctx := c.Context()

	limit := c.QueryInt("limit", 50)
	if limit < 1 || limit > 200 {
		limit = 50
	}
	offset := c.QueryInt("offset", 0)
	if offset < 0 {
		offset = 0
	}

	filter := services.AssessmentFilter{
		Search:    c.Query("search"),
		Status:    c.Query("status"),
		Severity:  c.Query("severity"),
		SortBy:    c.Query("sortBy", "assessedAt"),
		SortOrder: c.Query("sortOrder", "desc"),
		Limit:     limit,
		Offset:    offset,
	}

	if v := c.Query("minCvss"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			filter.MinCVSS = f
		}
	}
	if v := c.Query("findingActive"); v != "" {
		b := v == "true"
		filter.FindingActive = &b
	}
	if v := c.Query("hasFixAvailable"); v != "" {
		b := v == "true"
		filter.HasFixAvailable = &b
	}

	assessments, total, err := h.assessmentService.GetAll(ctx, filter)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"assessments": assessments,
		"total":       total,
	})
}

type assessmentRequest struct {
	CVEID      string `json:"cveId"`
	Status     string `json:"status"`
	Comment    string `json:"comment"`
	AssessedBy string `json:"assessedBy"`
}

// validAssessmentStatuses is the set of accepted assessment status values.
var validAssessmentStatuses = map[string]bool{
	models.AssessmentStatusPending:      true,
	models.AssessmentStatusRelevant:     true,
	models.AssessmentStatusNotRelevant:  true,
	models.AssessmentStatusAcceptedRisk: true,
}

// upsertAssessment validates the input, creates a Jira ticket when the status
// becomes "relevant" and Jira is enabled, and upserts the assessment. It is the
// single source of truth shared by the REST API and the MCP interface so both
// behave identically. Validation failures are returned as *fiber.Error so the
// REST error handler maps them to 4xx; the MCP layer surfaces the message.
func (h *Handler) upsertAssessment(ctx context.Context, cveID, status, comment, assessedBy string) (*models.Assessment, error) {
	if cveID == "" || status == "" {
		return nil, fiber.NewError(fiber.StatusBadRequest, "cveId and status are required")
	}
	if !validAssessmentStatuses[status] {
		return nil, fiber.NewError(fiber.StatusBadRequest, "Invalid status")
	}

	assessment := &models.Assessment{
		CVEID:      cveID,
		Status:     status,
		Comment:    comment,
		AssessedBy: assessedBy,
	}

	// Create Jira ticket when status is "relevant" and Jira is enabled
	if status == models.AssessmentStatusRelevant && h.jiraClient != nil && h.jiraClient.Enabled() {
		ticketURL, err := h.createJiraTicketForCVE(ctx, cveID, comment)
		if err != nil {
			log.Error().Err(err).Str("cveId", cveID).Msg("Failed to create Jira ticket")
			// Don't fail the assessment — log the error and continue without ticket
		} else {
			assessment.TicketURL = ticketURL
		}
	}

	return h.assessmentService.Upsert(ctx, assessment)
}

func (h *Handler) createAssessment(c *fiber.Ctx) error {
	var req assessmentRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	result, err := h.upsertAssessment(c.Context(), req.CVEID, req.Status, req.Comment, req.AssessedBy)
	if err != nil {
		return err
	}

	return c.Status(fiber.StatusCreated).JSON(result)
}

// createJiraTicketForCVE builds a Jira issue with CVE details and returns the ticket URL.
func (h *Handler) createJiraTicketForCVE(ctx context.Context, cveID, assessmentComment string) (string, error) {
	findings, err := h.findingService.GetServersByCVE(ctx, cveID)
	if err != nil {
		return "", fmt.Errorf("fetch findings for %s: %w", cveID, err)
	}

	// Build title
	title := cveID
	if len(findings) > 0 && findings[0].Severity != "" {
		title = fmt.Sprintf("%s (%s)", cveID, strings.ToUpper(findings[0].Severity))
	}
	if len(findings) > 0 && findings[0].Summary != "" {
		prefix := title + " \u2013 "
		maxSummaryRunes := 120 - len([]rune(prefix))
		s := []rune(findings[0].Summary)
		if len(s) > maxSummaryRunes {
			s = append(s[:maxSummaryRunes-1], '\u2026')
		}
		title = prefix + string(s)
	}
	if len([]rune(title)) > 120 {
		r := []rune(title)
		title = string(r[:119]) + "\u2026"
	}

	// Build ADF description
	var content []interface{}

	// Section: CVE Details
	content = append(content, jira.ADFHeading(2, "CVE Details"))
	if len(findings) > 0 {
		f := findings[0]
		var detailNodes []interface{}
		if f.Severity != "" {
			detailNodes = append(detailNodes, jira.ADFBold("Severity: "), jira.ADFText(strings.ToUpper(f.Severity)))
		}
		if f.CVSS3Score != nil {
			if len(detailNodes) > 0 {
				detailNodes = append(detailNodes, jira.ADFText("   "))
			}
			detailNodes = append(detailNodes, jira.ADFBold("CVSS 3: "), jira.ADFText(fmt.Sprintf("%.1f", *f.CVSS3Score)))
		}
		if len(detailNodes) > 0 {
			content = append(content, jira.ADFParagraph(detailNodes...))
		}
		if f.CVSS3Vector != "" {
			content = append(content, jira.ADFParagraph(jira.ADFBold("Vector: "), jira.ADFText(f.CVSS3Vector)))
		}
		if f.CVEPublishedAt != nil {
			content = append(content, jira.ADFParagraph(jira.ADFBold("Published: "), jira.ADFText(f.CVEPublishedAt.Format("2006-01-02"))))
		}
		if f.SourceLink != "" {
			content = append(content, jira.ADFParagraph(jira.ADFBold("Source: "), jira.ADFText(f.SourceLink)))
		}
		if f.HasExploit {
			exploitText := "\u26a0 Known exploit available"
			if f.VerifiedExploit {
				exploitText += " (verified)"
			}
			if f.ExploitCount > 1 {
				exploitText += fmt.Sprintf(" \u2013 %d exploits", f.ExploitCount)
			}
			content = append(content, jira.ADFParagraph(jira.ADFBold(exploitText)))
		}
	}

	// Section: Affected Systems
	if len(findings) > 0 {
		content = append(content, jira.ADFHeading(2, fmt.Sprintf("Affected Systems (%d)", len(findings))))
		items := make([]interface{}, 0, len(findings))
		for _, f := range findings {
			line := fmt.Sprintf("%s: %s %s", f.ServerName, f.PackageName, f.PackageVersion)
			if f.FixedIn != "" {
				line += fmt.Sprintf(" (fix: %s)", f.FixedIn)
			}
			if f.FixState != "" {
				line += fmt.Sprintf(" [%s]", f.FixState)
			}
			items = append(items, jira.ADFListItem(line))
		}
		content = append(content, jira.ADFBulletList(items...))
	}

	// Section: Assessment
	if assessmentComment != "" {
		content = append(content, jira.ADFHeading(2, "Assessment"))
		content = append(content, jira.ADFParagraph(jira.ADFText(assessmentComment)))
	}

	// Section: Description (full CVE description at the end)
	fullDesc := ""
	if len(findings) > 0 {
		f := findings[0]
		switch {
		case f.Description != "":
			fullDesc = f.Description
		case f.NVDDescription != "":
			fullDesc = f.NVDDescription
		case f.Summary != "":
			fullDesc = f.Summary
		}
	}
	if fullDesc != "" {
		content = append(content, jira.ADFHeading(2, "Description"))
		content = append(content, jira.ADFParagraph(jira.ADFText(fullDesc)))
	}

	content = append(content, jira.ADFRule())
	content = append(content, jira.ADFParagraph(jira.ADFText("Automatically created by VulTrack")))

	// Labels
	labels := []string{"vultrack", "security"}
	if len(findings) > 0 && findings[0].Severity != "" {
		labels = append(labels, strings.ToLower(findings[0].Severity))
	}

	result, err := h.jiraClient.CreateIssue(ctx, jira.CreateIssueRequest{
		Summary:     title,
		Description: jira.ADFDoc(content...),
		Labels:      labels,
	})
	if err != nil {
		return "", err
	}
	return result.URL, nil
}

func (h *Handler) updateAssessment(c *fiber.Ctx) error {
	cveID := c.Params("cveId")

	var req assessmentRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	req.CVEID = cveID

	assessment := &models.Assessment{
		CVEID:      req.CVEID,
		Status:     req.Status,
		Comment:    req.Comment,
		AssessedBy: req.AssessedBy,
	}

	ctx := c.Context()
	result, err := h.assessmentService.Upsert(ctx, assessment)
	if err != nil {
		return err
	}

	return c.JSON(result)
}

func (h *Handler) deleteAssessment(c *fiber.Ctx) error {
	cveID := c.Params("cveId")

	ctx := c.Context()
	if err := h.assessmentService.Delete(ctx, cveID); err != nil {
		return err
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// Statistics
func (h *Handler) getSeverityStats(c *fiber.Ctx) error {
	ctx := c.Context()
	stats, err := h.statsService.GetDashboardStats(ctx)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"breakdown": stats.SeverityBreakdown,
	})
}

func (h *Handler) getTrendStats(c *fiber.Ctx) error {
	days := c.QueryInt("days", 30)

	ctx := c.Context()
	trend, err := h.statsService.GetFindingsTrend(ctx, days)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"trend": trend,
		"days":  days,
	})
}

func (h *Handler) getTopServers(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 10)

	ctx := c.Context()
	servers, err := h.statsService.GetTopServers(ctx, limit)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"servers": servers,
	})
}

func (h *Handler) getTopCVEs(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 10)

	ctx := c.Context()
	cves, err := h.statsService.GetTopCVEs(ctx, limit)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"cves": cves,
	})
}

func (h *Handler) getAssessmentsBySeverity(c *fiber.Ctx) error {
	ctx := c.Context()
	stats, err := h.statsService.GetAssessmentStatsBySeverity(ctx)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"stats": stats,
	})
}

func (h *Handler) getReasonTemplates(c *fiber.Ctx) error {
	appliesTo := c.Query("appliesTo")

	ctx := c.Context()
	var templates []models.ReasonTemplate
	var err error

	if appliesTo != "" {
		templates, err = h.reasonTemplateService.GetByType(ctx, appliesTo)
	} else {
		templates, err = h.reasonTemplateService.GetAll(ctx)
	}

	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"templates": templates,
	})
}

func (h *Handler) createReasonTemplate(c *fiber.Ctx) error {
	var input struct {
		Reason    string `json:"reason"`
		AppliesTo string `json:"appliesTo"`
		SortOrder int    `json:"sortOrder"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	template := &models.ReasonTemplate{
		Reason:    input.Reason,
		AppliesTo: input.AppliesTo,
		IsActive:  true,
		SortOrder: input.SortOrder,
	}

	ctx := c.Context()
	result, err := h.reasonTemplateService.Create(ctx, template)
	if err != nil {
		return err
	}

	return c.Status(fiber.StatusCreated).JSON(result)
}

func (h *Handler) updateReasonTemplate(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	var input struct {
		Reason    string `json:"reason"`
		AppliesTo string `json:"appliesTo"`
		IsActive  bool   `json:"isActive"`
		SortOrder int    `json:"sortOrder"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	template := &models.ReasonTemplate{
		ID:        id,
		Reason:    input.Reason,
		AppliesTo: input.AppliesTo,
		IsActive:  input.IsActive,
		SortOrder: input.SortOrder,
	}

	ctx := c.Context()
	result, err := h.reasonTemplateService.Update(ctx, template)
	if err != nil {
		return err
	}

	return c.JSON(result)
}

func (h *Handler) deleteReasonTemplate(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	if err := h.reasonTemplateService.Delete(ctx, id); err != nil {
		return err
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// Admin Settings handlers
func (h *Handler) getSettings(c *fiber.Ctx) error {
	ctx := c.Context()
	settings, err := h.settingsService.GetAll(ctx)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"settings": settings,
	})
}

func (h *Handler) updateSettings(c *fiber.Ctx) error {
	var input map[string]string
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Context()
	if err := h.settingsService.SetMultiple(ctx, input); err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"message": "Settings updated",
	})
}

// Server Groups handlers
func (h *Handler) getServerGroups(c *fiber.Ctx) error {
	ctx := c.Context()
	groups, err := h.serverGroupService.GetAll(ctx)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"groups": groups,
	})
}

func (h *Handler) getServerGroup(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	group, err := h.serverGroupService.GetByID(ctx, id)
	if err != nil {
		return err
	}

	return c.JSON(group)
}

func (h *Handler) createServerGroup(c *fiber.Ctx) error {
	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Color       string `json:"color"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	if input.Color == "" {
		input.Color = "#4ade80"
	}

	group := &models.ServerGroup{
		Name:        input.Name,
		Description: input.Description,
		Color:       input.Color,
	}

	ctx := c.Context()
	result, err := h.serverGroupService.Create(ctx, group)
	if err != nil {
		return err
	}

	return c.Status(fiber.StatusCreated).JSON(result)
}

func (h *Handler) updateServerGroup(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Color       string `json:"color"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	group := &models.ServerGroup{
		ID:          id,
		Name:        input.Name,
		Description: input.Description,
		Color:       input.Color,
	}

	ctx := c.Context()
	result, err := h.serverGroupService.Update(ctx, group)
	if err != nil {
		return err
	}

	return c.JSON(result)
}

func (h *Handler) deleteServerGroup(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	if err := h.serverGroupService.Delete(ctx, id); err != nil {
		return err
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) getServerGroupMembers(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	servers, err := h.serverGroupService.GetMembers(ctx, id)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"servers": servers,
	})
}

func (h *Handler) addServerGroupMember(c *fiber.Ctx) error {
	groupID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid group ID")
	}

	var input struct {
		ServerID int64 `json:"serverId"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Context()
	if err := h.serverGroupService.AddMember(ctx, groupID, input.ServerID); err != nil {
		return err
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Server added to group",
	})
}

func (h *Handler) setServerGroupMembers(c *fiber.Ctx) error {
	groupID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid group ID")
	}

	var input struct {
		ServerIDs []int64 `json:"serverIds"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}
	if input.ServerIDs == nil {
		input.ServerIDs = []int64{}
	}

	ctx := c.Context()
	if err := h.serverGroupService.SetMembers(ctx, groupID, input.ServerIDs); err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"message":     "Group members updated",
		"memberCount": len(input.ServerIDs),
	})
}

func (h *Handler) removeServerGroupMember(c *fiber.Ctx) error {
	groupID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid group ID")
	}

	serverID, err := strconv.ParseInt(c.Params("serverId"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}

	ctx := c.Context()
	if err := h.serverGroupService.RemoveMember(ctx, groupID, serverID); err != nil {
		return err
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) getServerGroupsForServer(c *fiber.Ctx) error {
	serverID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}

	ctx := c.Context()
	groups, err := h.serverGroupService.GetServerGroups(ctx, serverID)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"groups": groups,
	})
}

func (h *Handler) setServerGroups(c *fiber.Ctx) error {
	serverID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}

	var input struct {
		GroupIDs []int64 `json:"groupIds"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Context()
	if err := h.serverGroupService.SetServerGroups(ctx, serverID, input.GroupIDs); err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"message": "Server groups updated",
	})
}

// Report handlers

func (h *Handler) generateReport(c *fiber.Ctx) error {
	var input struct {
		ServerIDs            []int64 `json:"serverIds"`
		GroupIDs             []int64 `json:"groupIds"`
		StartDate            string  `json:"startDate"`
		EndDate              string  `json:"endDate"`
		ReportType           string  `json:"reportType"`
		IncludeSeverityChart bool    `json:"includeSeverityChart"`
		IncludeTrendChart    bool    `json:"includeTrendChart"`
		IncludeTopCVEs       bool    `json:"includeTopCVEs"`
		IncludeFullCVEList   bool    `json:"includeFullCVEList"`
	}

	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	// Parse dates
	var startDate, endDate time.Time
	var err error

	if input.StartDate != "" {
		startDate, err = time.Parse("2006-01-02", input.StartDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid start date format (use YYYY-MM-DD)")
		}
	} else {
		// Default to 30 days ago
		startDate = time.Now().AddDate(0, 0, -30)
	}

	if input.EndDate != "" {
		endDate, err = time.Parse("2006-01-02", input.EndDate)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid end date format (use YYYY-MM-DD)")
		}
		// Set to end of day
		endDate = endDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
	} else {
		// Default to today
		endDate = time.Now()
	}

	// Default report type
	if input.ReportType == "" {
		input.ReportType = "vulnerability_summary"
	}

	ctx := c.Context()

	req := services.ReportRequest{
		ServerIDs:            input.ServerIDs,
		GroupIDs:             input.GroupIDs,
		StartDate:            startDate,
		EndDate:              endDate,
		ReportType:           input.ReportType,
		IncludeSeverityChart: input.IncludeSeverityChart,
		IncludeTrendChart:    input.IncludeTrendChart,
		IncludeTopCVEs:       input.IncludeTopCVEs,
		IncludeFullCVEList:   input.IncludeFullCVEList,
	}

	var pdfBytes []byte

	switch input.ReportType {
	case "vulnerability_summary":
		pdfBytes, err = h.reportService.GenerateVulnerabilitySummary(ctx, req)
	default:
		return fiber.NewError(fiber.StatusBadRequest, "Unknown report type")
	}

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// Generate filename
	filename := fmt.Sprintf("vultrack-report-%s.pdf", time.Now().Format("2006-01-02"))

	c.Set("Content-Type", "application/pdf")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	return c.Send(pdfBytes)
}

// ============================================================================
// Report Schedule Handlers
// ============================================================================

func (h *Handler) getReportSchedules(c *fiber.Ctx) error {
	ctx := c.Context()
	schedules, err := h.reportScheduleService.GetAll(ctx)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if schedules == nil {
		schedules = []models.ReportSchedule{}
	}
	return c.JSON(fiber.Map{"schedules": schedules})
}

func (h *Handler) getReportSchedule(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}
	ctx := c.Context()
	rs, err := h.reportScheduleService.GetByID(ctx, id)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	return c.JSON(rs)
}

func (h *Handler) createReportSchedule(c *fiber.Ctx) error {
	var rs models.ReportSchedule
	if err := c.BodyParser(&rs); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	// Validate required fields
	if rs.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Name is required")
	}
	if rs.ScheduleType != "weekly" && rs.ScheduleType != "monthly_dom" && rs.ScheduleType != "monthly_dow" {
		return fiber.NewError(fiber.StatusBadRequest, "scheduleType must be 'weekly', 'monthly_dom', or 'monthly_dow'")
	}
	if err := validateRecipients(rs.Recipients); err != nil {
		return err
	}

	// Defaults
	if rs.IntervalValue < 1 {
		rs.IntervalValue = 1
	}
	if rs.Timezone == "" {
		rs.Timezone = "Europe/Berlin"
	}
	if rs.PeriodType == "" {
		rs.PeriodType = "last_month"
	}
	if rs.ServerIDs == nil {
		rs.ServerIDs = []int64{}
	}
	if rs.GroupIDs == nil {
		rs.GroupIDs = []int64{}
	}

	ctx := c.Context()
	if err := h.reportScheduleService.Create(ctx, &rs); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.Status(fiber.StatusCreated).JSON(rs)
}

func (h *Handler) updateReportSchedule(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	var rs models.ReportSchedule
	if err := c.BodyParser(&rs); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}
	rs.ID = id

	if rs.ServerIDs == nil {
		rs.ServerIDs = []int64{}
	}
	if rs.GroupIDs == nil {
		rs.GroupIDs = []int64{}
	}
	if err := validateRecipients(rs.Recipients); err != nil {
		return err
	}

	ctx := c.Context()
	if err := h.reportScheduleService.Update(ctx, &rs); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(rs)
}

func (h *Handler) deleteReportSchedule(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	if err := h.reportScheduleService.Delete(ctx, id); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) toggleReportSchedule(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	var input struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Context()
	if err := h.reportScheduleService.SetEnabled(ctx, id, input.Enabled); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	rs, _ := h.reportScheduleService.GetByID(ctx, id)
	return c.JSON(rs)
}

func (h *Handler) runReportScheduleNow(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	if h.reportScheduler == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "Report scheduler not available")
	}

	ctx := c.Context()
	if err := h.reportScheduler.RunNow(ctx, id); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{"message": "Report generated and sent successfully"})
}

// resetSystem resets VulTrack by clearing operational data, or only findings when resetType is "findings_only"
func (h *Handler) resetSystem(c *fiber.Ctx) error {
	var input struct {
		Confirm   string `json:"confirm"`
		ResetType string `json:"resetType"` // "full" (default) or "findings_only"
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	if input.ResetType == "findings_only" {
		if input.Confirm != "DELETE FINDINGS" {
			return fiber.NewError(fiber.StatusBadRequest, "Confirmation text does not match. Please type 'DELETE FINDINGS' to confirm.")
		}
		ctx := c.Context()
		findingsDeleted, err := h.settingsService.ResetFindingsOnly(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Reset findings only failed")
			return fiber.NewError(fiber.StatusInternalServerError, "Reset failed: "+err.Error())
		}
		log.Info().Int("findingsDeleted", findingsDeleted).Msg("Findings-only reset completed")
		return c.JSON(fiber.Map{
			"message":         "Findings deleted successfully",
			"resetType":       "findings_only",
			"findingsDeleted": findingsDeleted,
		})
	}

	// Full reset
	if input.Confirm != "RESET VULTRACK" {
		return fiber.NewError(fiber.StatusBadRequest, "Confirmation text does not match. Please type 'RESET VULTRACK' to confirm.")
	}

	ctx := c.Context()

	result, err := h.settingsService.ResetSystem(ctx)
	if err != nil {
		log.Error().Err(err).Msg("System reset failed")
		return fiber.NewError(fiber.StatusInternalServerError, "System reset failed: "+err.Error())
	}

	log.Warn().
		Int("serversDeleted", result.ServersDeleted).
		Int("findingsDeleted", result.FindingsDeleted).
		Int("assessmentsDeleted", result.AssessmentsDeleted).
		Int("agentsDeleted", result.AgentsDeleted).
		Msg("System reset completed")

	return c.JSON(fiber.Map{
		"message":               "System reset completed successfully",
		"resetType":             "full",
		"serversDeleted":        result.ServersDeleted,
		"findingsDeleted":       result.FindingsDeleted,
		"assessmentsDeleted":    result.AssessmentsDeleted,
		"serverGroupsDeleted":   result.ServerGroupsDeleted,
		"agentsDeleted":         result.AgentsDeleted,
		"enrollmentKeysDeleted": result.EnrollmentKeysDeleted,
	})
}

// deleteServer deletes a server and all its associated data
// DELETE /api/v1/admin/servers/:id
func (h *Handler) deleteServer(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}

	ctx := c.Context()

	// Get server info for logging before deletion
	server, err := h.serverService.GetByID(ctx, int64(id))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Server not found")
	}

	// Delete the server (CASCADE will handle findings, packages, etc.)
	if err := h.serverService.Delete(ctx, int64(id)); err != nil {
		log.Error().Err(err).Int64("serverId", int64(id)).Msg("Failed to delete server")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to delete server: "+err.Error())
	}

	log.Warn().
		Int64("serverId", int64(id)).
		Str("serverName", server.Name).
		Msg("Server deleted")

	return c.JSON(fiber.Map{
		"message":  "Server deleted successfully",
		"serverId": id,
	})
}

// ============================================================================
// SCAN JOBS
// ============================================================================

func (h *Handler) getScans(c *fiber.Ctx) error {
	ctx := c.Context()

	status := c.Query("status")
	search := c.Query("search")
	limit := c.QueryInt("limit", 50)
	offset := c.QueryInt("offset", 0)

	if limit < 1 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	jobs, total, err := h.scanQueue.GetJobs(ctx, status, search, limit, offset)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"jobs":  jobs,
		"total": total,
	})
}

func (h *Handler) getScanStats(c *fiber.Ctx) error {
	ctx := c.Context()
	stats, err := h.scanQueue.GetStats(ctx)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"stats": stats})
}

func (h *Handler) cancelScan(c *fiber.Ctx) error {
	jobID := c.Params("id")
	if err := h.scanQueue.CancelJob(jobID); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"message": "Scan cancelled"})
}

func (h *Handler) retryScan(c *fiber.Ctx) error {
	jobID := c.Params("id")
	ctx := c.Context()
	newJobID, err := h.scanQueue.RetryJob(ctx, jobID)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{"message": "Scan re-queued", "jobId": newJobID})
}

// validateRecipients checks that the list is non-empty, not too large, and contains only valid email addresses.
func validateRecipients(recipients []string) error {
	if len(recipients) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "At least one recipient is required")
	}
	if len(recipients) > 50 {
		return fiber.NewError(fiber.StatusBadRequest, "Too many recipients (maximum 50)")
	}
	for _, r := range recipients {
		if _, err := mail.ParseAddress(r); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("Invalid email address: %q", r))
		}
	}
	return nil
}
