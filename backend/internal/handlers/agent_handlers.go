package handlers

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/models"
)

// getClientIP returns the real client IP, with fallback to RemoteAddr if
// X-Forwarded-For is not set (e.g., direct connections without proxy)
func getClientIP(c *fiber.Ctx) string {
	// First try Fiber's IP() which respects ProxyHeader config
	ip := c.IP()
	if ip != "" {
		return ip
	}

	// Fallback: extract IP from RemoteAddr (format: "ip:port" or just "ip")
	remoteAddr := c.Context().RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// RemoteAddr might not have a port
		return remoteAddr
	}
	return host
}

// ============================================================================
// AGENT ENROLLMENT
// ============================================================================

// enrollAgent handles agent enrollment requests
// POST /api/v1/agent/enroll
func (h *Handler) enrollAgent(c *fiber.Ctx) error {
	// Get enrollment key from header
	enrollmentKey := c.Get("X-Enrollment-Key")
	if enrollmentKey == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "Missing X-Enrollment-Key header")
	}

	// Parse request body
	var req models.EnrollRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	if req.Hostname == "" {
		return fiber.NewError(fiber.StatusBadRequest, "hostname is required")
	}

	ctx := c.Context()

	// Validate enrollment key
	key, err := h.enrollmentService.ValidateKey(ctx, enrollmentKey)
	if err != nil {
		log.Warn().Err(err).Str("hostname", req.Hostname).Msg("Invalid enrollment key")
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid enrollment key")
	}

	// Check if agent already exists for this hostname
	existingAgent, err := h.agentService.GetByHostname(ctx, req.Hostname)
	if err != nil {
		return err
	}
	if existingAgent != nil {
		// Agent already exists - return error or regenerate token?
		// For now, return error - admin can revoke old agent if needed
		return fiber.NewError(fiber.StatusConflict, "Agent already registered for this hostname")
	}

	// Register the agent
	agent, fullToken, err := h.agentService.RegisterAgent(ctx, req.Hostname, key.ID, key.AutoApprove)
	if err != nil {
		log.Error().Err(err).Str("hostname", req.Hostname).Msg("Failed to register agent")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to register agent")
	}

	// Increment usage count for enrollment key
	if err := h.enrollmentService.IncrementUsageCount(ctx, key.ID); err != nil {
		log.Warn().Err(err).Int64("keyId", key.ID).Msg("Failed to increment usage count")
	}

	log.Info().
		Str("hostname", req.Hostname).
		Str("status", agent.Status).
		Int64("enrollmentKeyId", key.ID).
		Msg("Agent enrolled successfully")

	return c.Status(fiber.StatusCreated).JSON(models.EnrollResponse{
		AgentToken: fullToken,
		Status:     agent.Status,
	})
}

// ============================================================================
// AGENT REPORT
// ============================================================================

// receiveAgentReport handles agent report submissions
// POST /api/v1/agent/report
func (h *Handler) receiveAgentReport(c *fiber.Ctx) error {
	// Get agent token from header
	agentToken := c.Get("X-Agent-Token")
	if agentToken == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "Missing X-Agent-Token header")
	}

	ctx := c.Context()

	// Validate agent token
	agent, err := h.agentService.ValidateToken(ctx, agentToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid agent token")
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid agent token")
	}

	// Parse request body
	var report models.AgentReport
	if err := c.BodyParser(&report); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	// Validate required fields
	if report.Hostname == "" {
		return fiber.NewError(fiber.StatusBadRequest, "hostname is required")
	}
	if report.OSFamily == "" {
		return fiber.NewError(fiber.StatusBadRequest, "osFamily is required")
	}
	if report.OSRelease == "" {
		return fiber.NewError(fiber.StatusBadRequest, "osRelease is required")
	}
	if report.Kernel == "" {
		return fiber.NewError(fiber.StatusBadRequest, "kernel is required")
	}
	if report.Arch == "" {
		return fiber.NewError(fiber.StatusBadRequest, "arch is required")
	}
	if len(report.IPv4Addrs) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "ipv4Addrs is required and must contain at least one IP address")
	}

	// Set reported time if not provided
	if report.ReportedAt.IsZero() {
		report.ReportedAt = time.Now()
	}

	// Update agent last seen (including agent version)
	clientIP := getClientIP(c)
	if err := h.agentService.UpdateLastSeen(ctx, agent.ID, clientIP, report.AgentVersion); err != nil {
		log.Warn().Err(err).Int64("agentId", agent.ID).Msg("Failed to update agent last seen")
	}

	// Upsert server
	server := &models.Server{
		Name:           report.Hostname,
		OSFamily:       report.OSFamily,
		OSRelease:      report.OSRelease,
		OSCodename:     report.OSCodename,
		Kernel:         report.Kernel,
		Arch:           report.Arch,
		PackageManager: report.PackageManager,
		IPv4Addrs:      report.IPv4Addrs,
		LastScanAt:     &report.ReportedAt,
	}

	server, err = h.serverService.Upsert(ctx, server)
	if err != nil {
		log.Error().Err(err).Str("hostname", report.Hostname).Msg("Failed to upsert server")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to save server")
	}

	// Link agent to server if not already linked
	if agent.ServerID == nil || *agent.ServerID != server.ID {
		if err := h.agentService.LinkToServer(ctx, agent.ID, server.ID); err != nil {
			log.Warn().Err(err).Int64("agentId", agent.ID).Int64("serverId", server.ID).Msg("Failed to link agent to server")
		}
	}

	// Sync packages
	if len(report.Packages) > 0 {
		if err := h.packageService.SyncPackages(ctx, server.ID, report.Packages); err != nil {
			log.Error().Err(err).Int64("serverId", server.ID).Msg("Failed to sync packages")
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to sync packages")
		}
	}

	log.Info().
		Str("hostname", report.Hostname).
		Int64("serverId", server.ID).
		Int("packageCount", len(report.Packages)).
		Msg("Agent report processed successfully")

	// Enqueue vulnerability scan
	var scanJobID string
	if h.scanQueue != nil {
		jobID, err := h.scanQueue.Enqueue(server.ID, server.Name, "agent_report")
		if err != nil {
			log.Warn().Err(err).Int64("serverId", server.ID).Msg("Failed to enqueue scan")
		} else {
			scanJobID = jobID
		}
	}

	return c.JSON(fiber.Map{
		"message":      "Report processed successfully",
		"serverId":     server.ID,
		"packageCount": len(report.Packages),
		"scanJobId":    scanJobID,
	})
}

// ============================================================================
// ADMIN: ENROLLMENT KEYS
// ============================================================================

// getEnrollmentKeys returns all enrollment keys
// GET /api/v1/admin/enrollment-keys
func (h *Handler) getEnrollmentKeys(c *fiber.Ctx) error {
	ctx := c.Context()
	keys, err := h.enrollmentService.GetAll(ctx)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"keys": keys,
	})
}

// createEnrollmentKey creates a new enrollment key
// POST /api/v1/admin/enrollment-keys
func (h *Handler) createEnrollmentKey(c *fiber.Ctx) error {
	var input struct {
		Name        string     `json:"name"`
		AutoApprove bool       `json:"autoApprove"`
		ExpiresAt   *time.Time `json:"expiresAt"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	if input.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	ctx := c.Context()
	key, fullKey, err := h.enrollmentService.CreateEnrollmentKey(ctx, input.Name, input.AutoApprove, input.ExpiresAt)
	if err != nil {
		return err
	}

	log.Info().Str("name", input.Name).Str("prefix", key.KeyPrefix).Msg("Enrollment key created")

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"key":     key,
		"fullKey": fullKey, // Only returned once!
	})
}

// updateEnrollmentKey updates an enrollment key
// PUT /api/v1/admin/enrollment-keys/:id
func (h *Handler) updateEnrollmentKey(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	var input struct {
		Name        string     `json:"name"`
		IsActive    bool       `json:"isActive"`
		AutoApprove bool       `json:"autoApprove"`
		ExpiresAt   *time.Time `json:"expiresAt"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	ctx := c.Context()
	key, err := h.enrollmentService.Update(ctx, int64(id), input.Name, input.IsActive, input.AutoApprove, input.ExpiresAt)
	if err != nil {
		return err
	}

	return c.JSON(key)
}

// deleteEnrollmentKey deletes an enrollment key
// DELETE /api/v1/admin/enrollment-keys/:id
func (h *Handler) deleteEnrollmentKey(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	if err := h.enrollmentService.Delete(ctx, int64(id)); err != nil {
		return err
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// ============================================================================
// ADMIN: REGISTERED AGENTS
// ============================================================================

// getRegisteredAgents returns all registered agents
// GET /api/v1/admin/agents
func (h *Handler) getRegisteredAgents(c *fiber.Ctx) error {
	statusFilter := c.Query("status")

	ctx := c.Context()
	agents, err := h.agentService.GetAll(ctx, statusFilter)
	if err != nil {
		return err
	}

	// Get stats
	stats, err := h.agentService.GetAgentStats(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get agent stats")
		stats = make(map[string]interface{})
	}

	return c.JSON(fiber.Map{
		"agents": agents,
		"stats":  stats,
	})
}

// approveAgent approves a pending agent
// PUT /api/v1/admin/agents/:id/approve
func (h *Handler) approveAgent(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	if err := h.agentService.Approve(ctx, int64(id)); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	log.Info().Int64("agentId", int64(id)).Msg("Agent approved")

	return c.JSON(fiber.Map{
		"message": "Agent approved",
	})
}

// revokeAgent revokes an agent's access
// PUT /api/v1/admin/agents/:id/revoke
func (h *Handler) revokeAgent(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	if err := h.agentService.Revoke(ctx, int64(id)); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	log.Info().Int64("agentId", int64(id)).Msg("Agent revoked")

	return c.JSON(fiber.Map{
		"message": "Agent revoked",
	})
}

// deleteAgent deletes an agent
// DELETE /api/v1/admin/agents/:id
func (h *Handler) deleteAgent(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	if err := h.agentService.Delete(ctx, int64(id)); err != nil {
		return err
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// ============================================================================
// SERVER PACKAGES
// ============================================================================

// triggerServerScan triggers a vulnerability scan for a server
// POST /api/v1/servers/:id/scan
func (h *Handler) triggerServerScan(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}

	if h.scanQueue == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "Scan queue not available")
	}

	// Look up server name for the job
	ctx := context.Background()
	server, err := h.serverService.GetByID(ctx, int64(id))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Server not found")
	}

	jobID, err := h.scanQueue.Enqueue(server.ID, server.Name, "manual")
	if err != nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, err.Error())
	}

	return c.JSON(fiber.Map{
		"message": "Scan enqueued",
		"jobId":   jobID,
	})
}

// getServerPackages returns packages for a server
// GET /api/v1/servers/:id/packages
func (h *Handler) getServerPackages(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}

	includeRemoved := strings.ToLower(c.Query("includeRemoved")) == "true"

	ctx := c.Context()
	packages, err := h.packageService.GetByServerID(ctx, int64(id), includeRemoved)
	if err != nil {
		return err
	}

	// Get counts
	activeCount, err := h.packageService.GetActivePackageCount(ctx, int64(id))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get active package count")
	}

	return c.JSON(fiber.Map{
		"packages":    packages,
		"total":       len(packages),
		"activeCount": activeCount,
	})
}
