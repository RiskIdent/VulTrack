package handlers

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/auth"
	"github.com/vultrack/vultrack/internal/models"
)

// extractBearerToken extracts the token from an "Authorization: Bearer <token>" header.
func extractBearerToken(c *fiber.Ctx) (string, error) {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return "", fiber.NewError(fiber.StatusUnauthorized, "Missing Authorization header")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fiber.NewError(fiber.StatusUnauthorized, "Invalid Authorization header — expected 'Bearer <token>'")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", fiber.NewError(fiber.StatusUnauthorized, "Empty token in Authorization header")
	}
	return token, nil
}

// enrollAgentV2 handles v2 agent enrollment.
// The enrollment key is passed via the standard Authorization: Bearer header.
//
// POST /api/v2/agent/enroll
func (h *Handler) enrollAgentV2(c *fiber.Ctx) error {
	enrollmentKey, err := extractBearerToken(c)
	if err != nil {
		return err
	}

	var req models.EnrollRequestV2
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}
	if req.Hostname == "" {
		return fiber.NewError(fiber.StatusBadRequest, "hostname is required")
	}

	ctx := c.Context()

	// Validate the enrollment key
	key, err := h.enrollmentService.ValidateKey(ctx, enrollmentKey)
	if err != nil {
		log.Warn().Err(err).Str("hostname", req.Hostname).Msg("Invalid enrollment key (v2)")
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid enrollment key")
	}

	// Check for an existing active/pending agent with the same hostname
	existing, err := h.agentService.GetByHostname(ctx, req.Hostname)
	if err != nil {
		return err
	}
	if existing != nil {
		if !req.Force {
			return fiber.NewError(fiber.StatusConflict,
				"Agent already registered for this hostname. Set force=true to re-enroll.")
		}
		// Forceful re-enrollment: revoke old agent and its refresh tokens
		if err := h.agentService.RevokeAllRefreshTokens(ctx, existing.ID); err != nil {
			log.Warn().Err(err).Int64("agentId", existing.ID).Msg("Failed to revoke old refresh tokens during re-enrollment")
		}
		if err := h.agentService.Revoke(ctx, existing.ID); err != nil {
			log.Warn().Err(err).Int64("agentId", existing.ID).Msg("Failed to revoke old agent during re-enrollment")
		}
	}

	// Register the new agent (v1 RegisterAgent still works — we just skip the v1 token)
	agent, _, err := h.agentService.RegisterAgent(ctx, req.Hostname, key.ID, key.AutoApprove)
	if err != nil {
		log.Error().Err(err).Str("hostname", req.Hostname).Msg("Failed to register agent (v2)")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to register agent")
	}

	if err := h.enrollmentService.IncrementUsageCount(ctx, key.ID); err != nil {
		log.Warn().Err(err).Int64("keyId", key.ID).Msg("Failed to increment enrollment key usage count")
	}

	// Read TTL settings
	refreshTTLDays := h.settingsService.GetIntWithDefault(ctx, "agent_refresh_token_ttl_days", 90)
	accessTTLHours := h.settingsService.GetIntWithDefault(ctx, "agent_access_token_ttl_hours", 24)

	// Create long-lived refresh token
	_, fullRefreshToken, err := h.agentService.CreateRefreshToken(ctx, agent.ID, refreshTTLDays)
	if err != nil {
		log.Error().Err(err).Int64("agentId", agent.ID).Msg("Failed to create refresh token (v2)")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to create refresh token")
	}

	// Create short-lived JWT access token
	accessToken, err := auth.CreateAgentJWT(
		h.jwtSecret, agent.ID, req.Hostname,
		time.Duration(accessTTLHours)*time.Hour,
	)
	if err != nil {
		log.Error().Err(err).Int64("agentId", agent.ID).Msg("Failed to create JWT (v2)")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to create access token")
	}

	log.Info().
		Str("hostname", req.Hostname).
		Str("status", agent.Status).
		Int64("enrollmentKeyId", key.ID).
		Bool("forced", req.Force).
		Msg("Agent enrolled (v2)")

	return c.Status(fiber.StatusCreated).JSON(models.EnrollResponseV2{
		TokenType:    "Bearer",
		AccessToken:  accessToken,
		RefreshToken: fullRefreshToken,
		ExpiresIn:    accessTTLHours * 3600,
		Status:       agent.Status,
	})
}

// refreshAgentToken issues a new short-lived JWT and a new rotated refresh token.
// The current refresh token is revoked atomically (one-time use).
//
// POST /api/v2/agent/token
func (h *Handler) refreshAgentToken(c *fiber.Ctx) error {
	refreshToken, err := extractBearerToken(c)
	if err != nil {
		return err
	}

	ctx := c.Context()

	refreshTTLDays := h.settingsService.GetIntWithDefault(ctx, "agent_refresh_token_ttl_days", 90)
	accessTTLHours := h.settingsService.GetIntWithDefault(ctx, "agent_access_token_ttl_hours", 24)

	agent, newRefreshToken, err := h.agentService.ValidateAndRotateRefreshToken(ctx, refreshToken, refreshTTLDays)
	if err != nil {
		log.Warn().Err(err).Msg("Token refresh failed (v2)")
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid or expired refresh token")
	}

	accessToken, err := auth.CreateAgentJWT(
		h.jwtSecret, agent.ID, agent.Hostname,
		time.Duration(accessTTLHours)*time.Hour,
	)
	if err != nil {
		log.Error().Err(err).Int64("agentId", agent.ID).Msg("Failed to create JWT during refresh (v2)")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to create access token")
	}

	// Update last-seen while we're here
	if err := h.agentService.UpdateLastSeen(ctx, agent.ID, getClientIP(c), ""); err != nil {
		log.Warn().Err(err).Int64("agentId", agent.ID).Msg("Failed to update agent last seen during token refresh")
	}

	return c.JSON(models.TokenRefreshResponse{
		TokenType:    "Bearer",
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    accessTTLHours * 3600,
	})
}

// receiveAgentReportV2 handles agent report submissions using a JWT access token.
//
// POST /api/v2/agent/report
func (h *Handler) receiveAgentReportV2(c *fiber.Ctx) error {
	token, err := extractBearerToken(c)
	if err != nil {
		return err
	}

	// Validate JWT signature + expiry (no DB lookup)
	claims, err := auth.ValidateAgentJWT(h.jwtSecret, token)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid JWT on report endpoint (v2)")
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid or expired access token")
	}

	// Parse agent ID from the JWT subject claim
	var agentID int64
	if _, err := fmt.Sscanf(claims.Subject, "%d", &agentID); err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid token subject")
	}

	ctx := c.Context()

	// Lightweight DB check: verify agent is still active (handles revocation within JWT lifetime)
	agent, err := h.agentService.GetByID(ctx, agentID)
	if err != nil {
		return err
	}
	if agent == nil || agent.Status != models.AgentStatusActive {
		return fiber.NewError(fiber.StatusUnauthorized, "Agent not found or not active")
	}

	// Parse the report body — reuse the same AgentReport struct as v1
	var report models.AgentReport
	if err := c.BodyParser(&report); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

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
		return fiber.NewError(fiber.StatusBadRequest, "ipv4Addrs is required and must contain at least one address")
	}

	if report.ReportedAt.IsZero() {
		report.ReportedAt = time.Now()
	}

	// Update agent last-seen (version comes from the report body)
	clientIP := getClientIP(c)
	if err := h.agentService.UpdateLastSeen(ctx, agent.ID, clientIP, report.AgentVersion); err != nil {
		log.Warn().Err(err).Int64("agentId", agent.ID).Msg("Failed to update agent last seen (v2)")
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
		log.Error().Err(err).Str("hostname", report.Hostname).Msg("Failed to upsert server (v2)")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to save server")
	}

	// Link agent → server if not already done
	if agent.ServerID == nil || *agent.ServerID != server.ID {
		if err := h.agentService.LinkToServer(ctx, agent.ID, server.ID); err != nil {
			log.Warn().Err(err).Int64("agentId", agent.ID).Int64("serverId", server.ID).Msg("Failed to link agent to server (v2)")
		}
	}

	// Sync packages
	if len(report.Packages) > 0 {
		if err := h.packageService.SyncPackages(ctx, server.ID, report.Packages); err != nil {
			log.Error().Err(err).Int64("serverId", server.ID).Msg("Failed to sync packages (v2)")
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to sync packages")
		}
	}

	log.Info().
		Str("hostname", report.Hostname).
		Int64("serverId", server.ID).
		Int("packageCount", len(report.Packages)).
		Msg("Agent report processed (v2)")

	// Enqueue vulnerability scan
	var scanJobID string
	if h.scanQueue != nil {
		jobID, err := h.scanQueue.Enqueue(server.ID, server.Name, "agent_report")
		if err != nil {
			log.Warn().Err(err).Int64("serverId", server.ID).Msg("Failed to enqueue scan (v2)")
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
