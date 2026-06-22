package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"

	"github.com/vultrack/vultrack/internal/models"
	"github.com/vultrack/vultrack/internal/services"
)

// getAIAssessments returns AI assessments with filtering and pagination. It
// backs the "AI Assessments" page.
func (h *Handler) getAIAssessments(c *fiber.Ctx) error {
	filter := services.AIAssessmentFilter{
		Status: c.Query("status"),
		Search: c.Query("search"),
		Limit:  c.QueryInt("limit", 50),
		Offset: c.QueryInt("offset", 0),
	}

	items, total, err := h.aiAssessmentService.GetAll(c.Context(), filter)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"assessments": items,
		"total":       total,
		"limit":       filter.Limit,
		"offset":      filter.Offset,
	})
}

// getAIAssessment returns the AI assessment for a single CVE, or 404 if none
// exists yet. The triage view uses this to show the AI assessment card.
func (h *Handler) getAIAssessment(c *fiber.Ctx) error {
	cveID := c.Params("cveId")
	a, err := h.aiAssessmentService.GetByCVE(c.Context(), cveID)
	if err == pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusNotFound, "No AI assessment for this CVE")
	}
	if err != nil {
		return err
	}
	return c.JSON(a)
}

// requestAIAssessment enqueues an AI assessment for a CVE. Use ?force=true to
// request a fresh assessment when one already exists. The background worker
// picks up the queued row; this endpoint only enqueues.
func (h *Handler) requestAIAssessment(c *fiber.Ctx) error {
	if !h.cfg.AIConfigured() {
		return fiber.NewError(fiber.StatusServiceUnavailable, "AI assessment is not configured")
	}
	// Respect the admin master switch: when AI assessment is disabled, manual
	// requests are rejected just like auto-assessment is suppressed.
	if enabled, _ := h.settingsService.GetBool(c.Context(), services.SettingAIEnabled); !enabled {
		return fiber.NewError(fiber.StatusServiceUnavailable, "AI assessment is disabled")
	}

	cveID := c.Params("cveId")
	if cveID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "cveId is required")
	}

	// Only CVEs with at least one active (unresolved) finding can be assessed.
	// GetServersByCVE returns unresolved findings only, so this also rejects
	// unknown CVEs and CVEs whose findings have all been resolved.
	active, err := h.findingService.GetServersByCVE(c.Context(), cveID)
	if err != nil {
		return err
	}
	if len(active) == 0 {
		return fiber.NewError(fiber.StatusNotFound, "No active findings for this CVE")
	}

	force := c.QueryBool("force", false)
	outcome, err := h.aiAssessmentService.Enqueue(c.Context(), cveID, h.currentUserEmail(c), force)
	if err != nil {
		return err
	}
	switch outcome {
	case services.EnqueueProcessing:
		return fiber.NewError(fiber.StatusConflict, "An AI assessment is already queued or in progress for this CVE")
	case services.EnqueueCooldown:
		return fiber.NewError(fiber.StatusTooManyRequests, "A new AI assessment can be requested at most once every 30 minutes")
	}

	queued := outcome == services.EnqueueCreated || outcome == services.EnqueueRequeued
	return c.JSON(fiber.Map{
		"cveId":  cveID,
		"queued": queued,
		"status": string(outcome),
	})
}

// currentUserEmail returns the authenticated user's email, or "" when there is
// no user (e.g. OIDC disabled). Used to attribute manual assessment requests.
func (h *Handler) currentUserEmail(c *fiber.Ctx) string {
	if u, ok := c.Locals("user").(*models.User); ok && u != nil {
		return u.Email
	}
	return ""
}
