package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v2"

	"github.com/vultrack/vultrack/internal/autoassess"
	"github.com/vultrack/vultrack/internal/models"
	"github.com/vultrack/vultrack/internal/services"
)

// getAutoAssessmentConfig returns the configuration and the rule catalogue.
// GET /api/v1/auto-assessment/config
func (h *Handler) getAutoAssessmentConfig(c *fiber.Ctx) error {
	cfg, err := h.settingsService.LoadAutoAssessmentConfig(c.Context())
	if err != nil {
		return err
	}
	return c.JSON(autoassess.Info(cfg))
}

type autoAssessmentConfigInput struct {
	Mode         *string           `json:"mode"`
	RuleModes    map[string]string `json:"ruleModes"`
	GuardExploit *bool             `json:"guardExploit"`
	GuardEPSS    *float64          `json:"guardEpss"`
	// FactSettleMinutes: see services.AutoAssessmentConfig.
	FactSettleMinutes *int `json:"factSettleMinutes"`
}

// updateAutoAssessmentConfig validates and stores the configuration, then
// re-evaluates every server in the background.
// PUT /api/v1/admin/auto-assessment/config
func (h *Handler) updateAutoAssessmentConfig(c *fiber.Ctx) error {
	var in autoAssessmentConfigInput
	if err := c.BodyParser(&in); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}
	validMode := func(m string) bool {
		return m == services.AutoModeOff || m == services.AutoModeShadow || m == services.AutoModeActive
	}
	updates := map[string]string{}
	if in.Mode != nil {
		if !validMode(*in.Mode) {
			return fiber.NewError(fiber.StatusBadRequest, "mode must be off, shadow or active")
		}
		updates[services.SettingAutoMode] = *in.Mode
	}
	if in.RuleModes != nil {
		for id, m := range in.RuleModes {
			if autoassess.RuleByID(id) == nil {
				return fiber.NewError(fiber.StatusBadRequest, "unknown rule "+id)
			}
			if !validMode(m) {
				return fiber.NewError(fiber.StatusBadRequest, "rule mode must be off, shadow or active")
			}
		}
		b, _ := json.Marshal(in.RuleModes)
		updates[services.SettingAutoRuleModes] = string(b)
	}
	if in.GuardExploit != nil {
		updates[services.SettingAutoGuardExploit] = strconv.FormatBool(*in.GuardExploit)
	}
	if in.GuardEPSS != nil {
		if *in.GuardEPSS < 0 || *in.GuardEPSS > 1 {
			return fiber.NewError(fiber.StatusBadRequest, "guardEpss must be between 0 and 1")
		}
		updates[services.SettingAutoGuardEPSS] = strconv.FormatFloat(*in.GuardEPSS, 'f', -1, 64)
	}
	if in.FactSettleMinutes != nil {
		if *in.FactSettleMinutes < 0 || *in.FactSettleMinutes > 7*24*60 {
			return fiber.NewError(fiber.StatusBadRequest, "factSettleMinutes must be between 0 and 10080")
		}
		updates[services.SettingAutoFactSettle] = strconv.Itoa(*in.FactSettleMinutes)
	}
	if len(updates) > 0 {
		if err := h.settingsService.SetMultiple(c.Context(), updates); err != nil {
			return err
		}
		h.autoEvaluator.TriggerAll("configuration changed")
		if h.kernelSyncer != nil {
			go h.kernelSyncer.RunOnce(context.Background()) // R-KMOD may just have been switched on
		}
	}
	return h.getAutoAssessmentConfig(c)
}

// reevaluateAutoAssessment re-evaluates every server in the background.
// POST /api/v1/admin/auto-assessment/reevaluate
func (h *Handler) reevaluateAutoAssessment(c *fiber.Ctx) error {
	h.autoEvaluator.TriggerAll("manual")
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"message": "Re-evaluation started"})
}

// getAutoAssessmentStats returns decision counts per rule and overall.
// GET /api/v1/auto-assessment/stats
func (h *Handler) getAutoAssessmentStats(c *fiber.Ctx) error {
	cfg, err := h.settingsService.LoadAutoAssessmentConfig(c.Context())
	if err != nil {
		return err
	}
	st, err := h.autoAssessmentService.Stats(c.Context(), cfg)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"stats": st, "config": autoassess.Info(cfg)})
}

// getAutoDecisions lists stored decisions with their state.
// GET /api/v1/auto-assessment/decisions
func (h *Handler) getAutoDecisions(c *fiber.Ctx) error {
	cfg, err := h.settingsService.LoadAutoAssessmentConfig(c.Context())
	if err != nil {
		return err
	}
	f := services.DecisionFilter{
		RuleID:   c.Query("ruleId"),
		State:    c.Query("state"),
		Guard:    c.Query("guard"),
		ServerID: int64(c.QueryInt("serverId", 0)),
		CVEID:    c.Query("cveId"),
		Search:   c.Query("search"),
		Limit:    c.QueryInt("limit", 50),
		Offset:   c.QueryInt("offset", 0),
	}
	decisions, total, err := h.autoAssessmentService.ListDecisions(c.Context(), cfg, f)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"decisions": decisions, "total": total})
}

// getDecisionEvents returns the audit trail, optionally for one server or CVE.
// GET /api/v1/auto-assessment/events
func (h *Handler) getDecisionEvents(c *fiber.Ctx) error {
	events, err := h.autoAssessmentService.Events(c.Context(), int64(c.QueryInt("serverId", 0)), c.Query("cveId"), c.QueryInt("limit", 100))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"events": events})
}

// getCVEServerStatus returns the effective status of every affected server.
// GET /api/v1/cves/:id/server-status
func (h *Handler) getCVEServerStatus(c *fiber.Ctx) error {
	cfg, err := h.settingsService.LoadAutoAssessmentConfig(c.Context())
	if err != nil {
		return err
	}
	statuses, err := h.autoAssessmentService.CVEServerStatuses(c.Context(), cfg, c.Params("id"))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"servers": statuses, "mode": cfg.Mode})
}

type serverAssessmentInput struct {
	Status     string `json:"status"`
	Comment    string `json:"comment"`
	AssessedBy string `json:"assessedBy"`
}

// actorName identifies the user acting on a request: the signed-in user (name,
// else email), else the name the client sent (auth disabled).
func actorName(c *fiber.Ctx, fallback string) string {
	if u, ok := c.Locals("user").(*models.User); ok && u != nil {
		if u.Name != "" {
			return u.Name
		}
		return u.Email
	}
	return fallback
}

// setServerAssessment stores a human decision for one server.
// PUT /api/v1/servers/:id/cves/:cveId/assessment
func (h *Handler) setServerAssessment(c *fiber.Ctx) error {
	serverID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}
	var in serverAssessmentInput
	if err := c.BodyParser(&in); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}
	o, err := h.autoAssessmentService.SetOverride(c.Context(), serverID, c.Params("cveId"), in.Status, in.Comment, actorName(c, in.AssessedBy))
	if errors.Is(err, services.ErrInvalidOverride) {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if err != nil {
		return err
	}
	return c.JSON(o)
}

// deleteServerAssessment removes the human decision for one server.
// DELETE /api/v1/servers/:id/cves/:cveId/assessment
func (h *Handler) deleteServerAssessment(c *fiber.Ctx) error {
	serverID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}
	removed, err := h.autoAssessmentService.RemoveOverride(c.Context(), serverID, c.Params("cveId"), actorName(c, c.Query("assessedBy")))
	if err != nil {
		return err
	}
	if !removed {
		return fiber.NewError(fiber.StatusNotFound, "No decision for this server")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// getKernelIntelStatus reports the kernel data R-KMOD relies on: fetched CVE
// records and mapped kernel builds.
// GET /api/v1/admin/kernel-intel/status
func (h *Handler) getKernelIntelStatus(c *fiber.Ctx) error {
	st, err := h.kernelSyncer.GetStatus(c.Context())
	if err != nil {
		return err
	}
	return c.JSON(st)
}

// triggerKernelIntelSync fetches missing kernel data in the background.
// POST /api/v1/admin/kernel-intel/sync
func (h *Handler) triggerKernelIntelSync(c *fiber.Ctx) error {
	if h.kernelSyncer.Running() {
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"message": "Sync already running"})
	}
	go h.kernelSyncer.RunOnce(context.Background())
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"message": "Sync started"})
}
