package handlers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/vultrack/vultrack/internal/threatintel"
)

// getThreatIntelStatus returns the sync state of the KEV and EPSS feeds.
// GET /api/v1/admin/threat-intel/status
func (h *Handler) getThreatIntelStatus(c *fiber.Ctx) error {
	sources, err := h.threatIntelService.Status(c.Context())
	if err != nil {
		return err
	}
	for i := range sources {
		sources[i].Syncing = h.threatIntelSyncer.IsSyncing(threatintel.Source(sources[i].Source))
	}
	return c.JSON(fiber.Map{"sources": sources})
}

// triggerThreatIntelSync starts a sync of one feed (kev or epss).
// POST /api/v1/admin/threat-intel/:source/sync
func (h *Handler) triggerThreatIntelSync(c *fiber.Ctx) error {
	src := threatintel.Source(c.Params("source"))
	if src != threatintel.SourceKEV && src != threatintel.SourceEPSS {
		return fiber.NewError(fiber.StatusBadRequest, "Unknown source; use kev or epss")
	}
	if h.threatIntelSyncer.IsSyncing(src) {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": string(src) + " sync already in progress", "syncing": true})
	}
	if err := h.threatIntelSyncer.TriggerSync(src); err != nil {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	return c.JSON(fiber.Map{"message": string(src) + " sync started"})
}
