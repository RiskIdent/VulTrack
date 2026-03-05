package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"
)

// triggerVEXSync manually triggers a VEX sync
// POST /api/v1/admin/vex/sync
func (h *Handler) triggerVEXSync(c *fiber.Ctx) error {
	ctx := c.Context()

	if h.vexSyncer == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "VEX syncer not available")
	}

	if h.vexSyncer.IsSyncing() {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":   "VEX sync already in progress",
			"syncing": true,
		})
	}

	if err := h.vexSyncer.TriggerSync(ctx); err != nil {
		log.Error().Err(err).Msg("Failed to trigger VEX sync")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to trigger sync")
	}

	log.Info().Msg("VEX sync triggered manually")

	return c.JSON(fiber.Map{
		"message": "VEX sync started",
	})
}

// getVEXStatus returns the current VEX sync status
// GET /api/v1/admin/vex/status
func (h *Handler) getVEXStatus(c *fiber.Ctx) error {
	ctx := c.Context()

	syncing := false
	if h.vexSyncer != nil {
		syncing = h.vexSyncer.IsSyncing()
	}

	response := fiber.Map{
		"syncing": syncing,
	}

	if h.vexService == nil {
		return c.JSON(response)
	}

	// Statement count
	count, err := h.vexService.GetStatementCount(ctx)
	if err == nil {
		response["statementCount"] = count
	}

	// Sync status record
	ss, err := h.vexService.GetSyncStatus(ctx)
	if err == nil && ss != nil {
		if ss.StartedAt != nil {
			response["lastSync"] = ss.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		response["status"] = ss.Status
		if ss.ErrorMessage != "" {
			response["error"] = ss.ErrorMessage
		}
		if ss.ItemsProcessed > 0 {
			response["recordsProcessed"] = ss.ItemsProcessed
		}
	}

	return c.JSON(response)
}
