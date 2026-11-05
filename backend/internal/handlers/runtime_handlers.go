package handlers

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"
)

// ingestRuntime stores the runtime facts of an agent report. Errors are
// logged, not returned: the report itself (packages) must not fail because of
// optional data.
func (h *Handler) ingestRuntime(ctx context.Context, serverID int64, raw json.RawMessage) {
	res, err := h.runtimeFactsService.Ingest(ctx, serverID, raw)
	if err != nil {
		log.Error().Err(err).Int64("serverId", serverID).Msg("Failed to store runtime facts")
		return
	}
	if len(res.Changed) > 0 || len(res.Removed) > 0 || res.IndexNew {
		log.Info().Int64("serverId", serverID).Strs("changed", res.Changed).Strs("removed", res.Removed).
			Bool("moduleIndexStored", res.IndexNew).Msg("Runtime facts updated")
	}
}

// getServerRuntime returns the stored runtime facts of a server.
// GET /api/v1/servers/:id/runtime
func (h *Handler) getServerRuntime(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid server ID")
	}
	rt, err := h.runtimeFactsService.Get(c.Context(), id)
	if err != nil {
		return err
	}
	return c.JSON(rt)
}
