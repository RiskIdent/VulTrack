package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/services"
)

// ============================================================================
// OVAL DISTRIBUTIONS (read-only, from seed data)
// ============================================================================

// getOVALDistributions returns all known OVAL distributions
// GET /api/v1/admin/oval/distributions
func (h *Handler) getOVALDistributions(c *fiber.Ctx) error {
	ctx := c.Context()
	distributions, err := h.ovalService.GetDistributions(ctx)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"distributions": distributions,
	})
}

// ============================================================================
// OVAL SOURCES (user-enabled feeds)
// ============================================================================

// getOVALSources returns all OVAL sources
// GET /api/v1/admin/oval/sources
func (h *Handler) getOVALSources(c *fiber.Ctx) error {
	enabledOnly := c.Query("enabled") == "true"

	ctx := c.Context()
	sources, err := h.ovalService.GetSources(ctx, enabledOnly)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"sources": sources,
	})
}

// enableOVALSource enables an OVAL source for a distribution version
// POST /api/v1/admin/oval/sources
func (h *Handler) enableOVALSource(c *fiber.Ctx) error {
	var input struct {
		Distribution string `json:"distribution"`
		Version      string `json:"version"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	if input.Distribution == "" || input.Version == "" {
		return fiber.NewError(fiber.StatusBadRequest, "distribution and version are required")
	}

	ctx := c.Context()
	source, err := h.ovalService.EnableSource(ctx, input.Distribution, input.Version)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	log.Info().
		Str("distribution", source.Distribution).
		Str("version", source.Version).
		Msg("OVAL source enabled")

	// Optionally trigger sync
	if h.ovalSyncer != nil {
		go func() {
			if err := h.ovalSyncer.TriggerSync(c.Context(), source.ID); err != nil {
				log.Warn().Err(err).Msg("Failed to trigger OVAL sync after enable")
			}
		}()
	}

	return c.Status(fiber.StatusCreated).JSON(source)
}

// disableOVALSource disables an OVAL source
// PUT /api/v1/admin/oval/sources/:id/disable
func (h *Handler) disableOVALSource(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	if err := h.ovalService.DisableSource(ctx, int64(id)); err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"message": "Source disabled",
	})
}

// deleteOVALSource deletes an OVAL source and all its data
// DELETE /api/v1/admin/oval/sources/:id
func (h *Handler) deleteOVALSource(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	if err := h.ovalService.DeleteSource(ctx, int64(id)); err != nil {
		return err
	}

	log.Info().Int64("sourceId", int64(id)).Msg("OVAL source deleted")

	return c.SendStatus(fiber.StatusNoContent)
}

// ============================================================================
// SYNC OPERATIONS
// ============================================================================

// triggerOVALSync triggers a sync for a specific OVAL source
// POST /api/v1/admin/oval/sources/:id/sync
func (h *Handler) triggerOVALSync(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	if h.ovalSyncer == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "OVAL syncer not available")
	}

	// Check if already syncing
	if h.ovalSyncer.IsSyncing(int64(id)) {
		return fiber.NewError(fiber.StatusConflict, "Sync already in progress")
	}

	if err := h.ovalSyncer.TriggerSync(c.Context(), int64(id)); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	log.Info().Int("sourceId", id).Msg("OVAL sync triggered")

	return c.JSON(fiber.Map{
		"message": "Sync started",
	})
}

// triggerOVALSyncAll triggers a sync for all enabled OVAL sources
// POST /api/v1/admin/oval/sync-all
func (h *Handler) triggerOVALSyncAll(c *fiber.Ctx) error {
	if h.ovalSyncer == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "OVAL syncer not available")
	}

	if err := h.ovalSyncer.TriggerSyncAll(c.Context()); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	log.Info().Msg("OVAL sync all triggered")

	return c.JSON(fiber.Map{
		"message": "Sync started for all enabled sources",
	})
}

// ============================================================================
// SYNC STATUS
// ============================================================================

// getSyncStatus returns the latest sync status
// GET /api/v1/admin/sync/status
func (h *Handler) getSyncStatus(c *fiber.Ctx) error {
	ctx := c.Context()

	// Get running syncs
	running, err := h.ovalService.GetRunningSyncs(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get running syncs")
		running = nil
	}

	// Get latest completed syncs
	latest, err := h.ovalService.GetLatestSyncStatus(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get latest sync status")
		latest = nil
	}

	return c.JSON(fiber.Map{
		"running": running,
		"latest":  latest,
	})
}

// ============================================================================
// OVAL DEFINITIONS (public browsing)
// ============================================================================

// getOVALDefinitions returns OVAL definitions with filtering and pagination
// GET /api/v1/oval/definitions
func (h *Handler) getOVALDefinitions(c *fiber.Ctx) error {
	ctx := c.Context()

	filter := services.OVALDefinitionFilter{
		Limit:     c.QueryInt("limit", 50),
		Offset:    c.QueryInt("offset", 0),
		SortBy:    c.Query("sortBy", "createdAt"),
		SortOrder: c.Query("sortOrder", "desc"),
	}

	// Parse optional filters
	if dist := c.Query("distribution"); dist != "" {
		filter.Distribution = &dist
	}
	if version := c.Query("version"); version != "" {
		filter.Version = &version
	}
	if codename := c.Query("codename"); codename != "" {
		filter.Codename = &codename
	}
	if cveID := c.Query("cveId"); cveID != "" {
		filter.CVEID = &cveID
	}
	if severity := c.Query("severity"); severity != "" {
		filter.Severity = &severity
	}
	if sourceType := c.Query("sourceType"); sourceType != "" {
		filter.SourceType = &sourceType
	}
	if pkg := c.Query("package"); pkg != "" {
		filter.Package = &pkg
	}
	if search := c.Query("search"); search != "" {
		filter.Search = &search
	}
	if c.Query("hasExploit") == "true" {
		t := true
		filter.HasExploit = &t
	}

	definitions, total, err := h.ovalService.GetDefinitions(ctx, filter)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"definitions": definitions,
		"total":       total,
		"limit":       filter.Limit,
		"offset":      filter.Offset,
	})
}

// getOVALDefinitionByID returns a single OVAL definition with full details
// GET /api/v1/oval/definitions/:id
func (h *Handler) getOVALDefinitionByID(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	definition, err := h.ovalService.GetDefinitionByID(ctx, int64(id))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	if definition == nil {
		return fiber.NewError(fiber.StatusNotFound, "Definition not found")
	}

	return c.JSON(definition)
}
