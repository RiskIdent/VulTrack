package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"
)

// triggerNVDSync manually triggers an NVD sync
// POST /api/v1/admin/nvd/sync
func (h *Handler) triggerNVDSync(c *fiber.Ctx) error {
	ctx := c.Context()

	if h.nvdSyncer == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "NVD syncer not available")
	}

	if h.nvdSyncer.IsSyncing() {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":   "NVD sync already in progress",
			"syncing": true,
		})
	}

	if err := h.nvdSyncer.TriggerSync(ctx); err != nil {
		log.Error().Err(err).Msg("Failed to trigger NVD sync")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to trigger sync")
	}

	log.Info().Msg("NVD sync triggered manually")

	return c.JSON(fiber.Map{
		"message": "NVD sync started",
	})
}

// getNVDStatus returns the current NVD sync status
// GET /api/v1/admin/nvd/status
func (h *Handler) getNVDStatus(c *fiber.Ctx) error {
	ctx := c.Context()

	// Get CVE count
	var cveCount int
	err := h.settingsService.DB().QueryRow(ctx, `
		SELECT COUNT(*) FROM cve_catalog
	`).Scan(&cveCount)
	if err != nil {
		cveCount = 0
	}

	// Get last sync info
	var lastSync, status, errorMsg *string
	var recordsProcessed *int
	h.settingsService.DB().QueryRow(ctx, `
		SELECT 
			TO_CHAR(last_sync_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			status,
			error_message,
			records_processed
		FROM sync_status 
		WHERE source_type = 'nvd' AND source_name = 'nvd'
		ORDER BY last_sync_at DESC 
		LIMIT 1
	`).Scan(&lastSync, &status, &errorMsg, &recordsProcessed)

	// Check if API key is configured
	hasAPIKey := false
	settings, _ := h.settingsService.GetAll(ctx)
	for _, s := range settings {
		if s.Key == "nvd_api_key" && s.Value != "" {
			hasAPIKey = true
			break
		}
	}

	syncing := false
	if h.nvdSyncer != nil {
		syncing = h.nvdSyncer.IsSyncing()
	}

	response := fiber.Map{
		"cveCount":  cveCount,
		"syncing":   syncing,
		"hasApiKey": hasAPIKey,
	}

	if lastSync != nil {
		response["lastSync"] = *lastSync
	}
	if status != nil {
		response["status"] = *status
	}
	if errorMsg != nil && *errorMsg != "" {
		response["error"] = *errorMsg
	}
	if recordsProcessed != nil {
		response["recordsProcessed"] = *recordsProcessed
	}

	return c.JSON(response)
}
