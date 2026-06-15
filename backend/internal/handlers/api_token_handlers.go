package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/models"
)

// ============================================================================
// ADMIN: API TOKENS (MCP interface)
// ============================================================================

// getAPITokens returns all API tokens (without hashes).
// GET /api/v1/admin/api-tokens
func (h *Handler) getAPITokens(c *fiber.Ctx) error {
	ctx := c.Context()
	tokens, err := h.apiTokenService.GetAll(ctx)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"tokens": tokens,
	})
}

// createAPIToken creates a new API token.
// POST /api/v1/admin/api-tokens
func (h *Handler) createAPIToken(c *fiber.Ctx) error {
	var input struct {
		Description string     `json:"description"`
		IsReadOnly  bool       `json:"isReadOnly"`
		ExpiresAt   *time.Time `json:"expiresAt"`
	}
	if err := c.BodyParser(&input); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	if input.Description == "" {
		return fiber.NewError(fiber.StatusBadRequest, "description is required")
	}
	if input.ExpiresAt != nil && !input.ExpiresAt.After(time.Now()) {
		return fiber.NewError(fiber.StatusBadRequest, "expiresAt must be in the future")
	}

	// Resolve the creating user (nil when OIDC is disabled).
	var createdBy *int64
	if u, ok := c.Locals("user").(*models.User); ok && u != nil {
		createdBy = &u.ID
	}

	ctx := c.Context()
	token, fullToken, err := h.apiTokenService.Create(ctx, input.Description, input.IsReadOnly, createdBy, input.ExpiresAt)
	if err != nil {
		return err
	}

	log.Info().
		Str("description", input.Description).
		Str("prefix", token.TokenPrefix).
		Bool("readOnly", token.IsReadOnly).
		Msg("API token created")

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"token":     token,
		"fullToken": fullToken, // Only returned once!
	})
}

// deleteAPIToken deletes an API token.
// DELETE /api/v1/admin/api-tokens/:id
func (h *Handler) deleteAPIToken(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	ctx := c.Context()
	if err := h.apiTokenService.Delete(ctx, int64(id)); err != nil {
		return err
	}

	return c.SendStatus(fiber.StatusNoContent)
}
