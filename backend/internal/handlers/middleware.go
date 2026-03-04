package handlers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/vultrack/vultrack/internal/models"
)

// requireAuth returns a Fiber handler that, when OIDC is enabled, loads the session from the cookie,
// resolves the user, and sets c.Locals("user", *models.User). If OIDC is disabled or no valid session, continues or 401.
func (h *Handler) requireAuth(c *fiber.Ctx) error {
	if !h.cfg.OIDCEnabled {
		return c.Next()
	}
	sessionID := h.getSessionID(c)
	if sessionID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Not authenticated",
		})
	}
	ctx := c.Context()
	userID, _, ok := h.sessionStore.Get(ctx, sessionID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Session expired or invalid",
		})
	}
	user, err := h.userService.GetByID(ctx, userID)
	if err != nil || user == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User not found",
		})
	}
	c.Locals("user", user)
	return c.Next()
}

// requireAdmin returns a Fiber handler that must be used after requireAuth. It returns 403 if the user is not an admin.
func (h *Handler) requireAdmin(c *fiber.Ctx) error {
	if !h.cfg.OIDCEnabled {
		return c.Next()
	}
	user := c.Locals("user")
	if user == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Not authenticated",
		})
	}
	u, ok := user.(*models.User)
	if !ok || !u.IsAdmin {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Admin access required",
		})
	}
	return c.Next()
}
