package handlers

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"

	vtmcp "github.com/vultrack/vultrack/internal/mcp"
	"github.com/vultrack/vultrack/internal/models"
)

// apiTokenLocalsKey is the Fiber Locals key under which requireMCPAuth stores
// the authenticated API token. It is shared with the mcp package so that write
// tools can read the acting token from the request context for audit logging.
const apiTokenLocalsKey = vtmcp.TokenContextKey

// requireMCPAuth authenticates a machine client against the MCP interface using
// an API token presented as `Authorization: Bearer vt_...`.
//
// Unlike requireAuth, this middleware ALWAYS enforces authentication, regardless
// of whether OIDC is enabled — the MCP interface is a machine surface and must
// never be exposed unauthenticated. On success it stores the *models.APIToken in
// c.Locals(apiTokenLocalsKey) so downstream handlers can enforce the token's
// read-only flag. All failures return an identical 401 so the response cannot be
// used to distinguish "unknown token" from "expired" from "malformed".
func (h *Handler) requireMCPAuth(c *fiber.Ctx) error {
	const unauthorized = "Invalid or missing API token"

	authHeader := c.Get(fiber.HeaderAuthorization)
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": unauthorized})
	}

	// Expect exactly "Bearer <token>". The scheme is matched case-insensitively
	// per RFC 7235; the token value itself is taken verbatim.
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "bearer") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": unauthorized})
	}
	tokenStr := strings.TrimSpace(parts[1])
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": unauthorized})
	}

	token, err := h.apiTokenService.Authenticate(c.Context(), tokenStr)
	if err != nil || token == nil {
		// Log the failure with request metadata only — never the token itself.
		log.Warn().
			Str("ip", c.IP()).
			Str("path", c.Path()).
			Msg("MCP authentication failed")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": unauthorized})
	}

	c.Locals(apiTokenLocalsKey, token)
	return c.Next()
}

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
