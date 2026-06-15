package handlers

import (
	"net/http"

	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	vtmcp "github.com/vultrack/vultrack/internal/mcp"
	"github.com/vultrack/vultrack/internal/models"
)

// registerMCPRoutes builds the read-only and read-write MCP servers, wraps each
// in a Streamable HTTP handler, and mounts them at /api/mcp behind requireMCPAuth.
//
// The two servers are built once at startup. The endpoint dispatches each
// authenticated request to the server matching the token's read-only flag, so a
// read-only token never reaches the mutating tools — read-only is enforced at
// the protocol level, not by per-tool checks.
//
// JSONResponse + Stateless are enabled so every interaction is a self-contained
// request/response (application/json) with no long-lived SSE stream. This is
// required because the gofiber adaptor buffers responses and cannot stream
// text/event-stream. DisableLocalhostProtection is set because access is gated
// by the API token (a browser DNS-rebinding attacker cannot forge it) and the
// service runs behind a reverse proxy where the Host header is not trustworthy
// for this check anyway.
func (h *Handler) registerMCPRoutes(app *fiber.App) {
	roServer, rwServer := vtmcp.BuildServers(vtmcp.Deps{
		ServerService:      h.serverService,
		FindingService:     h.findingService,
		AssessmentService:  h.assessmentService,
		StatsService:       h.statsService,
		ServerGroupService: h.serverGroupService,
		SettingsService:    h.settingsService,
		ScanQueue:          h.scanQueue,
		UpsertAssessment:   h.upsertAssessment,
	})

	opts := &mcpsdk.StreamableHTTPOptions{
		Stateless:                  true,
		JSONResponse:               true,
		DisableLocalhostProtection: true,
	}
	roHandler := adaptor.HTTPHandler(mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return roServer }, opts))
	rwHandler := adaptor.HTTPHandler(mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return rwServer }, opts))

	app.All("/api/mcp", h.requireMCPAuth, func(c *fiber.Ctx) error {
		token, ok := c.Locals(apiTokenLocalsKey).(*models.APIToken)
		if !ok || token == nil {
			// requireMCPAuth always sets the token on success, so this should be
			// unreachable. Fail closed rather than defaulting to read-write.
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or missing API token"})
		}
		if token.IsReadOnly {
			return roHandler(c)
		}
		return rwHandler(c)
	})
}
