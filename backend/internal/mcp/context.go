package mcp

import (
	"context"

	"github.com/vultrack/vultrack/internal/models"
)

// TokenContextKey is the key under which the authenticated *models.APIToken is
// stored. The HTTP layer sets it via Fiber Locals (which backs onto the
// fasthttp RequestCtx); because the gofiber adaptor exposes that RequestCtx as
// the http.Request context, and the MCP SDK threads the request context through
// to tool handlers, write tools can read the acting token here for audit logging.
const TokenContextKey = "vultrack.apiToken"

// tokenFromContext returns the authenticated API token from the context, or nil
// if none is present.
func tokenFromContext(ctx context.Context) *models.APIToken {
	t, _ := ctx.Value(TokenContextKey).(*models.APIToken)
	return t
}

// tokenAudit returns identifying fields for the acting token, for audit logging.
// When no token is present in the context it returns ("unknown", "").
func tokenAudit(ctx context.Context) (prefix, description string) {
	if t := tokenFromContext(ctx); t != nil {
		return t.TokenPrefix, t.Description
	}
	return "unknown", ""
}
