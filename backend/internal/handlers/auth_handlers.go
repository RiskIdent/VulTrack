package handlers

import (
	"html"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/session"
)

// authLogin handles GET /api/v1/auth/login - redirects to OIDC IdP.
func (h *Handler) authLogin(c *fiber.Ctx) error {
	if !h.cfg.OIDCEnabled || h.oidcProvider == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "OIDC authentication is disabled",
		})
	}
	state, err := h.oidcProvider.NewState()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate OIDC state")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to start login",
		})
	}
	redirectURL := h.oidcProvider.AuthCodeURL(state)
	return c.Redirect(redirectURL, fiber.StatusFound)
}

// authCallback handles GET /api/v1/auth/callback - OIDC callback after IdP login.
func (h *Handler) authCallback(c *fiber.Ctx) error {
	if !h.cfg.OIDCEnabled || h.oidcProvider == nil {
		return c.Redirect(h.frontendURL(), fiber.StatusFound)
	}

	state := c.Query("state")
	code := c.Query("code")
	if state == "" || code == "" {
		log.Debug().Str("state", state).Msg("Callback missing state or code")
		return c.Redirect(h.frontendURL(), fiber.StatusFound)
	}
	if !h.oidcProvider.ValidateState(state) {
		log.Warn().Msg("Invalid or expired OIDC state")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid or expired state. Please try logging in again.",
		})
	}

	ctx := c.Context()
	claims, err := h.oidcProvider.ExchangeCode(ctx, code)
	if err != nil {
		log.Debug().Err(err).Msg("OIDC token exchange failed")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication failed",
		})
	}
	if claims == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "No identity token received",
		})
	}

	email := claims.Email
	if email == "" {
		email = claims.PreferredUsername
	}
	if email == "" {
		email = claims.Name
	}
	if email == "" {
		email = claims.Sub
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}

	user, err := h.userService.GetOrCreateFromOIDC(ctx, claims.Sub, claims.Issuer, email, name)
	if err != nil {
		log.Error().Err(err).Msg("GetOrCreateFromOIDC failed")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create or update user",
		})
	}

	sessionID, expiresAt, err := h.sessionStore.Create(ctx, user.ID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create session")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create session",
		})
	}

	// Clear any existing session cookies (domain and host-only) so only one valid cookie remains
	h.clearAllSessionCookies(c)
	h.setSessionCookie(c, sessionID, expiresAt)
	// Return 200 with HTML redirect so the browser reliably stores the Set-Cookie
	// (some browsers do not store cookies on 302 redirect responses from cross-site navigations)
	frontend := h.frontendURL()
	escaped := html.EscapeString(frontend)
	c.Set(fiber.HeaderContentType, "text/html; charset=utf-8")
	return c.Status(fiber.StatusOK).SendString(
		`<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=` + escaped + `"></head><body>Sign-in successful. <a href="` + escaped + `">Continue</a>.</body></html>`,
	)
}

// getSessionID returns the session cookie value. If the browser sends multiple vultrack_session
// cookies (e.g. old + new), returns the last one so the most recent session is used.
func (h *Handler) getSessionID(c *fiber.Ctx) string {
	raw := c.Get(fiber.HeaderCookie)
	if raw == "" {
		return ""
	}
	var last string
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, "=")
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(part[:idx])
		if name == session.CookieName {
			last = strings.TrimSpace(part[idx+1:])
		}
	}
	return last
}

// authLogout handles POST /api/v1/auth/logout - destroys session and clears cookie.
func (h *Handler) authLogout(c *fiber.Ctx) error {
	sessionID := h.getSessionID(c)
	if sessionID != "" {
		ctx := c.Context()
		_ = h.sessionStore.Delete(ctx, sessionID)
	}
	h.clearAllSessionCookies(c)
	// Optional: redirect to frontend
	frontend := h.cfg.OIDCFrontendURL
	if frontend == "" || frontend == "/" {
		return c.JSON(fiber.Map{"message": "Logged out"})
	}
	return c.Redirect(frontend, fiber.StatusFound)
}

// authMe handles GET /api/v1/auth/me - returns current user or auth config when OIDC disabled.
// This route has no requireAuth middleware, so we resolve the session manually.
func (h *Handler) authMe(c *fiber.Ctx) error {
	if !h.cfg.OIDCEnabled {
		return c.JSON(fiber.Map{
			"authEnabled": false,
		})
	}
	sessionID := h.getSessionID(c)
	if sessionID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"authEnabled": true,
			"error":      "Not authenticated",
		})
	}
	ctx := c.Context()
	userID, _, ok := h.sessionStore.Get(ctx, sessionID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"authEnabled": true,
			"error":      "Session expired or invalid",
		})
	}
	u, err := h.userService.GetByID(ctx, userID)
	if err != nil || u == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"authEnabled": true,
			"error":      "User not found",
		})
	}
	return c.JSON(fiber.Map{
		"authEnabled": true,
		"id":         u.ID,
		"email":      u.Email,
		"name":       u.Name,
		"isAdmin":    u.IsAdmin,
	})
}

func (h *Handler) frontendURL() string {
	u := strings.TrimSpace(h.cfg.OIDCFrontendURL)
	if u == "" {
		return "/"
	}
	return u
}

func (h *Handler) cookieDomain() string {
	u, err := url.Parse(strings.TrimSpace(h.cfg.OIDCFrontendURL))
	if err != nil || u.Host == "" {
		return ""
	}
	// Use host without port so the cookie works for the whole domain
	return u.Hostname()
}

func (h *Handler) setSessionCookie(c *fiber.Ctx, sessionID string, expiresAt time.Time) {
	u, err := url.Parse(strings.TrimSpace(h.cfg.OIDCFrontendURL))
	isHTTPS := err == nil && u.Scheme == "https"

	cookie := &fiber.Cookie{
		Name:     session.CookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  expiresAt,
		HTTPOnly: true,
		// SameSite=None so the cookie is stored when user is redirected from IdP (cross-site).
		// Secure is required when SameSite=None.
		SameSite: "None",
		Secure:   isHTTPS,
	}
	if domain := h.cookieDomain(); domain != "" && domain != "localhost" {
		cookie.Domain = domain
	}
	if !isHTTPS {
		cookie.SameSite = "Lax" // for localhost HTTP
	}
	c.Cookie(cookie)
}

// clearAllSessionCookies removes vultrack_session for both domain cookie and host-only cookie,
// so the browser never sends duplicate session cookies (which can make the backend use the wrong one).
func (h *Handler) clearAllSessionCookies(c *fiber.Ctx) {
	u, err := url.Parse(strings.TrimSpace(h.cfg.OIDCFrontendURL))
	sameSite := "Lax"
	secure := false
	if err == nil && u.Scheme == "https" {
		sameSite = "None"
		secure = true
	}
	// Clear domain cookie (e.g. Domain=vultrack.2rioffice.com)
	if domain := h.cookieDomain(); domain != "" && domain != "localhost" {
		c.Cookie(&fiber.Cookie{
			Name:     session.CookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HTTPOnly: true,
			SameSite: sameSite,
			Secure:   secure,
			Domain:   domain,
		})
	}
	// Clear host-only cookie (no Domain) so any old cookie from a previous deploy is removed
	c.Cookie(&fiber.Cookie{
		Name:     session.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HTTPOnly: true,
		SameSite: sameSite,
		Secure:   secure,
	})
}
