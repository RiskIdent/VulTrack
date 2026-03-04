package handlers

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
)

// getAdminUsers returns all users (admin only). Used for user management UI.
func (h *Handler) getAdminUsers(c *fiber.Ctx) error {
	ctx := c.Context()
	list, err := h.userService.List(ctx)
	if err != nil {
		return err
	}
	// Map to API shape (no OIDC fields)
	type userResp struct {
		ID          int64   `json:"id"`
		Email       string  `json:"email"`
		Name        string  `json:"name"`
		IsAdmin     bool    `json:"isAdmin"`
		LastLoginAt *string `json:"lastLoginAt,omitempty"`
		CreatedAt   string  `json:"createdAt"`
		UpdatedAt   string  `json:"updatedAt"`
	}
	out := make([]userResp, len(list))
	for i, u := range list {
		var lastLogin *string
		if u.LastLoginAt != nil {
			s := u.LastLoginAt.Format("2006-01-02T15:04:05Z07:00")
			lastLogin = &s
		}
		out[i] = userResp{
			ID:          u.ID,
			Email:       u.Email,
			Name:        u.Name,
			IsAdmin:     u.IsAdmin,
			LastLoginAt: lastLogin,
			CreatedAt:   u.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:   u.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}
	return c.JSON(fiber.Map{"users": out})
}

// patchAdminUser updates a user (admin only). Body: { "isAdmin": true|false }.
func (h *Handler) patchAdminUser(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid user ID")
	}
	var body struct {
		IsAdmin *bool `json:"isAdmin"`
	}
	if err := c.BodyParser(&body); err != nil || body.IsAdmin == nil {
		return fiber.NewError(fiber.StatusBadRequest, "Request body must include isAdmin (boolean)")
	}
	ctx := c.Context()
	if err := h.userService.SetAdmin(ctx, id, *body.IsAdmin); err != nil {
		return err
	}
	u, _ := h.userService.GetByID(ctx, id)
	if u == nil {
		return fiber.NewError(fiber.StatusNotFound, "User not found")
	}
	return c.JSON(fiber.Map{
		"id":      u.ID,
		"email":   u.Email,
		"name":    u.Name,
		"isAdmin": u.IsAdmin,
	})
}
