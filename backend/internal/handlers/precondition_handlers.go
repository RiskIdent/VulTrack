package handlers

import (
	"context"
	"slices"
	"strconv"

	"github.com/gofiber/fiber/v2"

	"github.com/vultrack/vultrack/internal/services"
)

// getPreconditionStatus returns configuration, cost and progress of the AI
// precondition analysis.
// GET /api/v1/admin/ai-preconditions/status
func (h *Handler) getPreconditionStatus(c *fiber.Ctx) error {
	st, err := h.preconditionAnalyzer.GetStatus(c.Context())
	if err != nil {
		return err
	}
	return c.JSON(st)
}

type preconditionConfigInput struct {
	Enabled   *bool    `json:"enabled"`
	Model     *string  `json:"model"`
	UseBatch  *bool    `json:"useBatch"`
	BudgetUSD *float64 `json:"budgetUsd"`
	DailyMax  *int     `json:"dailyMax"`
	// FallbackModel: "" switches the fallback off.
	FallbackModel *string `json:"fallbackModel"`
}

// updatePreconditionConfig stores the configuration.
// PUT /api/v1/admin/ai-preconditions/config
func (h *Handler) updatePreconditionConfig(c *fiber.Ctx) error {
	var in preconditionConfigInput
	if err := c.BodyParser(&in); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}
	updates := map[string]string{}
	if in.Enabled != nil {
		updates[services.SettingPreEnabled] = strconv.FormatBool(*in.Enabled)
	}
	if in.Model != nil {
		if !slices.Contains(services.PreconditionModels, *in.Model) {
			return fiber.NewError(fiber.StatusBadRequest, "unsupported model")
		}
		updates[services.SettingPreModel] = *in.Model
	}
	if in.UseBatch != nil {
		updates[services.SettingPreBatch] = strconv.FormatBool(*in.UseBatch)
	}
	if in.BudgetUSD != nil {
		if *in.BudgetUSD < 0 || *in.BudgetUSD > 100000 {
			return fiber.NewError(fiber.StatusBadRequest, "budgetUsd must be between 0 and 100000")
		}
		updates[services.SettingPreBudget] = strconv.FormatFloat(*in.BudgetUSD, 'f', -1, 64)
	}
	if in.DailyMax != nil {
		if *in.DailyMax < 0 || *in.DailyMax > 100000 {
			return fiber.NewError(fiber.StatusBadRequest, "dailyMax must be between 0 and 100000")
		}
		updates[services.SettingPreDaily] = strconv.Itoa(*in.DailyMax)
	}
	if in.FallbackModel != nil {
		if *in.FallbackModel != "" && !slices.Contains(services.PreconditionFallbackModels, *in.FallbackModel) {
			return fiber.NewError(fiber.StatusBadRequest, "unsupported fallback model")
		}
		updates[services.SettingPreFallback] = *in.FallbackModel
	}
	if len(updates) > 0 {
		if err := h.settingsService.SetMultiple(c.Context(), updates); err != nil {
			return err
		}
	}
	return h.getPreconditionStatus(c)
}

// runPreconditionAnalysis starts a run now (collect batches, start analyses).
// POST /api/v1/admin/ai-preconditions/run
func (h *Handler) runPreconditionAnalysis(c *fiber.Ctx) error {
	if !h.preconditionAnalyzer.Configured() {
		return fiber.NewError(fiber.StatusConflict, "ANTHROPIC_API_KEY is not set")
	}
	go h.preconditionAnalyzer.RunOnce(context.Background())
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"message": "Run started"})
}

// getCVEPreconditions returns the stored analysis of a CVE (null if none).
// GET /api/v1/cves/:id/preconditions
func (h *Handler) getCVEPreconditions(c *fiber.Ctx) error {
	an, err := h.preconditionAnalyzer.GetAnalysis(c.Context(), c.Params("id"))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"analysis": an})
}
