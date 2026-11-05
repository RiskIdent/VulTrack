package services

import (
	"context"
	"strconv"
	"strings"
)

// Settings of the AI precondition analysis (docs/AUTO_ASSESSMENT_PLAN.md §8).
const (
	SettingPreEnabled  = "ai_precondition_enabled"
	SettingPreModel    = "ai_precondition_model"
	SettingPreBatch    = "ai_precondition_batch"
	SettingPreBudget   = "ai_precondition_budget_usd"
	SettingPreDaily    = "ai_precondition_daily_limit"
	SettingPreFallback = "ai_precondition_fallback_model"
)

// Defaults of the precondition analysis. It is off until an admin enables
// it; the decisions it enables are a rule (AI-PRE) with the usual modes.
const (
	DefaultPreModel  = "claude-sonnet-5-5"
	DefaultPreBudget = 20.0
	DefaultPreDaily  = 200
)

// PreconditionModels are the models selectable for the analysis.
var PreconditionModels = []string{"claude-sonnet-5-5", "claude-opus-5-5"}

// PreconditionFallbackModels can analyse CVEs the main model declined.
var PreconditionFallbackModels = []string{"claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5"}

// PreconditionConfig controls the AI precondition analysis. Shared by the
// analyzer, the REST API and MCP.
type PreconditionConfig struct {
	Enabled   bool    `json:"enabled"`
	Model     string  `json:"model"`
	UseBatch  bool    `json:"useBatch"`  // Message Batches API: half price, results within hours
	BudgetUSD float64 `json:"budgetUsd"` // per calendar month; the analysis pauses when reached
	DailyMax  int     `json:"dailyMax"`  // analyses started per day
	// FallbackModel analyses CVEs the main model declined (refusal); "" = none.
	FallbackModel string `json:"fallbackModel"`
}

// LoadPreconditionConfig reads the configuration; invalid values fall back
// to the defaults.
func (s *SettingsService) LoadPreconditionConfig(ctx context.Context) (PreconditionConfig, error) {
	cfg := PreconditionConfig{Model: DefaultPreModel, UseBatch: true, BudgetUSD: DefaultPreBudget, DailyMax: DefaultPreDaily}
	all, err := s.GetAll(ctx)
	if err != nil {
		return cfg, err
	}
	for _, st := range all {
		v := strings.TrimSpace(st.Value)
		switch st.Key {
		case SettingPreEnabled:
			cfg.Enabled = v == "true"
		case SettingPreModel:
			for _, m := range PreconditionModels {
				if v == m {
					cfg.Model = v
				}
			}
		case SettingPreBatch:
			cfg.UseBatch = v != "false"
		case SettingPreBudget:
			if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
				cfg.BudgetUSD = f
			}
		case SettingPreDaily:
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				cfg.DailyMax = n
			}
		case SettingPreFallback:
			for _, m := range PreconditionFallbackModels {
				if v == m {
					cfg.FallbackModel = v
				}
			}
		}
	}
	if cfg.FallbackModel == cfg.Model {
		cfg.FallbackModel = ""
	}
	return cfg, nil
}
