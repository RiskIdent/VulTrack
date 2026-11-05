package preconditions

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/vultrack/vultrack/internal/ai"
	"github.com/vultrack/vultrack/internal/services"
)

// Status summarises the analysis for the Admin UI and MCP.
type Status struct {
	Config     services.PreconditionConfig `json:"config"`
	Models     []string                    `json:"models"`
	Configured bool                        `json:"configured"` // API key set
	Running    bool                        `json:"running"`
	SpentMonth float64                     `json:"spentMonth"`
	SpentTotal float64                     `json:"spentTotal"`
	AvgCost    float64                     `json:"avgCost"` // per analysis, current model and mode
	Analyses   struct {
		OK           int `json:"ok"`
		Determinable int `json:"determinable"`
		Pending      int `json:"pending"`
		Errors       int `json:"errors"`
	} `json:"analyses"`
	BatchesInProgress int    `json:"batchesInProgress"`
	LastError         string `json:"lastError,omitempty"`
}

// GetStatus reports the state of the analysis.
func (a *Analyzer) GetStatus(ctx context.Context) (*Status, error) {
	cfg, err := a.settings.LoadPreconditionConfig(ctx)
	if err != nil {
		return nil, err
	}
	st := &Status{Config: cfg, Models: services.PreconditionModels, Configured: a.client != nil}
	a.mu.Lock()
	st.Running, st.LastError = a.running, a.lastErr
	a.mu.Unlock()
	if st.SpentMonth, err = a.SpentThisMonth(ctx); err != nil {
		return nil, err
	}
	if err := a.db.QueryRow(ctx, `SELECT COALESCE(SUM(cost_usd), 0)::float8 FROM ai_usage WHERE stage = $1`, Stage).Scan(&st.SpentTotal); err != nil {
		return nil, err
	}
	st.AvgCost = a.estimate(ctx, cfg.Model, cfg.UseBatch)
	if err := a.db.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE status = 'ok'), COUNT(*) FILTER (WHERE status = 'ok' AND determinable),
		       COUNT(*) FILTER (WHERE status = 'pending'), COUNT(*) FILTER (WHERE status = 'error')
		FROM precondition_analyses
	`).Scan(&st.Analyses.OK, &st.Analyses.Determinable, &st.Analyses.Pending, &st.Analyses.Errors); err != nil {
		return nil, err
	}
	err = a.db.QueryRow(ctx, `SELECT COUNT(*) FROM precondition_batches WHERE status = 'in_progress'`).Scan(&st.BatchesInProgress)
	return st, err
}

// Analysis is the stored analysis of one CVE.
type Analysis struct {
	CVEID      string                 `json:"cveId"`
	Status     string                 `json:"status"`
	Model      string                 `json:"model"`
	Current    bool                   `json:"current"` // made with the configured model and prompt
	Result     *ai.PreconditionResult `json:"result,omitempty"`
	Error      string                 `json:"error,omitempty"`
	AnalysedAt *time.Time             `json:"analysedAt,omitempty"`
}

// GetAnalysis returns the analysis of a CVE, or nil.
func (a *Analyzer) GetAnalysis(ctx context.Context, cveID string) (*Analysis, error) {
	cfg, err := a.settings.LoadPreconditionConfig(ctx)
	if err != nil {
		return nil, err
	}
	var an Analysis
	var prompt string
	var raw []byte
	var errText *string
	err = a.db.QueryRow(ctx, `
		SELECT cve_id, status, model, prompt_hash, result, error, analysed_at FROM precondition_analyses WHERE cve_id = $1
	`, cveID).Scan(&an.CVEID, &an.Status, &an.Model, &prompt, &raw, &errText, &an.AnalysedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	an.Current = prompt == ai.PreconditionPromptHash(cfg.Model)
	if errText != nil {
		an.Error = *errText
	}
	if raw != nil {
		var r ai.PreconditionResult
		if json.Unmarshal(raw, &r) == nil {
			an.Result = &r
		}
	}
	return &an, nil
}
