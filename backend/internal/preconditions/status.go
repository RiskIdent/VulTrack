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
	Config services.PreconditionConfig `json:"config"`
	Models []string                    `json:"models"`
	// FallbackModels can analyse CVEs the main model declined.
	FallbackModels []string `json:"fallbackModels"`
	Configured     bool     `json:"configured"` // API key set
	Running        bool     `json:"running"`
	SpentMonth     float64  `json:"spentMonth"`
	SpentTotal     float64  `json:"spentTotal"`
	AvgCost        float64  `json:"avgCost"` // per analysis, current model and mode
	Analyses       struct {
		OK           int `json:"ok"`
		Determinable int `json:"determinable"`
		Pending      int `json:"pending"`
		Errors       int `json:"errors"`
		Refused      int `json:"refused"`    // declined by the main model
		ByFallback   int `json:"byFallback"` // analysed by the fallback model after a refusal
	} `json:"analyses"`
	// Refusals lists the latest CVEs a model declined.
	Refusals          []Refusal `json:"refusals"`
	BatchesInProgress int       `json:"batchesInProgress"`
	LastError         string    `json:"lastError,omitempty"`
}

// Refusal is a CVE a model declined to analyse.
type Refusal struct {
	CVEID    string    `json:"cveId"`
	Model    string    `json:"model"`    // the model that declined last
	Fallback bool      `json:"fallback"` // the fallback model declined too
	Error    string    `json:"error"`
	At       time.Time `json:"at"`
}

// GetStatus reports the state of the analysis.
func (a *Analyzer) GetStatus(ctx context.Context) (*Status, error) {
	cfg, err := a.settings.LoadPreconditionConfig(ctx)
	if err != nil {
		return nil, err
	}
	st := &Status{Config: cfg, Models: services.PreconditionModels, FallbackModels: services.PreconditionFallbackModels,
		Configured: a.client != nil, Refusals: []Refusal{}}
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
		       COUNT(*) FILTER (WHERE status = 'pending'), COUNT(*) FILTER (WHERE status = 'error'),
		       COUNT(*) FILTER (WHERE refused_by IS NOT NULL),
		       COUNT(*) FILTER (WHERE status = 'ok' AND refused_by IS NOT NULL)
		FROM precondition_analyses
	`).Scan(&st.Analyses.OK, &st.Analyses.Determinable, &st.Analyses.Pending, &st.Analyses.Errors,
		&st.Analyses.Refused, &st.Analyses.ByFallback); err != nil {
		return nil, err
	}
	rows, err := a.db.Query(ctx, `
		SELECT cve_id, model, model <> refused_by, COALESCE(error, ''), COALESCE(analysed_at, requested_at)
		FROM precondition_analyses WHERE status = 'error' AND refused_by IS NOT NULL
		ORDER BY COALESCE(analysed_at, requested_at) DESC LIMIT 20
	`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r Refusal
		if err := rows.Scan(&r.CVEID, &r.Model, &r.Fallback, &r.Error, &r.At); err != nil {
			rows.Close()
			return nil, err
		}
		st.Refusals = append(st.Refusals, r)
	}
	rows.Close()
	err = a.db.QueryRow(ctx, `SELECT COUNT(*) FROM precondition_batches WHERE status = 'in_progress'`).Scan(&st.BatchesInProgress)
	return st, err
}

// Analysis is the stored analysis of one CVE.
type Analysis struct {
	CVEID      string                 `json:"cveId"`
	Status     string                 `json:"status"`
	Model      string                 `json:"model"`
	Current    bool                   `json:"current"`             // made with the configured model (or its fallback) and prompt
	RefusedBy  string                 `json:"refusedBy,omitempty"` // the main model declined; Model is the fallback
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
	var errText, refused *string
	err = a.db.QueryRow(ctx, `
		SELECT cve_id, status, model, prompt_hash, result, error, refused_by, analysed_at FROM precondition_analyses WHERE cve_id = $1
	`, cveID).Scan(&an.CVEID, &an.Status, &an.Model, &prompt, &raw, &errText, &refused, &an.AnalysedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if refused != nil {
		an.RefusedBy = *refused
	}
	an.Current = prompt == ai.PreconditionPromptHash(cfg.Model) ||
		(cfg.FallbackModel != "" && an.RefusedBy == cfg.Model && prompt == ai.PreconditionPromptHash(cfg.FallbackModel))
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
