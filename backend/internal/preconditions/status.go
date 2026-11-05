package preconditions

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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
	// Failures lists the latest failed analyses (refusals included).
	Failures          []Failure `json:"failures"`
	BatchesInProgress int       `json:"batchesInProgress"`
	LastError         string    `json:"lastError,omitempty"`
}

// Failure is a CVE whose analysis failed, including refusals.
type Failure struct {
	CVEID    string    `json:"cveId"`
	Model    string    `json:"model"`    // the model of the failed attempt
	Refused  bool      `json:"refused"`  // the model declined (safety classifier)
	Fallback bool      `json:"fallback"` // the attempt was the fallback model's
	Terminal bool      `json:"terminal"` // will not be retried until the CVE data or the model changes
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
		Configured: a.client != nil, Failures: []Failure{}}
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
		SELECT cve_id, model, refused_by IS NOT NULL, COALESCE(model <> refused_by, false), terminal,
		       COALESCE(error, ''), COALESCE(analysed_at, requested_at)
		FROM precondition_analyses WHERE status = 'error'
		ORDER BY COALESCE(analysed_at, requested_at) DESC LIMIT 200
	`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f Failure
		if err := rows.Scan(&f.CVEID, &f.Model, &f.Refused, &f.Fallback, &f.Terminal, &f.Error, &f.At); err != nil {
			rows.Close()
			return nil, err
		}
		st.Failures = append(st.Failures, f)
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

// Backlog counts the CVEs of the triage queue, not yet decided by a rule,
// that have no current analysis: no analysis with the configured model (or,
// after a refusal, its fallback), none pending and no failure that will not
// be retried. A changed CVE input is not detected here; such CVEs are
// redone on the next run anyway.
func Backlog(ctx context.Context, db *pgxpool.Pool, settings *services.SettingsService, findings *services.FindingService) (int, error) {
	cfg, err := settings.LoadPreconditionConfig(ctx)
	if err != nil {
		return 0, err
	}
	opts, err := settings.BuildTriageOptions(ctx)
	if err != nil {
		return 0, err
	}
	ids, err := findings.TriageQueueCVEIDs(ctx, opts, RuleID, 1_000_000)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	fallbackHash := ""
	if cfg.FallbackModel != "" {
		fallbackHash = ai.PreconditionPromptHash(cfg.FallbackModel)
	}
	var covered int
	err = db.QueryRow(ctx, `
		SELECT COUNT(*) FROM precondition_analyses
		WHERE cve_id = ANY($1)
		  AND (prompt_hash = $2 OR (refused_by = $3 AND prompt_hash = $4))
		  AND (status IN ('ok', 'pending') OR terminal OR refused_by IS NOT NULL)
	`, ids, ai.PreconditionPromptHash(cfg.Model), cfg.Model, fallbackHash).Scan(&covered)
	return len(ids) - covered, err
}

// Cleanup deletes analyses of CVEs without active findings that are older
// than retention, ended batches older than retention, and cost records older
// than costRetention (kept longer for the monthly statistics).
func (a *Analyzer) Cleanup(ctx context.Context, retention, costRetention time.Duration) (analyses, batches, usage int64, err error) {
	tag, err := a.db.Exec(ctx, `
		DELETE FROM precondition_analyses p
		WHERE COALESCE(p.analysed_at, p.requested_at) < NOW() - make_interval(secs => $1) AND p.status <> 'pending'
		  AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.cve_id = p.cve_id AND f.resolved_at IS NULL)
	`, retention.Seconds())
	if err != nil {
		return 0, 0, 0, err
	}
	analyses = tag.RowsAffected()
	tag, err = a.db.Exec(ctx, `
		DELETE FROM precondition_batches WHERE status = 'ended' AND ended_at < NOW() - make_interval(secs => $1)
	`, retention.Seconds())
	if err != nil {
		return analyses, 0, 0, err
	}
	batches = tag.RowsAffected()
	tag, err = a.db.Exec(ctx, `DELETE FROM ai_usage WHERE created_at < NOW() - make_interval(secs => $1)`, costRetention.Seconds())
	if err != nil {
		return analyses, batches, 0, err
	}
	return analyses, batches, tag.RowsAffected(), nil
}
