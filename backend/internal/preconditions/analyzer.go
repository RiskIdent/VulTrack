// Package preconditions runs the AI precondition analysis: for CVEs of the
// triage queue that no rule has decided, a model lists the attack paths and
// their conditions; the rule AI-PRE (internal/autoassess) checks them per
// server. See docs/AUTO_ASSESSMENT_PLAN.md §8.
package preconditions

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/ai"
	"github.com/vultrack/vultrack/internal/services"
)

// RuleID is the rule that applies the analyses.
const RuleID = "AI-PRE"

// Stage is the ai_usage stage name.
const Stage = "preconditions"

// Analyzer schedules and stores analyses.
type Analyzer struct {
	db       *pgxpool.Pool
	settings *services.SettingsService
	findings *services.FindingService
	client   *ai.Client // nil when no API key is configured

	// AfterChange runs when new analyses arrived (re-evaluate decisions).
	AfterChange func(reason string)

	mu      sync.Mutex
	running bool
	lastErr string
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// New creates an Analyzer. client may be nil.
func New(db *pgxpool.Pool, settings *services.SettingsService, findings *services.FindingService, client *ai.Client) *Analyzer {
	return &Analyzer{db: db, settings: settings, findings: findings, client: client, stopCh: make(chan struct{})}
}

// Configured reports whether an API key is set.
func (a *Analyzer) Configured() bool { return a.client != nil }

// Start runs every 15 minutes: collect finished batches, start new analyses.
func (a *Analyzer) Start() {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		t := time.NewTimer(3 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-a.stopCh:
				return
			case <-t.C:
				a.RunOnce(context.Background())
				t.Reset(15 * time.Minute)
			}
		}
	}()
}

// Stop stops the schedule.
func (a *Analyzer) Stop() {
	close(a.stopCh)
	a.wg.Wait()
}

// RunOnce collects finished batches (even when the analysis has been switched
// off since: they are paid for) and, when enabled, starts new analyses within
// budget and daily limit.
func (a *Analyzer) RunOnce(ctx context.Context) {
	if a.client == nil {
		return
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return
	}
	a.running = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
	}()

	stored, err := a.collectBatches(ctx)
	if err != nil {
		a.fail("collect batches", err)
	}
	cfg, err := a.settings.LoadPreconditionConfig(ctx)
	if err == nil && cfg.Enabled {
		n, err := a.startAnalyses(ctx, cfg)
		if err != nil {
			a.fail("start analyses", err)
		}
		stored += n
	}
	if stored > 0 && a.AfterChange != nil {
		a.AfterChange("AI precondition analysis")
	}
}

func (a *Analyzer) fail(what string, err error) {
	log.Error().Err(err).Msg("AI precondition analysis: " + what)
	a.mu.Lock()
	a.lastErr = what + ": " + err.Error()
	a.mu.Unlock()
}

// estimate is the expected cost of one analysis: the mean of recent ones, or
// a conservative guess before there are any.
func (a *Analyzer) estimate(ctx context.Context, model string, batch bool) float64 {
	var avg *float64
	_ = a.db.QueryRow(ctx, `
		SELECT AVG(cost_usd)::float8 FROM (
			SELECT cost_usd FROM ai_usage WHERE stage = $1 AND model = $2 AND batch = $3
			ORDER BY id DESC LIMIT 50) x
	`, Stage, model, batch).Scan(&avg)
	if avg != nil && *avg > 0 {
		return *avg
	}
	guess := ai.Cost(model, ai.Usage{InputTokens: 2500, OutputTokens: 3000}, batch)
	return guess
}

// SpentThisMonth sums the stage's cost in the current calendar month.
func (a *Analyzer) SpentThisMonth(ctx context.Context) (float64, error) {
	var spent float64
	err := a.db.QueryRow(ctx, `
		SELECT COALESCE(SUM(cost_usd), 0)::float8 FROM ai_usage
		WHERE stage = $1 AND created_at >= date_trunc('month', NOW())
	`, Stage).Scan(&spent)
	return spent, err
}

func (a *Analyzer) startAnalyses(ctx context.Context, cfg services.PreconditionConfig) (int, error) {
	spent, err := a.SpentThisMonth(ctx)
	if err != nil {
		return 0, err
	}
	var pending, today int
	if err := a.db.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE status = 'pending'),
		       COUNT(*) FILTER (WHERE requested_at >= date_trunc('day', NOW()))
		FROM precondition_analyses
	`).Scan(&pending, &today); err != nil {
		return 0, err
	}
	est := a.estimate(ctx, cfg.Model, cfg.UseBatch)
	room := cfg.BudgetUSD - spent - float64(pending)*est
	n := cfg.DailyMax - today
	if byBudget := int(math.Floor(room / est)); byBudget < n {
		n = byBudget
	}
	if !cfg.UseBatch && n > 25 {
		n = 25 // synchronous calls: keep a run short
	}
	if n <= 0 {
		return 0, nil
	}

	primary, fallback, err := a.candidates(ctx, cfg, n)
	if err != nil {
		return 0, err
	}
	stored, err := a.run(ctx, cfg, cfg.Model, "", primary)
	if err != nil {
		return stored, err
	}
	if len(fallback) > 0 {
		n, err := a.run(ctx, cfg, cfg.FallbackModel, cfg.Model, fallback)
		stored += n
		if err != nil {
			return stored, err
		}
	}
	return stored, nil
}

// run analyses inputs with model, as a batch or synchronously. refusedBy is
// set when model is the fallback for CVEs the main model declined.
func (a *Analyzer) run(ctx context.Context, cfg services.PreconditionConfig, model, refusedBy string, inputs []ai.PreconditionInput) (int, error) {
	if len(inputs) == 0 {
		return 0, nil
	}
	promptHash := ai.PreconditionPromptHash(model)
	var refusedArg any
	if refusedBy != "" {
		refusedArg = refusedBy
	}

	if cfg.UseBatch {
		items := make([]ai.BatchItem, len(inputs))
		for i, in := range inputs {
			items[i] = ai.BatchItem{CustomID: in.CVEID, Input: in}
		}
		id, err := a.client.SubmitPreconditionBatch(ctx, model, items)
		if err != nil {
			return 0, err
		}
		tx, err := a.db.Begin(ctx)
		if err != nil {
			return 0, err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `INSERT INTO precondition_batches (id, model, requests, status) VALUES ($1, $2, $3, 'in_progress')`,
			id, model, len(items)); err != nil {
			return 0, err
		}
		for _, in := range inputs {
			if _, err := tx.Exec(ctx, `
				INSERT INTO precondition_analyses (cve_id, status, model, prompt_hash, input_hash, batch_id, refused_by, requested_at)
				VALUES ($1, 'pending', $2, $3, $4, $5, $6, NOW())
				ON CONFLICT (cve_id) DO UPDATE SET status = 'pending', model = EXCLUDED.model, prompt_hash = EXCLUDED.prompt_hash,
					input_hash = EXCLUDED.input_hash, batch_id = EXCLUDED.batch_id, refused_by = EXCLUDED.refused_by,
					error = NULL, terminal = false, requested_at = NOW()
			`, in.CVEID, model, promptHash, in.Hash(), id, refusedArg); err != nil {
				return 0, err
			}
		}
		log.Info().Str("batch", id).Int("cves", len(items)).Str("model", model).Bool("fallback", refusedBy != "").
			Msg("AI precondition analysis: batch submitted")
		return 0, tx.Commit(ctx)
	}

	stored := 0
	for _, in := range inputs {
		select {
		case <-a.stopCh:
			return stored, nil
		default:
		}
		res, usage, err := a.client.AnalyzePreconditions(ctx, model, in)
		if err := a.store(ctx, in.CVEID, model, promptHash, in.Hash(), "", refusedBy, res, usage, false, err); err != nil {
			return stored, err
		}
		stored++
		// A refusal of the main model goes to the fallback right away.
		if errors.Is(err, ai.ErrRefusal) && refusedBy == "" && cfg.FallbackModel != "" {
			fres, fusage, ferr := a.client.AnalyzePreconditions(ctx, cfg.FallbackModel, in)
			if err := a.store(ctx, in.CVEID, cfg.FallbackModel, ai.PreconditionPromptHash(cfg.FallbackModel), in.Hash(), "",
				model, fres, fusage, false, ferr); err != nil {
				return stored, err
			}
		}
	}
	return stored, nil
}

// candidates returns up to n inputs that need an analysis, in queue order:
// primary are CVEs of the triage queue without a current analysis (same
// model, prompt and input) and without a recent failure; fallback are CVEs
// the main model declined, when a fallback model is configured. A fallback
// result (or a second refusal) is current as long as the input is unchanged.
func (a *Analyzer) candidates(ctx context.Context, cfg services.PreconditionConfig, n int) (primary, fallback []ai.PreconditionInput, err error) {
	opts, err := a.settings.BuildTriageOptions(ctx)
	if err != nil {
		return nil, nil, err
	}
	ids, err := a.findings.TriageQueueCVEIDs(ctx, opts, RuleID, 2000)
	if err != nil || len(ids) == 0 {
		return nil, nil, err
	}
	inputs, err := BuildInputs(ctx, a.db, ids)
	if err != nil {
		return nil, nil, err
	}
	type existing struct {
		status, prompt, input, refusedBy string
		terminal, recent                 bool
	}
	have := map[string]existing{}
	rows, err := a.db.Query(ctx, `
		SELECT cve_id, status, prompt_hash, input_hash, COALESCE(refused_by, ''), terminal, requested_at > NOW() - interval '1 day'
		FROM precondition_analyses WHERE cve_id = ANY($1)
	`, ids)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var id string
		var e existing
		if err := rows.Scan(&id, &e.status, &e.prompt, &e.input, &e.refusedBy, &e.terminal, &e.recent); err != nil {
			rows.Close()
			return nil, nil, err
		}
		have[id] = e
	}
	rows.Close()

	mainHash := ai.PreconditionPromptHash(cfg.Model)
	fallbackHash := ""
	if cfg.FallbackModel != "" {
		fallbackHash = ai.PreconditionPromptHash(cfg.FallbackModel)
	}
	for _, id := range ids { // queue order
		if len(primary)+len(fallback) >= n {
			break
		}
		in, ok := inputs[id]
		if !ok || in.Description == "" {
			continue
		}
		e, ok := have[id]
		if !ok || e.input != in.Hash() {
			primary = append(primary, in)
			continue
		}
		switch e.prompt {
		case mainHash:
			switch {
			case e.status != "error":
			case e.refusedBy == cfg.Model:
				if fallbackHash != "" {
					fallback = append(fallback, in)
				}
			case !e.terminal && !e.recent:
				primary = append(primary, in)
			}
		case fallbackHash:
			if e.refusedBy != cfg.Model {
				primary = append(primary, in) // a fallback analysis for another main model
			}
		default:
			primary = append(primary, in) // made with another model or prompt
		}
	}
	return primary, fallback, nil
}

// BuildInputs assembles the model input of each CVE from the catalog and the
// active findings.
func BuildInputs(ctx context.Context, db *pgxpool.Pool, ids []string) (map[string]ai.PreconditionInput, error) {
	out := map[string]ai.PreconditionInput{}
	rows, err := db.Query(ctx, `
		SELECT x.cve_id, COALESCE(c.description, ''), COALESCE(c.cvss3_score, 0)::float8, COALESCE(c.cvss3_vector, ''),
		       COALESCE(c.cwe_ids, '{}')
		FROM unnest($1::text[]) AS x(cve_id) LEFT JOIN cve_catalog c ON c.cve_id = x.cve_id
	`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var in ai.PreconditionInput
		if err := rows.Scan(&in.CVEID, &in.Description, &in.CVSS3Score, &in.CVSS3Vector, &in.CWEIDs); err != nil {
			rows.Close()
			return nil, err
		}
		sort.Strings(in.CWEIDs)
		in.Packages = []ai.InputPackage{}
		out[in.CVEID] = in
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = db.Query(ctx, `
		SELECT DISTINCT f.cve_id, f.package_name, COALESCE(sp.source_package, '')
		FROM findings f
		LEFT JOIN server_packages sp ON sp.server_id = f.server_id AND sp.name = f.package_name AND sp.removed_at IS NULL
		WHERE f.cve_id = ANY($1) AND f.resolved_at IS NULL
		ORDER BY 1, 2, 3
	`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var id, name, source string
		if err := rows.Scan(&id, &name, &source); err != nil {
			return nil, err
		}
		in := out[id]
		if name == "kernel" {
			in.Kernel = true
		} else if !seen[id+"\x00"+name] {
			seen[id+"\x00"+name] = true
			in.Packages = append(in.Packages, ai.InputPackage{Name: name, Source: source})
		}
		out[id] = in
	}
	return out, rows.Err()
}

func (a *Analyzer) collectBatches(ctx context.Context) (int, error) {
	rows, err := a.db.Query(ctx, `SELECT id, model FROM precondition_batches WHERE status = 'in_progress' ORDER BY created_at`)
	if err != nil {
		return 0, err
	}
	type batch struct{ id, model string }
	var batches []batch
	for rows.Next() {
		var b batch
		if err := rows.Scan(&b.id, &b.model); err != nil {
			rows.Close()
			return 0, err
		}
		batches = append(batches, b)
	}
	rows.Close()

	stored := 0
	for _, b := range batches {
		done, outcomes, err := a.client.PreconditionBatchResults(ctx, b.id)
		if err != nil {
			return stored, err
		}
		if !done {
			continue
		}
		for _, o := range outcomes {
			var promptHash, inputHash, refusedBy, status string
			err := a.db.QueryRow(ctx, `
				SELECT prompt_hash, input_hash, COALESCE(refused_by, ''), status FROM precondition_analyses WHERE cve_id = $1 AND batch_id = $2
			`, o.CustomID, b.id).Scan(&promptHash, &inputHash, &refusedBy, &status)
			if err == nil && status != "pending" {
				// Stored by an earlier collection that was interrupted (e.g. a
				// restart) before the batch was marked ended; its cost is logged.
				continue
			}
			if errors.Is(err, pgx.ErrNoRows) {
				// Superseded by a newer request; still account for the cost.
				if err := a.logUsage(ctx, a.db, o.CustomID, b.model, o.Usage, true); err != nil {
					return stored, err
				}
				continue
			}
			if err != nil {
				return stored, err
			}
			if err := a.store(ctx, o.CustomID, b.model, promptHash, inputHash, b.id, refusedBy, o.Result, o.Usage, true, o.Err); err != nil {
				return stored, err
			}
			stored++
		}
		// Requests the results did not mention (should not happen) become retryable errors.
		if _, err := a.db.Exec(ctx, `
			UPDATE precondition_analyses SET status = 'error', error = 'missing from batch results', analysed_at = NOW()
			WHERE batch_id = $1 AND status = 'pending'`, b.id); err != nil {
			return stored, err
		}
		if _, err := a.db.Exec(ctx, `UPDATE precondition_batches SET status = 'ended', ended_at = NOW() WHERE id = $1`, b.id); err != nil {
			return stored, err
		}
		log.Info().Str("batch", b.id).Int("results", len(outcomes)).Msg("AI precondition analysis: batch collected")
	}
	return stored, nil
}

func (a *Analyzer) logUsage(ctx context.Context, db *pgxpool.Pool, cveID, model string, u ai.Usage, batch bool) error {
	if u == (ai.Usage{}) {
		return nil
	}
	_, err := db.Exec(ctx, `
		INSERT INTO ai_usage (stage, model, cve_id, batch, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, cost_usd)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, Stage, model, cveID, batch, u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheCreationTokens, ai.Cost(model, u, batch))
	return err
}

// store records one outcome and its cost. refusedBy is the main model when
// model is the fallback; a refusal of the main model records the model
// itself, so the fallback can pick the CVE up.
func (a *Analyzer) store(ctx context.Context, cveID, model, promptHash, inputHash, batchID, refusedBy string,
	res ai.PreconditionResult, u ai.Usage, batch bool, callErr error) error {
	if err := a.logUsage(ctx, a.db, cveID, model, u, batch); err != nil {
		return err
	}
	var batchArg, refusedArg any
	if batchID != "" {
		batchArg = batchID
	}
	if refusedBy != "" {
		refusedArg = refusedBy
	}
	if callErr != nil {
		if errors.Is(callErr, ai.ErrRefusal) {
			log.Warn().Str("cve", cveID).Str("model", model).Bool("fallback", refusedBy != "").Err(callErr).
				Msg("AI precondition analysis: the model declined the CVE")
			if refusedBy == "" {
				refusedArg = model
			}
		}
		_, err := a.db.Exec(ctx, `
			INSERT INTO precondition_analyses (cve_id, status, model, prompt_hash, input_hash, batch_id, refused_by, error, terminal, analysed_at)
			VALUES ($1, 'error', $2, $3, $4, $5, $6, $7, $8, NOW())
			ON CONFLICT (cve_id) DO UPDATE SET status = 'error', model = EXCLUDED.model, prompt_hash = EXCLUDED.prompt_hash,
				input_hash = EXCLUDED.input_hash, batch_id = EXCLUDED.batch_id, refused_by = EXCLUDED.refused_by,
				error = EXCLUDED.error, terminal = EXCLUDED.terminal, analysed_at = NOW()
		`, cveID, model, promptHash, inputHash, batchArg, refusedArg, callErr.Error(), ai.IsTerminal(callErr))
		return err
	}
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(ctx, `
		INSERT INTO precondition_analyses (cve_id, status, model, prompt_hash, input_hash, batch_id, refused_by, determinable, result, analysed_at)
		VALUES ($1, 'ok', $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (cve_id) DO UPDATE SET status = 'ok', model = EXCLUDED.model, prompt_hash = EXCLUDED.prompt_hash,
			input_hash = EXCLUDED.input_hash, batch_id = EXCLUDED.batch_id, refused_by = EXCLUDED.refused_by,
			determinable = EXCLUDED.determinable, result = EXCLUDED.result, error = NULL, terminal = false, analysed_at = NOW()
	`, cveID, model, promptHash, inputHash, batchArg, refusedArg, res.Determinable, b)
	return err
}
