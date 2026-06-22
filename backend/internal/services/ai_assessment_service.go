package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/ai"
	"github.com/vultrack/vultrack/internal/models"
)

// AIReassessCooldown is the minimum time between assessments for the same CVE.
// A forced re-run is rejected until this much time has passed since the last
// completed/failed assessment, to bound API cost.
const AIReassessCooldown = 30 * time.Minute

// EnqueueOutcome describes the result of an Enqueue call so callers can produce
// precise responses (created, re-queued, blocked by cooldown, etc.).
type EnqueueOutcome string

const (
	EnqueueCreated    EnqueueOutcome = "created"    // newly queued
	EnqueueRequeued   EnqueueOutcome = "requeued"   // forced re-run accepted
	EnqueueExists     EnqueueOutcome = "exists"     // already present, not forced
	EnqueueProcessing EnqueueOutcome = "processing" // already queued or running
	EnqueueCooldown   EnqueueOutcome = "cooldown"   // within the re-assessment cooldown
)

// AIAssessmentService manages the ai_assessments table. The table doubles as
// the work queue: 'pending' rows are claimed and processed by the AI worker.
type AIAssessmentService struct {
	db *pgxpool.Pool
}

// NewAIAssessmentService creates a new AIAssessmentService.
func NewAIAssessmentService(db *pgxpool.Pool) *AIAssessmentService {
	return &AIAssessmentService{db: db}
}

// aiAssessmentColumns lists the SELECT columns in the order scanAIAssessment
// expects, with NULLs coalesced so they scan into non-pointer Go fields.
const aiAssessmentColumns = `
	id, cve_id, status,
	COALESCE(attack_vector, ''), COALESCE(prerequisites, ''),
	COALESCE(recommended_status, ''), COALESCE(recommendation_reasoning, ''),
	COALESCE(confidence, ''), COALESCE(model, ''), COALESCE(prompt_hash, ''),
	COALESCE(input_tokens, 0), COALESCE(output_tokens, 0),
	COALESCE(error, ''), retry_count, COALESCE(requested_by, ''),
	created_at, updated_at`

// scanAIAssessment scans a single row in aiAssessmentColumns order.
func scanAIAssessment(row pgx.Row) (*models.AIAssessment, error) {
	var a models.AIAssessment
	err := row.Scan(
		&a.ID, &a.CVEID, &a.Status,
		&a.AttackVector, &a.Prerequisites,
		&a.RecommendedStatus, &a.RecommendationReasoning,
		&a.Confidence, &a.Model, &a.PromptHash,
		&a.InputTokens, &a.OutputTokens,
		&a.Error, &a.RetryCount, &a.RequestedBy,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetByCVE returns the AI assessment for a CVE, or pgx.ErrNoRows if none exists.
func (s *AIAssessmentService) GetByCVE(ctx context.Context, cveID string) (*models.AIAssessment, error) {
	row := s.db.QueryRow(ctx, `SELECT `+aiAssessmentColumns+` FROM ai_assessments WHERE cve_id = $1`, cveID)
	return scanAIAssessment(row)
}

// AIAssessmentFilter defines filter/pagination options for listing assessments.
type AIAssessmentFilter struct {
	Status string // pending|processing|completed|failed, or empty for all
	Search string // free-text across cve_id
	Limit  int
	Offset int
}

// GetAll returns AI assessments with filtering and pagination, newest first.
func (s *AIAssessmentService) GetAll(ctx context.Context, filter AIAssessmentFilter) ([]models.AIAssessment, int, error) {
	where := " WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if filter.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, filter.Status)
		idx++
	}
	if filter.Search != "" {
		where += fmt.Sprintf(" AND cve_id ILIKE $%d", idx)
		args = append(args, "%"+strings.ToLower(filter.Search)+"%")
		idx++
	}

	var total int
	if err := s.db.QueryRow(ctx, "SELECT COUNT(*) FROM ai_assessments"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count ai_assessments: %w", err)
	}

	query := "SELECT " + aiAssessmentColumns + " FROM ai_assessments" + where +
		fmt.Sprintf(" ORDER BY updated_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	rows, err := s.db.Query(ctx, query, append(args, filter.Limit, filter.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("query ai_assessments: %w", err)
	}
	defer rows.Close()

	var out []models.AIAssessment
	for rows.Next() {
		a, err := scanAIAssessment(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan ai_assessment: %w", err)
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

// Enqueue queues an AI assessment for a CVE.
//   - If no row exists, a new 'pending' row is created (EnqueueCreated).
//   - If a row exists and force is false, nothing happens (EnqueueExists) — this
//     is the "assess each CVE only once" guard.
//   - If force is true: a completed/failed row older than AIReassessCooldown is
//     reset to 'pending' for a re-run (EnqueueRequeued); a row that is still
//     queued/running yields EnqueueProcessing; one within the cooldown window
//     yields EnqueueCooldown.
func (s *AIAssessmentService) Enqueue(ctx context.Context, cveID, requestedBy string, force bool) (EnqueueOutcome, error) {
	tag, err := s.db.Exec(ctx, `
		INSERT INTO ai_assessments (cve_id, status, requested_by)
		VALUES ($1, 'pending', NULLIF($2, ''))
		ON CONFLICT (cve_id) DO NOTHING`, cveID, requestedBy)
	if err != nil {
		return "", fmt.Errorf("enqueue ai_assessment: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return EnqueueCreated, nil // newly queued
	}
	if !force {
		return EnqueueExists, nil // already exists; leave it
	}

	// Forced re-run: enforce the cooldown and avoid racing the worker. All time
	// math is done server-side with NOW() so it never depends on the application
	// server's clock or timezone.
	cooldownMins := int(AIReassessCooldown.Minutes())
	var status string
	var withinCooldown bool
	err = s.db.QueryRow(ctx, `
		SELECT status, updated_at >= NOW() - make_interval(mins => $2)
		FROM ai_assessments WHERE cve_id = $1`, cveID, cooldownMins).Scan(&status, &withinCooldown)
	if err != nil {
		return "", fmt.Errorf("load ai_assessment for re-run: %w", err)
	}
	if status == "pending" || status == "processing" {
		return EnqueueProcessing, nil
	}
	if withinCooldown {
		return EnqueueCooldown, nil
	}

	// Clear the previous result and reset to pending. The WHERE clause re-checks
	// status and cooldown so a concurrent request can't double-trigger the re-run.
	tag, err = s.db.Exec(ctx, `
		UPDATE ai_assessments
		SET status = 'pending', requested_by = NULLIF($2, ''),
		    attack_vector = NULL, prerequisites = NULL, recommended_status = NULL,
		    recommendation_reasoning = NULL, confidence = NULL, model = NULL,
		    prompt_hash = NULL, input_tokens = NULL, output_tokens = NULL,
		    error = NULL, retry_count = 0, updated_at = NOW()
		WHERE cve_id = $1 AND status IN ('completed', 'failed')
		      AND updated_at < NOW() - make_interval(mins => $3)`,
		cveID, requestedBy, cooldownMins)
	if err != nil {
		return "", fmt.Errorf("requeue ai_assessment: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return EnqueueRequeued, nil
	}
	// Lost a race: another request changed the row between the check and update.
	return EnqueueProcessing, nil
}

// ClaimNextPending atomically claims the oldest pending row, marking it
// 'processing'. The second return value is false when nothing is pending.
// FOR UPDATE SKIP LOCKED makes this safe for multiple concurrent workers.
func (s *AIAssessmentService) ClaimNextPending(ctx context.Context) (*models.AIAssessment, bool, error) {
	row := s.db.QueryRow(ctx, `
		UPDATE ai_assessments SET status = 'processing', updated_at = NOW()
		WHERE id = (
			SELECT id FROM ai_assessments
			WHERE status = 'pending'
			ORDER BY created_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+aiAssessmentColumns)
	a, err := scanAIAssessment(row)
	if err == pgx.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("claim pending ai_assessment: %w", err)
	}
	return a, true, nil
}

// SaveResult stores a successful assessment and marks the row completed.
func (s *AIAssessmentService) SaveResult(ctx context.Context, cveID string, r ai.AssessmentResult, meta ai.AssessmentMeta) error {
	_, err := s.db.Exec(ctx, `
		UPDATE ai_assessments
		SET status = 'completed',
		    attack_vector = $2, prerequisites = $3, recommended_status = $4,
		    recommendation_reasoning = $5, confidence = $6,
		    model = $7, prompt_hash = $8, input_tokens = $9, output_tokens = $10,
		    error = NULL, updated_at = NOW()
		WHERE cve_id = $1`,
		cveID, r.AttackVector, r.Prerequisites, r.RecommendedStatus,
		r.RecommendationReasoning, r.Confidence,
		meta.Model, meta.PromptHash, meta.InputTokens, meta.OutputTokens)
	return err
}

// MarkFailed marks the row failed with an error message and retry count.
func (s *AIAssessmentService) MarkFailed(ctx context.Context, cveID, errMsg string, retryCount int, meta ai.AssessmentMeta) error {
	_, err := s.db.Exec(ctx, `
		UPDATE ai_assessments
		SET status = 'failed', error = $2, retry_count = $3,
		    model = COALESCE(NULLIF($4, ''), model),
		    prompt_hash = COALESCE(NULLIF($5, ''), prompt_hash),
		    input_tokens = $6, output_tokens = $7, updated_at = NOW()
		WHERE cve_id = $1`,
		cveID, errMsg, retryCount, meta.Model, meta.PromptHash, meta.InputTokens, meta.OutputTokens)
	return err
}

// MarkPendingRetry resets the row to pending so it gets re-claimed, recording
// the incremented retry count and the last transient error.
func (s *AIAssessmentService) MarkPendingRetry(ctx context.Context, cveID, errMsg string, retryCount int) error {
	_, err := s.db.Exec(ctx, `
		UPDATE ai_assessments SET status = 'pending', error = $2, retry_count = $3, updated_at = NOW()
		WHERE cve_id = $1`, cveID, errMsg, retryCount)
	return err
}

// RecoverProcessing resets rows left in 'processing' by an interrupted run back
// to 'pending'. Called once on startup.
func (s *AIAssessmentService) RecoverProcessing(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx, `
		UPDATE ai_assessments SET status = 'pending', updated_at = NOW() WHERE status = 'processing'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// BuildInput gathers the CVE facts sent to the model. It aggregates across all
// findings for the CVE (a representative package, fix availability, affected
// server count) and enriches with NVD catalog data and exploit availability.
func (s *AIAssessmentService) BuildInput(ctx context.Context, cveID string) (ai.AssessmentInput, error) {
	in := ai.AssessmentInput{CVEID: cveID}
	row := s.db.QueryRow(ctx, `
		WITH rep AS (
			SELECT package_name, package_version, severity, summary, cvss3_score, vex_status
			FROM findings
			WHERE cve_id = $1
			ORDER BY cvss3_score DESC NULLS LAST
			LIMIT 1
		),
		agg AS (
			SELECT
				COUNT(*) FILTER (WHERE resolved_at IS NULL) AS affected_servers,
				BOOL_OR(fix_state = 'fix_available') AS fix_available
			FROM findings
			WHERE cve_id = $1
		)
		SELECT
			COALESCE(cve.description, rep.summary, '')               AS description,
			COALESCE(cve.cvss3_score, rep.cvss3_score, 0)            AS cvss3_score,
			COALESCE(cve.cvss3_vector, '')                          AS cvss3_vector,
			COALESCE(NULLIF(rep.severity, ''), cve.cvss3_severity, '') AS severity,
			COALESCE(cve.cwe_ids, ARRAY[]::text[])                   AS cwe_ids,
			COALESCE(rep.package_name, '')                          AS package_name,
			COALESCE(rep.package_version, '')                       AS package_version,
			COALESCE(agg.fix_available, false)                      AS fix_available,
			COALESCE(rep.vex_status, '')                            AS vex_status,
			COALESCE(agg.affected_servers, 0)                       AS affected_servers,
			EXISTS (SELECT 1 FROM exploits e WHERE $1 = ANY(e.cve_ids)) AS exploit_available
		FROM agg
		LEFT JOIN rep ON true
		LEFT JOIN cve_catalog cve ON cve.cve_id = $1`, cveID)

	err := row.Scan(
		&in.Description, &in.CVSS3Score, &in.CVSS3Vector, &in.Severity, &in.CWEIDs,
		&in.PackageName, &in.PackageVersion, &in.FixAvailable, &in.VexStatus,
		&in.AffectedServers, &in.ExploitAvailable,
	)
	if err != nil {
		return ai.AssessmentInput{}, fmt.Errorf("build ai input for %s: %w", cveID, err)
	}
	return in, nil
}
