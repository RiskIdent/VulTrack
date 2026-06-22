// Package aiqueue runs the background workers that produce AI assessments.
// The ai_assessments table is the queue: a reconciler enqueues triage CVEs that
// have no assessment yet, and workers claim and process 'pending' rows.
package aiqueue

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/ai"
	"github.com/vultrack/vultrack/internal/config"
	"github.com/vultrack/vultrack/internal/services"
)

const (
	// idlePoll is how long a worker waits before re-checking for pending work.
	idlePoll = 5 * time.Second
	// reconcileInterval is how often the reconciler scans the triage queue.
	reconcileInterval = 5 * time.Minute
	// reconcilePageSize bounds each triage-queue page the reconciler reads.
	reconcilePageSize = 500
)

// Queue coordinates AI assessment workers and the triage reconciler.
type Queue struct {
	client         *ai.Client
	aiService      *services.AIAssessmentService
	findingService *services.FindingService
	settings       *services.SettingsService
	cfg            *config.Config

	stopCh chan struct{}
	doneCh chan struct{} // closed when all goroutines have exited
}

// New creates the AI assessment queue. The client may be nil when the feature
// is not configured; Start is then a no-op.
func New(
	client *ai.Client,
	aiService *services.AIAssessmentService,
	findingService *services.FindingService,
	settings *services.SettingsService,
	cfg *config.Config,
) *Queue {
	return &Queue{
		client:         client,
		aiService:      aiService,
		findingService: findingService,
		settings:       settings,
		cfg:            cfg,
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}
}

// Start launches the worker pool and the reconciler. It is a no-op when the AI
// feature is not configured (no API key).
func (q *Queue) Start() {
	if !q.cfg.AIConfigured() || q.client == nil {
		log.Info().Msg("AI assessment disabled (ANTHROPIC_API_KEY not set)")
		close(q.doneCh)
		return
	}

	workers := q.cfg.AIWorkers
	if workers < 1 {
		workers = 1
	}

	// Re-queue assessments left mid-flight by a previous run.
	if n, err := q.aiService.RecoverProcessing(context.Background()); err != nil {
		log.Warn().Err(err).Msg("Failed to recover interrupted AI assessments")
	} else if n > 0 {
		log.Info().Int64("count", n).Msg("Recovered interrupted AI assessments")
	}

	log.Info().Int("workers", workers).Msg("Starting AI assessment queue")

	finished := make(chan struct{})
	total := workers + 1 // workers + reconciler
	done := make(chan struct{})
	go func() {
		for i := 0; i < total; i++ {
			<-finished
		}
		close(done)
	}()

	for i := 0; i < workers; i++ {
		go func(id int) {
			defer func() { finished <- struct{}{} }()
			q.worker(id)
		}(i)
	}
	go func() {
		defer func() { finished <- struct{}{} }()
		q.reconcileLoop()
	}()

	go func() {
		<-done
		close(q.doneCh)
	}()
}

// Stop signals all goroutines to finish and waits for them.
func (q *Queue) Stop() {
	close(q.stopCh)
	<-q.doneCh
	log.Info().Msg("AI assessment queue stopped")
}

// worker claims and processes pending assessments until stopped.
func (q *Queue) worker(id int) {
	for {
		select {
		case <-q.stopCh:
			return
		default:
		}

		// Respect the admin master switch: when disabled, don't process queued
		// work. Pending rows stay untouched and resume when re-enabled.
		if enabled, _ := q.settings.GetBool(context.Background(), services.SettingAIEnabled); !enabled {
			if q.sleep(idlePoll) {
				return
			}
			continue
		}

		a, ok, err := q.aiService.ClaimNextPending(context.Background())
		if err != nil {
			log.Warn().Err(err).Int("worker", id).Msg("Failed to claim AI assessment")
			if q.sleep(idlePoll) {
				return
			}
			continue
		}
		if !ok {
			if q.sleep(idlePoll) {
				return
			}
			continue
		}

		q.process(a.CVEID, a.RetryCount)
	}
}

// process runs one assessment and records the outcome.
func (q *Queue) process(cveID string, retryCount int) {
	ctx := context.Background()

	in, err := q.aiService.BuildInput(ctx, cveID)
	if err != nil {
		log.Warn().Err(err).Str("cve", cveID).Msg("Failed to build AI assessment input")
		_ = q.aiService.MarkFailed(ctx, cveID, err.Error(), retryCount, ai.AssessmentMeta{})
		return
	}

	model, _ := q.settings.GetValue(ctx, services.SettingAIModel)
	if model == "" {
		model = services.DefaultAIModel
	}
	infra, _ := q.settings.GetValue(ctx, services.SettingAISystemPrompt)

	result, meta, err := q.client.Assess(ctx, in, ai.AssessOptions{Model: model, InfraContext: infra})
	if err != nil {
		q.handleError(ctx, cveID, retryCount, meta, err)
		return
	}

	if err := q.aiService.SaveResult(ctx, cveID, result, meta); err != nil {
		log.Warn().Err(err).Str("cve", cveID).Msg("Failed to save AI assessment result")
		return
	}
	log.Info().Str("cve", cveID).Str("model", meta.Model).
		Int("inputTokens", meta.InputTokens).Int("outputTokens", meta.OutputTokens).
		Msg("AI assessment completed")
}

// handleError decides whether to fail an assessment or schedule a retry.
func (q *Queue) handleError(ctx context.Context, cveID string, retryCount int, meta ai.AssessmentMeta, err error) {
	terminal := errors.Is(err, ai.ErrRefusal) || errors.Is(err, ai.ErrIncompleteOutput) || errors.Is(err, ai.ErrBadOutput)
	nextRetry := retryCount + 1

	if terminal || nextRetry > q.cfg.AIMaxRetries {
		log.Warn().Err(err).Str("cve", cveID).Bool("terminal", terminal).Msg("AI assessment failed")
		_ = q.aiService.MarkFailed(ctx, cveID, err.Error(), retryCount, meta)
		return
	}

	// Transient error: back off (keeping the row in 'processing' so it isn't
	// re-claimed during the wait), then reset it to pending for another attempt.
	backoff := time.Duration(10*nextRetry) * time.Second
	log.Warn().Err(err).Str("cve", cveID).Int("attempt", nextRetry).Dur("backoff", backoff).
		Msg("AI assessment failed, scheduling retry")
	if q.sleep(backoff) {
		return // shutting down; leave the row as-is (recovered on next start)
	}
	if err := q.aiService.MarkPendingRetry(ctx, cveID, err.Error(), nextRetry); err != nil {
		log.Warn().Err(err).Str("cve", cveID).Msg("Failed to reschedule AI assessment")
	}
}

// reconcileLoop periodically enqueues triage CVEs that lack an assessment.
func (q *Queue) reconcileLoop() {
	// Run shortly after startup, then on a fixed interval.
	if q.sleep(10 * time.Second) {
		return
	}
	q.reconcile()

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-q.stopCh:
			return
		case <-ticker.C:
			q.reconcile()
		}
	}
}

// reconcile enqueues every triage-queue CVE that has no assessment yet. It uses
// the same BuildTriageOptions as the UI and MCP, so the set stays in sync.
func (q *Queue) reconcile() {
	if enabled, _ := q.settings.GetBool(context.Background(), services.SettingAIEnabled); !enabled {
		return
	}
	if auto, _ := q.settings.GetBool(context.Background(), services.SettingAIAutoAssess); !auto {
		return
	}

	ctx := context.Background()
	opts, err := q.settings.BuildTriageOptions(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("AI reconcile: failed to build triage options")
		return
	}
	opts.Limit = reconcilePageSize

	seen := map[string]struct{}{}
	queued := 0
	for offset := 0; ; offset += reconcilePageSize {
		opts.Offset = offset
		findings, total, err := q.findingService.GetTriageQueue(ctx, opts)
		if err != nil {
			log.Warn().Err(err).Msg("AI reconcile: failed to read triage queue")
			return
		}
		for _, f := range findings {
			if _, ok := seen[f.CVEID]; ok {
				continue
			}
			seen[f.CVEID] = struct{}{}
			outcome, err := q.aiService.Enqueue(ctx, f.CVEID, "", false)
			if err != nil {
				log.Warn().Err(err).Str("cve", f.CVEID).Msg("AI reconcile: failed to enqueue")
				continue
			}
			if outcome == services.EnqueueCreated {
				queued++
			}
		}
		if len(findings) == 0 || offset+reconcilePageSize >= total {
			break
		}
	}
	if queued > 0 {
		log.Info().Int("queued", queued).Msg("AI reconcile: enqueued triage CVEs")
	}
}

// sleep waits for d or until Stop is called. It returns true if Stop fired.
func (q *Queue) sleep(d time.Duration) bool {
	select {
	case <-q.stopCh:
		return true
	case <-time.After(d):
		return false
	}
}
