package scanqueue

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/config"
	"github.com/vultrack/vultrack/internal/scanner"
)

// TriggerType describes what initiated the scan.
const (
	TriggerAgentReport = "agent_report"
	TriggerManual      = "manual"
	TriggerScheduled   = "scheduled"
)

// Job status constants.
const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// ScanJob represents a single scan work item.
type ScanJob struct {
	ID              string     `json:"id"`
	ServerID        int64      `json:"serverId"`
	ServerName      string     `json:"serverName"`
	TriggerType     string     `json:"triggerType"`
	Status          string     `json:"status"`
	RetryCount      int        `json:"retryCount"`
	MaxRetries      int        `json:"maxRetries"`
	Error           string     `json:"error,omitempty"`
	NewFindings     *int       `json:"newFindings,omitempty"`
	UpdatedFindings *int       `json:"updatedFindings,omitempty"`
	ResolvedFindings *int      `json:"resolvedFindings,omitempty"`
	TotalChecks     *int       `json:"totalChecks,omitempty"`
	DurationMs      *int64     `json:"durationMs,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
	StartedAt       *time.Time `json:"startedAt,omitempty"`
	FinishedAt      *time.Time `json:"finishedAt,omitempty"`
}

// Queue coordinates vulnerability scans through a bounded worker pool.
type Queue struct {
	db          *pgxpool.Pool
	scanner     *scanner.Scanner
	cfg         *config.Config
	jobs        chan *ScanJob
	wg          sync.WaitGroup
	stopCh      chan struct{}

	// Deduplication: track servers currently queued or running
	mu          sync.Mutex
	activeJobs  map[int64]string // serverID -> jobID
}

// New creates a new scan queue.
func New(db *pgxpool.Pool, s *scanner.Scanner, cfg *config.Config) *Queue {
	return &Queue{
		db:         db,
		scanner:    s,
		cfg:        cfg,
		jobs:       make(chan *ScanJob, cfg.ScanQueueSize),
		stopCh:     make(chan struct{}),
		activeJobs: make(map[int64]string),
	}
}

// Start launches the worker pool and the cleanup goroutine.
func (q *Queue) Start() {
	workers := q.cfg.ScanWorkers
	if workers < 1 {
		workers = 1
	}

	log.Info().
		Int("workers", workers).
		Int("queueSize", q.cfg.ScanQueueSize).
		Int("timeoutSec", q.cfg.ScanTimeoutSec).
		Int("maxRetries", q.cfg.ScanMaxRetries).
		Msg("Starting scan queue")

	// Re-queue jobs that were running when the process was interrupted
	q.recoverRunningJobs()

	for i := 0; i < workers; i++ {
		q.wg.Add(1)
		go q.worker(i)
	}

	// Periodic cleanup of old jobs (>30 days)
	go q.cleanupLoop()
}

// Stop signals all workers to finish and waits for them.
func (q *Queue) Stop() {
	log.Info().Msg("Stopping scan queue...")
	close(q.stopCh)
	q.wg.Wait()
	log.Info().Msg("Scan queue stopped")
}

// Enqueue adds a scan job to the queue.
// Returns the job ID or empty string if the server is already queued/running.
func (q *Queue) Enqueue(serverID int64, serverName string, trigger string) (string, error) {
	q.mu.Lock()
	if existingID, ok := q.activeJobs[serverID]; ok {
		q.mu.Unlock()
		log.Debug().
			Int64("serverId", serverID).
			Str("existingJobId", existingID).
			Msg("Scan already queued/running for server, skipping")
		return existingID, nil
	}

	jobID := uuid.New().String()
	q.activeJobs[serverID] = jobID
	q.mu.Unlock()

	job := &ScanJob{
		ID:          jobID,
		ServerID:    serverID,
		ServerName:  serverName,
		TriggerType: trigger,
		Status:      StatusQueued,
		RetryCount:  0,
		MaxRetries:  q.cfg.ScanMaxRetries,
		CreatedAt:   time.Now(),
	}

	// Persist to DB
	if err := q.insertJob(job); err != nil {
		q.mu.Lock()
		delete(q.activeJobs, serverID)
		q.mu.Unlock()
		return "", fmt.Errorf("failed to persist scan job: %w", err)
	}

	// Non-blocking send to channel; if queue is full, mark as failed
	select {
	case q.jobs <- job:
		log.Info().
			Str("jobId", jobID).
			Int64("serverId", serverID).
			Str("trigger", trigger).
			Msg("Scan job enqueued")
	default:
		q.mu.Lock()
		delete(q.activeJobs, serverID)
		q.mu.Unlock()
		q.updateJobStatus(job.ID, StatusFailed, "scan queue is full", nil)
		return "", fmt.Errorf("scan queue is full")
	}

	return jobID, nil
}

// CancelJob cancels a queued or running job.
func (q *Queue) CancelJob(jobID string) error {
	q.updateJobStatus(jobID, StatusCancelled, "cancelled by user", nil)

	// Remove from active tracking
	q.mu.Lock()
	for serverID, id := range q.activeJobs {
		if id == jobID {
			delete(q.activeJobs, serverID)
			break
		}
	}
	q.mu.Unlock()

	return nil
}

// RetryJob re-enqueues a failed job.
func (q *Queue) RetryJob(ctx context.Context, jobID string) (string, error) {
	job, err := q.GetJob(ctx, jobID)
	if err != nil {
		return "", err
	}
	if job.Status != StatusFailed && job.Status != StatusCancelled {
		return "", fmt.Errorf("can only retry failed or cancelled jobs")
	}

	return q.Enqueue(job.ServerID, job.ServerName, job.TriggerType)
}

// worker is the main worker loop that processes scan jobs.
func (q *Queue) worker(id int) {
	defer q.wg.Done()
	log.Debug().Int("workerId", id).Msg("Scan worker started")

	for {
		select {
		case <-q.stopCh:
			log.Debug().Int("workerId", id).Msg("Scan worker stopping")
			return
		case job := <-q.jobs:
			if job == nil {
				return
			}
			q.processJob(id, job)
		}
	}
}

// processJob executes a single scan job with timeout and retry logic.
func (q *Queue) processJob(workerID int, job *ScanJob) {
	// Check if cancelled
	if job.Status == StatusCancelled {
		return
	}

	// Mark as running
	now := time.Now()
	job.StartedAt = &now
	job.Status = StatusRunning
	q.updateJobStarted(job.ID, now)

	log.Info().
		Int("workerId", workerID).
		Str("jobId", job.ID).
		Int64("serverId", job.ServerID).
		Str("serverName", job.ServerName).
		Int("attempt", job.RetryCount+1).
		Msg("Processing scan job")

	// Create context with timeout
	timeout := time.Duration(q.cfg.ScanTimeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Execute scan
	result, err := q.scanner.ScanServer(ctx, job.ServerID)

	finished := time.Now()
	job.FinishedAt = &finished

	if err != nil {
		q.handleScanError(workerID, job, err)
		return
	}

	// Success
	durationMs := result.Duration.Milliseconds()
	job.Status = StatusCompleted
	job.NewFindings = &result.NewFindings
	job.ResolvedFindings = &result.ResolvedFindings
	job.TotalChecks = &result.TotalChecks
	job.DurationMs = &durationMs

	q.updateJobCompleted(job.ID, finished, result)

	// Remove from active tracking
	q.mu.Lock()
	delete(q.activeJobs, job.ServerID)
	q.mu.Unlock()

	log.Info().
		Int("workerId", workerID).
		Str("jobId", job.ID).
		Int64("serverId", job.ServerID).
		Int("newFindings", result.NewFindings).
		Int("resolvedFindings", result.ResolvedFindings).
		Dur("duration", result.Duration).
		Msg("Scan job completed")
}

// handleScanError handles a failed scan, applying retry logic.
func (q *Queue) handleScanError(workerID int, job *ScanJob, err error) {
	job.RetryCount++
	job.Error = err.Error()

	if job.RetryCount <= job.MaxRetries {
		// Retry with exponential backoff: 10s, 30s, 90s
		backoff := time.Duration(10*pow(3, job.RetryCount-1)) * time.Second

		log.Warn().
			Int("workerId", workerID).
			Str("jobId", job.ID).
			Int64("serverId", job.ServerID).
			Err(err).
			Int("attempt", job.RetryCount).
			Dur("backoff", backoff).
			Msg("Scan failed, scheduling retry")

		q.updateJobRetry(job.ID, job.RetryCount, err.Error())

		// Wait for backoff, then re-enqueue
		go func() {
			select {
			case <-time.After(backoff):
				job.Status = StatusQueued
				select {
				case q.jobs <- job:
					// Re-queued successfully
				default:
					// Queue full, mark failed
					q.updateJobStatus(job.ID, StatusFailed, "retry failed: queue full", nil)
					q.mu.Lock()
					delete(q.activeJobs, job.ServerID)
					q.mu.Unlock()
				}
			case <-q.stopCh:
				q.updateJobStatus(job.ID, StatusFailed, "retry cancelled: server shutting down", nil)
				q.mu.Lock()
				delete(q.activeJobs, job.ServerID)
				q.mu.Unlock()
			}
		}()
	} else {
		// Max retries exceeded
		job.Status = StatusFailed
		q.updateJobStatus(job.ID, StatusFailed, err.Error(), job.FinishedAt)

		q.mu.Lock()
		delete(q.activeJobs, job.ServerID)
		q.mu.Unlock()

		log.Error().
			Int("workerId", workerID).
			Str("jobId", job.ID).
			Int64("serverId", job.ServerID).
			Err(err).
			Int("retries", job.RetryCount).
			Msg("Scan job failed after all retries")
	}
}

// recoverRunningJobs marks any leftover "running" or "queued" jobs as failed on startup.
func (q *Queue) recoverRunningJobs() {
	ctx := context.Background()
	tag, err := q.db.Exec(ctx, `
		UPDATE scan_jobs
		SET status = 'failed', error = 'interrupted: server restarted', finished_at = NOW()
		WHERE status IN ('running', 'queued')
	`)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to recover interrupted scan jobs")
		return
	}
	if tag.RowsAffected() > 0 {
		log.Info().Int64("count", tag.RowsAffected()).Msg("Recovered interrupted scan jobs")
	}
}

// cleanupLoop deletes scan jobs older than 30 days.
func (q *Queue) cleanupLoop() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-q.stopCh:
			return
		case <-ticker.C:
			ctx := context.Background()
			tag, err := q.db.Exec(ctx, `
				DELETE FROM scan_jobs WHERE created_at < NOW() - INTERVAL '30 days'
			`)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to cleanup old scan jobs")
			} else if tag.RowsAffected() > 0 {
				log.Info().Int64("deleted", tag.RowsAffected()).Msg("Cleaned up old scan jobs")
			}
		}
	}
}

// ── DB helpers ──────────────────────────────────────────────────────────────

func (q *Queue) insertJob(job *ScanJob) error {
	_, err := q.db.Exec(context.Background(), `
		INSERT INTO scan_jobs (id, server_id, server_name, trigger_type, status, retry_count, max_retries, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, job.ID, job.ServerID, job.ServerName, job.TriggerType, job.Status, job.RetryCount, job.MaxRetries, job.CreatedAt)
	return err
}

func (q *Queue) updateJobStarted(jobID string, startedAt time.Time) {
	_, err := q.db.Exec(context.Background(), `
		UPDATE scan_jobs SET status = 'running', started_at = $2 WHERE id = $1
	`, jobID, startedAt)
	if err != nil {
		log.Warn().Err(err).Str("jobId", jobID).Msg("Failed to update job started")
	}
}

func (q *Queue) updateJobCompleted(jobID string, finishedAt time.Time, result *scanner.ScanResult) {
	durationMs := result.Duration.Milliseconds()
	_, err := q.db.Exec(context.Background(), `
		UPDATE scan_jobs
		SET status = 'completed',
		    finished_at = $2,
		    new_findings = $3,
		    resolved_findings = $4,
		    total_checks = $5,
		    duration_ms = $6,
		    error = NULL
		WHERE id = $1
	`, jobID, finishedAt, result.NewFindings, result.ResolvedFindings, result.TotalChecks, durationMs)
	if err != nil {
		log.Warn().Err(err).Str("jobId", jobID).Msg("Failed to update job completed")
	}
}

func (q *Queue) updateJobRetry(jobID string, retryCount int, errMsg string) {
	_, err := q.db.Exec(context.Background(), `
		UPDATE scan_jobs SET status = 'queued', retry_count = $2, error = $3 WHERE id = $1
	`, jobID, retryCount, errMsg)
	if err != nil {
		log.Warn().Err(err).Str("jobId", jobID).Msg("Failed to update job retry")
	}
}

func (q *Queue) updateJobStatus(jobID, status, errMsg string, finishedAt *time.Time) {
	_, err := q.db.Exec(context.Background(), `
		UPDATE scan_jobs SET status = $2, error = $3, finished_at = $4 WHERE id = $1
	`, jobID, status, errMsg, finishedAt)
	if err != nil {
		log.Warn().Err(err).Str("jobId", jobID).Msg("Failed to update job status")
	}
}

// GetJob retrieves a single scan job by ID.
func (q *Queue) GetJob(ctx context.Context, jobID string) (*ScanJob, error) {
	var job ScanJob
	err := q.db.QueryRow(ctx, `
		SELECT id, server_id, server_name, trigger_type, status, retry_count, max_retries,
		       COALESCE(error, ''), new_findings, updated_findings, resolved_findings,
		       total_checks, duration_ms, created_at, started_at, finished_at
		FROM scan_jobs WHERE id = $1
	`, jobID).Scan(
		&job.ID, &job.ServerID, &job.ServerName, &job.TriggerType, &job.Status,
		&job.RetryCount, &job.MaxRetries, &job.Error,
		&job.NewFindings, &job.UpdatedFindings, &job.ResolvedFindings,
		&job.TotalChecks, &job.DurationMs,
		&job.CreatedAt, &job.StartedAt, &job.FinishedAt,
	)
	if err != nil {
		return nil, err
	}
	return &job, nil
}

// GetJobs retrieves scan jobs with filtering and pagination.
func (q *Queue) GetJobs(ctx context.Context, status, search string, limit, offset int) ([]ScanJob, int, error) {
	where := " WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, status)
		idx++
	}
	if search != "" {
		pattern := "%" + search + "%"
		where += fmt.Sprintf(" AND (server_name ILIKE $%d OR id ILIKE $%d)", idx, idx)
		args = append(args, pattern)
		idx++
	}

	// Count
	var total int
	err := q.db.QueryRow(ctx, "SELECT COUNT(*) FROM scan_jobs"+where, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Fetch page
	query := fmt.Sprintf(`
		SELECT id, server_id, server_name, trigger_type, status, retry_count, max_retries,
		       COALESCE(error, ''), new_findings, updated_findings, resolved_findings,
		       total_checks, duration_ms, created_at, started_at, finished_at
		FROM scan_jobs %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1)
	dataArgs := append(args, limit, offset)

	rows, err := q.db.Query(ctx, query, dataArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var jobs []ScanJob
	for rows.Next() {
		var j ScanJob
		err := rows.Scan(
			&j.ID, &j.ServerID, &j.ServerName, &j.TriggerType, &j.Status,
			&j.RetryCount, &j.MaxRetries, &j.Error,
			&j.NewFindings, &j.UpdatedFindings, &j.ResolvedFindings,
			&j.TotalChecks, &j.DurationMs,
			&j.CreatedAt, &j.StartedAt, &j.FinishedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		jobs = append(jobs, j)
	}

	return jobs, total, nil
}

// GetStats returns aggregate counts by status.
func (q *Queue) GetStats(ctx context.Context) (map[string]int, error) {
	rows, err := q.db.Query(ctx, `
		SELECT status, COUNT(*)
		FROM scan_jobs
		WHERE created_at > NOW() - INTERVAL '24 hours'
		GROUP BY status
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := map[string]int{
		"queued": 0, "running": 0, "completed": 0, "failed": 0, "cancelled": 0,
	}
	for rows.Next() {
		var s string
		var c int
		if err := rows.Scan(&s, &c); err == nil {
			stats[s] = c
		}
	}

	// Also include current live queue depth
	stats["queueDepth"] = len(q.jobs)

	return stats, nil
}

// pow returns base^exp for small positive integers.
func pow(base, exp int) int {
	result := 1
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}
