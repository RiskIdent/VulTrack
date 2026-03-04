package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/vultrack/vultrack/internal/services"
)

const (
	nvdAPIBaseURL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	maxResultsPerPage = 2000
	
	// Rate limits
	rateLimitWithKey    = 50  // requests per 30 seconds with API key
	rateLimitWithoutKey = 5   // requests per 30 seconds without API key
	rateLimitWindow     = 30 * time.Second
)

// Syncer handles synchronization with the NVD CVE database
type Syncer struct {
	db              *pgxpool.Pool
	settingsService *services.SettingsService
	httpClient      *http.Client
	
	running    bool
	mu         sync.Mutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
	
	// Rate limiting
	requestCount int
	windowStart  time.Time
}

// New creates a new NVD syncer
func New(db *pgxpool.Pool, settingsService *services.SettingsService) *Syncer {
	return &Syncer{
		db:              db,
		settingsService: settingsService,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		stopCh:      make(chan struct{}),
		windowStart: time.Now(),
	}
}

// Start starts the background sync scheduler
func (s *Syncer) Start() {
	s.wg.Add(1)
	go s.scheduleLoop()
	log.Info().Msg("NVD syncer started")
}

// Stop stops the syncer
func (s *Syncer) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	log.Info().Msg("NVD syncer stopped")
}

// scheduleLoop runs periodic syncs based on settings
func (s *Syncer) scheduleLoop() {
	defer s.wg.Done()

	// Check if sync is needed after a short delay
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-timer.C:
			s.syncIfNeeded()
			
			interval := s.getSyncInterval()
			timer.Reset(interval)
		}
	}
}

// getSyncInterval returns the sync interval from settings
func (s *Syncer) getSyncInterval() time.Duration {
	ctx := context.Background()
	settings, err := s.settingsService.GetAll(ctx)
	if err != nil {
		return 6 * time.Hour
	}

	for _, setting := range settings {
		if setting.Key == "nvd_sync_interval_hours" {
			var hours int
			if _, err := fmt.Sscanf(setting.Value, "%d", &hours); err == nil && hours > 0 {
				return time.Duration(hours) * time.Hour
			}
		}
	}

	return 6 * time.Hour
}

// syncIfNeeded checks if sync is needed and runs it
func (s *Syncer) syncIfNeeded() {
	ctx := context.Background()
	interval := s.getSyncInterval()
	
	// Check last sync time
	lastSync, err := s.getLastSyncTime(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get NVD last sync time")
		return
	}

	if lastSync != nil {
		timeSinceSync := time.Since(*lastSync)
		if timeSinceSync < interval {
			log.Debug().
				Time("lastSync", *lastSync).
				Dur("interval", interval).
				Msg("NVD sync not needed yet")
			return
		}
	}

	// Run sync
	go func() {
		if err := s.Sync(context.Background()); err != nil {
			log.Error().Err(err).Msg("NVD sync failed")
		}
	}()
}

// TriggerSync manually triggers a sync
func (s *Syncer) TriggerSync(ctx context.Context) error {
	go func() {
		if err := s.Sync(context.Background()); err != nil {
			log.Error().Err(err).Msg("Manual NVD sync failed")
		}
	}()
	return nil
}

// Sync performs a full or incremental sync with NVD
func (s *Syncer) Sync(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("NVD sync already running")
	}
	s.running = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	// Get API key from settings
	apiKey := s.getAPIKey(ctx)
	
	// Check if this is initial sync or incremental
	lastSync, err := s.getLastSyncTime(ctx)
	if err != nil {
		return fmt.Errorf("failed to get last sync time: %w", err)
	}

	var totalProcessed int
	startTime := time.Now()

	if lastSync == nil {
		// Initial sync - load recent years
		years := s.getInitialSyncYears(ctx)
		log.Info().Int("years", years).Msg("Starting initial NVD sync")
		totalProcessed, err = s.syncFromDate(ctx, apiKey, time.Now().AddDate(-years, 0, 0))
	} else {
		// Check if this is resuming an interrupted sync or a regular incremental sync
		isResuming := s.isResumingSync(ctx)
		if isResuming {
			log.Info().Time("resumeFrom", *lastSync).Msg("Resuming interrupted NVD sync")
		} else {
			log.Info().Time("since", *lastSync).Msg("Starting incremental NVD sync")
		}
		totalProcessed, err = s.syncFromDate(ctx, apiKey, *lastSync)
	}

	if err != nil {
		s.updateSyncStatus(ctx, "failed", err.Error(), totalProcessed)
		return err
	}

	// Update sync status
	s.updateSyncStatus(ctx, "success", "", totalProcessed)
	
	log.Info().
		Int("cves", totalProcessed).
		Dur("duration", time.Since(startTime)).
		Msg("NVD sync completed")

	return nil
}

// syncFromDate syncs all CVEs modified since the given date
// NVD API allows max 120 days per request, so we chunk the requests
func (s *Syncer) syncFromDate(ctx context.Context, apiKey string, since time.Time) (int, error) {
	totalProcessed := 0
	
	// Maximum time range per API request is 120 days
	const maxDays = 120
	chunkDuration := time.Duration(maxDays) * 24 * time.Hour
	
	now := time.Now().UTC()
	chunkStart := since.UTC()
	
	for chunkStart.Before(now) {
		chunkEnd := chunkStart.Add(chunkDuration)
		if chunkEnd.After(now) {
			chunkEnd = now
		}
		
		log.Info().
			Time("from", chunkStart).
			Time("to", chunkEnd).
			Msg("Syncing NVD CVE chunk")
		
		processed, err := s.syncDateRange(ctx, apiKey, chunkStart, chunkEnd)
		if err != nil {
			return totalProcessed, err
		}
		totalProcessed += processed
		
		// Save progress after each chunk - allows resuming on restart
		s.saveChunkProgress(ctx, chunkEnd, totalProcessed)
		
		chunkStart = chunkEnd
	}

	return totalProcessed, nil
}

// saveChunkProgress saves the progress after each chunk for resumability
func (s *Syncer) saveChunkProgress(ctx context.Context, syncedUntil time.Time, recordsProcessed int) {
	_, err := s.db.Exec(ctx, `
		INSERT INTO sync_status (source_type, source_name, status, last_sync_at, records_processed, updated_at)
		VALUES ('nvd', 'nvd', 'syncing', $1, $2, NOW())
		ON CONFLICT (source_type, source_name) DO UPDATE SET
			last_sync_at = $1,
			records_processed = $2,
			updated_at = NOW()
	`, syncedUntil, recordsProcessed)
	
	if err != nil {
		log.Warn().Err(err).Msg("Failed to save NVD sync progress")
	}
}

// syncDateRange syncs CVEs for a specific date range (max 120 days)
func (s *Syncer) syncDateRange(ctx context.Context, apiKey string, startDate, endDate time.Time) (int, error) {
	processed := 0
	startIndex := 0

	for {
		select {
		case <-ctx.Done():
			return processed, ctx.Err()
		default:
		}

		// Rate limiting
		if err := s.waitForRateLimit(apiKey); err != nil {
			return processed, err
		}

		// Build request URL
		reqURL := s.buildRequestURL(startDate, endDate, startIndex)
		
		log.Debug().
			Int("startIndex", startIndex).
			Msg("Fetching NVD CVEs")

		// Make request
		resp, err := s.makeRequest(ctx, reqURL, apiKey)
		if err != nil {
			return processed, fmt.Errorf("API request failed: %w", err)
		}

		// Process results
		for _, vuln := range resp.Vulnerabilities {
			if err := s.upsertCVE(ctx, vuln.CVE); err != nil {
				log.Warn().Err(err).Str("cve", vuln.CVE.ID).Msg("Failed to upsert CVE")
				continue
			}
			processed++
		}

		log.Debug().
			Int("processed", len(resp.Vulnerabilities)).
			Int("totalResults", resp.TotalResults).
			Int("startIndex", startIndex).
			Msg("Processed NVD batch")

		// Check if more results
		startIndex += len(resp.Vulnerabilities)
		if startIndex >= resp.TotalResults || len(resp.Vulnerabilities) == 0 {
			break
		}
	}

	return processed, nil
}

// buildRequestURL builds the NVD API request URL
func (s *Syncer) buildRequestURL(startDate, endDate time.Time, startIndex int) string {
	params := url.Values{}
	// NVD API requires ISO-8601 format - using Z suffix for UTC
	params.Set("lastModStartDate", startDate.UTC().Format("2006-01-02T15:04:05.000Z"))
	params.Set("lastModEndDate", endDate.UTC().Format("2006-01-02T15:04:05.000Z"))
	params.Set("resultsPerPage", strconv.Itoa(maxResultsPerPage))
	params.Set("startIndex", strconv.Itoa(startIndex))
	
	return nvdAPIBaseURL + "?" + params.Encode()
}

// makeRequest makes an HTTP request to the NVD API
func (s *Syncer) makeRequest(ctx context.Context, reqURL, apiKey string) (*NVDResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "VulTrack/1.0")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("rate limited by NVD API")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &nvdResp, nil
}

// waitForRateLimit implements rate limiting
func (s *Syncer) waitForRateLimit(apiKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	limit := rateLimitWithoutKey
	if apiKey != "" {
		limit = rateLimitWithKey
	}

	// Reset window if needed
	if time.Since(s.windowStart) >= rateLimitWindow {
		s.requestCount = 0
		s.windowStart = time.Now()
	}

	// Check if we need to wait
	if s.requestCount >= limit {
		waitTime := rateLimitWindow - time.Since(s.windowStart)
		if waitTime > 0 {
			log.Debug().Dur("wait", waitTime).Msg("Rate limit reached, waiting")
			s.mu.Unlock()
			time.Sleep(waitTime)
			s.mu.Lock()
			s.requestCount = 0
			s.windowStart = time.Now()
		}
	}

	s.requestCount++
	return nil
}

// upsertCVE inserts or updates a CVE in the database
func (s *Syncer) upsertCVE(ctx context.Context, cve CVE) error {
	// Extract description (prefer English)
	description := ""
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			description = desc.Value
			break
		}
	}
	if description == "" && len(cve.Descriptions) > 0 {
		description = cve.Descriptions[0].Value
	}

	// Extract CVSS scores
	var cvss2Score, cvss3Score *float64
	var cvss2Vector, cvss3Vector, cvss3Severity string

	if cve.Metrics.CVSSV2 != nil && len(cve.Metrics.CVSSV2) > 0 {
		score := cve.Metrics.CVSSV2[0].CVSSData.BaseScore
		cvss2Score = &score
		cvss2Vector = cve.Metrics.CVSSV2[0].CVSSData.VectorString
	}

	if cve.Metrics.CVSSV31 != nil && len(cve.Metrics.CVSSV31) > 0 {
		score := cve.Metrics.CVSSV31[0].CVSSData.BaseScore
		cvss3Score = &score
		cvss3Vector = cve.Metrics.CVSSV31[0].CVSSData.VectorString
		cvss3Severity = cve.Metrics.CVSSV31[0].CVSSData.BaseSeverity
	} else if cve.Metrics.CVSSV30 != nil && len(cve.Metrics.CVSSV30) > 0 {
		score := cve.Metrics.CVSSV30[0].CVSSData.BaseScore
		cvss3Score = &score
		cvss3Vector = cve.Metrics.CVSSV30[0].CVSSData.VectorString
		cvss3Severity = cve.Metrics.CVSSV30[0].CVSSData.BaseSeverity
	}

	// Extract CWE IDs
	var cweIDs []string
	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
			if desc.Lang == "en" && desc.Value != "NVD-CWE-noinfo" && desc.Value != "NVD-CWE-Other" {
				cweIDs = append(cweIDs, desc.Value)
			}
		}
	}

	// Parse timestamps
	var publishedAt, modifiedAt *time.Time
	if cve.Published != "" {
		if t, err := time.Parse(time.RFC3339, cve.Published); err == nil {
			publishedAt = &t
		}
	}
	if cve.LastModified != "" {
		if t, err := time.Parse(time.RFC3339, cve.LastModified); err == nil {
			modifiedAt = &t
		}
	}

	// Upsert CVE
	_, err := s.db.Exec(ctx, `
		INSERT INTO cve_catalog (cve_id, description, cvss2_score, cvss2_vector, 
			cvss3_score, cvss3_vector, cvss3_severity, cwe_ids, published_at, modified_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
		ON CONFLICT (cve_id) DO UPDATE SET
			description = EXCLUDED.description,
			cvss2_score = EXCLUDED.cvss2_score,
			cvss2_vector = EXCLUDED.cvss2_vector,
			cvss3_score = EXCLUDED.cvss3_score,
			cvss3_vector = EXCLUDED.cvss3_vector,
			cvss3_severity = EXCLUDED.cvss3_severity,
			cwe_ids = EXCLUDED.cwe_ids,
			published_at = EXCLUDED.published_at,
			modified_at = EXCLUDED.modified_at,
			updated_at = NOW()
	`, cve.ID, description, cvss2Score, cvss2Vector, cvss3Score, cvss3Vector, 
		cvss3Severity, cweIDs, publishedAt, modifiedAt)

	if err != nil {
		return err
	}

	// Upsert references
	for _, ref := range cve.References {
		_, err := s.db.Exec(ctx, `
			INSERT INTO cve_references (cve_id, url, source, tags)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING
		`, cve.ID, ref.URL, ref.Source, ref.Tags)
		if err != nil {
			log.Warn().Err(err).Str("cve", cve.ID).Str("url", ref.URL).Msg("Failed to insert reference")
		}
	}

	return nil
}

// getAPIKey returns the NVD API key from settings
func (s *Syncer) getAPIKey(ctx context.Context) string {
	settings, err := s.settingsService.GetAll(ctx)
	if err != nil {
		return ""
	}

	for _, setting := range settings {
		if setting.Key == "nvd_api_key" {
			return setting.Value
		}
	}
	return ""
}

// getInitialSyncYears returns how many years of CVE history to load
func (s *Syncer) getInitialSyncYears(ctx context.Context) int {
	settings, err := s.settingsService.GetAll(ctx)
	if err != nil {
		return 5
	}

	for _, setting := range settings {
		if setting.Key == "nvd_initial_sync_years" {
			var years int
			if _, err := fmt.Sscanf(setting.Value, "%d", &years); err == nil && years > 0 {
				return years
			}
		}
	}
	return 5
}

// getLastSyncTime returns the last NVD sync time (success or in-progress for resumability)
func (s *Syncer) getLastSyncTime(ctx context.Context) (*time.Time, error) {
	var lastSync *time.Time
	// Check for any sync (success or syncing) - allows resuming interrupted syncs
	err := s.db.QueryRow(ctx, `
		SELECT last_sync_at FROM sync_status 
		WHERE source_type = 'nvd' AND source_name = 'nvd' 
		  AND status IN ('success', 'syncing')
		  AND last_sync_at IS NOT NULL
		ORDER BY last_sync_at DESC LIMIT 1
	`).Scan(&lastSync)
	
	if err != nil && err.Error() != "no rows in result set" {
		return nil, err
	}
	return lastSync, nil
}

// isResumingSync checks if we're resuming an interrupted sync
func (s *Syncer) isResumingSync(ctx context.Context) bool {
	var status string
	err := s.db.QueryRow(ctx, `
		SELECT status FROM sync_status 
		WHERE source_type = 'nvd' AND source_name = 'nvd'
	`).Scan(&status)
	
	if err != nil {
		return false
	}
	return status == "syncing"
}

// updateSyncStatus updates the sync status in the database
func (s *Syncer) updateSyncStatus(ctx context.Context, status, errorMsg string, recordsProcessed int) {
	_, err := s.db.Exec(ctx, `
		INSERT INTO sync_status (source_type, source_name, status, last_sync_at, error_message, records_processed, updated_at)
		VALUES ('nvd', 'nvd', $1, NOW(), $2, $3, NOW())
		ON CONFLICT (source_type, source_name) DO UPDATE SET
			status = EXCLUDED.status,
			last_sync_at = EXCLUDED.last_sync_at,
			error_message = EXCLUDED.error_message,
			records_processed = EXCLUDED.records_processed,
			updated_at = NOW()
	`, status, errorMsg, recordsProcessed)
	
	if err != nil {
		log.Error().Err(err).Msg("Failed to update NVD sync status")
	}
}

// IsSyncing returns true if a sync is currently running
func (s *Syncer) IsSyncing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
