package oval

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/ulikunitz/xz"

	"github.com/vultrack/vultrack/internal/models"
	"github.com/vultrack/vultrack/internal/services"
)

// Syncer handles OVAL feed synchronization
type Syncer struct {
	ovalService     *services.OVALService
	settingsService *services.SettingsService
	// pkgFeedService is optional: without it, sources of type 'pkg' are skipped
	// and VulTrack behaves exactly as it did with the OVAL feeds alone.
	pkgFeedService *services.PkgFeedService
	httpClient     *http.Client

	stopCh  chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	running map[int64]bool // Track running syncs by source ID
}

// NewSyncer creates a new OVAL Syncer. pkgFeedService may be nil, in which case
// Canonical's package vulnerability feed is not imported.
func NewSyncer(ovalService *services.OVALService, settingsService *services.SettingsService, pkgFeedService *services.PkgFeedService) *Syncer {
	return &Syncer{
		ovalService:     ovalService,
		settingsService: settingsService,
		pkgFeedService:  pkgFeedService,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute, // OVAL files can be large
		},
		stopCh:  make(chan struct{}),
		running: make(map[int64]bool),
	}
}

// Start starts the background sync scheduler
func (s *Syncer) Start() {
	s.wg.Add(1)
	go s.scheduleLoop()
	log.Info().Msg("OVAL syncer started")
}

// Stop stops the syncer
func (s *Syncer) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	log.Info().Msg("OVAL syncer stopped")
}

// scheduleLoop runs periodic syncs based on settings
func (s *Syncer) scheduleLoop() {
	defer s.wg.Done()

	// Check if sync is needed after a short delay (let DB initialize)
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-timer.C:
			// Only sync if enough time has passed since last sync
			s.syncIfNeeded()

			// Check again after the interval
			interval := s.getSyncInterval()
			timer.Reset(interval)
		}
	}
}

// syncIfNeeded checks each source and only syncs if the interval has passed
func (s *Syncer) syncIfNeeded() {
	ctx := context.Background()
	interval := s.getSyncInterval()

	sources, err := s.ovalService.GetSources(ctx, true) // enabled only
	if err != nil {
		log.Error().Err(err).Msg("Failed to get OVAL sources")
		return
	}

	if len(sources) == 0 {
		log.Debug().Msg("No enabled OVAL sources to sync")
		return
	}

	now := time.Now()
	syncCount := 0

	for _, source := range sources {
		// Check when this source was last synced
		needsSync := false

		if source.LastSyncAt == nil {
			// Never synced
			needsSync = true
		} else {
			timeSinceSync := now.Sub(*source.LastSyncAt)
			if timeSinceSync >= interval {
				needsSync = true
			}
		}

		if needsSync {
			syncCount++
			go func(src models.OVALSource) {
				if err := s.SyncSource(context.Background(), src.ID); err != nil {
					log.Error().Err(err).
						Str("distribution", src.Distribution).
						Str("version", src.Version).
						Msg("Failed to sync OVAL source")
				}
			}(source)
		} else {
			log.Debug().
				Str("distribution", source.Distribution).
				Str("version", source.Version).
				Time("lastSync", *source.LastSyncAt).
				Msg("OVAL source sync not needed yet")
		}
	}

	if syncCount > 0 {
		log.Info().Int("count", syncCount).Msg("Starting OVAL sync for sources that need update")
	}
}

// getSyncInterval returns the sync interval from settings
func (s *Syncer) getSyncInterval() time.Duration {
	ctx := context.Background()
	settings, err := s.settingsService.GetAll(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get settings, using default interval")
		return 24 * time.Hour
	}

	for _, setting := range settings {
		if setting.Key == "oval_sync_interval_hours" {
			var hours int
			if _, err := fmt.Sscanf(setting.Value, "%d", &hours); err == nil && hours > 0 {
				return time.Duration(hours) * time.Hour
			}
		}
	}

	return 24 * time.Hour
}

// syncAll syncs all enabled OVAL sources
func (s *Syncer) syncAll() {
	ctx := context.Background()

	sources, err := s.ovalService.GetSources(ctx, true) // enabled only
	if err != nil {
		log.Error().Err(err).Msg("Failed to get OVAL sources")
		return
	}

	if len(sources) == 0 {
		log.Debug().Msg("No enabled OVAL sources to sync")
		return
	}

	log.Info().Int("count", len(sources)).Msg("Starting OVAL sync for enabled sources")

	for _, source := range sources {
		select {
		case <-s.stopCh:
			return
		default:
			if err := s.SyncSource(ctx, source.ID); err != nil {
				log.Error().Err(err).
					Str("distribution", source.Distribution).
					Str("version", source.Version).
					Msg("Failed to sync OVAL source")
			}
		}
	}
}

// SyncSource syncs a single OVAL source
func (s *Syncer) SyncSource(ctx context.Context, sourceID int64) error {
	// Check if already running
	s.mu.Lock()
	if s.running[sourceID] {
		s.mu.Unlock()
		return fmt.Errorf("sync already running for source %d", sourceID)
	}
	s.running[sourceID] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.running, sourceID)
		s.mu.Unlock()
	}()

	// Get source info
	source, err := s.ovalService.GetSourceByID(ctx, sourceID)
	if err != nil {
		return fmt.Errorf("failed to get source: %w", err)
	}
	if source == nil {
		return fmt.Errorf("source not found: %d", sourceID)
	}

	log.Info().
		Str("distribution", source.Distribution).
		Str("version", source.Version).
		Str("sourceType", source.SourceType).
		Str("url", source.URL).
		Msg("Starting OVAL sync")

	// Create sync status
	sourceName := fmt.Sprintf("%s-%s", source.Distribution, source.Version)
	syncStatus, err := s.ovalService.CreateSyncStatus(ctx, "oval", sourceName)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to create sync status")
	}

	fail := func(stage string, cause error) error {
		errMsg := fmt.Sprintf("%s failed: %v", stage, cause)
		s.ovalService.UpdateSyncStatus(ctx, sourceID, "failed", errMsg)
		if syncStatus != nil {
			s.ovalService.CompleteSyncStatus(ctx, syncStatus.ID, "failed", errMsg)
		}
		return fmt.Errorf("failed to %s %s source: %w", stage, source.SourceType, cause)
	}

	if source.SourceType == models.SourceTypePkg {
		return s.syncPkgSource(ctx, source, syncStatus, fail)
	}

	// Download OVAL file
	xmlData, err := s.downloadOVAL(ctx, source.URL)
	if err != nil {
		return fail("download", err)
	}

	log.Info().
		Str("distribution", source.Distribution).
		Str("version", source.Version).
		Int("size", len(xmlData)).
		Msg("Downloaded OVAL file")

	// Parse and store OVAL data
	parser := NewParser(s.ovalService)
	stats, err := parser.ParseAndStore(ctx, sourceID, xmlData)
	if err != nil {
		return fail("parse", err)
	}

	// The import replaced this source's whole dataset; refresh planner
	// statistics so the following scans do not run on stale ones.
	if err := s.ovalService.AnalyzeOVALTables(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to refresh OVAL table statistics; scans may be slow until autovacuum runs")
	}

	// Update sync status
	s.ovalService.UpdateSyncStatus(ctx, sourceID, "success", "")
	if syncStatus != nil {
		s.ovalService.UpdateSyncProgress(ctx, syncStatus.ID, stats.TotalDefinitions)
		s.ovalService.CompleteSyncStatus(ctx, syncStatus.ID, "success", "")
	}

	log.Info().
		Str("distribution", source.Distribution).
		Str("version", source.Version).
		Str("sourceType", source.SourceType).
		Int("definitions", stats.TotalDefinitions).
		Int("tests", stats.TotalTests).
		Int("objects", stats.TotalObjects).
		Int("states", stats.TotalStates).
		Msg("OVAL sync completed")

	return nil
}

// syncPkgSource imports Canonical's package vulnerability feed for a source of
// type 'pkg'. The feed is streamed straight from the HTTP response through the
// xz decompressor into the parser: uncompressed it is around 170 MB, which is
// not worth holding in memory.
func (s *Syncer) syncPkgSource(ctx context.Context, source *models.OVALSource, syncStatus *models.SyncStatus, fail func(string, error) error) error {
	if s.pkgFeedService == nil {
		return fail("import", fmt.Errorf("package vulnerability feed support is not configured"))
	}

	body, err := s.openStream(ctx, source.URL)
	if err != nil {
		return fail("download", err)
	}
	defer body.Close()

	xzReader, err := xz.NewReader(body)
	if err != nil {
		return fail("download", fmt.Errorf("failed to open xz stream: %w", err))
	}

	stats, err := NewPkgParser(s.pkgFeedService).ParseAndStore(ctx, source.ID, xzReader)
	if err != nil {
		return fail("parse", err)
	}

	// The import replaced this source's whole dataset; refresh planner
	// statistics so the following scans do not run on stale ones.
	if err := s.pkgFeedService.AnalyzePkgTables(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to refresh package feed statistics; scans may be slow until autovacuum runs")
	}

	// Fill CVSS scores and descriptions NVD has not delivered yet.
	backfilled, err := s.pkgFeedService.BackfillCVECatalog(ctx, source.ID)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to backfill the CVE catalog from the package feed")
	}

	s.ovalService.UpdateSyncStatus(ctx, source.ID, "success", "")
	if syncStatus != nil {
		s.ovalService.UpdateSyncProgress(ctx, syncStatus.ID, stats.CVEStatuses)
		s.ovalService.CompleteSyncStatus(ctx, syncStatus.ID, "success", "")
	}

	log.Info().
		Str("distribution", source.Distribution).
		Str("version", source.Version).
		Str("sourceType", source.SourceType).
		Int("sourcePackages", stats.SourcePackages).
		Int("kernelPackages", stats.KernelPackages).
		Int("binaryVersions", stats.BinaryVersions).
		Int("cveStatuses", stats.CVEStatuses).
		Int("cveMetadata", stats.CVEMetadata).
		Int("skippedNotVulnerable", stats.SkippedStatus).
		Int64("cveCatalogBackfilled", backfilled).
		Msg("Package vulnerability feed sync completed")

	return nil
}

// openStream performs the GET and returns the undecoded response body. The
// caller closes it and applies whatever decompression the format needs.
func (s *Syncer) openStream(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulTrack/1.0")
	req.Header.Set("Accept", "application/json, application/x-xz")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}
	return resp.Body, nil
}

// downloadOVAL downloads an OVAL file from the given URL
func (s *Syncer) downloadOVAL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "VulTrack/1.0")
	req.Header.Set("Accept", "application/xml, application/x-bzip2, application/gzip")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Handle compressed responses
	var reader io.Reader = resp.Body

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "bzip2") || strings.HasSuffix(url, ".bz2") {
		reader = bzip2.NewReader(resp.Body)
	} else if strings.Contains(contentType, "gzip") || strings.HasSuffix(url, ".gz") {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return data, nil
}

// TriggerSync manually triggers a sync for a source
func (s *Syncer) TriggerSync(ctx context.Context, sourceID int64) error {
	go func() {
		if err := s.SyncSource(context.Background(), sourceID); err != nil {
			log.Error().Err(err).Int64("sourceId", sourceID).Msg("Manual OVAL sync failed")
		}
	}()
	return nil
}

// TriggerSyncAll manually triggers sync for all enabled sources
func (s *Syncer) TriggerSyncAll(ctx context.Context) error {
	go s.syncAll()
	return nil
}

// IsSyncing returns true if a sync is running for the given source
func (s *Syncer) IsSyncing(sourceID int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[sourceID]
}

// GetSourceForServer finds the best matching OVAL source for a server
func (s *Syncer) GetSourceForServer(ctx context.Context, server *models.Server) (*models.OVALSource, error) {
	// Try exact match first
	source, err := s.ovalService.GetSourceByDistroVersion(ctx, server.OSFamily, server.OSRelease)
	if err != nil {
		return nil, err
	}
	if source != nil && source.IsEnabled {
		return source, nil
	}

	// Try by codename if available
	if server.OSCodename != "" {
		sources, err := s.ovalService.GetSources(ctx, true)
		if err != nil {
			return nil, err
		}
		for _, src := range sources {
			if src.Distribution == server.OSFamily && src.Codename == server.OSCodename {
				return &src, nil
			}
		}
	}

	return nil, nil
}
